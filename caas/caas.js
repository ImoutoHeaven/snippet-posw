// Cloudflare Snippet/Worker: Challenge-as-a-Service (CaaS)
// - postMessage-first (iframe/popup), redirect fallback
// - stateless tokens (HMAC + AEAD)
// - Phase 2 (PoW) included in this file; does not rely on request.cf bindings

const DEFAULTS = {
  API_PREFIX: "/__pow/v1",
  CAAS_VERSION: 1,

  POW_TOKEN: "",
  SERVICE_TOKEN: "",

  TURNSTILE_SITEKEY: "",
  TURNSTILE_SECRET: "",

  ALLOWED_PARENT_ORIGINS: [],
  ALLOWED_CLIENT_ORIGINS: [],

  CAAS_GLUE_URL: "",
  CAAS_POW_ESM_URL: "",

  CHAL_TTL_SEC: 300,
  STATE_TTL_SEC: 300,
  PROOF_TTL_SEC: 600,
  CTX_B64_MAX_LEN: 32768,
  CHAL_B64_MAX_LEN: 65536,
  STATE_B64_MAX_LEN: 4096,
  LANDING_CHAL_MAX_LEN: 4096,

  POW_STEPS: 2048,
  POW_MIN_STEPS: 512,
  POW_MAX_STEPS: 8192,
  POW_HASHCASH_BITS: 3,
  POW_SEGMENT_LEN: "48-64",
  POW_SAMPLE_K: 15,
  POW_SPINE_K: 2,
  POW_CHAL_ROUNDS: 12,
  POW_OPEN_BATCH: 15,
  POW_FORCE_EDGE_1: true,
  POW_FORCE_EDGE_LAST: true,
  POW_COMMIT_TTL_SEC: 300,
};

// Configuration:
// - For single-site deployment: set CONFIG to an object.
// - For multi-site deployment: set CONFIG to an array of `{ pattern, config }` entries
//   (first-match-wins; pattern syntax matches the Gate snippet).
const CONFIG = {
  // Master secret used for chal/state/proofToken HMAC + AES-GCM ctx sealing.
  POW_TOKEN: "replace-with-powToken",

  // Auth token for backend callers (server/* endpoints).
  SERVICE_TOKEN: "replace-with-serviceToken",

  // Turnstile
  TURNSTILE_SITEKEY: "replace-with-sitekey",
  TURNSTILE_SECRET: "replace-with-secret",

  // Allowlist of parent origins (for CSP frame-ancestors + postMessage origin checks).
  // Example: ["https://app.example.com", "http://localhost:8788"]
  ALLOWED_PARENT_ORIGINS: [],

  // Optional CORS allowlist if your app calls /client/* directly (instead of same-origin landing).
  ALLOWED_CLIENT_ORIGINS: [],

  // Landing page dynamically imports this glue module (recommended: self-host or trusted CDN).
  // Example: "https://caas.example.com/assets/caas-glue.js"
  CAAS_GLUE_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@bb71f3ec21ec7a5a46126d997ce7374159fabea7/caas/glue.js",

  // PoW solver (computePoswCommit) module URL (recommended: self-host / pin the version).
  // Example: "https://caas.example.com/assets/esm.js"
  CAAS_POW_ESM_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@bb71f3ec21ec7a5a46126d997ce7374159fabea7/caas/esm/esm.js",
};

const HTML_TEMPLATE = typeof __HTML_TEMPLATE__ === "string" ? __HTML_TEMPLATE__ : "";

const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

// --- Optional multi-site config picker (pattern syntax matches Gate) ---

const splitPattern = (pattern) => {
  if (typeof pattern !== "string") return null;
  const trimmed = pattern.trim();
  if (!trimmed) return null;
  const slashIndex = trimmed.indexOf("/");
  if (slashIndex === -1) return { host: trimmed, path: null };
  const host = trimmed.slice(0, slashIndex);
  if (!host) return null;
  return { host, path: trimmed.slice(slashIndex) };
};

const escapeRegex = (value) => value.replace(/[.+?^${}()|[\]\\]/g, "\\$&");

const compileHostPattern = (pattern) => {
  if (typeof pattern !== "string") return null;
  const host = pattern.trim().toLowerCase();
  if (!host) return null;
  const escaped = escapeRegex(host).replace(/\*/g, "[^.]*");
  try {
    return new RegExp(`^${escaped}$`);
  } catch {
    return null;
  }
};

const compilePathPattern = (pattern) => {
  if (typeof pattern !== "string") return null;
  const path = pattern.trim();
  if (!path.startsWith("/")) return null;
  let out = "";
  for (let i = 0; i < path.length; i++) {
    const ch = path[i];
    if (ch === "*") {
      if (path[i + 1] === "*") {
        const isLast = i + 2 >= path.length;
        const prevIsSlash = i > 0 && path[i - 1] === "/";
        if (isLast && prevIsSlash && out.endsWith("/") && out.length > 1) {
          out = `${out.slice(0, -1)}(?:/.*)?`;
        } else {
          out += ".*";
        }
        i++;
      } else {
        out += "[^/]*";
      }
      continue;
    }
    out += /[.+?^${}()|[\]\\]/.test(ch) ? `\\${ch}` : ch;
  }
  try {
    return new RegExp(`^${out}$`);
  } catch {
    return null;
  }
};

const compileConfigEntry = (entry) => {
  const pattern = entry && entry.pattern;
  const parts = splitPattern(pattern);
  if (!parts) {
    return { pattern, hostRegex: null, pathRegex: null, config: (entry && entry.config) || {} };
  }
  const hostRegex = compileHostPattern(parts.host);
  if (!hostRegex) {
    return { pattern, hostRegex: null, pathRegex: null, config: (entry && entry.config) || {} };
  }
  const pathRegex = parts.path ? compilePathPattern(parts.path) : null;
  if (parts.path && !pathRegex) {
    return { pattern, hostRegex: null, pathRegex: null, config: (entry && entry.config) || {} };
  }
  return { pattern, hostRegex, pathRegex, config: (entry && entry.config) || {} };
};

const USE_CONFIG_LIST = Array.isArray(CONFIG);
const COMPILED_CONFIG = USE_CONFIG_LIST ? CONFIG.map(compileConfigEntry) : null;

const pickConfig = (hostname, path) => {
  if (!COMPILED_CONFIG) return null;
  const host = typeof hostname === "string" ? hostname.toLowerCase() : "";
  const requestPath = typeof path === "string" ? path : "";
  if (!host) return null;
  for (let i = 0; i < COMPILED_CONFIG.length; i++) {
    const rule = COMPILED_CONFIG[i];
    if (!rule || !rule.hostRegex) continue;
    if (!rule.hostRegex.test(host)) continue;
    if (rule.pathRegex && !rule.pathRegex.test(requestPath)) continue;
    return rule.config || null;
  }
  return null;
};

const getEffectiveConfig = (hostname, requestPath) => {
  if (!USE_CONFIG_LIST) return { ...DEFAULTS, ...CONFIG };
  const picked = pickConfig(hostname, requestPath);
  return picked ? { ...DEFAULTS, ...picked } : null;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hmacKeyCache = new Map();
const aeadKeyCache = new Map();

const utf8ToBytes = (value) => encoder.encode(String(value ?? ""));
const bytesToUtf8 = (bytes) => decoder.decode(bytes);

const base64UrlEncode = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_");
const base64UrlEncodeNoPad = (bytes) => base64UrlEncode(bytes).replace(/=+$/g, "");

const base64UrlDecodeToBytes = (b64u) => {
  if (!b64u || typeof b64u !== "string") return null;
  let b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
};

const b64uJsonEncode = (obj) => base64UrlEncodeNoPad(utf8ToBytes(JSON.stringify(obj)));
const b64uJsonDecode = (b64u) => {
  const bytes = base64UrlDecodeToBytes(b64u);
  if (!bytes) return null;
  try {
    const obj = JSON.parse(bytesToUtf8(bytes));
    return obj && typeof obj === "object" ? obj : null;
  } catch {
    return null;
  }
};

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const B64_HASH_MAX_LEN = 64;
const B64_TICKET_MAX_LEN = 4096;
const NONCE_MIN_LEN = 16;
const NONCE_MAX_LEN = 64;
const SID_LEN = 16;
const TOKEN_MIN_LEN = 16;
const TOKEN_MAX_LEN = 64;
const TB_LEN = 16;
const TURN_TOKEN_MIN_LEN = 20;
const TURN_TOKEN_MAX_LEN = 4096;
const SPINE_SEED_MIN_LEN = 16;
const SPINE_SEED_MAX_LEN = 64;
const MAX_PROOF_SIBS = 64;
const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;

const isBase64Url = (value, minLen, maxLen) => {
  if (typeof value !== "string") return false;
  const len = value.length;
  if (len < minLen || len > maxLen) return false;
  return BASE64URL_RE.test(value);
};

const isBase64UrlOrAny = (value, minLen, maxLen) =>
  value === "any" || isBase64Url(value, minLen, maxLen);

const normalizeNumber = (value, fallback) => {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
};

const normalizeApiPrefix = (value, fallback) => {
  const raw = typeof value === "string" ? value.trim() : "";
  const base = raw || (typeof fallback === "string" ? fallback.trim() : "");
  if (!base) return null;
  let out = base.startsWith("/") ? base : `/${base}`;
  while (out.length > 1 && out.endsWith("/")) out = out.slice(0, -1);
  if (out === "/") return null;
  return out;
};

const normalizePath = (pathname) => {
  if (typeof pathname !== "string") return null;
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  if (decoded.length === 0) return "/";
  return decoded.startsWith("/") ? decoded : `/${decoded}`;
};

const timingSafeEqual = (a, b) => {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) {
    const ca = i < a.length ? a.charCodeAt(i) : 0;
    const cb = i < b.length ? b.charCodeAt(i) : 0;
    diff |= ca ^ cb;
  }
  return diff === 0;
};

const randomBase64Url = (byteLength) => {
  const len = Number.isInteger(byteLength) && byteLength > 0 ? byteLength : 16;
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return base64UrlEncodeNoPad(bytes);
};

const base64EncodeNoPad = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/=+$/g, "");

const randomBase64NoPad = (byteLength) => {
  const len = Number.isInteger(byteLength) && byteLength > 0 ? byteLength : 16;
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return base64EncodeNoPad(bytes);
};

const sha256Bytes = async (data) => {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
};

const validateTurnToken = (value) => {
  if (typeof value !== "string") return null;
  const token = value.trim();
  if (token.length < TURN_TOKEN_MIN_LEN || token.length > TURN_TOKEN_MAX_LEN) return null;
  if (CONTROL_CHAR_RE.test(token)) return null;
  return token;
};

const tbFromToken = async (token) =>
  base64UrlEncodeNoPad((await sha256Bytes(token)).slice(0, 12));

const getHmacKey = (secret) => {
  const key = typeof secret === "string" ? secret : "";
  if (!key) return Promise.reject(new Error("HMAC secret missing"));
  if (!hmacKeyCache.has(key)) {
    hmacKeyCache.set(
      key,
      crypto.subtle.importKey(
        "raw",
        encoder.encode(key),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      )
    );
  }
  return hmacKeyCache.get(key);
};

const hmacSha256 = async (secret, data) => {
  const key = await getHmacKey(secret);
  const payload = encoder.encode(data);
  const buf = await crypto.subtle.sign("HMAC", key, payload);
  return new Uint8Array(buf);
};

const hmacSha256Base64UrlNoPad = async (secret, data) => {
  const bytes = await hmacSha256(secret, data);
  return base64UrlEncodeNoPad(bytes);
};

const getAeadKey = async (secret) => {
  const key = typeof secret === "string" ? secret : "";
  if (!key) throw new Error("AEAD secret missing");
  if (!aeadKeyCache.has(key)) {
    aeadKeyCache.set(
      key,
      (async () => {
        const digest = await sha256Bytes(`caas-ctx-key|${key}`);
        return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"]);
      })()
    );
  }
  return aeadKeyCache.get(key);
};

const aeadEncrypt = async (secret, plaintextBytes, aadBytes) => {
  const key = await getAeadKey(secret);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const buf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aadBytes || new Uint8Array() },
    key,
    plaintextBytes
  );
  return {
    iv: base64UrlEncodeNoPad(iv),
    ct: base64UrlEncodeNoPad(new Uint8Array(buf)),
  };
};

const aeadDecrypt = async (secret, enc, aadBytes) => {
  const key = await getAeadKey(secret);
  const ivBytes = base64UrlDecodeToBytes(enc && enc.iv);
  const ctBytes = base64UrlDecodeToBytes(enc && enc.ct);
  if (!ivBytes || !ctBytes) return null;
  try {
    const buf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes, additionalData: aadBytes || new Uint8Array() },
      key,
      ctBytes
    );
    return new Uint8Array(buf);
  } catch {
    return null;
  }
};

const clampInt = (value, lo, hi) => {
  const num = Number(value);
  if (!Number.isFinite(num)) return lo;
  return Math.max(lo, Math.min(hi, Math.floor(num)));
};

const normalizeMaxLen = (value, fallback) => {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.max(1, Math.floor(num));
};

const normalizeMaxLenAllowZero = (value, fallback) => {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.max(0, Math.floor(num));
};

const getCtxB64MaxLen = (config) =>
  normalizeMaxLen(config?.CTX_B64_MAX_LEN, DEFAULTS.CTX_B64_MAX_LEN);
const getChalB64MaxLen = (config) =>
  normalizeMaxLen(config?.CHAL_B64_MAX_LEN, DEFAULTS.CHAL_B64_MAX_LEN);
const getStateB64MaxLen = (config) =>
  normalizeMaxLen(config?.STATE_B64_MAX_LEN, DEFAULTS.STATE_B64_MAX_LEN);
const getLandingChalMaxLen = (config) =>
  normalizeMaxLenAllowZero(config?.LANDING_CHAL_MAX_LEN, DEFAULTS.LANDING_CHAL_MAX_LEN);

const normalizeOrigin = (raw) => {
  if (typeof raw !== "string") return null;
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (!/^https?:$/.test(url.protocol)) return null;
  if (url.username || url.password) return null;
  return url.origin;
};

const isOriginAllowed = (origin, allowlist) => {
  if (!origin) return false;
  if (!Array.isArray(allowlist) || allowlist.length === 0) return false;
  return allowlist.includes(origin);
};

const validateReturnUrl = (raw, parentOrigin) => {
  if (typeof raw !== "string" || !raw) return null;
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (!/^https?:$/.test(url.protocol)) return null;
  if (url.origin !== parentOrigin) return null;
  if (!url.pathname || !url.pathname.startsWith("/")) return null;
  if (url.username || url.password) return null;
  return url.toString();
};

const S = (status, headers) => new Response(null, { status, headers });
const T = (text, status, headers) => new Response(text, { status, headers });
const J = (obj, status = 200, headers) => {
  const h = headers instanceof Headers ? headers : new Headers(headers || {});
  h.set("Content-Type", "application/json; charset=utf-8");
  h.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(obj ?? null), { status, headers: h });
};

const deny = () => J({ ok: false }, 403);

const requireAuth = (request, config) => {
  const service = typeof config.SERVICE_TOKEN === "string" ? config.SERVICE_TOKEN : "";
  if (!service) return false;
  const got = request.headers.get("Authorization") || "";
  const want = `Bearer ${service}`;
  return timingSafeEqual(got, want);
};

const parseChal = async (powSecret, chal, payloadMaxLen = DEFAULTS.CHAL_B64_MAX_LEN) => {
  const parts = String(chal || "").split(".");
  if (parts.length !== 3 || parts[0] !== "c1") return null;
  const payloadB64 = parts[1] || "";
  const mac = parts[2] || "";
  if (!isBase64Url(payloadB64, 1, payloadMaxLen)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  const expected = await hmacSha256Base64UrlNoPad(powSecret, `chal|${payloadB64}`);
  if (!timingSafeEqual(expected, mac)) return null;
  const payload = b64uJsonDecode(payloadB64);
  if (!payload) return null;
  const chalIdBytes = await sha256Bytes(`chalid|${payloadB64}`);
  const chalId = base64UrlEncodeNoPad(chalIdBytes);
  return { payload, payloadB64, chalId };
};

const makeChal = async (powSecret, payload) => {
  const payloadB64 = b64uJsonEncode(payload);
  const mac = await hmacSha256Base64UrlNoPad(powSecret, `chal|${payloadB64}`);
  const chalIdBytes = await sha256Bytes(`chalid|${payloadB64}`);
  const chalId = base64UrlEncodeNoPad(chalIdBytes);
  return { chal: `c1.${payloadB64}.${mac}`, chalId, payloadB64 };
};

const parseState = async (powSecret, state, payloadMaxLen = DEFAULTS.STATE_B64_MAX_LEN) => {
  const parts = String(state || "").split(".");
  if (parts.length !== 3 || parts[0] !== "s1") return null;
  const payloadB64 = parts[1] || "";
  const mac = parts[2] || "";
  if (!isBase64Url(payloadB64, 1, payloadMaxLen)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  const expected = await hmacSha256Base64UrlNoPad(powSecret, `state|${payloadB64}`);
  if (!timingSafeEqual(expected, mac)) return null;
  return b64uJsonDecode(payloadB64);
};

const makeState = async (powSecret, payload) => {
  const payloadB64 = b64uJsonEncode(payload);
  const mac = await hmacSha256Base64UrlNoPad(powSecret, `state|${payloadB64}`);
  return `s1.${payloadB64}.${mac}`;
};

const makeProofToken = async (powSecret, mask, chalId, iat, exp) => {
  const m = Number(mask);
  if (!Number.isFinite(m) || m < 0 || m > 3) {
    throw new Error("invalid proof mask");
  }
  const mac = await hmacSha256Base64UrlNoPad(
    powSecret,
    `proof|${m}|${chalId}|${iat}|${exp}`
  );
  return `p1.${m}.${chalId}.${iat}.${exp}.${mac}`;
};

const verifyProofToken = async (powSecret, requiredMask, token, chalId, nowSeconds) => {
  const parts = String(token || "").split(".");
  if (parts.length !== 6 || parts[0] !== "p1") return null;
  if (parts[2] !== chalId) return null;
  const m = Number.parseInt(parts[1], 10);
  const iat = Number.parseInt(parts[3], 10);
  const exp = Number.parseInt(parts[4], 10);
  const mac = parts[5] || "";
  if (!Number.isFinite(m) || m < 0 || m > 3) return null;
  if (!Number.isFinite(iat) || !Number.isFinite(exp)) return null;
  if (exp <= nowSeconds) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  if ((m & requiredMask) !== requiredMask) return null;
  const expected = await hmacSha256Base64UrlNoPad(
    powSecret,
    `proof|${m}|${chalId}|${iat}|${exp}`
  );
  if (!timingSafeEqual(expected, mac)) return null;
  return { mask: m, iat, exp };
};

const buildLandingHtml = (config, cfgObj, scriptNonce) => {
  const glueUrl =
    typeof config.CAAS_GLUE_URL === "string" && config.CAAS_GLUE_URL
      ? config.CAAS_GLUE_URL
      : "";
  const nonce = typeof scriptNonce === "string" && scriptNonce ? scriptNonce : "";
  if (!glueUrl || !nonce || !HTML_TEMPLATE) return null;
  const cfgB64 = base64UrlEncodeNoPad(utf8ToBytes(JSON.stringify(cfgObj)));
  return HTML_TEMPLATE.replace("__GLUE_URL__", glueUrl)
    .replace("__CFG_B64__", cfgB64)
    .replace("__SCRIPT_NONCE__", nonce);
};

const applyCors = (headers, request, config) => {
  const origin = request.headers.get("Origin") || "";
  const allow = Array.isArray(config.ALLOWED_CLIENT_ORIGINS)
    ? config.ALLOWED_CLIENT_ORIGINS
    : [];
  if (origin && allow.includes(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
    headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type");
  }
};

// ---------- PoW (Phase 2) ----------

const u32BE = (bytes, offset) =>
  ((bytes[offset] << 24) |
    (bytes[offset + 1] << 16) |
    (bytes[offset + 2] << 8) |
    bytes[offset + 3]) >>> 0;

const rotl = (value, count) => ((value << count) | (value >>> (32 - count))) >>> 0;

const bytesEqual = (a, b) => {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

const concatBytes = (...chunks) => {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

const encodeUint32BE = (value) => {
  const out = new Uint8Array(4);
  const num = Number(value) >>> 0;
  out[0] = (num >>> 24) & 0xff;
  out[1] = (num >>> 16) & 0xff;
  out[2] = (num >>> 8) & 0xff;
  out[3] = num & 0xff;
  return out;
};

const makeXoshiro128ss = (seed16) => {
  let a = u32BE(seed16, 0);
  let b = u32BE(seed16, 4);
  let c = u32BE(seed16, 8);
  let d = u32BE(seed16, 12);
  if ((a | b | c | d) === 0) d = 1;

  const nextU32 = () => {
    const result = rotl(Math.imul(a, 5) >>> 0, 7);
    const out = Math.imul(result, 9) >>> 0;
    const t = (b << 9) >>> 0;
    c ^= a;
    d ^= b;
    b ^= c;
    a ^= d;
    c ^= t;
    d = rotl(d, 11);
    return out >>> 0;
  };

  const nextFloat = () => nextU32() / 4294967296;
  const randInt = (span) => Math.floor(nextFloat() * span);
  const shuffle = (array) => {
    for (let i = array.length - 1; i > 0; i--) {
      const j = randInt(i + 1);
      const tmp = array[i];
      array[i] = array[j];
      array[j] = tmp;
    }
  };
  return { nextU32, nextFloat, randInt, shuffle };
};

const derivePowSid = async (powSecret, chalId, commitMac) => {
  const bytes = await hmacSha256(powSecret, `pow-sid-v3|${chalId}|${commitMac}`);
  return base64UrlEncodeNoPad(bytes.slice(0, 12));
};

const derivePowSeedBytes16 = async (powSecret, chalId, commitMac, sid) => {
  const bytes = await hmacSha256(powSecret, `pow-seed-v3|${chalId}|${commitMac}|${sid}`);
  return bytes.slice(0, 16);
};

const deriveSpineSeed16 = async (powSecret, chalId, commitMac, sid, cursor, batchLen, spineSeed) => {
  const bytes = await hmacSha256(
    powSecret,
    `pow-spine-v3|${chalId}|${commitMac}|${sid}|${cursor}|${batchLen}|${spineSeed}`
  );
  return bytes.slice(0, 16);
};

const deriveSegLenSeed16 = async (powSecret, chalId, commitMac, sid) => {
  const bytes = await hmacSha256(powSecret, `pow-seglen-v3|${chalId}|${commitMac}|${sid}`);
  return bytes.slice(0, 16);
};

const derivePowPlanSeedBytes16 = async (powSecret, chalId, powSeed) => {
  const bytes = await hmacSha256(powSecret, `pow-plan-seed-v3|${chalId}|${powSeed}`);
  return bytes.slice(0, 16);
};

const derivePowPlanSegLenSeed16 = async (powSecret, chalId, powSeed) => {
  const bytes = await hmacSha256(powSecret, `pow-plan-seglen-v3|${chalId}|${powSeed}`);
  return bytes.slice(0, 16);
};

const derivePowPlanSpineSeed16 = async (powSecret, chalId, powSeed, cursor, batchLen) => {
  const bytes = await hmacSha256(
    powSecret,
    `pow-plan-spine-v3|${chalId}|${powSeed}|${cursor}|${batchLen}`
  );
  return bytes.slice(0, 16);
};

const bucketIdOf = (idx, max, bucketCount) => {
  const value = Math.floor(((idx - 1) * bucketCount) / max);
  return Math.max(0, Math.min(bucketCount - 1, value));
};

const bucketRange = (bucket, max, bucketCount) => {
  const start = 1 + Math.floor((bucket * max) / bucketCount);
  const end = 1 + Math.floor(((bucket + 1) * max) / bucketCount);
  const lo = Math.max(1, Math.min(max, start));
  const hi = Math.max(lo, Math.min(max + 1, end));
  return { lo, hi };
};

const pickFromBucket = (rng, bucket, max, bucketCount) => {
  const { lo, hi } = bucketRange(bucket, max, bucketCount);
  const span = Math.max(1, hi - lo);
  const idx = lo + rng.randInt(span);
  return Math.max(1, Math.min(max, idx));
};

const computeMidIndex = (idx, segmentLen) => {
  const effectiveSegmentLen = Math.min(segmentLen, idx);
  if (effectiveSegmentLen <= 1) return null;
  const offset = Math.max(1, Math.floor(effectiveSegmentLen / 2));
  return idx - offset;
};

const randomUint32 = () => {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0];
};

const pickSpinePosForBatch = (indices, segs, maxIndex, spineK, rng) => {
  const target = Math.max(0, Math.floor(spineK || 0));
  if (!target || !Array.isArray(indices) || !Array.isArray(segs)) return [];
  const eligible = [];
  const count = Math.min(indices.length, segs.length);
  for (let pos = 0; pos < count; pos++) {
    const idx = indices[pos];
    const segLen = segs[pos];
    if (!Number.isFinite(idx) || !Number.isFinite(segLen)) continue;
    if (idx === 1 || idx === maxIndex) continue;
    if (computeMidIndex(idx, segLen) === null) continue;
    eligible.push(pos);
  }
  if (eligible.length <= target) return eligible.slice();
  for (let i = eligible.length - 1; i > 0; i--) {
    const j = rng ? rng.randInt(i + 1) : randomUint32() % (i + 1);
    const tmp = eligible[i];
    eligible[i] = eligible[j];
    eligible[j] = tmp;
  }
  return eligible.slice(0, target);
};

const normalizeSpinePosList = (value, maxLen) => {
  if (!Array.isArray(value)) return null;
  const seen = new Set();
  const out = [];
  for (const raw of value) {
    const pos = Number.parseInt(raw, 10);
    if (!Number.isFinite(pos) || pos < 0) return null;
    if (Number.isFinite(maxLen) && pos >= maxLen) return null;
    if (seen.has(pos)) return null;
    seen.add(pos);
    out.push(pos);
  }
  return out;
};

const sampleIndicesDeterministicV2 = ({ maxIndex, extraCount, forceEdge1, forceEdgeLast, rng }) => {
  const max = Math.floor(Number(maxIndex) || 0);
  if (max <= 0) return [];
  const out = new Set();
  if (forceEdge1 && max >= 1) out.add(1);
  if (forceEdgeLast && max >= 1) out.add(max);
  const extra = Math.max(0, Math.floor(Number(extraCount) || 0));
  const target = Math.min(max, out.size + extra);
  if (target <= out.size) {
    return Array.from(out).sort((a, b) => a - b);
  }
  const bucketCount = Math.min(64, Math.max(1, Math.floor(max / 128)));
  const covered = new Array(bucketCount).fill(false);
  for (const v of out) {
    covered[bucketIdOf(v, max, bucketCount)] = true;
  }
  let need = target - out.size;
  const buckets = [];
  for (let b = 0; b < bucketCount; b++) {
    if (!covered[b]) buckets.push(b);
  }
  rng.shuffle(buckets);
  const coverN = Math.min(need, buckets.length);
  for (let i = 0; i < coverN; i++) {
    const bucket = buckets[i];
    const idx = pickFromBucket(rng, bucket, max, bucketCount);
    out.add(idx);
    covered[bucket] = true;
    need = target - out.size;
    if (need <= 0) break;
  }
  let attempts = 0;
  const maxAttempts = Math.max(256, need * 32);
  while (need > 0 && attempts < maxAttempts) {
    const bucket = rng.randInt(bucketCount);
    const idx = pickFromBucket(rng, bucket, max, bucketCount);
    const before = out.size;
    out.add(idx);
    if (out.size !== before) need -= 1;
    attempts += 1;
  }
  if (need > 0) {
    for (let i = 1; i <= max && need > 0; i++) {
      if (!out.has(i)) {
        out.add(i);
        need -= 1;
      }
    }
  }
  const result = Array.from(out);
  rng.shuffle(result);
  const anchors = [];
  if (forceEdge1 && max >= 1) anchors.push(1);
  if (forceEdgeLast && max >= 1 && max !== 1) anchors.push(max);
  if (anchors.length) {
    for (const anchor of anchors) {
      const idx = result.indexOf(anchor);
      if (idx >= 0) result.splice(idx, 1);
    }
    return anchors.concat(result);
  }
  return result;
};

const parseSegmentLenSpec = (raw, defaultValue) => {
  const fallback = clampInt(defaultValue, 1, 64);
  if (raw === null || raw === undefined) {
    return { mode: "fixed", fixed: fallback };
  }
  const isNumericString = typeof raw === "string" && /^\d+$/.test(raw.trim());
  if (typeof raw === "number" || isNumericString) {
    const fixed = clampInt(raw, 1, 64);
    return { mode: "fixed", fixed };
  }
  if (typeof raw === "string") {
    const match = raw.trim().match(/^(\d+)\s*-\s*(\d+)$/);
    if (match) {
      const min = clampInt(match[1], 1, 64);
      const max = clampInt(match[2], 1, 64);
      if (min <= max && max - min <= 63) {
        return { mode: "range", min, max };
      }
    }
  }
  return { mode: "fixed", fixed: fallback };
};

const computeSegLensForIndices = (indices, segSpec, rngSeg) => {
  if (!segSpec || segSpec.mode !== "range") {
    const fixed = clampInt(segSpec && segSpec.fixed, 1, 64);
    return indices.map(() => fixed);
  }
  const span = Math.max(1, Math.floor(segSpec.max - segSpec.min + 1));
  return indices.map(() => segSpec.min + rngSeg.randInt(span));
};

const serializeSpinePos = (spinePos) =>
  Array.isArray(spinePos) && spinePos.length ? spinePos.join(",") : "";

const makePowStateToken = async (powSecret, chalId, sid, commitMac, cursor, batchLen, spinePos) =>
  hmacSha256Base64UrlNoPad(
    powSecret,
    `pow-state-v3|${chalId}|${sid}|${commitMac}|${cursor}|${batchLen}|${serializeSpinePos(
      spinePos
    )}`
  );

const POSW_SEED_PREFIX = encoder.encode("posw|seed|");
const POSW_STEP_PREFIX = encoder.encode("posw|step|");
const MERKLE_LEAF_PREFIX = encoder.encode("leaf|");
const MERKLE_NODE_PREFIX = encoder.encode("node|");
const PIPE_BYTES = encoder.encode("|");
const HASHCASH_PREFIX = encoder.encode("hashcash|v3|");

const hashPoswSeed = async (bindingString, nonce) =>
  sha256Bytes(
    concatBytes(POSW_SEED_PREFIX, utf8ToBytes(bindingString), PIPE_BYTES, utf8ToBytes(nonce || ""))
  );

const hashPoswStep = async (prevBytes, index) =>
  sha256Bytes(concatBytes(POSW_STEP_PREFIX, encodeUint32BE(index), prevBytes));

const hashMerkleLeaf = async (leafIndex, leafBytes) =>
  sha256Bytes(concatBytes(MERKLE_LEAF_PREFIX, encodeUint32BE(leafIndex), leafBytes));

const hashMerkleNode = async (leftBytes, rightBytes) =>
  sha256Bytes(concatBytes(MERKLE_NODE_PREFIX, leftBytes, rightBytes));

const hashcashRootLast = async (rootBytes, lastBytes) =>
  sha256Bytes(concatBytes(HASHCASH_PREFIX, rootBytes, lastBytes));

const leadingZeroBits = (bytes) => {
  let count = 0;
  for (const b of bytes || []) {
    if (b === 0) {
      count += 8;
      continue;
    }
    for (let i = 7; i >= 0; i--) {
      if (b & (1 << i)) {
        return count + (7 - i);
      }
    }
  }
  return count;
};

const computeMerkleDepth = (leafCount) => {
  let depth = 0;
  let size = Math.max(0, Math.floor(Number(leafCount) || 0));
  while (size > 1) {
    size = Math.ceil(size / 2);
    depth += 1;
  }
  return depth;
};

const verifyMerkleProof = async (rootBytes, leafBytes, leafIndex, leafCount, proof) => {
  if (!rootBytes || rootBytes.length !== 32) return false;
  if (!leafBytes || leafBytes.length !== 32) return false;
  const idx = Math.floor(Number(leafIndex));
  if (!Number.isFinite(idx) || idx < 0 || idx >= leafCount) return false;
  const sibs = proof && Array.isArray(proof.sibs) ? proof.sibs : null;
  const dirs = proof && typeof proof.dirs === "string" ? proof.dirs : "";
  const depth = computeMerkleDepth(leafCount);
  if (!sibs || sibs.length !== depth) return false;
  if (dirs && dirs.length !== depth) return false;
  let current = await hashMerkleLeaf(idx, leafBytes);
  let curIdx = idx;
  for (let i = 0; i < depth; i++) {
    const sibBytes = base64UrlDecodeToBytes(String(sibs[i] || ""));
    if (!sibBytes || sibBytes.length !== 32) return false;
    const dir = curIdx % 2 === 0 ? 0 : 1;
    if (dirs && Number(dirs[i]) !== dir) return false;
    current =
      dir === 0
        ? await hashMerkleNode(current, sibBytes)
        : await hashMerkleNode(sibBytes, current);
    curIdx = Math.floor(curIdx / 2);
  }
  return bytesEqual(current, rootBytes);
};

const makePowCommitMac = async (powSecret, chalId, rootB64, tb, nonce, exp, spineSeed) =>
  hmacSha256Base64UrlNoPad(
    powSecret,
    `pow-commit-v1|${chalId}|${rootB64}|${tb}|${nonce}|${exp}|${spineSeed}`
  );

const makePowCommitToken = async (powSecret, payload) => {
  const payloadB64 = b64uJsonEncode(payload);
  const mac = await hmacSha256Base64UrlNoPad(powSecret, `pow-commit-token|${payloadB64}`);
  return `pc1.${payloadB64}.${mac}`;
};

const parsePowCommitToken = async (powSecret, token) => {
  const parts = String(token || "").split(".");
  if (parts.length !== 3 || parts[0] !== "pc1") return null;
  const payloadB64 = parts[1] || "";
  const mac = parts[2] || "";
  if (!isBase64Url(payloadB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  const expected = await hmacSha256Base64UrlNoPad(powSecret, `pow-commit-token|${payloadB64}`);
  if (!timingSafeEqual(expected, mac)) return null;
  return b64uJsonDecode(payloadB64);
};

// ---------- Handlers ----------

const handleServerGenerate = async (request, url, nowSeconds, config) => {
  if (!requireAuth(request, config)) return deny();
  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") return S(400);

  const powSecret = typeof config.POW_TOKEN === "string" ? config.POW_TOKEN : "";
  if (!powSecret) return S(500);

  const ctxB64 = typeof body.ctxB64 === "string" ? body.ctxB64 : "";
  const ctxMaxLen = getCtxB64MaxLen(config);
  if (!isBase64Url(ctxB64, 1, ctxMaxLen)) return S(400);
  const ctxBytes = base64UrlDecodeToBytes(ctxB64);
  if (!ctxBytes) return S(400);

  const ttlSec = clampInt(body.ttlSec, 30, 1800);
  const exp = nowSeconds + ttlSec;
  const policy = body.policy && typeof body.policy === "object" ? body.policy : {};
  const requireTurn = policy.requireTurn === true;
  const requirePow = policy.requirePow === true;

  const turnReq = body.turn && typeof body.turn === "object" ? body.turn : {};
  const powReq = body.pow && typeof body.pow === "object" ? body.pow : {};
  const turnEnabled = requireTurn && turnReq.enable === true;
  const powEnabled = requirePow && powReq.enable === true;

  if (requireTurn && !turnEnabled) {
    return J({ ok: false, error: "turn disabled" }, 400);
  }
  if (requirePow && !powEnabled) {
    return J({ ok: false, error: "pow disabled" }, 400);
  }

  const uiEnabled = turnEnabled || powEnabled;
  let parentOrigin = null;
  let allowRedirect = false;
  let returnUrl = null;
  let nonce = null;
  if (uiEnabled) {
    parentOrigin = normalizeOrigin(turnReq.parentOrigin);
    if (!parentOrigin) return J({ ok: false, error: "parentOrigin invalid" }, 400);
    if (!isOriginAllowed(parentOrigin, config.ALLOWED_PARENT_ORIGINS)) {
      return J({ ok: false, error: "parentOrigin denied" }, 403);
    }
    allowRedirect = turnReq.allowRedirect === true;
    returnUrl = turnReq.returnUrl ? validateReturnUrl(turnReq.returnUrl, parentOrigin) : null;
    nonce = randomBase64Url(16);
  }
  if (turnEnabled) {
    if (!config.TURNSTILE_SITEKEY || !config.TURNSTILE_SECRET) return S(500);
  }

  const aad = utf8ToBytes(`aad|v=${DEFAULTS.CAAS_VERSION}|exp=${exp}|turn=${turnEnabled}|pow=${powEnabled}`);
  const ctxEnc = await aeadEncrypt(powSecret, ctxBytes, aad);

  const powStepsRaw = powReq.steps ?? powReq.L ?? DEFAULTS.POW_STEPS;
  const steps = clampInt(powStepsRaw, DEFAULTS.POW_MIN_STEPS, DEFAULTS.POW_MAX_STEPS);
  const hashcashBits = clampInt(powReq.hashcashBits ?? DEFAULTS.POW_HASHCASH_BITS, 0, 30);
  const segmentLenSpec = powReq.segmentLenSpec ?? DEFAULTS.POW_SEGMENT_LEN;
  const sampleK = clampInt(powReq.sampleK ?? DEFAULTS.POW_SAMPLE_K, 0, 64);
  const spineK = clampInt(powReq.spineK ?? DEFAULTS.POW_SPINE_K, 0, 8);
  const rounds = clampInt(powReq.rounds ?? DEFAULTS.POW_CHAL_ROUNDS, 1, 64);
  const openBatch = clampInt(powReq.openBatch ?? DEFAULTS.POW_OPEN_BATCH, 1, 32);
  const forceEdge1 = true;
  const forceEdgeLast = powReq.forceEdgeLast ?? DEFAULTS.POW_FORCE_EDGE_LAST;

  const chalPayload = {
    v: DEFAULTS.CAAS_VERSION,
    exp,
    policy: { requireTurn, requirePow },
    turn: { enabled: turnEnabled },
    pow: powEnabled
      ? {
          enabled: true,
          seed: randomBase64Url(16),
          params: {
            steps,
            hashcashBits,
            segmentLenSpec,
            sampleK,
            spineK,
            rounds,
            openBatch,
            forceEdge1,
            forceEdgeLast: forceEdgeLast === true || hashcashBits > 0,
          },
        }
      : { enabled: false },
    ctxEnc,
  };

  const { chal, chalId, payloadB64 } = await makeChal(powSecret, chalPayload);
  const chalMaxLen = getChalB64MaxLen(config);
  if (payloadB64.length > chalMaxLen) {
    return J({ ok: false, error: "chal too large" }, 400);
  }

  let ui = { enabled: false };
  if (uiEnabled) {
    const statePayload = {
      chalId,
      parentOrigin,
      exp: Math.min(exp, nowSeconds + clampInt(config.STATE_TTL_SEC ?? DEFAULTS.STATE_TTL_SEC, 30, 1800)),
      nonce,
      allowRedirect,
      returnUrl,
    };
    const state = await makeState(powSecret, statePayload);
    const landingUrl = `${url.origin}${config.API_PREFIX}/ui/landing?state=${encodeURIComponent(state)}`;

    let landingUrlRedirect = null;
    const landingChalMaxLen = getLandingChalMaxLen(config);
    if (allowRedirect && returnUrl && landingChalMaxLen > 0 && chal.length <= landingChalMaxLen) {
      landingUrlRedirect = `${url.origin}${config.API_PREFIX}/ui/landing?state=${encodeURIComponent(
        state
      )}#chal=${encodeURIComponent(chal)}`;
    }
    ui = { enabled: true, landingUrl, landingUrlRedirect };
  }

  const turn = turnEnabled
    ? { enabled: true, sitekey: config.TURNSTILE_SITEKEY }
    : { enabled: false };

  return J({
    chal,
    chalId,
    exp,
    policy: { requireTurn, requirePow },
    ui,
    turn,
    pow: chalPayload.pow,
  });
};

const handleServerAttest = async (request, nowSeconds, config) => {
  if (!requireAuth(request, config)) return deny();
  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") return S(400);

  const powSecret = typeof config.POW_TOKEN === "string" ? config.POW_TOKEN : "";
  if (!powSecret) return S(500);

  const chal = typeof body.chal === "string" ? body.chal : "";
  const parsed = await parseChal(powSecret, chal, getChalB64MaxLen(config));
  if (!parsed) return deny();
  const { payload, payloadB64, chalId } = parsed;
  const exp = Number(payload.exp);
  if (!Number.isFinite(exp) || exp <= nowSeconds) return deny();
  const policy = payload.policy && typeof payload.policy === "object" ? payload.policy : {};

  const requireTurn = policy.requireTurn === true;
  const requirePow = policy.requirePow === true;
  const requiredMask = (requirePow ? 1 : 0) | (requireTurn ? 2 : 0);
  if (requiredMask) {
    const proofToken = typeof body.proofToken === "string" ? body.proofToken : "";
    if (!proofToken) return deny();
    if (!(await verifyProofToken(powSecret, requiredMask, proofToken, chalId, nowSeconds))) {
      return deny();
    }
  }

  const aad = utf8ToBytes(
    `aad|v=${DEFAULTS.CAAS_VERSION}|exp=${payload.exp}|turn=${payload.turn?.enabled === true}|pow=${payload.pow?.enabled === true}`
  );
  const ctxBytes = await aeadDecrypt(powSecret, payload.ctxEnc, aad);
  if (!ctxBytes) return deny();
  return J({
    ok: true,
    chalId,
    exp,
    ctxB64: base64UrlEncodeNoPad(ctxBytes),
    chalPayloadB64: payloadB64,
  });
};

const handleClientTurn = async (request, nowSeconds, config) => {
  const headers = new Headers();
  applyCors(headers, request, config);

  if (request.method === "OPTIONS") {
    return S(204, headers);
  }
  if (request.method !== "POST") return S(405, headers);

  const powSecret = typeof config.POW_TOKEN === "string" ? config.POW_TOKEN : "";
  if (!powSecret) return S(500, headers);
  if (!config.TURNSTILE_SECRET) return S(500, headers);

  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") return S(400, headers);
  const chal = typeof body.chal === "string" ? body.chal : "";
  const turnstileToken = typeof body.turnstileToken === "string" ? body.turnstileToken : "";
  if (!chal || !turnstileToken) return S(400, headers);
  const turnToken = validateTurnToken(turnstileToken);
  if (!turnToken) return S(400, headers);

  const parsed = await parseChal(powSecret, chal, getChalB64MaxLen(config));
  if (!parsed) return J({ ok: false }, 403, headers);
  const { payload, chalId } = parsed;
  if (Number(payload.exp) <= nowSeconds) return J({ ok: false }, 403, headers);
  if (!(payload.policy && payload.policy.requireTurn === true)) return J({ ok: false }, 403, headers);
  const requirePow = payload.policy && payload.policy.requirePow === true;
  if (requirePow) return S(404, headers);

  const form = new URLSearchParams();
  form.set("secret", config.TURNSTILE_SECRET);
  form.set("response", turnToken);

  let verifyRes;
  try {
    verifyRes = await fetch(TURNSTILE_SITEVERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    });
  } catch {
    return J({ ok: false }, 403, headers);
  }
  const verify = await verifyRes.json().catch(() => null);
  if (!verify || verify.success !== true) return J({ ok: false }, 403, headers);
  const cdata = typeof verify.cdata === "string" ? verify.cdata : "";
  if (cdata !== chalId) return J({ ok: false }, 403, headers);

  const ttl = Math.max(1, Math.min(clampInt(config.PROOF_TTL_SEC ?? DEFAULTS.PROOF_TTL_SEC, 30, 3600), Number(payload.exp) - nowSeconds));
  const iat = nowSeconds;
  const exp = nowSeconds + ttl;
  const proofToken = await makeProofToken(powSecret, 2, chalId, iat, exp);

  return J({ ok: true, proofToken, exp }, 200, headers);
};

const handleUiLanding = async (request, url, nowSeconds, config) => {
  const powSecret = typeof config.POW_TOKEN === "string" ? config.POW_TOKEN : "";
  if (!powSecret) return S(500);

  const state = url.searchParams.get("state") || "";
  if (!state) return S(400);
  const payload = await parseState(powSecret, state, getStateB64MaxLen(config));
  if (!payload) return deny();

  const exp = Number(payload.exp);
  if (!Number.isFinite(exp) || exp <= nowSeconds) return deny();

  const parentOrigin = typeof payload.parentOrigin === "string" ? payload.parentOrigin : "";
  const chalId = typeof payload.chalId === "string" ? payload.chalId : "";
  const nonce = typeof payload.nonce === "string" ? payload.nonce : "";
  const allowRedirect = payload.allowRedirect === true;
  const returnUrl = typeof payload.returnUrl === "string" ? payload.returnUrl : "";
  const chal = typeof payload.chal === "string" ? payload.chal : "";

  if (!chalId || !nonce || !parentOrigin) return deny();

  const cfgObj = {
    apiPrefix: config.API_PREFIX,
    chalId,
    nonce,
    parentOrigin,
    allowRedirect,
    returnUrl,
    chal,
    turnSitekey: config.TURNSTILE_SITEKEY,
    powEsmUrl: config.CAAS_POW_ESM_URL || "",
  };
  const scriptNonce = randomBase64NoPad(16);
  const html = buildLandingHtml(config, cfgObj, scriptNonce);
  if (!html) return S(500);

  const headers = new Headers();
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.set("Referrer-Policy", "no-referrer");
  const scriptSrc = new Set([`'nonce-${scriptNonce}'`, "'self'", "https://challenges.cloudflare.com"]);
  try {
    const glue = new URL(String(config.CAAS_GLUE_URL || ""), url.origin);
    if (/^https?:$/.test(glue.protocol) && glue.origin !== url.origin) {
      scriptSrc.add(glue.origin);
    }
  } catch {}
  try {
    const esm = new URL(String(config.CAAS_POW_ESM_URL || ""), url.origin);
    if (/^https?:$/.test(esm.protocol) && esm.origin !== url.origin) {
      scriptSrc.add(esm.origin);
    }
  } catch {}
  const workerSrc = new Set(["'self'", "blob:", "https://challenges.cloudflare.com"]);
  for (const value of scriptSrc) {
    if (typeof value === "string" && value.startsWith("http")) {
      workerSrc.add(value);
    }
  }
  const connectSrc = new Set(["'self'", "https://challenges.cloudflare.com"]);
  for (const value of scriptSrc) {
    if (typeof value === "string" && value.startsWith("http")) {
      connectSrc.add(value);
    }
  }
  const frameSrc = new Set(["https://challenges.cloudflare.com"]);
  const imgSrc = new Set(["'self'", "data:", "https://challenges.cloudflare.com"]);
  const styleSrc = new Set(["'unsafe-inline'"]);
  const csp = [
    "default-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    `frame-ancestors ${parentOrigin}`,
    `script-src ${Array.from(scriptSrc).join(" ")}`,
    `worker-src ${Array.from(workerSrc).join(" ")}`,
    `connect-src ${Array.from(connectSrc).join(" ")}`,
    `frame-src ${Array.from(frameSrc).join(" ")}`,
    `img-src ${Array.from(imgSrc).join(" ")}`,
    `style-src ${Array.from(styleSrc).join(" ")}`,
  ].join("; ");
  headers.set("Content-Security-Policy", csp);
  return T(html, 200, headers);
};

const handleClientPowCommit = async (request, nowSeconds, config) => {
  const headers = new Headers();
  applyCors(headers, request, config);

  if (request.method === "OPTIONS") return S(204, headers);
  if (request.method !== "POST") return S(405, headers);

  const powSecret = typeof config.POW_TOKEN === "string" ? config.POW_TOKEN : "";
  if (!powSecret) return S(500, headers);

  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") return S(400, headers);

  const chal = typeof body.chal === "string" ? body.chal : "";
  const rootB64 = typeof body.rootB64 === "string" ? body.rootB64 : "";
  const nonce = typeof body.nonce === "string" ? body.nonce : "";
  const turnTokenRaw = typeof body.turnToken === "string" ? body.turnToken : "";
  if (!chal || !rootB64 || !nonce) return S(400, headers);

  if (!isBase64Url(rootB64, 1, B64_HASH_MAX_LEN) || !isBase64Url(nonce, NONCE_MIN_LEN, NONCE_MAX_LEN)) {
    return S(400, headers);
  }
  const rootBytes = base64UrlDecodeToBytes(rootB64);
  if (!rootBytes || rootBytes.length !== 32) {
    return S(400, headers);
  }

  const parsed = await parseChal(powSecret, chal, getChalB64MaxLen(config));
  if (!parsed) return J({ ok: false }, 403, headers);
  const { payload, chalId } = parsed;
  if (Number(payload.exp) <= nowSeconds) return J({ ok: false }, 403, headers);
  if (!(payload.policy && payload.policy.requirePow === true)) return J({ ok: false }, 403, headers);
  const requireTurn = payload.policy && payload.policy.requireTurn === true;
  if (!(payload.pow && payload.pow.enabled === true && payload.pow.params)) return J({ ok: false }, 403, headers);
  let turnToken = "";
  if (requireTurn) {
    turnToken = validateTurnToken(turnTokenRaw);
    if (!turnToken) return S(400, headers);
  }

  const params = payload.pow.params;
  const L = clampInt(params.steps, DEFAULTS.POW_MIN_STEPS, DEFAULTS.POW_MAX_STEPS);
  const rounds = clampInt(params.rounds, 1, 64);
  const sampleK = clampInt(params.sampleK, 0, 64);
  const hashcashBits = clampInt(params.hashcashBits, 0, 30);
  const spineK = clampInt(params.spineK, 0, 8);
  const openBatch = clampInt(params.openBatch, 1, 32);
  const segSpec = parseSegmentLenSpec(params.segmentLenSpec, DEFAULTS.POW_SEGMENT_LEN);
  const powSeed =
    typeof payload.pow.seed === "string" && isBase64Url(payload.pow.seed, 1, B64_HASH_MAX_LEN)
      ? payload.pow.seed
      : chalId;
  const forceEdge1 = true;
  const forceEdgeLast = params.forceEdgeLast === true || hashcashBits > 0;

  const commitTtl = clampInt(config.POW_COMMIT_TTL_SEC ?? DEFAULTS.POW_COMMIT_TTL_SEC, 30, 1800);
  const commitExp = Math.min(Number(payload.exp), nowSeconds + commitTtl);
  if (commitExp <= nowSeconds) return J({ ok: false }, 403, headers);

  const spineSeed = randomBase64Url(16);
  const tb = requireTurn ? await tbFromToken(turnToken) : "any";
  const commitMac = await makePowCommitMac(
    powSecret,
    chalId,
    rootB64,
    tb,
    nonce,
    commitExp,
    spineSeed
  );
  const commitToken = await makePowCommitToken(powSecret, {
    v: 1,
    chalId,
    rootB64,
    tb,
    nonce,
    exp: commitExp,
    spineSeed,
  });

  const sid = await derivePowSid(powSecret, chalId, commitMac);
  const seed16 = await derivePowPlanSeedBytes16(powSecret, chalId, powSeed);
  const rng = makeXoshiro128ss(seed16);
  const indicesAll = sampleIndicesDeterministicV2({
    maxIndex: L,
    extraCount: sampleK * rounds,
    forceEdge1,
    forceEdgeLast,
    rng,
  });
  if (!indicesAll.length) return J({ ok: false }, 403, headers);

  const segSeed16 = await derivePowPlanSegLenSeed16(powSecret, chalId, powSeed);
  const rngSeg = makeXoshiro128ss(segSeed16);
  const segLensAll = computeSegLensForIndices(indicesAll, segSpec, rngSeg);

  const cursor = 0;
  const batch = indicesAll.slice(cursor, cursor + openBatch);
  const segBatch = segLensAll.slice(cursor, cursor + openBatch);

  const spineSeed16 = await derivePowPlanSpineSeed16(powSecret, chalId, powSeed, cursor, openBatch);
  const rngSpine = makeXoshiro128ss(spineSeed16);
  const spinePos = spineK > 0 ? pickSpinePosForBatch(batch, segBatch, L, spineK, rngSpine) : [];

  const token = await makePowStateToken(powSecret, chalId, sid, commitMac, cursor, openBatch, spinePos);

  return J({
    done: false,
    commitToken,
    sid,
    cursor,
    indices: batch,
    segs: segBatch,
    spinePos,
    token,
  }, 200, headers);
};

const handleClientPowOpen = async (request, nowSeconds, config) => {
  const headers = new Headers();
  applyCors(headers, request, config);

  if (request.method === "OPTIONS") return S(204, headers);
  if (request.method !== "POST") return S(405, headers);

  const powSecret = typeof config.POW_TOKEN === "string" ? config.POW_TOKEN : "";
  if (!powSecret) return S(500, headers);

  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") return S(400, headers);

  const chal = typeof body.chal === "string" ? body.chal : "";
  const commitToken = typeof body.commitToken === "string" ? body.commitToken : "";
  const sid = typeof body.sid === "string" ? body.sid : "";
  const cursor = Number.parseInt(body.cursor, 10);
  const stateToken = typeof body.token === "string" ? body.token : "";
  const turnTokenRaw = typeof body.turnToken === "string" ? body.turnToken : "";
  const opens = Array.isArray(body.opens) ? body.opens : null;
  const spinePosRaw = body.spinePos;

  if (!chal || !commitToken || !sid || !stateToken || !opens || !Number.isFinite(cursor) || cursor < 0) {
    return S(400, headers);
  }
  if (!Array.isArray(spinePosRaw)) return S(400, headers);
  if (!isBase64Url(sid, SID_LEN, SID_LEN) || !isBase64Url(stateToken, TOKEN_MIN_LEN, TOKEN_MAX_LEN)) return S(400, headers);

  const parsedChal = await parseChal(powSecret, chal, getChalB64MaxLen(config));
  if (!parsedChal) return J({ ok: false }, 403, headers);
  const { payload, chalId } = parsedChal;
  if (Number(payload.exp) <= nowSeconds) return J({ ok: false }, 403, headers);
  if (!(payload.policy && payload.policy.requirePow === true)) return J({ ok: false }, 403, headers);
  const requireTurn = payload.policy && payload.policy.requireTurn === true;
  if (!(payload.pow && payload.pow.enabled === true && payload.pow.params)) return J({ ok: false }, 403, headers);

  const commit = await parsePowCommitToken(powSecret, commitToken);
  if (!commit || commit.v !== 1) return J({ ok: false }, 403, headers);
  if (commit.chalId !== chalId) return J({ ok: false }, 403, headers);
  const commitExp = Number(commit.exp);
  if (!Number.isFinite(commitExp) || commitExp <= nowSeconds) return J({ ok: false }, 403, headers);

  const rootB64 = String(commit.rootB64 || "");
  const tb = String(commit.tb || "");
  const nonce = String(commit.nonce || "");
  const spineSeed = String(commit.spineSeed || "");
  if (
    !isBase64Url(rootB64, 1, B64_HASH_MAX_LEN) ||
    !isBase64UrlOrAny(tb, TB_LEN, TB_LEN) ||
    !isBase64Url(nonce, NONCE_MIN_LEN, NONCE_MAX_LEN) ||
    !isBase64Url(spineSeed, SPINE_SEED_MIN_LEN, SPINE_SEED_MAX_LEN)
  ) {
    return J({ ok: false }, 403, headers);
  }
  if (requireTurn && !isBase64Url(tb, TB_LEN, TB_LEN)) {
    return J({ ok: false }, 403, headers);
  }

  const params = payload.pow.params;
  const L = clampInt(params.steps, DEFAULTS.POW_MIN_STEPS, DEFAULTS.POW_MAX_STEPS);
  const rounds = clampInt(params.rounds, 1, 64);
  const sampleK = clampInt(params.sampleK, 0, 64);
  const hashcashBits = clampInt(params.hashcashBits, 0, 30);
  const spineK = clampInt(params.spineK, 0, 8);
  const openBatch = clampInt(params.openBatch, 1, 32);
  const segSpec = parseSegmentLenSpec(params.segmentLenSpec, DEFAULTS.POW_SEGMENT_LEN);
  const powSeed =
    typeof payload.pow.seed === "string" && isBase64Url(payload.pow.seed, 1, B64_HASH_MAX_LEN)
      ? payload.pow.seed
      : chalId;
  const forceEdge1 = true;
  const forceEdgeLast = params.forceEdgeLast === true || hashcashBits > 0;

  const spinePos = normalizeSpinePosList(spinePosRaw, openBatch);
  if (!spinePos) return S(400, headers);

  const commitMac = await makePowCommitMac(powSecret, chalId, rootB64, tb, nonce, commitExp, spineSeed);
  const sidExpected = await derivePowSid(powSecret, chalId, commitMac);
  if (sid !== sidExpected) return J({ ok: false }, 403, headers);
  const expectedToken = await makePowStateToken(powSecret, chalId, sidExpected, commitMac, cursor, openBatch, spinePos);
  if (!timingSafeEqual(expectedToken, stateToken)) return J({ ok: false }, 403, headers);

  const seed16 = await derivePowPlanSeedBytes16(powSecret, chalId, powSeed);
  const rng = makeXoshiro128ss(seed16);
  const indicesAll = sampleIndicesDeterministicV2({
    maxIndex: L,
    extraCount: sampleK * rounds,
    forceEdge1,
    forceEdgeLast,
    rng,
  });
  if (!indicesAll.length) return J({ ok: false }, 403, headers);

  const segSeed16 = await derivePowPlanSegLenSeed16(powSecret, chalId, powSeed);
  const rngSeg = makeXoshiro128ss(segSeed16);
  const segLensAll = computeSegLensForIndices(indicesAll, segSpec, rngSeg);

  if (hashcashBits > 0 && !indicesAll.includes(L)) return J({ ok: false }, 403, headers);

  const expectedBatch = indicesAll.slice(cursor, cursor + openBatch);
  const segBatch = segLensAll.slice(cursor, cursor + openBatch);
  if (!expectedBatch.length) return J({ ok: false }, 403, headers);

  const eligibleSpine = [];
  for (let pos = 0; pos < expectedBatch.length; pos++) {
    const idx = expectedBatch[pos];
    const segLen = segBatch[pos];
    if (!Number.isFinite(idx) || !Number.isFinite(segLen)) continue;
    if (idx === 1 || idx === L) continue;
    if (computeMidIndex(idx, segLen) === null) continue;
    eligibleSpine.push(pos);
  }
  const expectedSpineCount = Math.min(spineK, eligibleSpine.length);
  if (spinePos.length !== expectedSpineCount) return J({ ok: false }, 403, headers);
  if (expectedSpineCount > 0) {
    const eligibleSet = new Set(eligibleSpine);
    for (const pos of spinePos) {
      if (!eligibleSet.has(pos)) return J({ ok: false }, 403, headers);
    }
  }
  const spinePosSet = spinePos.length ? new Set(spinePos) : null;

  if (opens.length !== expectedBatch.length) return J({ ok: false }, 403, headers);

  const batch = [];
  for (let i = 0; i < opens.length; i++) {
    const open = opens[i];
    const idx = open && Number.parseInt(open.i, 10);
    if (!Number.isFinite(idx) || idx < 1 || idx > L) return S(400, headers);
    if (idx !== expectedBatch[i]) return J({ ok: false }, 403, headers);
    const requiresMid = spinePosSet && spinePosSet.has(i);
    const segLen = segBatch[i];
    const hPrev = open && typeof open.hPrev === "string" ? open.hPrev : "";
    const hCurr = open && typeof open.hCurr === "string" ? open.hCurr : "";
    if (!isBase64Url(hPrev, 1, B64_HASH_MAX_LEN) || !isBase64Url(hCurr, 1, B64_HASH_MAX_LEN)) {
      return S(400, headers);
    }
    const proofPrev = open && open.proofPrev;
    const proofCurr = open && open.proofCurr;
    if (!proofPrev || !proofCurr || !Array.isArray(proofPrev.sibs) || !Array.isArray(proofCurr.sibs)) {
      return S(400, headers);
    }
    if (proofPrev.sibs.length > MAX_PROOF_SIBS || proofCurr.sibs.length > MAX_PROOF_SIBS) return S(400, headers);
    for (const sib of proofPrev.sibs) if (!isBase64Url(String(sib || ""), 1, B64_HASH_MAX_LEN)) return S(400, headers);
    for (const sib of proofCurr.sibs) if (!isBase64Url(String(sib || ""), 1, B64_HASH_MAX_LEN)) return S(400, headers);
    if (requiresMid) {
      const hMid = open && typeof open.hMid === "string" ? open.hMid : "";
      if (!isBase64Url(hMid, 1, B64_HASH_MAX_LEN)) return S(400, headers);
      const proofMid = open && open.proofMid;
      if (!proofMid || !Array.isArray(proofMid.sibs)) return S(400, headers);
      if (proofMid.sibs.length > MAX_PROOF_SIBS) return S(400, headers);
      for (const sib of proofMid.sibs) if (!isBase64Url(String(sib || ""), 1, B64_HASH_MAX_LEN)) return S(400, headers);
    }
    batch.push({ idx, open, requiresMid, segLen });
  }

  const rootBytes = base64UrlDecodeToBytes(rootB64);
  if (!rootBytes || rootBytes.length !== 32) return J({ ok: false }, 403, headers);
  const leafCount = L + 1;
  if (leafCount < 2) return J({ ok: false }, 403, headers);

  const bindingString = `chalId=${chalId}`;
  const powBindingString = requireTurn ? `${bindingString}&tb=${tb}` : bindingString;
  const seedHash = await hashPoswSeed(powBindingString, nonce);

  for (const entry of batch) {
    const idx = entry.idx;
    const open = entry.open;
    const requiresMid = entry.requiresMid === true;
    const segLen = entry.segLen;
    const hPrevBytes = base64UrlDecodeToBytes(String(open.hPrev || ""));
    const hCurrBytes = base64UrlDecodeToBytes(String(open.hCurr || ""));
    if (!hPrevBytes || !hCurrBytes || hPrevBytes.length !== 32 || hCurrBytes.length !== 32) return S(400, headers);

    const effectiveSegmentLen = Math.min(segLen, idx);
    let prevBytes = hPrevBytes;
    const firstIdx = idx - effectiveSegmentLen;
    if (firstIdx < 0) return J({ ok: false }, 403, headers);
    const midIdx = requiresMid ? computeMidIndex(idx, segLen) : null;
    let midExpected = null;

    for (let step = 1; step <= effectiveSegmentLen; step++) {
      const expected = await hashPoswStep(prevBytes, firstIdx + step);
      if (requiresMid && firstIdx + step === midIdx) {
        midExpected = expected;
      }
      if (step === effectiveSegmentLen) {
        if (!bytesEqual(expected, hCurrBytes)) return J({ ok: false }, 403, headers);
      } else {
        prevBytes = expected;
      }
    }

    if (requiresMid) {
      if (midIdx === null || !midExpected) return J({ ok: false }, 403, headers);
      const hMidBytes = base64UrlDecodeToBytes(String(open.hMid || ""));
      if (!hMidBytes || hMidBytes.length !== 32) return S(400, headers);
      if (!bytesEqual(midExpected, hMidBytes)) return J({ ok: false }, 403, headers);
      const okMid = await verifyMerkleProof(rootBytes, hMidBytes, midIdx, leafCount, open.proofMid);
      if (!okMid) return J({ ok: false }, 403, headers);
    }

    if (idx === 1 && !bytesEqual(hPrevBytes, seedHash)) return J({ ok: false }, 403, headers);

    const okPrev = await verifyMerkleProof(
      rootBytes,
      hPrevBytes,
      idx - effectiveSegmentLen,
      leafCount,
      open.proofPrev
    );
    if (!okPrev) return J({ ok: false }, 403, headers);
    const okCurr = await verifyMerkleProof(rootBytes, hCurrBytes, idx, leafCount, open.proofCurr);
    if (!okCurr) return J({ ok: false }, 403, headers);

    if (idx === L && hashcashBits > 0) {
      const digest = await hashcashRootLast(rootBytes, hCurrBytes);
      if (leadingZeroBits(digest) < hashcashBits) return J({ ok: false }, 403, headers);
    }
  }

  const nextCursor = cursor + expectedBatch.length;
  if (nextCursor < indicesAll.length) {
    const nextBatch = indicesAll.slice(nextCursor, nextCursor + openBatch);
    const nextSegBatch = segLensAll.slice(nextCursor, nextCursor + openBatch);
    const nextSpineSeed16 = await derivePowPlanSpineSeed16(
      powSecret,
      chalId,
      powSeed,
      nextCursor,
      openBatch
    );
    const rngSpineNext = makeXoshiro128ss(nextSpineSeed16);
    const nextSpinePos = spineK > 0 ? pickSpinePosForBatch(nextBatch, nextSegBatch, L, spineK, rngSpineNext) : [];
    const nextToken = await makePowStateToken(powSecret, chalId, sidExpected, commitMac, nextCursor, openBatch, nextSpinePos);
    return J({
      done: false,
      commitToken,
      sid: sidExpected,
      cursor: nextCursor,
      indices: nextBatch,
      segs: nextSegBatch,
      spinePos: nextSpinePos,
      token: nextToken,
    }, 200, headers);
  }

  if (requireTurn) {
    const turnSecret = typeof config.TURNSTILE_SECRET === "string" ? config.TURNSTILE_SECRET : "";
    if (!turnSecret) return S(500, headers);
    const turnToken = validateTurnToken(turnTokenRaw);
    if (!turnToken) return J({ ok: false }, 403, headers);
    const tbCheck = await tbFromToken(turnToken);
    if (tbCheck !== tb) return J({ ok: false }, 403, headers);

    const form = new URLSearchParams();
    form.set("secret", turnSecret);
    form.set("response", turnToken);
    let verifyRes;
    try {
      verifyRes = await fetch(TURNSTILE_SITEVERIFY_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form,
      });
    } catch {
      return J({ ok: false }, 403, headers);
    }
    const verify = await verifyRes.json().catch(() => null);
    if (!verify || verify.success !== true) return J({ ok: false }, 403, headers);
    const cdata = typeof verify.cdata === "string" ? verify.cdata : "";
    if (cdata !== chalId) return J({ ok: false }, 403, headers);
  }

  const proofTtl = clampInt(config.PROOF_TTL_SEC ?? DEFAULTS.PROOF_TTL_SEC, 30, 3600);
  const ttl = Math.max(1, Math.min(proofTtl, Number(payload.exp) - nowSeconds));
  const iat = nowSeconds;
  const exp = nowSeconds + ttl;
  const mask = requireTurn ? 3 : 1;
  const proofToken = await makeProofToken(powSecret, mask, chalId, iat, exp);
  return J({ done: true, proofToken, exp }, 200, headers);
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const nowSeconds = Math.floor(Date.now() / 1000);
    const requestPath = normalizePath(url.pathname);
    if (!requestPath) return S(400);

    const config = getEffectiveConfig(url.hostname, requestPath);
    if (!config) return S(500);
    const apiPrefix = normalizeApiPrefix(config.API_PREFIX, DEFAULTS.API_PREFIX);
    if (!apiPrefix) return S(500);
    config.API_PREFIX = apiPrefix;

    if (!requestPath.startsWith(`${apiPrefix}/`)) {
      return S(404);
    }

    const subpath = requestPath.slice(apiPrefix.length);

    if (subpath === "/server/generate") {
      if (request.method !== "POST") return S(405);
      return handleServerGenerate(request, url, nowSeconds, config);
    }
    if (subpath === "/server/attest") {
      if (request.method !== "POST") return S(405);
      return handleServerAttest(request, nowSeconds, config);
    }

    if (subpath === "/client/turn") {
      if (request.method !== "POST" && request.method !== "OPTIONS") return S(405);
      return handleClientTurn(request, nowSeconds, config);
    }
    if (subpath === "/client/pow/commit") {
      if (request.method !== "POST" && request.method !== "OPTIONS") return S(405);
      return handleClientPowCommit(request, nowSeconds, config);
    }
    if (subpath === "/client/pow/open") {
      if (request.method !== "POST" && request.method !== "OPTIONS") return S(405);
      return handleClientPowOpen(request, nowSeconds, config);
    }

    if (subpath === "/ui/landing") {
      if (request.method !== "GET") return S(405);
      return handleUiLanding(request, url, nowSeconds, config);
    }

    return S(404);
  },
};
