// Cloudflare Snippet: stateless PoW (generic L7 WAF)
// Set POW_TOKEN in CONFIG to your PoW secret.

const DEFAULTS = {
  powcheck: false,
  turncheck: false,
  bindPathMode: "none",
  bindPathQueryName: "path",
  bindPathHeaderName: "",
  stripBindPathHeader: false,
  POW_VERSION: 3,
  POW_API_PREFIX: "/__pow",
  POW_DIFFICULTY_BASE: 8192,
  POW_DIFFICULTY_COEFF: 1.0,
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
  POW_COMMIT_TTL_SEC: 120,
  POW_TICKET_TTL_SEC: 600,
  PROOF_TTL_SEC: 600,
  PROOF_RENEW_ENABLE: false,
  PROOF_RENEW_MAX: 2,
  PROOF_RENEW_WINDOW_SEC: 90,
  PROOF_RENEW_MIN_SEC: 30,
  POW_BIND_PATH: true,
  POW_BIND_IPRANGE: true,
  POW_BIND_COUNTRY: false,
  POW_BIND_ASN: false,
  POW_BIND_TLS: true,
  IPV4_PREFIX: 32,
  IPV6_PREFIX: 64,
  POW_COMMIT_COOKIE: "__Host-pow_commit",
  POW_ESM_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@be6f2d2ca5801c459f5fb99469d1802b5dbd469b/esm/esm.js",
  POW_GLUE_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@be6f2d2ca5801c459f5fb99469d1802b5dbd469b/glue.js",
};

const CONFIG = [
  // Example:
  // { pattern: "alist-landing-*.example.com/**", config: { POW_TOKEN: "replace-with-powToken", powcheck: true } },
  // Proxy endpoint bindPath (only affects PoW binding input; does not affect rule matching/difficulty):
  // { pattern: "alist-landing-*.example.com/info", config: { POW_TOKEN: "replace-with-powToken", powcheck: true, bindPathMode: "query", bindPathQueryName: "path" } },
];

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

const COMPILED_CONFIG = CONFIG.map(compileConfigEntry);
const POW_API_PREFIX = DEFAULTS.POW_API_PREFIX;
const PROOF_COOKIE = "__Host-proof";
const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

const pickConfigWithId = (hostname, path) => {
  const host = typeof hostname === "string" ? hostname.toLowerCase() : "";
  const requestPath = typeof path === "string" ? path : "";
  if (!host) return null;
  for (let i = 0; i < COMPILED_CONFIG.length; i++) {
    const rule = COMPILED_CONFIG[i];
    if (!rule || !rule.hostRegex) continue;
    if (!rule.hostRegex.test(host)) continue;
    if (rule.pathRegex && !rule.pathRegex.test(requestPath)) continue;
    return { cfgId: i, config: rule.config || null };
  }
  return null;
};

const getConfigById = (cfgId) => {
  if (!Number.isInteger(cfgId) || cfgId < 0 || cfgId >= COMPILED_CONFIG.length) {
    return null;
  }
  const entry = COMPILED_CONFIG[cfgId];
  return entry && entry.config ? entry.config : null;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hmacKeyCache = new Map();

const getHmacKey = (secret) => {
  const key = typeof secret === "string" ? secret : "";
  if (!key) {
    return Promise.reject(new Error("HMAC secret missing"));
  }
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

const base64UrlEncode = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_");

const base64UrlEncodeNoPad = (bytes) =>
  base64UrlEncode(bytes).replace(/=+$/g, "");

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

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const B64_HASH_MAX_LEN = 64;
const B64_TICKET_MAX_LEN = 256;
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

const isBase64Url = (value, minLen, maxLen) => {
  if (typeof value !== "string") return false;
  const len = value.length;
  if (len < minLen || len > maxLen) return false;
  return BASE64URL_RE.test(value);
};

const isBase64UrlOrAny = (value, minLen, maxLen) =>
  value === "any" || isBase64Url(value, minLen, maxLen);

const utf8ToBytes = (value) => encoder.encode(String(value ?? ""));
const bytesToUtf8 = (bytes) => decoder.decode(bytes);
const normalizeNumber = (value, fallback) => {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
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

const normalizeDecodedPath = (pathname) => {
  if (typeof pathname !== "string") return null;
  if (pathname.length === 0) return "/";
  return pathname.startsWith("/") ? pathname : `/${pathname}`;
};

const decodePathParam = (value) => {
  if (typeof value !== "string") return null;
  let decoded;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return null;
  }
  return decoded;
};

const isExpired = (expire, nowSeconds) => expire > 0 && expire < nowSeconds;

const hmacSha256 = async (secret, data) => {
  const key = await getHmacKey(secret);
  const payload = encoder.encode(data);
  const buf = await crypto.subtle.sign("HMAC", key, payload);
  return new Uint8Array(buf);
};

const BIND_PATH_MAX_LEN = 4096;
const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;
const validateTurnToken = (value) => {
  if (typeof value !== "string") return null;
  const token = value.trim();
  if (token.length < TURN_TOKEN_MIN_LEN || token.length > TURN_TOKEN_MAX_LEN) return null;
  if (CONTROL_CHAR_RE.test(token)) return null;
  return token;
};

const normalizeBindPathInput = (raw) => {
  if (typeof raw !== "string") return null;
  const decoded = decodePathParam(raw);
  if (decoded === null) return null;
  const canonical = normalizeDecodedPath(decoded);
  if (!canonical) return null;
  if (canonical.length > BIND_PATH_MAX_LEN) return null;
  if (CONTROL_CHAR_RE.test(canonical)) return null;
  return canonical;
};

const resolveBindPathForPow = (request, url, requestPath, config) => {
  if (config.POW_BIND_PATH === false) {
    return { ok: true, canonicalPath: requestPath, forwardRequest: request };
  }
  const mode = typeof config.bindPathMode === "string" ? config.bindPathMode : "none";
  if (!mode || mode === "none") {
    return { ok: true, canonicalPath: requestPath, forwardRequest: request };
  }
  if (mode === "query") {
    const name =
      typeof config.bindPathQueryName === "string" ? config.bindPathQueryName.trim() : "";
    if (!name) return { ok: false, code: "misconfigured" };
    const raw = url.searchParams.get(name);
    if (!raw) return { ok: false, code: "missing" };
    const canonical = normalizeBindPathInput(raw);
    if (!canonical) return { ok: false, code: "invalid" };
    return { ok: true, canonicalPath: canonical, forwardRequest: request };
  }
  if (mode === "header") {
    const name =
      typeof config.bindPathHeaderName === "string" ? config.bindPathHeaderName.trim() : "";
    if (!name) return { ok: false, code: "misconfigured" };
    const raw = request.headers.get(name);
    if (!raw) return { ok: false, code: "missing" };
    const canonical = normalizeBindPathInput(raw);
    if (!canonical) return { ok: false, code: "invalid" };
    if (config.stripBindPathHeader === true) {
      const headers = new Headers(request.headers);
      headers.delete(name);
      const forwardRequest = new Request(request, { headers });
      return { ok: true, canonicalPath: canonical, forwardRequest };
    }
    return { ok: true, canonicalPath: canonical, forwardRequest: request };
  }
  return { ok: false, code: "misconfigured" };
};

const hmacSha256Base64UrlNoPad = async (secret, data) => {
  const bytes = await hmacSha256(secret, data);
  return base64UrlEncodeNoPad(bytes);
};

const sha256Bytes = async (data) => {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
};
const tbFromToken = async (token) =>
  base64UrlEncodeNoPad((await sha256Bytes(token)).slice(0, 12));

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

const u32BE = (bytes, offset) =>
  ((bytes[offset] << 24) |
    (bytes[offset + 1] << 16) |
    (bytes[offset + 2] << 8) |
    bytes[offset + 3]) >>> 0;

const rotl = (value, count) =>
  ((value << count) | (value >>> (32 - count))) >>> 0;

const bytesEqual = (a, b) => {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
};

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

const timingSafeEqual = (a, b) => {
  const aNorm = typeof a === "string" ? a : "";
  const bNorm = typeof b === "string" ? b : "";
  if (aNorm.length !== bNorm.length) return false;
  let diff = 0;
  for (let i = 0; i < aNorm.length; i++) {
    diff |= aNorm.charCodeAt(i) ^ bNorm.charCodeAt(i);
  }
  return diff === 0;
};

const S = (status) => new Response(null, { status });
const J = (payload, status = 200, headers) =>
  new Response(JSON.stringify(payload), { status, headers });
const deny = () => S(403);

const isNavigationRequest = (request) => {
  const mode = request.headers.get("Sec-Fetch-Mode") || "";
  if (mode === "navigate") return true;
  const accept = request.headers.get("Accept") || "";
  return accept.includes("text/html");
};

const parseCookieHeader = (cookieHeader) => {
  const out = new Map();
  if (!cookieHeader) return out;
  const parts = cookieHeader.split(";");
  for (let part of parts) {
    part = part.trim();
    if (!part) continue;
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim();
    let value = part.slice(eq + 1).trim();
    if (!key) continue;
    try {
      value = decodeURIComponent(value);
    } catch {
      // ignore decoding errors
    }
    out.set(key, value);
  }
  return out;
};

const getClientIP = (request) =>
  request.headers.get("CF-Connecting-IP") ||
  request.headers.get("cf-connecting-ip") ||
  "0.0.0.0";

const isIpv4 = (ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
const isIpv6 = (ip) => ip.includes(":");

const parseIpv4 = (ip) => {
  if (!isIpv4(ip)) return null;
  const parts = ip.split(".").map((v) => Number.parseInt(v, 10));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return null;
  }
  return parts;
};

const formatIpv4 = (bytes) => bytes.join(".");

const ipv4Cidr = (ip, prefix) => {
  const bytes = parseIpv4(ip);
  if (!bytes) return null;
  const p = Math.min(32, Math.max(0, Number(prefix)));
  const ipInt =
    (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  const mask = p === 0 ? 0 : (~0 << (32 - p)) >>> 0;
  const net = ipInt & mask;
  const netBytes = [
    (net >>> 24) & 0xff,
    (net >>> 16) & 0xff,
    (net >>> 8) & 0xff,
    net & 0xff,
  ];
  return `${formatIpv4(netBytes)}/${p}`;
};

const parseIpv6Hextets = (part) => {
  if (!part) return [];
  const tokens = part.split(":");
  const out = [];
  for (const token of tokens) {
    if (!token) continue;
    if (token.includes(".")) {
      const v4 = parseIpv4(token);
      if (!v4) return null;
      const hi = (v4[0] << 8) | v4[1];
      const lo = (v4[2] << 8) | v4[3];
      out.push(hi, lo);
      continue;
    }
    const value = Number.parseInt(token, 16);
    if (!Number.isFinite(value) || value < 0 || value > 0xffff) return null;
    out.push(value);
  }
  return out;
};

const parseIpv6 = (ip) => {
  if (!ip || typeof ip !== "string") return null;
  const raw = ip.split("%")[0];
  if (!raw) return null;
  if (raw === "::") return new Uint8Array(16);
  const parts = raw.split("::");
  if (parts.length > 2) return null;
  const head = parseIpv6Hextets(parts[0]);
  if (head === null) return null;
  const tail = parts.length === 2 ? parseIpv6Hextets(parts[1]) : [];
  if (tail === null) return null;
  const total = head.length + tail.length;
  if (total > 8) return null;
  const zeros = parts.length === 2 ? 8 - total : 0;
  if (parts.length === 1 && total !== 8) return null;
  const full = head.concat(Array(zeros).fill(0)).concat(tail);
  if (full.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (full[i] >>> 8) & 0xff;
    bytes[i * 2 + 1] = full[i] & 0xff;
  }
  return bytes;
};

const formatIpv6 = (bytes) => {
  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    const value = (bytes[i] << 8) | bytes[i + 1];
    parts.push(value.toString(16).padStart(4, "0"));
  }
  return parts.join(":");
};

const ipv6Cidr = (ip, prefix) => {
  const bytes = parseIpv6(ip);
  if (!bytes) return null;
  const p = Math.min(128, Math.max(0, Number(prefix)));
  const fullBytes = Math.floor(p / 8);
  const rem = p % 8;
  const out = new Uint8Array(bytes);
  for (let i = 0; i < 16; i++) {
    if (i < fullBytes) continue;
    if (i === fullBytes && rem > 0) {
      const mask = 0xff << (8 - rem);
      out[i] = out[i] & mask;
    } else {
      out[i] = 0;
    }
  }
  return `${formatIpv6(out)}/${p}`;
};

const computeIpScope = (ip, config) => {
  const v4Prefix = normalizeNumber(config.IPV4_PREFIX, DEFAULTS.IPV4_PREFIX);
  const v6Prefix = normalizeNumber(config.IPV6_PREFIX, DEFAULTS.IPV6_PREFIX);
  if (isIpv4(ip)) {
    return ipv4Cidr(ip, v4Prefix) || "unknown";
  }
  if (isIpv6(ip)) {
    return ipv6Cidr(ip, v6Prefix) || "unknown";
  }
  return "unknown";
};

const getRequestCf = (request) => {
  const cf = request && request.cf;
  return cf && typeof cf === "object" ? cf : null;
};

const normalizeCfValue = (value) => {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return String(value);
};

const normalizeCountry = (value) => {
  const raw = normalizeCfValue(value);
  return raw ? raw.toUpperCase() : "unknown";
};

const normalizeAsn = (value) => {
  const num = Number(value);
  return Number.isFinite(num) ? String(Math.trunc(num)) : "unknown";
};

const normalizeTlsFingerprint = (value) => {
  if (typeof value !== "string") return "";
  return value.trim();
};

const buildTlsFingerprintHash = async (request) => {
  const cf = getRequestCf(request);
  if (!cf) return "";
  const extensions = normalizeTlsFingerprint(cf.tlsClientExtensionsSha1);
  const ciphers = normalizeTlsFingerprint(cf.tlsClientCiphersSha1);
  if (!extensions || !ciphers) return "";
  const digest = await sha256Bytes(`${extensions}|${ciphers}`);
  return base64UrlEncodeNoPad(digest);
};

const getPowSteps = (config) => {
  const base = normalizeNumber(config.POW_DIFFICULTY_BASE, DEFAULTS.POW_DIFFICULTY_BASE);
  const coeff = normalizeNumber(config.POW_DIFFICULTY_COEFF, DEFAULTS.POW_DIFFICULTY_COEFF);
  const minSteps = normalizeNumber(config.POW_MIN_STEPS, DEFAULTS.POW_MIN_STEPS);
  const maxSteps = normalizeNumber(config.POW_MAX_STEPS, DEFAULTS.POW_MAX_STEPS);
  const raw =
    Number.isFinite(base) && base > 0
      ? Number.isFinite(coeff) && coeff > 0
        ? base * coeff
        : base
      : 1;
  const steps = Math.max(1, Math.round(raw));
  const minVal = Number.isFinite(minSteps) ? Math.max(1, Math.floor(minSteps)) : 1;
  const maxVal = Number.isFinite(maxSteps) ? Math.max(minVal, Math.floor(maxSteps)) : minVal;
  return Math.min(maxVal, Math.max(minVal, steps));
};

const randomBase64Url = (byteLength) => {
  const len = Number.isInteger(byteLength) && byteLength > 0 ? byteLength : 16;
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return base64UrlEncodeNoPad(bytes);
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

const derivePowSid = async (powSecret, cfgId, commitMac) => {
  const bytes = await hmacSha256(powSecret, `pow-sid-v3|${cfgId}|${commitMac}`);
  return base64UrlEncodeNoPad(bytes.slice(0, 12));
};

const derivePowSeedBytes16 = async (powSecret, cfgId, commitMac, sid) => {
  const bytes = await hmacSha256(powSecret, `pow-seed-v3|${cfgId}|${commitMac}|${sid}`);
  return bytes.slice(0, 16);
};

const deriveSpineSeed16 = async (
  powSecret,
  cfgId,
  commitMac,
  sid,
  cursor,
  batchLen,
  spineSeed
) => {
  const bytes = await hmacSha256(
    powSecret,
    `pow-spine-v3|${cfgId}|${commitMac}|${sid}|${cursor}|${batchLen}|${spineSeed}`
  );
  return bytes.slice(0, 16);
};

const deriveSegLenSeed16 = async (powSecret, cfgId, commitMac, sid) => {
  const bytes = await hmacSha256(powSecret, `pow-seglen-v3|${cfgId}|${commitMac}|${sid}`);
  return bytes.slice(0, 16);
};

const clampInt = (value, lo, hi) => {
  const num = Number(value);
  if (!Number.isFinite(num)) return lo;
  return Math.max(lo, Math.min(hi, Math.floor(num)));
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

const makePowCommitMac = async (
  powSecret,
  ticketB64,
  rootB64,
  pathHash,
  tb,
  nonce,
  exp,
  spineSeed
) =>
  hmacSha256Base64UrlNoPad(
    powSecret,
    `commit|${ticketB64}|${rootB64}|${pathHash}|${tb}|${nonce}|${exp}|${spineSeed}`
  );

const makePowStateToken = async (
  powSecret,
  cfgId,
  sid,
  commitMac,
  cursor,
  batchLen,
  spinePos
) =>
  hmacSha256Base64UrlNoPad(
    powSecret,
    `pow-state-v3|${cfgId}|${sid}|${commitMac}|${cursor}|${batchLen}|${serializeSpinePos(
      spinePos
    )}`
  );

const POSW_SEED_PREFIX = encoder.encode("posw|seed|");
const POSW_STEP_PREFIX = encoder.encode("posw|step|");
const MERKLE_LEAF_PREFIX = encoder.encode("leaf|");
const MERKLE_NODE_PREFIX = encoder.encode("node|");
const PIPE_BYTES = encoder.encode("|");
const HASHCASH_PREFIX = encoder.encode("hashcash|v3|");

const makePowBindingString = (
  ticket,
  hostname,
  pathHash,
  ipScope,
  country,
  asn,
  tlsFingerprint
) => {
  const host = typeof hostname === "string" ? hostname.toLowerCase() : "";
  return (
    "v=" +
    ticket.v +
    "&e=" +
    ticket.e +
    "&L=" +
    ticket.L +
    "&r=" +
    ticket.r +
    "&cfg=" +
    ticket.cfgId +
    "&h=" +
    host +
    "&ph=" +
    pathHash +
    "&s=" +
    ipScope +
    "&cc=" +
    country +
    "&asn=" +
    asn +
    "&tls=" +
    tlsFingerprint
  );
};

const hashPoswSeed = async (bindingString, nonce) =>
  sha256Bytes(
    concatBytes(
      POSW_SEED_PREFIX,
      utf8ToBytes(bindingString),
      PIPE_BYTES,
      utf8ToBytes(nonce || "")
    )
  );

const hashPoswStep = async (prevBytes, index) =>
  sha256Bytes(concatBytes(POSW_STEP_PREFIX, encodeUint32BE(index), prevBytes));

const hashMerkleLeaf = async (leafIndex, leafBytes) =>
  sha256Bytes(concatBytes(MERKLE_LEAF_PREFIX, encodeUint32BE(leafIndex), leafBytes));

const hashMerkleNode = async (leftBytes, rightBytes) =>
  sha256Bytes(concatBytes(MERKLE_NODE_PREFIX, leftBytes, rightBytes));

const hashcashRootLast = async (rootBytes, lastBytes) =>
  sha256Bytes(concatBytes(HASHCASH_PREFIX, rootBytes, lastBytes));

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

const encodePowTicket = (ticket) => {
  const raw = `${ticket.v}.${ticket.e}.${ticket.L}.${ticket.r}.${ticket.cfgId}.${ticket.mac}`;
  return base64UrlEncodeNoPad(utf8ToBytes(raw));
};

const parsePowTicket = (ticketB64) => {
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  const bytes = base64UrlDecodeToBytes(ticketB64);
  if (!bytes) return null;
  const raw = bytesToUtf8(bytes);
  const parts = raw.split(".");
  if (parts.length !== 6) return null;
  const v = Number.parseInt(parts[0], 10);
  const e = Number.parseInt(parts[1], 10);
  const L = Number.parseInt(parts[2], 10);
  const r = parts[3] || "";
  const cfgId = Number.parseInt(parts[4], 10);
  const mac = parts[5] || "";
  if (!Number.isFinite(v) || !Number.isFinite(e) || !Number.isFinite(L)) return null;
  if (!Number.isFinite(cfgId) || cfgId < 0) return null;
  if (!r || !mac) return null;
  if (!isBase64Url(r, 1, B64_HASH_MAX_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { v, e, L, r, cfgId, mac };
};

const parsePowCommitCookie = (value) => {
  if (!value || typeof value !== "string") return null;
  const parts = value.split(".");
  if (parts.length !== 9) return null;
  if (parts[0] !== "v4") return null;
  const ticketB64 = parts[1] || "";
  const rootB64 = parts[2] || "";
  const pathHash = parts[3] || "";
  const tb = parts[4] || "";
  const nonce = parts[5] || "";
  const exp = Number.parseInt(parts[6], 10);
  const spineSeed = parts[7] || "";
  const mac = parts[8] || "";
  if (!ticketB64 || !rootB64 || !pathHash || !tb || !nonce || !Number.isFinite(exp) || !mac) {
    return null;
  }
  if (!spineSeed) return null;
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(rootB64, 1, B64_HASH_MAX_LEN)) return null;
  if (!isBase64UrlOrAny(pathHash, 1, B64_HASH_MAX_LEN)) return null;
  if (!isBase64UrlOrAny(tb, TB_LEN, TB_LEN)) return null;
  if (!isBase64Url(nonce, NONCE_MIN_LEN, NONCE_MAX_LEN)) return null;
  if (!isBase64Url(spineSeed, SPINE_SEED_MIN_LEN, SPINE_SEED_MAX_LEN)) {
    return null;
  }
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { ticketB64, rootB64, pathHash, tb, nonce, exp, mac, spineSeed };
};

const parseProofCookie = (value) => {
  if (!value || typeof value !== "string") return null;
  const parts = value.split(".");
  if (parts.length !== 7 || parts[0] !== "v1") return null;
  const ticketB64 = parts[1] || "";
  const iat = Number.parseInt(parts[2], 10);
  const last = Number.parseInt(parts[3], 10);
  const n = Number.parseInt(parts[4], 10);
  const m = Number.parseInt(parts[5], 10);
  const mac = parts[6] || "";
  if (
    !ticketB64 ||
    !Number.isFinite(iat) ||
    !Number.isFinite(last) ||
    !Number.isFinite(n) ||
    !Number.isFinite(m) ||
    !mac
  ) {
    return null;
  }
  if (iat <= 0 || last <= 0 || n < 0) return null;
  if (last < iat) return null;
  if (m < 0 || m > 3) return null;
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { v: 1, ticketB64, iat, last, n, m, mac };
};

const makeProofMac = async (powSecret, ticketB64, iat, last, n, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `proof|${ticketB64}|${iat}|${last}|${n}|${m}`);

const computePathHash = async (canonicalPath) =>
  base64UrlEncodeNoPad(await sha256Bytes(canonicalPath));

const getPowBindingValuesWithPathHash = async (request, pathHash, config) => {
  const bindPath = config.POW_BIND_PATH !== false;
  const bindIp = config.POW_BIND_IPRANGE !== false;
  const bindCountry = config.POW_BIND_COUNTRY === true;
  const bindAsn = config.POW_BIND_ASN === true;
  const bindTls = config.POW_BIND_TLS === true;
  const normalizedPathHash =
    bindPath && typeof pathHash === "string" && pathHash ? pathHash : bindPath ? "" : "any";
  if (bindPath && !normalizedPathHash) return null;
  const ipScope = bindIp ? computeIpScope(getClientIP(request), config) : "any";
  const cf = getRequestCf(request);
  const country = bindCountry ? normalizeCountry(cf && cf.country) : "any";
  const asn = bindAsn ? normalizeAsn(cf && cf.asn) : "any";
  let tlsFingerprint = "any";
  if (bindTls) {
    tlsFingerprint = await buildTlsFingerprintHash(request);
    if (!tlsFingerprint) {
      return null;
    }
  }
  return { pathHash: normalizedPathHash, ipScope, country, asn, tlsFingerprint };
};

const getPowBindingValues = async (request, canonicalPath, config) => {
  const bindPath = config.POW_BIND_PATH !== false;
  const pathHash = bindPath ? await computePathHash(canonicalPath) : "any";
  return getPowBindingValuesWithPathHash(request, pathHash, config);
};

const verifyProofCookie = async (
  request,
  url,
  canonicalPath,
  nowSeconds,
  config,
  powSecret,
  cfgId,
  requiredMask
) => {
  const cookies = parseCookieHeader(request.headers.get("Cookie"));
  const raw = cookies.get(PROOF_COOKIE) || "";
  const proof = parseProofCookie(raw);
  if (!proof) return null;
  if (!Number.isFinite(proof.iat) || proof.iat <= 0 || proof.iat > nowSeconds) return null;
  if (!Number.isFinite(proof.last) || proof.last <= 0 || proof.last > nowSeconds) return null;
  if (proof.last < proof.iat) return null;
  if (!Number.isFinite(proof.n) || proof.n < 0) return null;
  if (!Number.isFinite(proof.m) || proof.m < 0 || proof.m > 3) return null;
  const ticket = parsePowTicket(proof.ticketB64);
  if (!ticket) return null;
  const powVersion = normalizeNumber(config.POW_VERSION, DEFAULTS.POW_VERSION);
  if (ticket.v !== powVersion) return null;
  if (!Number.isFinite(ticket.e) || ticket.e <= nowSeconds) return null;
  if (!Number.isFinite(ticket.L) || ticket.L <= 0) return null;
  if (ticket.cfgId !== cfgId) return null;
  if (proof.last > ticket.e) return null;
  const bindingValues = await getPowBindingValues(request, canonicalPath, config);
  if (!bindingValues) return null;
  const { pathHash, ipScope, country, asn, tlsFingerprint } = bindingValues;
  const bindingString = makePowBindingString(
    ticket,
    url.hostname,
    pathHash,
    ipScope,
    country,
    asn,
    tlsFingerprint
  );
  const expectedMac = await hmacSha256Base64UrlNoPad(powSecret, bindingString);
  if (!timingSafeEqual(expectedMac, ticket.mac)) return null;
  const expectedProofMac = await makeProofMac(
    powSecret,
    proof.ticketB64,
    proof.iat,
    proof.last,
    proof.n,
    proof.m
  );
  if (!timingSafeEqual(expectedProofMac, proof.mac)) return null;
  if ((proof.m & requiredMask) !== requiredMask) return null;
  return { proof, ticket, bindingValues };
};

const maybeRenewProof = async (
  request,
  url,
  nowSeconds,
  config,
  powSecret,
  cfgId,
  meta,
  response
) => {
  if (!meta || !meta.proof || !meta.bindingValues || !response) return response;
  if (config.PROOF_RENEW_ENABLE !== true) return response;
  if (!isNavigationRequest(request)) return response;

  const proof = meta.proof;
  const renewMax = Math.max(
    0,
    Math.floor(normalizeNumber(config.PROOF_RENEW_MAX, DEFAULTS.PROOF_RENEW_MAX))
  );
  if (!renewMax || proof.n >= renewMax) return response;

  const ttl = Math.max(
    1,
    Math.floor(normalizeNumber(config.PROOF_TTL_SEC, DEFAULTS.PROOF_TTL_SEC))
  );
  const window = Math.max(
    0,
    Math.floor(
      normalizeNumber(config.PROOF_RENEW_WINDOW_SEC, DEFAULTS.PROOF_RENEW_WINDOW_SEC)
    )
  );
  const minSinceLast = Math.max(
    0,
    Math.floor(
      normalizeNumber(config.PROOF_RENEW_MIN_SEC, DEFAULTS.PROOF_RENEW_MIN_SEC)
    )
  );
  const curExp = meta.ticket && Number.isFinite(meta.ticket.e) ? meta.ticket.e : 0;
  if (!Number.isFinite(curExp) || curExp <= 0) return response;
  if (curExp - nowSeconds > window) return response;
  if (nowSeconds - proof.last < minSinceLast) return response;

  const hardLimit = proof.iat + ttl * (renewMax + 1);
  if (!Number.isFinite(hardLimit) || hardLimit <= nowSeconds) return response;

  const newExp = Math.min(nowSeconds + ttl, hardLimit);
  if (!Number.isFinite(newExp) || newExp <= nowSeconds || newExp <= curExp) return response;

  const ticket = {
    v: meta.ticket.v,
    e: newExp,
    L: meta.ticket.L,
    r: randomBase64Url(16),
    cfgId,
    mac: "",
  };
  const b = meta.bindingValues;
  const bindingString = makePowBindingString(
    ticket,
    url.hostname,
    b.pathHash,
    b.ipScope,
    b.country,
    b.asn,
    b.tlsFingerprint
  );
  ticket.mac = await hmacSha256Base64UrlNoPad(powSecret, bindingString);
  const ticketB64 = encodePowTicket(ticket);

  const nextN = proof.n + 1;
  const mac = await makeProofMac(powSecret, ticketB64, proof.iat, nowSeconds, nextN, proof.m);
  const proofValue = `v1.${ticketB64}.${proof.iat}.${nowSeconds}.${nextN}.${proof.m}.${mac}`;

  const headers = new Headers(response.headers);
  setCookie(headers, PROOF_COOKIE, proofValue, newExp - nowSeconds);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
};

const buildPowChallengeHtml = ({
  bindingStringB64,
  steps,
  ticketB64,
  pathHash,
  hashcashBits,
  segmentLen,
  reloadUrlB64,
  apiPrefixB64,
  esmUrlB64,
  turnSiteKeyB64,
  glueUrl,
}) => __HTML_TEMPLATE__
  .replace('__BINDING_STRING_B64__', bindingStringB64)
  .replace('__STEPS__', String(steps))
  .replace('__TICKET_B64__', ticketB64)
  .replace('__PATH_HASH__', pathHash)
  .replace('__HASHCASH_BITS__', String(hashcashBits))
  .replace('__SEGMENT_LEN__', String(segmentLen))
  .replace('__GLUE_URL__', glueUrl)
  .replace('__RELOAD_URL_B64__', reloadUrlB64)
  .replace('__API_PREFIX_B64__', apiPrefixB64)
  .replace('__ESM_URL_B64__', esmUrlB64)
  .replace('__TURN_SITEKEY_B64__', turnSiteKeyB64);

const respondPowChallengeHtml = async (
  request,
  url,
  canonicalPath,
  nowSeconds,
  config,
  powSecret,
  cfgId,
  requirements
) => {
  const ticketTtl = normalizeNumber(
    config.POW_TICKET_TTL_SEC,
    DEFAULTS.POW_TICKET_TTL_SEC
  ) || 0;
  const exp = nowSeconds + Math.max(1, ticketTtl);
  const needPow = requirements && requirements.needPow === true;
  const needTurn = requirements && requirements.needTurn === true;
  const steps = needPow ? getPowSteps(config) : 1;
  const glueSteps = needPow ? steps : 0;
  const hashcashBits = needPow
    ? Math.max(
        0,
        Math.floor(
          normalizeNumber(config.POW_HASHCASH_BITS, DEFAULTS.POW_HASHCASH_BITS)
        )
      )
    : 0;
  const segSpec = needPow
    ? parseSegmentLenSpec(config.POW_SEGMENT_LEN, DEFAULTS.POW_SEGMENT_LEN)
    : { mode: "fixed", fixed: 1 };
  const bindingValues = await getPowBindingValues(request, canonicalPath, config);
  if (!bindingValues) return deny();
  const { pathHash, ipScope, country, asn, tlsFingerprint } = bindingValues;
  const powVersion = normalizeNumber(config.POW_VERSION, DEFAULTS.POW_VERSION);
  const ticket = {
    v: powVersion,
    e: exp,
    L: steps,
    r: randomBase64Url(16),
    cfgId,
    mac: "",
  };
  const bindingString = makePowBindingString(
    ticket,
    url.hostname,
    pathHash,
    ipScope,
    country,
    asn,
    tlsFingerprint
  );
  ticket.mac = await hmacSha256Base64UrlNoPad(powSecret, bindingString);
  const ticketB64 = encodePowTicket(ticket);
  const bindingStringB64 = base64UrlEncodeNoPad(utf8ToBytes(bindingString));
  const reloadUrlB64 = base64UrlEncodeNoPad(utf8ToBytes(url.toString()));
  const apiPrefixB64 = base64UrlEncodeNoPad(utf8ToBytes(POW_API_PREFIX));
  const esmUrlB64 = needPow
    ? base64UrlEncodeNoPad(utf8ToBytes(String(config.POW_ESM_URL)))
    : "";
  const turnSiteKeyB64 = needTurn
    ? base64UrlEncodeNoPad(utf8ToBytes(String(config.TURNSTILE_SITEKEY)))
    : "";
  const glueUrl = typeof config.POW_GLUE_URL === "string" ? config.POW_GLUE_URL : "";
  const segmentLenFixed = Math.max(
    1,
    Math.min(
      steps,
      Math.floor(segSpec.mode === "fixed" ? segSpec.fixed : segSpec.min)
    )
  );
  const html = buildPowChallengeHtml({
    bindingStringB64,
    steps: glueSteps,
    ticketB64,
    pathHash,
    hashcashBits,
    segmentLen: segmentLenFixed,
    glueUrl,
    reloadUrlB64,
    apiPrefixB64,
    esmUrlB64,
    turnSiteKeyB64,
  });
  const headers = new Headers();
  headers.set("Content-Type", "text/html");
  headers.set("Cache-Control", "no-store");
  return new Response(html, { status: 200, headers });
};

const readJsonBody = async (request) => {
  try {
    return await request.json();
  } catch {
    return null;
  }
};

const setCookie = (headers, name, value, maxAge) => {
  const parts = [
    `${name}=${encodeURIComponent(String(value || ""))}`,
    "Path=/",
    "Secure",
    "SameSite=None",
    "HttpOnly",
  ];
  if (typeof maxAge === "number") {
    parts.push(`Max-Age=${Math.max(0, Math.floor(maxAge))}`);
  }
  headers.append("Set-Cookie", parts.join("; "));
};

const clearCookie = (headers, name) => {
  setCookie(headers, name, "deleted", 0);
};

const getPowSecret = (config) => {
  const powToken = typeof config.POW_TOKEN === "string" ? config.POW_TOKEN : "";
  return powToken;
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

const sampleIndicesDeterministicV2 = ({
  maxIndex,
  extraCount,
  forceEdge1,
  forceEdgeLast,
  rng,
}) => {
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

const handlePowCommit = async (request, url, nowSeconds) => {
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object") {
    return S(400);
  }
  const ticketB64 = typeof body.ticketB64 === "string" ? body.ticketB64 : "";
  const rootB64 = typeof body.rootB64 === "string" ? body.rootB64 : "";
  const pathHash = typeof body.pathHash === "string" ? body.pathHash : "";
  const nonce = typeof body.nonce === "string" ? body.nonce : "";
  const token = typeof body.token === "string" ? body.token : "";
  if (!ticketB64 || !rootB64 || !nonce) {
    return S(400);
  }
  if (
    !isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN) ||
    !isBase64Url(rootB64, 1, B64_HASH_MAX_LEN) ||
    !isBase64Url(nonce, NONCE_MIN_LEN, NONCE_MAX_LEN) ||
    pathHash.length > B64_HASH_MAX_LEN
  ) {
    return S(400);
  }
  const ticket = parsePowTicket(ticketB64);
  if (!ticket) return deny();
  const baseConfig = getConfigById(ticket.cfgId);
  if (!baseConfig) return deny();
  const config = { ...DEFAULTS, ...baseConfig };
  const powSecret = getPowSecret(config);
  if (!powSecret) return S(500);
  if (config.powcheck !== true) return S(500);
  const needTurn = config.turncheck === true;
  let turnToken = "";
  if (needTurn) {
    turnToken = validateTurnToken(token);
    if (!turnToken) return S(400);
  }
  const powVersion = normalizeNumber(config.POW_VERSION, DEFAULTS.POW_VERSION);
  if (ticket.v !== powVersion) return deny();
  if (isExpired(ticket.e, nowSeconds)) return deny();
  const bindPath = config.POW_BIND_PATH !== false;
  if (bindPath && !isBase64Url(pathHash, 1, B64_HASH_MAX_LEN)) {
    return S(400);
  }
  const normalizedPathHash = bindPath ? pathHash : "any";
  if (bindPath && !normalizedPathHash) {
    return S(400);
  }
  const bindingValues = await getPowBindingValuesWithPathHash(
    request,
    normalizedPathHash,
    config
  );
  if (!bindingValues) return deny();
  const bindingString = makePowBindingString(
    ticket,
    url.hostname,
    bindingValues.pathHash,
    bindingValues.ipScope,
    bindingValues.country,
    bindingValues.asn,
    bindingValues.tlsFingerprint
  );
  const expectedMac = await hmacSha256Base64UrlNoPad(powSecret, bindingString);
  if (!timingSafeEqual(expectedMac, ticket.mac)) return deny();
  const rootBytes = base64UrlDecodeToBytes(rootB64);
  if (!rootBytes || rootBytes.length !== 32) {
    return S(400);
  }
  const ttl = normalizeNumber(config.POW_COMMIT_TTL_SEC, DEFAULTS.POW_COMMIT_TTL_SEC) || 0;
  const exp = nowSeconds + Math.max(1, ttl);
  const spineSeed = randomBase64Url(16);
  const tb = needTurn ? await tbFromToken(turnToken) : "any";
  const mac = await makePowCommitMac(
    powSecret,
    ticketB64,
    rootB64,
    bindingValues.pathHash,
    tb,
    nonce,
    exp,
    spineSeed
  );
  const value = `v4.${ticketB64}.${rootB64}.${bindingValues.pathHash}.${tb}.${nonce}.${exp}.${spineSeed}.${mac}`;
  const headers = new Headers();
  setCookie(headers, DEFAULTS.POW_COMMIT_COOKIE, value, ttl);
  return new Response(null, { status: 200, headers });
};

const handleTurn = async (request, url, nowSeconds) => {
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object") return S(400);
  const ticketB64 = typeof body.ticketB64 === "string" ? body.ticketB64 : "";
  const pathHash = typeof body.pathHash === "string" ? body.pathHash : "";
  const token = typeof body.token === "string" ? body.token : "";
  if (!ticketB64 || !token) return S(400);
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN) || pathHash.length > B64_HASH_MAX_LEN) {
    return S(400);
  }

  const ticket = parsePowTicket(ticketB64);
  if (!ticket) return deny();
  const baseConfig = getConfigById(ticket.cfgId);
  if (!baseConfig) return deny();
  const config = { ...DEFAULTS, ...baseConfig };
  const powSecret = getPowSecret(config);
  if (!powSecret) return S(500);
  const needPow = config.powcheck === true;
  const needTurn = config.turncheck === true;
  if (!needTurn || needPow) return S(404);
  const turnSecret = typeof config.TURNSTILE_SECRET === "string" ? config.TURNSTILE_SECRET : "";
  if (!turnSecret) return S(500);
  const turnToken = validateTurnToken(token);
  if (!turnToken) return S(400);

  const powVersion = normalizeNumber(config.POW_VERSION, DEFAULTS.POW_VERSION);
  if (ticket.v !== powVersion) return deny();
  if (isExpired(ticket.e, nowSeconds)) return deny();

  const bindPath = config.POW_BIND_PATH !== false;
  if (bindPath && !isBase64Url(pathHash, 1, B64_HASH_MAX_LEN)) {
    return S(400);
  }
  const normalizedPathHash = bindPath ? pathHash : "any";
  if (bindPath && !normalizedPathHash) return S(400);

  const bindingValues = await getPowBindingValuesWithPathHash(request, normalizedPathHash, config);
  if (!bindingValues) return deny();
  const bindingString = makePowBindingString(
    ticket,
    url.hostname,
    bindingValues.pathHash,
    bindingValues.ipScope,
    bindingValues.country,
    bindingValues.asn,
    bindingValues.tlsFingerprint
  );
  const expectedMac = await hmacSha256Base64UrlNoPad(powSecret, bindingString);
  if (!timingSafeEqual(expectedMac, ticket.mac)) return deny();

  const form = new URLSearchParams();
  form.set("secret", turnSecret);
  form.set("response", turnToken);
  const remoteip = getClientIP(request);
  if (remoteip && remoteip !== "0.0.0.0") form.set("remoteip", remoteip);
  let verifyRes;
  try {
    verifyRes = await fetch(TURNSTILE_SITEVERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    });
  } catch {
    return deny();
  }
  let verify;
  try {
    verify = await verifyRes.json();
  } catch {
    verify = null;
  }
  if (!verify || verify.success !== true) return deny();
  const cdata = typeof verify.cdata === "string" ? verify.cdata : "";
  if (cdata !== ticket.mac) return deny();

  const proofTtl = normalizeNumber(config.PROOF_TTL_SEC, DEFAULTS.PROOF_TTL_SEC) || 0;
  const remaining = ticket.e - nowSeconds;
  const ttl = Math.max(1, Math.min(proofTtl, remaining));
  if (!Number.isFinite(ttl) || ttl <= 0) return deny();
  const exp = nowSeconds + ttl;
  const proofTicket = {
    v: powVersion,
    e: exp,
    L: ticket.L,
    r: randomBase64Url(16),
    cfgId: ticket.cfgId,
    mac: "",
  };
  const proofBindingString = makePowBindingString(
    proofTicket,
    url.hostname,
    bindingValues.pathHash,
    bindingValues.ipScope,
    bindingValues.country,
    bindingValues.asn,
    bindingValues.tlsFingerprint
  );
  proofTicket.mac = await hmacSha256Base64UrlNoPad(powSecret, proofBindingString);
  const proofTicketB64 = encodePowTicket(proofTicket);
  const iat = nowSeconds;
  const last = nowSeconds;
  const n = 0;
  const m = 2;
  const proofMac = await makeProofMac(powSecret, proofTicketB64, iat, last, n, m);
  const proofValue = `v1.${proofTicketB64}.${iat}.${last}.${n}.${m}.${proofMac}`;
  const headers = new Headers();
  setCookie(headers, PROOF_COOKIE, proofValue, ttl);
  return new Response(null, { status: 200, headers });
};

const handlePowChallenge = async (request, url, nowSeconds) => {
  const cookies = parseCookieHeader(request.headers.get("Cookie"));
  const commitRaw = cookies.get(DEFAULTS.POW_COMMIT_COOKIE) || "";
  const commit = parsePowCommitCookie(commitRaw);
  if (!commit) return deny();
  const ticket = parsePowTicket(commit.ticketB64);
  if (!ticket) return deny();
  const baseConfig = getConfigById(ticket.cfgId);
  if (!baseConfig) return deny();
  const config = { ...DEFAULTS, ...baseConfig };
  const powSecret = getPowSecret(config);
  if (!powSecret) return S(500);
  if (config.powcheck !== true) return S(500);
  const needTurn = config.turncheck === true;
  if (needTurn && !isBase64Url(commit.tb, TB_LEN, TB_LEN)) return deny();
  if (isExpired(commit.exp, nowSeconds)) return deny();
  if (isExpired(ticket.e, nowSeconds)) return deny();
  const expectedMac = await makePowCommitMac(
    powSecret,
    commit.ticketB64,
    commit.rootB64,
    commit.pathHash,
    commit.tb,
    commit.nonce,
    commit.exp,
    commit.spineSeed
  );
  if (!timingSafeEqual(expectedMac, commit.mac)) return deny();
  const powVersion = normalizeNumber(config.POW_VERSION, DEFAULTS.POW_VERSION);
  if (ticket.v !== powVersion) return deny();
  if (!Number.isFinite(ticket.L) || ticket.L <= 0) return deny();
  const rounds = Math.max(
    1,
    Math.floor(
      normalizeNumber(config.POW_CHAL_ROUNDS, DEFAULTS.POW_CHAL_ROUNDS)
    )
  );
  const sampleK = Math.max(
    0,
    Math.floor(
      normalizeNumber(config.POW_SAMPLE_K, DEFAULTS.POW_SAMPLE_K)
    )
  );
  const hashcashBits = Math.max(
    0,
    Math.floor(
      normalizeNumber(config.POW_HASHCASH_BITS, DEFAULTS.POW_HASHCASH_BITS)
    )
  );
  const spineK = Math.max(
    0,
    Math.floor(normalizeNumber(config.POW_SPINE_K, DEFAULTS.POW_SPINE_K))
  );
  const segSpec = parseSegmentLenSpec(
    config.POW_SEGMENT_LEN,
    DEFAULTS.POW_SEGMENT_LEN
  );
  const sid = await derivePowSid(powSecret, ticket.cfgId, commit.mac);
  const seed16 = await derivePowSeedBytes16(powSecret, ticket.cfgId, commit.mac, sid);
  const rng = makeXoshiro128ss(seed16);
  const indices = sampleIndicesDeterministicV2({
    maxIndex: ticket.L,
    extraCount: sampleK * rounds,
    forceEdge1: config.POW_FORCE_EDGE_1 === true,
    forceEdgeLast: config.POW_FORCE_EDGE_LAST === true || hashcashBits > 0,
    rng,
  });
  if (!indices.length) return deny();
  const segSeed16 = await deriveSegLenSeed16(powSecret, ticket.cfgId, commit.mac, sid);
  const rngSeg = makeXoshiro128ss(segSeed16);
  const segLensAll = computeSegLensForIndices(indices, segSpec, rngSeg);
  const batchLen = Math.max(
    1,
    Math.min(
      32,
      Math.floor(
        normalizeNumber(config.POW_OPEN_BATCH, DEFAULTS.POW_OPEN_BATCH)
      )
    )
  );
  const cursor = 0;
  const batch = indices.slice(cursor, cursor + batchLen);
  if (!batch.length) return deny();
  const segBatch = segLensAll.slice(cursor, cursor + batchLen);
  const spineSeed16 = await deriveSpineSeed16(
    powSecret,
    ticket.cfgId,
    commit.mac,
    sid,
    cursor,
    batchLen,
    commit.spineSeed
  );
  const rngSpine = makeXoshiro128ss(spineSeed16);
  const spinePos = spineK > 0
    ? pickSpinePosForBatch(batch, segBatch, ticket.L, spineK, rngSpine)
    : [];
  const token = await makePowStateToken(
    powSecret,
    ticket.cfgId,
    sid,
    commit.mac,
    cursor,
    batchLen,
    spinePos
  );
  return J({
    done: false,
    sid,
    cursor,
    indices: batch,
    segs: segBatch,
    spinePos,
    token,
  });
};

const handlePowOpen = async (request, url, nowSeconds) => {
  const cookies = parseCookieHeader(request.headers.get("Cookie"));
  const commitRaw = cookies.get(DEFAULTS.POW_COMMIT_COOKIE) || "";
  const commit = parsePowCommitCookie(commitRaw);
  if (!commit) return deny();
  const ticket = parsePowTicket(commit.ticketB64);
  if (!ticket) return deny();
  const baseConfig = getConfigById(ticket.cfgId);
  if (!baseConfig) return deny();
  const config = { ...DEFAULTS, ...baseConfig };
  const powSecret = getPowSecret(config);
  if (!powSecret) return S(500);
  if (config.powcheck !== true) return S(500);
  const needTurn = config.turncheck === true;
  if (needTurn && !isBase64Url(commit.tb, TB_LEN, TB_LEN)) return deny();
  const powVersion = normalizeNumber(config.POW_VERSION, DEFAULTS.POW_VERSION);
  if (ticket.v !== powVersion) return deny();
  if (isExpired(commit.exp, nowSeconds)) return deny();
  if (isExpired(ticket.e, nowSeconds)) return deny();
  const commitMac = await makePowCommitMac(
    powSecret,
    commit.ticketB64,
    commit.rootB64,
    commit.pathHash,
    commit.tb,
    commit.nonce,
    commit.exp,
    commit.spineSeed
  );
  if (!timingSafeEqual(commitMac, commit.mac)) return deny();
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object") {
    return S(400);
  }
  const sid = typeof body.sid === "string" ? body.sid : "";
  const cursor = Number.parseInt(body.cursor, 10);
  const stateToken = typeof body.token === "string" ? body.token : "";
  const turnToken = typeof body.turnToken === "string" ? body.turnToken : "";
  const opens = Array.isArray(body.opens) ? body.opens : null;
  const spinePosRaw = body.spinePos;
  if (!sid || !stateToken || !opens || !Number.isFinite(cursor) || cursor < 0) {
    return S(400);
  }
  if (!Array.isArray(spinePosRaw)) {
    return S(400);
  }
  if (
    !isBase64Url(sid, SID_LEN, SID_LEN) ||
    !isBase64Url(stateToken, TOKEN_MIN_LEN, TOKEN_MAX_LEN)
  ) {
    return S(400);
  }
  const batchMax = Math.max(
    1,
    Math.min(
      32,
      Math.floor(
        normalizeNumber(config.POW_OPEN_BATCH, DEFAULTS.POW_OPEN_BATCH)
      )
    )
  );
  if (batchMax <= 0) return S(500);
  const spinePos = normalizeSpinePosList(spinePosRaw, batchMax);
  if (!spinePos) {
    return S(400);
  }
  const sidExpected = await derivePowSid(powSecret, ticket.cfgId, commit.mac);
  if (sid !== sidExpected) return deny();
  const expectedToken = await makePowStateToken(
    powSecret,
    ticket.cfgId,
    sidExpected,
    commit.mac,
    cursor,
    batchMax,
    spinePos
  );
  if (!timingSafeEqual(expectedToken, stateToken)) return deny();
  const rounds = Math.max(
    1,
    Math.floor(
      normalizeNumber(config.POW_CHAL_ROUNDS, DEFAULTS.POW_CHAL_ROUNDS)
    )
  );
  const sampleK = Math.max(
    0,
    Math.floor(
      normalizeNumber(config.POW_SAMPLE_K, DEFAULTS.POW_SAMPLE_K)
    )
  );
  const hashcashBits = Math.max(
    0,
    Math.floor(
      normalizeNumber(config.POW_HASHCASH_BITS, DEFAULTS.POW_HASHCASH_BITS)
    )
  );
  const spineK = Math.max(
    0,
    Math.floor(normalizeNumber(config.POW_SPINE_K, DEFAULTS.POW_SPINE_K))
  );
  const segSpec = parseSegmentLenSpec(
    config.POW_SEGMENT_LEN,
    DEFAULTS.POW_SEGMENT_LEN
  );
  const seed16 = await derivePowSeedBytes16(
    powSecret,
    ticket.cfgId,
    commit.mac,
    sidExpected
  );
  const rng = makeXoshiro128ss(seed16);
  const indices = sampleIndicesDeterministicV2({
    maxIndex: ticket.L,
    extraCount: sampleK * rounds,
    forceEdge1: config.POW_FORCE_EDGE_1 === true,
    forceEdgeLast: config.POW_FORCE_EDGE_LAST === true || hashcashBits > 0,
    rng,
  });
  if (!indices || !indices.length) return deny();
  const segSeed16 = await deriveSegLenSeed16(
    powSecret,
    ticket.cfgId,
    commit.mac,
    sidExpected
  );
  const rngSeg = makeXoshiro128ss(segSeed16);
  const segLensAll = computeSegLensForIndices(indices, segSpec, rngSeg);
  if (hashcashBits > 0 && !indices.includes(ticket.L)) {
    return deny();
  }
  const expectedBatch = indices.slice(cursor, cursor + batchMax);
  if (!expectedBatch.length) return deny();
  const segBatch = segLensAll.slice(cursor, cursor + batchMax);
  if (spinePos.length) {
    for (const pos of spinePos) {
      if (pos >= expectedBatch.length) return deny();
    }
  }
  const eligibleSpine = [];
  for (let pos = 0; pos < expectedBatch.length; pos++) {
    const idx = expectedBatch[pos];
    const segLen = segBatch[pos];
    if (!Number.isFinite(idx) || !Number.isFinite(segLen)) continue;
    if (idx === 1 || idx === ticket.L) continue;
    if (computeMidIndex(idx, segLen) === null) continue;
    eligibleSpine.push(pos);
  }
  const expectedSpineCount = Math.min(spineK, eligibleSpine.length);
  if (spinePos.length !== expectedSpineCount) {
    return deny();
  }
  if (expectedSpineCount > 0) {
    const eligibleSet = new Set(eligibleSpine);
    for (const pos of spinePos) {
      if (!eligibleSet.has(pos)) return deny();
    }
  }
  const spinePosSet = spinePos.length ? new Set(spinePos) : null;
  const batchSize = opens.length;
  if (batchSize !== expectedBatch.length) {
    return deny();
  }
  const batch = [];
  for (let i = 0; i < batchSize; i++) {
    const open = opens[i];
    const idx = open && Number.parseInt(open.i, 10);
    if (!Number.isFinite(idx) || idx < 1 || idx > ticket.L) {
      return S(400);
    }
    const expectedIdx = expectedBatch[i];
    if (idx !== expectedIdx) return deny();
    const requiresMid = spinePosSet && spinePosSet.has(i);
    const segLen = segBatch[i];
    if (!Number.isFinite(segLen) || segLen <= 0) {
      return deny();
    }
    const hPrev = open && typeof open.hPrev === "string" ? open.hPrev : "";
    const hCurr = open && typeof open.hCurr === "string" ? open.hCurr : "";
    if (
      !isBase64Url(hPrev, 1, B64_HASH_MAX_LEN) ||
      !isBase64Url(hCurr, 1, B64_HASH_MAX_LEN)
    ) {
      return S(400);
    }
    const proofPrev = open && open.proofPrev;
    const proofCurr = open && open.proofCurr;
    if (
      !proofPrev ||
      !proofCurr ||
      !Array.isArray(proofPrev.sibs) ||
      !Array.isArray(proofCurr.sibs)
    ) {
      return S(400);
    }
    if (proofPrev.sibs.length > MAX_PROOF_SIBS || proofCurr.sibs.length > MAX_PROOF_SIBS) {
      return S(400);
    }
    for (const sib of proofPrev.sibs) {
      if (!isBase64Url(String(sib || ""), 1, B64_HASH_MAX_LEN)) {
        return S(400);
      }
    }
    for (const sib of proofCurr.sibs) {
      if (!isBase64Url(String(sib || ""), 1, B64_HASH_MAX_LEN)) {
        return S(400);
      }
    }
    if (requiresMid) {
      const hMid = open && typeof open.hMid === "string" ? open.hMid : "";
      if (!isBase64Url(hMid, 1, B64_HASH_MAX_LEN)) {
        return S(400);
      }
      const proofMid = open && open.proofMid;
      if (!proofMid || !Array.isArray(proofMid.sibs)) {
        return S(400);
      }
      if (proofMid.sibs.length > MAX_PROOF_SIBS) {
        return S(400);
      }
      for (const sib of proofMid.sibs) {
        if (!isBase64Url(String(sib || ""), 1, B64_HASH_MAX_LEN)) {
          return S(400);
        }
      }
    }
    batch.push({ idx, open, requiresMid, segLen });
  }
  const bindingValues = await getPowBindingValuesWithPathHash(
    request,
    commit.pathHash,
    config
  );
  if (!bindingValues) return deny();
  const bindingString = makePowBindingString(
    ticket,
    url.hostname,
    bindingValues.pathHash,
    bindingValues.ipScope,
    bindingValues.country,
    bindingValues.asn,
    bindingValues.tlsFingerprint
  );
  const powBindingString = needTurn ? `${bindingString}&tb=${commit.tb}` : bindingString;
  const expectedMac = await hmacSha256Base64UrlNoPad(powSecret, bindingString);
  if (!timingSafeEqual(expectedMac, ticket.mac)) return deny();
  const rootBytes = base64UrlDecodeToBytes(commit.rootB64);
  if (!rootBytes || rootBytes.length !== 32) return deny();
  const leafCount = Math.max(0, Math.floor(ticket.L)) + 1;
  if (leafCount < 2) return deny();
  const seedHash = await hashPoswSeed(powBindingString, commit.nonce);
  for (const entry of batch) {
    const idx = entry.idx;
    const open = entry.open;
    const requiresMid = entry.requiresMid === true;
    const segLen = entry.segLen;
    const hPrevBytes = base64UrlDecodeToBytes(String(open.hPrev || ""));
    const hCurrBytes = base64UrlDecodeToBytes(String(open.hCurr || ""));
    if (!hPrevBytes || !hCurrBytes || hPrevBytes.length !== 32 || hCurrBytes.length !== 32) {
      return S(400);
    }
    const proofPrev = open.proofPrev;
    const proofCurr = open.proofCurr;
    const effectiveSegmentLen = Math.min(segLen, idx);
    let prevBytes = hPrevBytes;
    const firstIdx = idx - effectiveSegmentLen;
    if (firstIdx < 0) return deny();
    const midIdx = requiresMid ? computeMidIndex(idx, segLen) : null;
    let midExpected = null;
    for (let step = 1; step <= effectiveSegmentLen; step++) {
      const expected = await hashPoswStep(prevBytes, firstIdx + step);
      if (requiresMid && firstIdx + step === midIdx) {
        midExpected = expected;
      }
      if (step === effectiveSegmentLen) {
        if (!bytesEqual(expected, hCurrBytes)) return deny();
      } else {
        prevBytes = expected;
      }
    }
    if (requiresMid) {
      if (midIdx === null || !midExpected) return deny();
      const hMidBytes = base64UrlDecodeToBytes(String(open.hMid || ""));
      if (!hMidBytes || hMidBytes.length !== 32) {
        return S(400);
      }
      if (!bytesEqual(midExpected, hMidBytes)) return deny();
      const okMid = await verifyMerkleProof(
        rootBytes,
        hMidBytes,
        midIdx,
        leafCount,
        open.proofMid
      );
      if (!okMid) return deny();
    }
    if (idx === 1 && !bytesEqual(hPrevBytes, seedHash)) {
      return deny();
    }
    const okPrev = await verifyMerkleProof(
      rootBytes,
      hPrevBytes,
      idx - effectiveSegmentLen,
      leafCount,
      proofPrev
    );
    if (!okPrev) return deny();
    const okCurr = await verifyMerkleProof(
      rootBytes,
      hCurrBytes,
      idx,
      leafCount,
      proofCurr
    );
    if (!okCurr) return deny();
    if (idx === ticket.L && hashcashBits > 0) {
      const digest = await hashcashRootLast(rootBytes, hCurrBytes);
      if (leadingZeroBits(digest) < hashcashBits) {
        return deny();
      }
    }
  }
  const nextCursor = cursor + expectedBatch.length;
  if (nextCursor < indices.length) {
    const nextBatch = indices.slice(nextCursor, nextCursor + batchMax);
    const nextSegBatch = segLensAll.slice(nextCursor, nextCursor + batchMax);
    const nextSpineSeed16 = await deriveSpineSeed16(
      powSecret,
      ticket.cfgId,
      commit.mac,
      sidExpected,
      nextCursor,
      batchMax,
      commit.spineSeed
    );
    const rngSpineNext = makeXoshiro128ss(nextSpineSeed16);
    const nextSpinePos = spineK > 0
      ? pickSpinePosForBatch(nextBatch, nextSegBatch, ticket.L, spineK, rngSpineNext)
      : [];
    const nextToken = await makePowStateToken(
      powSecret,
      ticket.cfgId,
      sidExpected,
      commit.mac,
      nextCursor,
      batchMax,
      nextSpinePos
    );
    return J({
      done: false,
      sid: sidExpected,
      cursor: nextCursor,
      indices: nextBatch,
      segs: nextSegBatch,
      spinePos: nextSpinePos,
      token: nextToken,
    });
  }
  if (needTurn) {
    const turnSecret =
      typeof config.TURNSTILE_SECRET === "string" ? config.TURNSTILE_SECRET : "";
    if (!turnSecret) return S(500);
    const finalToken = validateTurnToken(turnToken);
    if (!finalToken) return deny();
    const tb = await tbFromToken(finalToken);
    if (tb !== commit.tb) return deny();
    const form = new URLSearchParams();
    form.set("secret", turnSecret);
    form.set("response", finalToken);
    const remoteip = getClientIP(request);
    if (remoteip && remoteip !== "0.0.0.0") form.set("remoteip", remoteip);
    let verifyRes;
    try {
      verifyRes = await fetch(TURNSTILE_SITEVERIFY_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form,
      });
    } catch {
      return deny();
    }
    let verify;
    try {
      verify = await verifyRes.json();
    } catch {
      verify = null;
    }
    if (!verify || verify.success !== true) return deny();
    const cdata = typeof verify.cdata === "string" ? verify.cdata : "";
    if (cdata !== ticket.mac) return deny();
  }

  const proofTtl = normalizeNumber(config.PROOF_TTL_SEC, DEFAULTS.PROOF_TTL_SEC) || 0;
  const remaining = ticket.e - nowSeconds;
  const ttl = Math.max(1, Math.min(proofTtl, remaining));
  if (!Number.isFinite(ttl) || ttl <= 0) return deny();
  const exp = nowSeconds + ttl;
  const proofTicket = {
    v: powVersion,
    e: exp,
    L: ticket.L,
    r: randomBase64Url(16),
    cfgId: ticket.cfgId,
    mac: "",
  };
  const proofBindingString = makePowBindingString(
    proofTicket,
    url.hostname,
    bindingValues.pathHash,
    bindingValues.ipScope,
    bindingValues.country,
    bindingValues.asn,
    bindingValues.tlsFingerprint
  );
  proofTicket.mac = await hmacSha256Base64UrlNoPad(powSecret, proofBindingString);
  const proofTicketB64 = encodePowTicket(proofTicket);
  const iat = nowSeconds;
  const last = nowSeconds;
  const n = 0;
  const m = needTurn ? 3 : 1;
  const proofMac = await makeProofMac(powSecret, proofTicketB64, iat, last, n, m);
  const proofValue = `v1.${proofTicketB64}.${iat}.${last}.${n}.${m}.${proofMac}`;
  const headers = new Headers();
  setCookie(headers, PROOF_COOKIE, proofValue, ttl);
  clearCookie(headers, DEFAULTS.POW_COMMIT_COOKIE);
  return J({ done: true }, 200, headers);
};

const handlePowApi = async (request, url, nowSeconds) => {
  if (request.method !== "POST") {
    return S(405);
  }
  const path = normalizePath(url.pathname);
  if (!path || !path.startsWith(`${POW_API_PREFIX}/`)) {
    return S(404);
  }
  const action = path.slice(POW_API_PREFIX.length);
  if (action === "/commit") {
    return handlePowCommit(request, url, nowSeconds);
  }
  if (action === "/challenge") {
    return handlePowChallenge(request, url, nowSeconds);
  }
  if (action === "/open") {
    return handlePowOpen(request, url, nowSeconds);
  }
  if (action === "/turn") {
    return handleTurn(request, url, nowSeconds);
  }
  return S(404);
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const hostname = url.hostname;

    if (request.method === "OPTIONS") {
      return S(204);
    }

    const nowSeconds = Math.floor(Date.now() / 1000);

    const requestPath = normalizePath(url.pathname);
    if (!requestPath) return S(400);
    if (requestPath.startsWith(`${POW_API_PREFIX}/`)) {
      return handlePowApi(request, url, nowSeconds);
    }

    const selected = pickConfigWithId(hostname, requestPath);
    const config = selected ? { ...DEFAULTS, ...selected.config } : null;
    if (!config) return S(500);
    const cfgId = selected.cfgId;

    const needPow = config.powcheck === true;
    const needTurn = config.turncheck === true;
    if (!needPow && !needTurn) {
      return fetch(request);
    }

    const bindRes = resolveBindPathForPow(request, url, requestPath, config);
    if (!bindRes.ok) {
      if (bindRes.code === "missing") return S(400);
      if (bindRes.code === "invalid") return S(400);
      return S(500);
    }

    const powSecret = getPowSecret(config);
    if (!powSecret) return S(500);
    if (needPow && !config.POW_ESM_URL) return S(500);
    if (needTurn) {
      const sitekey =
        typeof config.TURNSTILE_SITEKEY === "string" ? config.TURNSTILE_SITEKEY : "";
      const secret =
        typeof config.TURNSTILE_SECRET === "string" ? config.TURNSTILE_SECRET : "";
      if (!sitekey || !secret) return S(500);
    }

    const requiredMask = (needPow ? 1 : 0) | (needTurn ? 2 : 0);
    const proofMeta = await verifyProofCookie(
      request,
      url,
      bindRes.canonicalPath,
      nowSeconds,
      config,
      powSecret,
      cfgId,
      requiredMask
    );

    if (proofMeta) {
      let response = await fetch(bindRes.forwardRequest);
      response = await maybeRenewProof(
        request,
        url,
        nowSeconds,
        config,
        powSecret,
        cfgId,
        proofMeta,
        response
      );
      return response;
    }

    if (!isNavigationRequest(request)) {
      const code = needPow ? "pow_required" : "turn_required";
      return J({ code }, 403);
    }

    return respondPowChallengeHtml(
      request,
      url,
      bindRes.canonicalPath,
      nowSeconds,
      config,
      powSecret,
      cfgId,
      { needPow, needTurn }
    );
  },
};
