import { parentsOf } from "../mhg/graph.js";
import { mixPage } from "../mhg/mix-aes.js";
import { verifyProof } from "../mhg/merkle.js";

const PROOF_COOKIE = "__Host-proof";
const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const RECAPTCHA_SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const B64_HASH_MAX_LEN = 64;
const B64_TICKET_MAX_LEN = 256;
const NONCE_MIN_LEN = 16;
const NONCE_MAX_LEN = 64;
const TOKEN_MIN_LEN = 16;
const TOKEN_MAX_LEN = 64;
const CAPTCHA_TAG_LEN = 16;
const TURN_TOKEN_MIN_LEN = 20;
const TURN_TOKEN_MAX_LEN = 4096;
const MHG_PAGE_BYTES = 64;
const MHG_MAX_PROOF_DEPTH = 32;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hmacKeyCache = new Map();

const HASHCASH_PREFIX = encoder.encode("hashcash|v3|");

const S = (status) => new Response(null, { status });
const J = (payload, status = 200, headers) =>
  new Response(JSON.stringify(payload), { status, headers });
const deny = () => S(403);
const POW_HINT_HEADER = "x-pow-h";
const denyApi = (hint) => {
  const headers = new Headers();
  headers.set(POW_HINT_HEADER, hint);
  return new Response(null, { status: 403, headers });
};
const denyStale = () => denyApi("stale");
const denyCheat = () => denyApi("cheat");

const isBase64Url = (value, minLen, maxLen) => {
  if (typeof value !== "string") return false;
  const len = value.length;
  if (len < minLen || len > maxLen) return false;
  return BASE64URL_RE.test(value);
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

const isExpired = (expire, nowSeconds) => expire > 0 && expire < nowSeconds;

const base64UrlEncodeNoPad = (bytes) => {
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const base64UrlDecodeToBytes = (b64u) => {
  if (!b64u || typeof b64u !== "string") return null;
  let b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
};

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
        ["sign"],
      ),
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

const sha256Bytes = async (data) => {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
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

const u32BE = (bytes, offset) =>
  ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>>
  0;

const rotl = (value, count) => ((value << count) | (value >>> (32 - count))) >>> 0;

const bytesEqual = (a, b) => {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
};

const leadingZeroBits = (bytes) => {
  let count = 0;
  for (const b of bytes || []) {
    if (b === 0) {
      count += 8;
      continue;
    }
    for (let i = 7; i >= 0; i -= 1) {
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
  for (let i = 0; i < aNorm.length; i += 1) {
    diff |= aNorm.charCodeAt(i) ^ bNorm.charCodeAt(i);
  }
  return diff === 0;
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
  request.headers.get("CF-Connecting-IP") || request.headers.get("cf-connecting-ip") || "0.0.0.0";

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
    for (let i = array.length - 1; i > 0; i -= 1) {
      const j = randInt(i + 1);
      const tmp = array[i];
      array[i] = array[j];
      array[j] = tmp;
    }
  };
  return { nextU32, nextFloat, randInt, shuffle };
};

const derivePowSid = async (powSecret, cfgId, commitMac) => {
  const bytes = await hmacSha256(powSecret, `I|${cfgId}|${commitMac}`);
  return base64UrlEncodeNoPad(bytes.slice(0, 12));
};

const derivePowSeedBytes16 = async (powSecret, cfgId, commitMac, sid) => {
  const bytes = await hmacSha256(powSecret, `D|${cfgId}|${commitMac}|${sid}`);
  return bytes.slice(0, 16);
};

const deriveSegLenSeed16 = async (powSecret, cfgId, commitMac, sid) => {
  const bytes = await hmacSha256(powSecret, `G|${cfgId}|${commitMac}|${sid}`);
  return bytes.slice(0, 16);
};

const clampInt = (value, lo, hi) => {
  const num = Number(value);
  if (!Number.isFinite(num)) return lo;
  return Math.max(lo, Math.min(hi, Math.floor(num)));
};

const parseSegmentLenSpec = (raw) => {
  if (raw === null || raw === undefined) return null;
  const isNumericString = typeof raw === "string" && /^\d+$/.test(raw.trim());
  if (typeof raw === "number" && Number.isFinite(raw)) {
    const fixed = clampInt(raw, 1, 64);
    return { mode: "fixed", fixed };
  }
  if (isNumericString) {
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
  return null;
};

const computeSegLensForIndices = (indices, segSpec, rngSeg) => {
  if (!segSpec || segSpec.mode !== "range") {
    const fixed = clampInt(segSpec && segSpec.fixed, 1, 64);
    return indices.map(() => fixed);
  }
  const span = Math.max(1, Math.floor(segSpec.max - segSpec.min + 1));
  return indices.map(() => segSpec.min + rngSeg.randInt(span));
};

const getBatchMax = (config) => Math.max(1, Math.min(32, Math.floor(config.POW_OPEN_BATCH)));

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
  for (let b = 0; b < bucketCount; b += 1) {
    if (!covered[b]) buckets.push(b);
  }
  rng.shuffle(buckets);
  const coverN = Math.min(need, buckets.length);
  for (let i = 0; i < coverN; i += 1) {
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
    for (let i = 1; i <= max && need > 0; i += 1) {
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

const makePowCommitMac = async (powSecret, ticketB64, rootB64, pathHash, captchaTag, nonce, exp) =>
  hmacSha256Base64UrlNoPad(
    powSecret,
    `C2|${ticketB64}|${rootB64}|${pathHash}|${captchaTag}|${nonce}|${exp}`,
  );

const makeConsumeMac = async (powSecret, ticketB64, exp, captchaTag, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `U|${ticketB64}|${exp}|${captchaTag}|${m}`);

const makePowStateToken = async (powSecret, cfgId, sid, commitMac, cursor, batchLen) =>
  hmacSha256Base64UrlNoPad(powSecret, `S2|${cfgId}|${sid}|${commitMac}|${cursor}|${batchLen}`);

const makePowBindingString = (ticket, hostname, pathHash, ipScope, country, asn, tlsFingerprint) => {
  const host = typeof hostname === "string" ? hostname.toLowerCase() : "";
  return (
    ticket.v +
    "|" +
    ticket.e +
    "|" +
    ticket.L +
    "|" +
    ticket.r +
    "|" +
    ticket.cfgId +
    "|" +
    host +
    "|" +
    pathHash +
    "|" +
    ipScope +
    "|" +
    country +
    "|" +
    asn +
    "|" +
    tlsFingerprint
  );
};

const hashcashRootLast = async (rootBytes, lastBytes) =>
  sha256Bytes(concatBytes(HASHCASH_PREFIX, rootBytes, lastBytes));

const decodeMhgProof = (value) => {
  if (!Array.isArray(value) || value.length > MHG_MAX_PROOF_DEPTH) return null;
  const out = [];
  for (const entry of value) {
    if (!isBase64Url(String(entry || ""), 1, B64_HASH_MAX_LEN)) return null;
    const bytes = base64UrlDecodeToBytes(String(entry));
    if (!bytes || bytes.length !== 32) return null;
    out.push(bytes);
  }
  return out;
};

const decodeMhgPage = (value) => {
  if (!isBase64Url(String(value || ""), 1, 8192)) return null;
  const bytes = base64UrlDecodeToBytes(String(value));
  if (!bytes || bytes.length !== MHG_PAGE_BYTES) return null;
  return bytes;
};

const deriveMhgGraphSeed16 = async (ticketB64, nonce) =>
  (await sha256Bytes(`mhg|graph|v2|${ticketB64}|${nonce}`)).slice(0, 16);

const deriveMhgNonce16 = async (nonce) => {
  const raw = base64UrlDecodeToBytes(nonce);
  if (!raw) return null;
  if (raw.length >= 16) return raw.slice(0, 16);
  const digest = await sha256Bytes(raw);
  return digest.slice(0, 16);
};

const encodePowTicket = (ticket) => {
  const raw = `${ticket.v}.${ticket.e}.${ticket.L}.${ticket.r}.${ticket.cfgId}.${ticket.mac}`;
  return base64UrlEncodeNoPad(encoder.encode(raw));
};

const parsePowTicket = (ticketB64) => {
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  const bytes = base64UrlDecodeToBytes(ticketB64);
  if (!bytes) return null;
  const raw = decoder.decode(bytes);
  const parts = raw.split(".");
  if (parts.length !== 6) return null;
  const v = Number.parseInt(parts[0], 10);
  const e = Number.parseInt(parts[1], 10);
  const L = Number.parseInt(parts[2], 10);
  const r = parts[3] || "";
  const cfgId = Number.parseInt(parts[4], 10);
  const mac = parts[5] || "";
  if (!isBase64Url(r, 1, B64_HASH_MAX_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { v, e, L, r, cfgId, mac };
};

const parsePowCommitCookie = (value) => {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 8) return null;
  if (parts[0] !== "v5") return null;
  const ticketB64 = parts[1] || "";
  const rootB64 = parts[2] || "";
  const pathHash = parts[3] || "";
  const captchaTag = parts[4] || "";
  const nonce = parts[5] || "";
  const exp = Number.parseInt(parts[6], 10);
  const mac = parts[7] || "";
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(rootB64, 1, B64_HASH_MAX_LEN)) return null;
  if (!(pathHash === "any" || isBase64Url(pathHash, 1, B64_HASH_MAX_LEN))) return null;
  if (!(captchaTag === "any" || isBase64Url(captchaTag, CAPTCHA_TAG_LEN, CAPTCHA_TAG_LEN))) {
    return null;
  }
  if (!isBase64Url(nonce, NONCE_MIN_LEN, NONCE_MAX_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { ticketB64, rootB64, pathHash, captchaTag, nonce, exp, mac };
};

const makeProofMac = async (powSecret, ticketB64, iat, last, n, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `O|${ticketB64}|${iat}|${last}|${n}|${m}`);

const resolveCaptchaRequirements = (config) => {
  let needTurn = config.turncheck === true;
  let needRecaptcha = config.recaptchaEnabled === true;
  if (!needTurn && !needRecaptcha) {
    const providersRaw = typeof config.providers === "string" ? config.providers : "";
    const providers = providersRaw
      .split(/[\s,]+/u)
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean);
    needTurn = providers.includes("turnstile");
    needRecaptcha = providers.includes("recaptcha") || providers.includes("recaptcha_v3");
  }
  return { needTurn, needRecaptcha };
};

const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;

const validateTurnToken = (value) => {
  if (!value) return null;
  const token = String(value).trim();
  if (token.length < TURN_TOKEN_MIN_LEN || token.length > TURN_TOKEN_MAX_LEN) return null;
  if (CONTROL_CHAR_RE.test(token)) return null;
  return token;
};

const captchaTagV1 = async (turnToken, recaptchaToken) => {
  const turn = typeof turnToken === "string" ? turnToken : "";
  const recaptcha = typeof recaptchaToken === "string" ? recaptchaToken : "";
  const material = `ctag|v1|t=${turn}|r=${recaptcha}`;
  return base64UrlEncodeNoPad((await sha256Bytes(material)).slice(0, 12));
};

const parseCanonicalCaptchaTokens = (captchaToken, needTurn, needRecaptcha) => {
  if (!needTurn && !needRecaptcha) {
    return { ok: true, malformed: false, tokens: { turnstile: "", recaptcha_v3: "" } };
  }

  let envelope = null;
  if (typeof captchaToken === "string") {
    const raw = captchaToken.trim();
    if (!raw) return { ok: false, malformed: true, tokens: null };
    try {
      envelope = JSON.parse(raw);
    } catch {
      return { ok: false, malformed: true, tokens: null };
    }
  } else {
    envelope = captchaToken;
  }

  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    return { ok: false, malformed: true, tokens: null };
  }

  const keys = Object.keys(envelope);
  for (const key of keys) {
    if (key !== "turnstile" && key !== "recaptcha_v3") {
      return { ok: false, malformed: true, tokens: null };
    }
    if (typeof envelope[key] !== "string") {
      return { ok: false, malformed: true, tokens: null };
    }
  }

  const turnRaw = typeof envelope.turnstile === "string" ? envelope.turnstile : "";
  const recaptchaRaw = typeof envelope.recaptcha_v3 === "string" ? envelope.recaptcha_v3 : "";
  const turnstile = needTurn ? validateTurnToken(turnRaw) : "";
  const recaptcha_v3 = needRecaptcha ? validateTurnToken(recaptchaRaw) : "";
  if ((needTurn && !turnstile) || (needRecaptcha && !recaptcha_v3)) {
    return { ok: false, malformed: true, tokens: null };
  }
  return { ok: true, malformed: false, tokens: { turnstile, recaptcha_v3 } };
};

const deriveLocalCaptchaTag = async (config, captchaToken) => {
  const { needTurn, needRecaptcha } = resolveCaptchaRequirements(config);
  if (!needTurn && !needRecaptcha) return { ok: true, malformed: false, captchaTag: "any" };
  const parsed = parseCanonicalCaptchaTokens(captchaToken, needTurn, needRecaptcha);
  if (!parsed.ok) return { ok: false, malformed: parsed.malformed, captchaTag: "" };
  return {
    ok: true,
    malformed: false,
    captchaTag: await captchaTagV1(parsed.tokens.turnstile, parsed.tokens.recaptcha_v3),
  };
};

const resolveRecaptchaAction = (config) => {
  const action = typeof config?.RECAPTCHA_ACTION === "string" ? config.RECAPTCHA_ACTION.trim() : "";
  return action || "submit";
};

const pickRecaptchaPair = async (ticketMac, pairs) => {
  if (!Array.isArray(pairs) || pairs.length === 0) return null;
  const digest = await sha256Bytes(`kid|${typeof ticketMac === "string" ? ticketMac : ""}`);
  const number = ((digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]) >>> 0;
  const kid = number % pairs.length;
  return { kid, pair: pairs[kid] };
};

const getCaptchaProviderSpec = (provider) => {
  if (provider === "turnstile") {
    return { siteverifyUrl: TURNSTILE_SITEVERIFY_URL };
  }
  if (provider === "recaptcha_v3") {
    return { siteverifyUrl: RECAPTCHA_SITEVERIFY_URL };
  }
  return null;
};

const verifyCaptchaSiteverify = async (request, provider, secret, token) => {
  const spec = getCaptchaProviderSpec(provider);
  if (!spec) return null;
  const form = new URLSearchParams();
  form.set("secret", secret);
  form.set("response", token);
  const remoteip = getClientIP(request);
  if (remoteip && remoteip !== "0.0.0.0") form.set("remoteip", remoteip);
  let verifyRes;
  try {
    verifyRes = await fetch(spec.siteverifyUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    });
  } catch {
    return null;
  }
  let verify;
  try {
    verify = await verifyRes.json();
  } catch {
    verify = null;
  }
  if (!verify || verify.success !== true) return null;
  return {
    provider,
    raw: verify,
    cdata: typeof verify.cdata === "string" ? verify.cdata : "",
    hostname: typeof verify.hostname === "string" ? verify.hostname : "",
    remoteip: typeof verify.remoteip === "string" ? verify.remoteip : "",
    action: typeof verify.action === "string" ? verify.action : "",
    score: Number.isFinite(verify.score) ? verify.score : null,
  };
};

const verifyCaptchaForTicket = async (
  request,
  { provider, secret, token, ticketMac, action = "", minScore = 0 },
) => {
  const verify = await verifyCaptchaSiteverify(request, provider, secret, token);
  if (!verify) return false;
  if (provider === "turnstile") {
    return verify.cdata === ticketMac;
  }
  if (provider === "recaptcha_v3") {
    const host = (() => {
      try {
        return new URL(request.url).hostname;
      } catch {
        return "";
      }
    })();
    if (!verify.hostname || verify.hostname !== host) return false;
    const remoteip = getClientIP(request);
    if (remoteip && remoteip !== "0.0.0.0") {
      if (verify.remoteip && verify.remoteip !== remoteip) return false;
    }
    if (!Number.isFinite(verify.score) || verify.score < minScore) return false;
    const expectedAction = typeof action === "string" ? action.trim() : "";
    if (!expectedAction || verify.action !== expectedAction) return false;
    return true;
  }
  return false;
};

const verifyRequiredCaptchaForTicket = async (request, config, ticket, captchaToken) => {
  const { needTurn, needRecaptcha } = resolveCaptchaRequirements(config);
  if (!needTurn && !needRecaptcha) return { ok: true, malformed: false, captchaTag: "any" };
  const parsed = parseCanonicalCaptchaTokens(captchaToken, needTurn, needRecaptcha);
  if (!parsed.ok) return { ok: false, malformed: parsed.malformed, captchaTag: "" };
  const turnToken = parsed.tokens.turnstile;
  const recaptchaToken = parsed.tokens.recaptcha_v3;

  if (needTurn) {
    const turnSecret = config.TURNSTILE_SECRET;
    if (!turnSecret) return { ok: false, malformed: false, captchaTag: "" };
    const turnOk = await verifyCaptchaForTicket(request, {
      provider: "turnstile",
      secret: turnSecret,
      token: turnToken,
      ticketMac: ticket.mac,
    });
    if (!turnOk) return { ok: false, malformed: false, captchaTag: "" };
  }

  if (needRecaptcha) {
    const pairs = Array.isArray(config.RECAPTCHA_PAIRS) ? config.RECAPTCHA_PAIRS : [];
    const picked = await pickRecaptchaPair(ticket.mac, pairs);
    if (!picked || !picked.pair || !picked.pair.secret) {
      return { ok: false, malformed: false, captchaTag: "" };
    }
    const minScore = Number.isFinite(config.RECAPTCHA_MIN_SCORE) ? config.RECAPTCHA_MIN_SCORE : 0.5;
    const recapOk = await verifyCaptchaForTicket(request, {
      provider: "recaptcha_v3",
      secret: picked.pair.secret,
      token: recaptchaToken,
      ticketMac: ticket.mac,
      action: resolveRecaptchaAction(config),
      minScore,
    });
    if (!recapOk) return { ok: false, malformed: false, captchaTag: "" };
  }

  const captchaTag = await captchaTagV1(turnToken, recaptchaToken);
  return { ok: true, malformed: false, captchaTag };
};

const setCookie = (headers, name, value, maxAge) => {
  const parts = [
    `${name}=${encodeURIComponent(String(value || ""))}`,
    "Path=/",
    "Secure",
    "SameSite=Lax",
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

const ticketMatchesInner = (ticket, cfgId) =>
  Boolean(ticket && Number.isInteger(cfgId) && ticket.cfgId === cfgId);

const loadCommitFromRequest = (request, config) => {
  const cookies = parseCookieHeader(request.headers.get("Cookie"));
  const commitRaw = cookies.get(config.POW_COMMIT_COOKIE) || "";
  const commit = parsePowCommitCookie(commitRaw);
  if (!commit) return null;
  const ticket = parsePowTicket(commit.ticketB64);
  if (!ticket) return null;
  return { commit, ticket };
};

const validateTicket = (ticket, config, nowSeconds) => {
  const powVersion = config.POW_VERSION;
  if (ticket.v !== powVersion) return 0;
  if (isExpired(ticket.e, nowSeconds)) return 0;
  return powVersion;
};

const verifyCommit = async (commit, ticket, config, powSecret, nowSeconds) => {
  const { needTurn, needRecaptcha } = resolveCaptchaRequirements(config);
  if (
    (needTurn || needRecaptcha) &&
    !isBase64Url(commit.captchaTag, CAPTCHA_TAG_LEN, CAPTCHA_TAG_LEN)
  ) {
    return 0;
  }
  if (isExpired(commit.exp, nowSeconds)) return 0;
  const powVersion = validateTicket(ticket, config, nowSeconds);
  if (!powVersion) return 0;
  const commitMac = await makePowCommitMac(
    powSecret,
    commit.ticketB64,
    commit.rootB64,
    commit.pathHash,
    commit.captchaTag,
    commit.nonce,
    commit.exp,
  );
  if (!timingSafeEqual(commitMac, commit.mac)) return 0;
  return powVersion;
};

const normalizePathHash = (pathHash, config) => {
  if (config.POW_BIND_PATH === false) return "any";
  return isBase64Url(pathHash, 1, B64_HASH_MAX_LEN) ? pathHash : "";
};

const getPowBindingValuesWithPathHash = async (pathHash, config, derived) => {
  const bindPath = config.POW_BIND_PATH !== false;
  const bindIp = config.POW_BIND_IPRANGE !== false;
  const bindCountry = config.POW_BIND_COUNTRY === true;
  const bindAsn = config.POW_BIND_ASN === true;
  const bindTls = config.POW_BIND_TLS === true;
  const normalizedPathHash =
    bindPath && typeof pathHash === "string" && pathHash ? pathHash : bindPath ? "" : "any";
  if (bindPath && !normalizedPathHash) return null;
  const source = derived && typeof derived === "object" ? derived : null;
  const ipScope = bindIp && source && typeof source.ipScope === "string" ? source.ipScope : "";
  if (bindIp && !ipScope) return null;
  const country = bindCountry && source && typeof source.country === "string" ? source.country : "";
  if (bindCountry && !country) return null;
  const asn = bindAsn && source && typeof source.asn === "string" ? source.asn : "";
  if (bindAsn && !asn) return null;
  const tlsFingerprint =
    bindTls && source && typeof source.tlsFingerprint === "string" ? source.tlsFingerprint : "";
  if (bindTls && !tlsFingerprint) return null;
  return {
    pathHash: normalizedPathHash,
    ipScope: bindIp ? ipScope : "any",
    country: bindCountry ? country : "any",
    asn: bindAsn ? asn : "any",
    tlsFingerprint: bindTls ? tlsFingerprint : "any",
  };
};

const verifyTicketMac = async (ticket, url, bindingValues, powSecret) => {
  const bindingString = makePowBindingString(
    ticket,
    url.hostname,
    bindingValues.pathHash,
    bindingValues.ipScope,
    bindingValues.country,
    bindingValues.asn,
    bindingValues.tlsFingerprint,
  );
  const expectedMac = await hmacSha256Base64UrlNoPad(powSecret, bindingString);
  if (!timingSafeEqual(expectedMac, ticket.mac)) return "";
  return bindingString;
};

const getProofTtl = (ticket, config, nowSeconds) => {
  const proofTtl = config.PROOF_TTL_SEC || 0;
  const remaining = ticket.e - nowSeconds;
  const ttl = Math.max(1, Math.min(proofTtl, remaining));
  return Number.isFinite(ttl) && ttl > 0 ? ttl : 0;
};

const issueProofCookie = async (
  headers,
  powSecret,
  url,
  ticket,
  bindingValues,
  powVersion,
  nowSeconds,
  ttl,
  m,
) => {
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
    bindingValues.tlsFingerprint,
  );
  proofTicket.mac = await hmacSha256Base64UrlNoPad(powSecret, proofBindingString);
  const proofTicketB64 = encodePowTicket(proofTicket);
  const iat = nowSeconds;
  const last = nowSeconds;
  const n = 0;
  const proofMac = await makeProofMac(powSecret, proofTicketB64, iat, last, n, m);
  const proofValue = `v1.${proofTicketB64}.${iat}.${last}.${n}.${m}.${proofMac}`;
  setCookie(headers, PROOF_COOKIE, proofValue, ttl);
};

const buildPowSample = async (config, powSecret, ticket, commitMac, sid) => {
  const rounds = Math.max(1, Math.floor(config.POW_CHAL_ROUNDS));
  const sampleK = Math.max(0, Math.floor(config.POW_SAMPLE_K));
  const hashcashBits = Math.max(0, Math.floor(config.POW_HASHCASH_BITS));
  const segSpec = parseSegmentLenSpec(config.POW_SEGMENT_LEN);
  if (!segSpec) return null;
  const seed16 = await derivePowSeedBytes16(powSecret, ticket.cfgId, commitMac, sid);
  const rng = makeXoshiro128ss(seed16);
  const indices = sampleIndicesDeterministicV2({
    maxIndex: ticket.L,
    extraCount: sampleK * rounds,
    forceEdge1: true,
    forceEdgeLast: true,
    rng,
  });
  if (!indices.length) return null;
  const segSeed16 = await deriveSegLenSeed16(powSecret, ticket.cfgId, commitMac, sid);
  const rngSeg = makeXoshiro128ss(segSeed16);
  const segLensAll = computeSegLensForIndices(indices, segSpec, rngSeg);
  return { indices, segLensAll, hashcashBits };
};

const buildPowBatchResponse = async (
  indices,
  segLensAll,
  ticket,
  commit,
  powSecret,
  sid,
  cursor,
  batchLen,
) => {
  const batch = indices.slice(cursor, cursor + batchLen);
  if (!batch.length) return null;
  const segBatch = segLensAll.slice(cursor, cursor + batchLen);
  const token = await makePowStateToken(powSecret, ticket.cfgId, sid, commit.mac, cursor, batchLen);
  return { done: false, sid, cursor, indices: batch, segs: segBatch, token };
};

const readJsonBody = async (request) => {
  try {
    return await request.json();
  } catch {
    return null;
  }
};

const handlePowCommit = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId } = innerCtx;
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object") {
    return S(400);
  }
  const ticketB64 = typeof body.ticketB64 === "string" ? body.ticketB64 : "";
  const rootB64 = typeof body.rootB64 === "string" ? body.rootB64 : "";
  const pathHash = typeof body.pathHash === "string" ? body.pathHash : "";
  const nonce = typeof body.nonce === "string" ? body.nonce : "";
  const captchaToken = body.captchaToken;
  if (
    !isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN) ||
    !isBase64Url(rootB64, 1, B64_HASH_MAX_LEN) ||
    !isBase64Url(nonce, NONCE_MIN_LEN, NONCE_MAX_LEN) ||
    pathHash.length > B64_HASH_MAX_LEN
  ) {
    return S(400);
  }
  const ticket = parsePowTicket(ticketB64);
  if (!ticket) return denyStale();
  if (!ticketMatchesInner(ticket, cfgId)) return denyStale();
  if (!powSecret) return S(500);
  if (config.powcheck !== true) return S(500);
  const { needTurn, needRecaptcha } = resolveCaptchaRequirements(config);
  const powVersion = validateTicket(ticket, config, nowSeconds);
  if (!powVersion) return denyStale();
  const normalizedPathHash = normalizePathHash(pathHash, config);
  if (!normalizedPathHash) return S(400);
  const bindingValues = await getPowBindingValuesWithPathHash(normalizedPathHash, config, derived);
  if (!bindingValues) return denyStale();
  const bindingString = await verifyTicketMac(ticket, url, bindingValues, powSecret);
  if (!bindingString) return denyStale();
  const rootBytes = base64UrlDecodeToBytes(rootB64);
  if (!rootBytes || rootBytes.length !== 32) {
    return S(400);
  }
  const ttl = config.POW_COMMIT_TTL_SEC || 0;
  const exp = nowSeconds + Math.max(1, ttl);
  let captchaTag = "any";
  if (needTurn || needRecaptcha) {
    const localCaptcha = await deriveLocalCaptchaTag(config, captchaToken);
    if (!localCaptcha.ok) return localCaptcha.malformed ? S(400) : deny();
    captchaTag = localCaptcha.captchaTag;
  }
  const mac = await makePowCommitMac(
    powSecret,
    ticketB64,
    rootB64,
    bindingValues.pathHash,
    captchaTag,
    nonce,
    exp,
  );
  const value = `v5.${ticketB64}.${rootB64}.${bindingValues.pathHash}.${captchaTag}.${nonce}.${exp}.${mac}`;
  const headers = new Headers();
  setCookie(headers, config.POW_COMMIT_COOKIE, value, ttl);
  return new Response(null, { status: 200, headers });
};

const handleCap = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId } = innerCtx;
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object") return S(400);
  const ticketB64 = typeof body.ticketB64 === "string" ? body.ticketB64 : "";
  const pathHash = typeof body.pathHash === "string" ? body.pathHash : "";
  const captchaToken = body.captchaToken;
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN) || pathHash.length > B64_HASH_MAX_LEN) {
    return S(400);
  }

  const ticket = parsePowTicket(ticketB64);
  if (!ticket) return deny();
  if (!ticketMatchesInner(ticket, cfgId)) return deny();
  if (!powSecret) return S(500);
  const needPow = config.powcheck === true;
  const { needTurn, needRecaptcha } = resolveCaptchaRequirements(config);
  const requiredMask = (needPow ? 1 : 0) | (needTurn ? 2 : 0) | (needRecaptcha ? 4 : 0);
  if (needPow || (!needTurn && !needRecaptcha) || config.ATOMIC_CONSUME === true) return S(404);

  const powVersion = validateTicket(ticket, config, nowSeconds);
  if (!powVersion) return deny();

  const normalizedPathHash = normalizePathHash(pathHash, config);
  if (!normalizedPathHash) return S(400);

  const bindingValues = await getPowBindingValuesWithPathHash(normalizedPathHash, config, derived);
  if (!bindingValues) return deny();
  const bindingString = await verifyTicketMac(ticket, url, bindingValues, powSecret);
  if (!bindingString) return deny();

  const verifiedCaptcha = await verifyRequiredCaptchaForTicket(request, config, ticket, captchaToken);
  if (!verifiedCaptcha.ok) {
    return verifiedCaptcha.malformed ? S(400) : denyStale();
  }

  const ttl = getProofTtl(ticket, config, nowSeconds);
  if (!ttl) return denyStale();
  const headers = new Headers();
  await issueProofCookie(
    headers,
    powSecret,
    url,
    ticket,
    bindingValues,
    powVersion,
    nowSeconds,
    ttl,
    requiredMask,
  );
  return new Response(null, { status: 200, headers });
};

const handlePowChallenge = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId } = innerCtx;
  const commitCtx = loadCommitFromRequest(request, config);
  if (!commitCtx) return deny();
  const { commit, ticket } = commitCtx;
  if (!ticketMatchesInner(ticket, cfgId)) return deny();
  if (!powSecret) return S(500);
  if (config.powcheck !== true) return S(500);
  if (isExpired(ticket.e, nowSeconds) || isExpired(commit.exp, nowSeconds)) return denyStale();
  if (!(await verifyCommit(commit, ticket, config, powSecret, nowSeconds))) return denyCheat();
  if (!Number.isFinite(ticket.L) || ticket.L <= 0) return deny();
  const bindingValues = await getPowBindingValuesWithPathHash(commit.pathHash, config, derived);
  if (!bindingValues) return deny();
  if (!(await verifyTicketMac(ticket, url, bindingValues, powSecret))) return deny();
  const sid = await derivePowSid(powSecret, ticket.cfgId, commit.mac);
  const sample = await buildPowSample(config, powSecret, ticket, commit.mac, sid);
  if (!sample) return deny();
  const { indices, segLensAll } = sample;
  const batchLen = getBatchMax(config);
  const batchResp = await buildPowBatchResponse(
    indices,
    segLensAll,
    ticket,
    commit,
    powSecret,
    sid,
    0,
    batchLen,
  );
  if (!batchResp) return deny();
  return J(batchResp);
};

const handlePowOpen = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId } = innerCtx;
  const commitCtx = loadCommitFromRequest(request, config);
  if (!commitCtx) return deny();
  const { commit, ticket } = commitCtx;
  if (!ticketMatchesInner(ticket, cfgId)) return deny();
  if (!powSecret) return S(500);
  if (config.powcheck !== true) return S(500);
  const { needTurn, needRecaptcha } = resolveCaptchaRequirements(config);
  const requiredMask = 1 | (needTurn ? 2 : 0) | (needRecaptcha ? 4 : 0);
  if (isExpired(ticket.e, nowSeconds) || isExpired(commit.exp, nowSeconds)) return denyStale();
  const powVersion = await verifyCommit(commit, ticket, config, powSecret, nowSeconds);
  if (!powVersion) return denyCheat();
  const bindingValues = await getPowBindingValuesWithPathHash(commit.pathHash, config, derived);
  if (!bindingValues) return deny();
  if (!(await verifyTicketMac(ticket, url, bindingValues, powSecret))) return deny();
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object") {
    return S(400);
  }
  const cursor = Number.parseInt(body.cursor, 10);
  const stateToken = typeof body.token === "string" ? body.token : "";
  const captchaToken = body.captchaToken;
  const opens = Array.isArray(body.opens) ? body.opens : null;
  if (!stateToken || !opens || !Number.isFinite(cursor) || cursor < 0) {
    return S(400);
  }
  if (!isBase64Url(stateToken, TOKEN_MIN_LEN, TOKEN_MAX_LEN)) {
    return S(400);
  }
  const batchMax = getBatchMax(config);
  if (batchMax <= 0) return S(500);
  const sidExpected = await derivePowSid(powSecret, ticket.cfgId, commit.mac);
  const expectedToken = await makePowStateToken(
    powSecret,
    ticket.cfgId,
    sidExpected,
    commit.mac,
    cursor,
    batchMax,
  );
  if (!timingSafeEqual(expectedToken, stateToken)) return denyCheat();
  const sample = await buildPowSample(config, powSecret, ticket, commit.mac, sidExpected);
  if (!sample) return denyCheat();
  const { indices, segLensAll, hashcashBits } = sample;
  if (hashcashBits > 0 && !indices.includes(ticket.L)) return denyCheat();
  const expectedBatch = indices.slice(cursor, cursor + batchMax);
  if (!expectedBatch.length) return denyCheat();
  const segBatch = segLensAll.slice(cursor, cursor + batchMax);
  const batchSize = opens.length;
  if (batchSize !== expectedBatch.length) {
    return denyCheat();
  }
  const mhgBatch = [];
  for (let i = 0; i < batchSize; i += 1) {
    const open = opens[i];
    if (!open || typeof open !== "object" || Array.isArray(open)) return S(400);
    const idx = Number.parseInt(open.i, 10);
    if (!Number.isFinite(idx) || idx < 1 || idx > ticket.L) {
      return S(400);
    }
    const expectedIdx = expectedBatch[i];
    if (idx !== expectedIdx) return denyCheat();
    const segLen = segBatch[i];
    if (!Number.isFinite(segLen) || segLen <= 0) {
      return denyCheat();
    }
    const page = decodeMhgPage(open.page);
    const p0 = decodeMhgPage(open.p0);
    const p1 = decodeMhgPage(open.p1);
    const p2 = decodeMhgPage(open.p2);
    const proofObj = open.proof && typeof open.proof === "object" ? open.proof : null;
    if (!page || !p0 || !p1 || !p2 || !proofObj) return S(400);
    const proofPage = decodeMhgProof(proofObj.page);
    const proofP0 = decodeMhgProof(proofObj.p0);
    const proofP1 = decodeMhgProof(proofObj.p1);
    const proofP2 = decodeMhgProof(proofObj.p2);
    if (!proofPage || !proofP0 || !proofP1 || !proofP2) return S(400);
    mhgBatch.push({ idx, segLen, page, p0, p1, p2, proofPage, proofP0, proofP1, proofP2 });
  }

  if (mhgBatch.length !== expectedBatch.length) return denyCheat();
  const rootBytes = base64UrlDecodeToBytes(commit.rootB64);
  if (!rootBytes || rootBytes.length !== 32) return denyCheat();
  const graphSeed = await deriveMhgGraphSeed16(commit.ticketB64, commit.nonce);
  const nonce16 = await deriveMhgNonce16(commit.nonce);
  if (!nonce16) return denyCheat();
  const leafCount = ticket.L + 1;
  for (const entry of mhgBatch) {
    const { idx, page, p0, p1, p2, proofPage, proofP0, proofP1, proofP2 } = entry;
    const parents = await parentsOf(idx, graphSeed);
    const validPage = await verifyProof({ root: rootBytes, index: idx, page, proof: proofPage, leafCount });
    const validP0 = await verifyProof({
      root: rootBytes,
      index: parents.p0,
      page: p0,
      proof: proofP0,
      leafCount,
    });
    const validP1 = await verifyProof({
      root: rootBytes,
      index: parents.p1,
      page: p1,
      proof: proofP1,
      leafCount,
    });
    const validP2 = await verifyProof({
      root: rootBytes,
      index: parents.p2,
      page: p2,
      proof: proofP2,
      leafCount,
    });
    if (!validPage || !validP0 || !validP1 || !validP2) return denyCheat();
    const expectedPage = await mixPage({
      i: idx,
      p0,
      p1,
      p2,
      graphSeed,
      nonce: nonce16,
      pageBytes: MHG_PAGE_BYTES,
    });
    if (!bytesEqual(expectedPage, page)) return denyCheat();
    if (idx === ticket.L && hashcashBits > 0) {
      const digest = await hashcashRootLast(rootBytes, page);
      if (leadingZeroBits(digest) < hashcashBits) return denyCheat();
    }
  }

  const nextCursor = cursor + expectedBatch.length;
  if (nextCursor < indices.length) {
    const nextResp = await buildPowBatchResponse(
      indices,
      segLensAll,
      ticket,
      commit,
      powSecret,
      sidExpected,
      nextCursor,
      batchMax,
    );
    if (!nextResp) return denyCheat();
    return J(nextResp);
  }
  const ttl = getProofTtl(ticket, config, nowSeconds);
  if (!ttl) return deny();

  if ((needTurn || needRecaptcha) && config.ATOMIC_CONSUME === true) {
    const localCaptcha = await deriveLocalCaptchaTag(config, captchaToken);
    if (!localCaptcha.ok) return localCaptcha.malformed ? S(400) : denyStale();
    if (localCaptcha.captchaTag !== commit.captchaTag) return denyCheat();
    const exp = nowSeconds + ttl;
    const mac = await makeConsumeMac(
      powSecret,
      commit.ticketB64,
      exp,
      localCaptcha.captchaTag,
      requiredMask,
    );
    const headers = new Headers();
    clearCookie(headers, config.POW_COMMIT_COOKIE);
    return J(
      {
        done: true,
        consume: `v2.${commit.ticketB64}.${exp}.${localCaptcha.captchaTag}.${requiredMask}.${mac}`,
      },
      200,
      headers,
    );
  }

  if (needTurn || needRecaptcha) {
    const verifiedCaptcha = await verifyRequiredCaptchaForTicket(request, config, ticket, captchaToken);
    if (!verifiedCaptcha.ok) return verifiedCaptcha.malformed ? S(400) : denyStale();
    if (verifiedCaptcha.captchaTag !== commit.captchaTag) return denyCheat();
  }

  const headers = new Headers();
  await issueProofCookie(
    headers,
    powSecret,
    url,
    ticket,
    bindingValues,
    powVersion,
    nowSeconds,
    ttl,
    requiredMask,
  );
  clearCookie(headers, config.POW_COMMIT_COOKIE);
  return J({ done: true }, 200, headers);
};

export const handlePowApi = async (request, url, nowSeconds, innerCtx) => {
  if (request.method !== "POST") {
    return S(405);
  }
  if (!innerCtx) return S(500);
  const { config } = innerCtx;
  const path = normalizePath(url.pathname);
  if (!path || !path.startsWith(`${config.POW_API_PREFIX}/`)) {
    return S(404);
  }
  const action = path.slice(config.POW_API_PREFIX.length);
  if (action === "/commit") {
    return handlePowCommit(request, url, nowSeconds, innerCtx);
  }
  if (action === "/challenge") {
    return handlePowChallenge(request, url, nowSeconds, innerCtx);
  }
  if (action === "/open") {
    return handlePowOpen(request, url, nowSeconds, innerCtx);
  }
  if (action === "/cap") {
    return handleCap(request, url, nowSeconds, innerCtx);
  }
  return S(404);
};
