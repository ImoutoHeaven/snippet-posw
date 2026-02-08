// Cloudflare Snippet: pow-config header injector

const CONFIG = [];

const DEFAULTS = {
  powcheck: false,
  turncheck: false,
  recaptchaEnabled: false,
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
  ATOMIC_CONSUME: false,
  ATOMIC_TURN_QUERY: "__ts",
  ATOMIC_TICKET_QUERY: "__tt",
  ATOMIC_CONSUME_QUERY: "__ct",
  ATOMIC_TURN_HEADER: "x-turnstile",
  ATOMIC_TICKET_HEADER: "x-ticket",
  ATOMIC_CONSUME_HEADER: "x-consume",
  ATOMIC_COOKIE_NAME: "__Secure-pow_a",
  STRIP_ATOMIC_QUERY: true,
  STRIP_ATOMIC_HEADERS: true,
  INNER_AUTH_QUERY_NAME: "",
  INNER_AUTH_QUERY_VALUE: "",
  INNER_AUTH_HEADER_NAME: "",
  INNER_AUTH_HEADER_VALUE: "",
  stripInnerAuthQuery: false,
  stripInnerAuthHeader: false,
  POW_BIND_PATH: true,
  POW_BIND_IPRANGE: true,
  POW_BIND_COUNTRY: false,
  POW_BIND_ASN: false,
  POW_BIND_TLS: true,
  IPV4_PREFIX: 32,
  IPV6_PREFIX: 64,
  POW_COMMIT_COOKIE: "__Host-pow_commit",
  POW_ESM_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@1d96b767b998d2620b41d73ab41662020214f056/esm/esm.js",
  POW_GLUE_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@1d96b767b998d2620b41d73ab41662020214f056/glue.js",
  RECAPTCHA_PAIRS: [],
  RECAPTCHA_MIN_SCORE: 0.5,
};

const normalizeCompiledEntry = (entry) => ({
  hostRegex:
    entry.hostRegex instanceof RegExp
      ? entry.hostRegex
      : entry.host
        ? new RegExp(entry.host.s, entry.host.f || "")
        : null,
  pathRegex:
    entry.pathRegex instanceof RegExp
      ? entry.pathRegex
      : entry.path
        ? new RegExp(entry.path.s, entry.path.f || "")
        : null,
  hostType: entry.hostType,
  hostExact: entry.hostExact,
  hostLabels: entry.hostLabels,
  hostLabelCount: entry.hostLabelCount,
  pathType: entry.pathType,
  pathExact: entry.pathExact,
  pathPrefix: entry.pathPrefix,
  whenNeeds: entry.whenNeeds,
  when: entry.when ?? null,
  config: entry.config || {},
});

let COMPILED_CONFIG = (
  typeof __COMPILED_CONFIG__ === "undefined" ? [] : __COMPILED_CONFIG__
).map(normalizeCompiledEntry);

const INNER_HEADER = "X-Pow-Inner";
const INNER_MAC = "X-Pow-Inner-Mac";
const INNER_EXPIRE_HEADER = "X-Pow-Inner-Expire";
const INNER_COUNT_HEADER = "X-Pow-Inner-Count";
const INNER_HEADER_PREFIX = "X-Pow-Inner-";
const INNER_CHUNK_SIZE = 1800;
const CONFIG_SECRET = "replace-me";
const isPlaceholderConfigSecret = (value) =>
  typeof value !== "string" || !value.trim() || value === "replace-me";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hmacKeyCache = new Map();

const base64UrlEncode = (bytes) => {
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_");
};

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

const utf8ToBytes = (value) => encoder.encode(String(value ?? ""));

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

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const B64_HASH_MAX_LEN = 64;
const B64_TICKET_MAX_LEN = 256;
const BIND_PATH_INPUT_MAX_LEN = 2048;
const ATOMIC_CAPTCHA_MAX_LEN = 8192;
const ATOMIC_TICKET_MAX_LEN = 2048;
const ATOMIC_CONSUME_MAX_LEN = 256;
const ATOMIC_COOKIE_NAME_MAX_LEN = 128;
const ATOMIC_SNAPSHOT_MAX_LEN = 12288;
const NONCE_MIN_LEN = 16;
const NONCE_MAX_LEN = 64;
const SPINE_SEED_MIN_LEN = 16;
const SPINE_SEED_MAX_LEN = 64;
const CAPTCHA_TAG_LEN = 16;
const TURN_TOKEN_MIN_LEN = 20;
const TURN_TOKEN_MAX_LEN = 4096;
const PREFLIGHT_REASON_MAX_LEN = 64;
const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

const isBase64Url = (value, minLen, maxLen) => {
  if (typeof value !== "string") return false;
  const len = value.length;
  if (len < minLen || len > maxLen) return false;
  return BASE64URL_RE.test(value);
};

const normalizeNumber = (value, fallback) => {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
};

const normalizeNumberClamp = (value, fallback, min, max) => {
  const num = normalizeNumber(value, fallback);
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
};

const normalizeBoolean = (value, fallback) =>
  value === true ? true : value === false ? false : fallback;

const normalizeString = (value, fallback) =>
  typeof value === "string" ? value : fallback;

const normalizeRecaptchaPairs = (value) => {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const pair of value) {
    const sitekey = normalizeString(pair && pair.sitekey, "").trim();
    const secret = normalizeString(pair && pair.secret, "").trim();
    if (!sitekey || !secret) continue;
    out.push({ sitekey, secret });
  }
  return out;
};

const clampIntRange = (value, min, max) =>
  Math.min(max, Math.max(min, Math.floor(value)));

const normalizeSegmentLen = (value, fallback) => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return clampIntRange(value, 1, 64);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (/^\d+$/.test(trimmed)) {
      return clampIntRange(Number(trimmed), 1, 64);
    }
    const match = trimmed.match(/^(\d+)\s*-\s*(\d+)$/);
    if (match) {
      let min = clampIntRange(Number(match[1]), 1, 64);
      let max = clampIntRange(Number(match[2]), 1, 64);
      if (min > max) {
        [min, max] = [max, min];
      }
      return `${min}-${max}`;
    }
  }
  return fallback;
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

const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;

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

const normalizeBindPathInput = (raw) => {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > BIND_PATH_INPUT_MAX_LEN) {
    return null;
  }
  let decoded;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return null;
  }
  const canonical = decoded[0] === "/" ? decoded : `/${decoded}`;
  if (canonical.length > BIND_PATH_INPUT_MAX_LEN) return null;
  if (CONTROL_CHAR_RE.test(canonical)) return null;
  return canonical;
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

const resolveBypassRequest = (request, url, config) => {
  const queryName = config.INNER_AUTH_QUERY_NAME.trim();
  const queryValue = config.INNER_AUTH_QUERY_VALUE;
  const headerName = config.INNER_AUTH_HEADER_NAME.trim();
  const headerValue = config.INNER_AUTH_HEADER_VALUE;
  const queryConfigured = Boolean(queryName && queryValue);
  const headerConfigured = Boolean(headerName && headerValue);
  const queryMatch = queryConfigured
    ? (() => {
        const got = url.searchParams.get(queryName);
        return typeof got === "string" && timingSafeEqual(got, queryValue);
      })()
    : false;
  const headerMatch = headerConfigured
    ? (() => {
        const got = request.headers.get(headerName);
        return typeof got === "string" && timingSafeEqual(got, headerValue);
      })()
    : false;

  const bypass =
    queryConfigured && headerConfigured
      ? queryMatch && headerMatch
      : queryConfigured
        ? queryMatch
        : headerConfigured
          ? headerMatch
          : false;

  if (!bypass) {
    return { bypass: false, forwardRequest: request };
  }

  const stripQuery = queryMatch && config.stripInnerAuthQuery === true;
  const stripHeader = headerMatch && config.stripInnerAuthHeader === true;
  let forwardRequest = request;

  if (stripQuery) {
    const nextUrl = new URL(url.toString());
    nextUrl.searchParams.delete(queryName);
    forwardRequest = new Request(nextUrl, request);
  }

  if (stripHeader) {
    const headers = new Headers(forwardRequest.headers);
    headers.delete(headerName);
    forwardRequest = new Request(forwardRequest, { headers });
  }

  return { bypass: true, forwardRequest };
};

const resolveBindPathForPow = (request, url, requestPath, config) => {
  if (config.POW_BIND_PATH === false) {
    return { ok: true, canonicalPath: requestPath, forwardRequest: request };
  }
  const mode = config.bindPathMode;
  if (!mode || mode === "none") {
    return { ok: true, canonicalPath: requestPath, forwardRequest: request };
  }
  if (mode === "query") {
    const name = config.bindPathQueryName.trim();
    if (!name) return { ok: false, code: "misconfigured", forwardRequest: request };
    const raw = url.searchParams.get(name);
    if (!raw) return { ok: false, code: "missing", forwardRequest: request };
    const canonical = normalizeBindPathInput(raw);
    if (!canonical) return { ok: false, code: "invalid", forwardRequest: request };
    return { ok: true, canonicalPath: canonical, forwardRequest: request };
  }
  if (mode === "header") {
    const name = config.bindPathHeaderName.trim();
    if (!name) return { ok: false, code: "misconfigured", forwardRequest: request };
    const raw = request.headers.get(name);
    if (!raw) return { ok: false, code: "missing", forwardRequest: request };
    const canonical = normalizeBindPathInput(raw);
    if (!canonical) return { ok: false, code: "invalid", forwardRequest: request };
    if (config.stripBindPathHeader === true) {
      const headers = new Headers(request.headers);
      headers.delete(name);
      const forwardRequest = new Request(request, { headers });
      return { ok: true, canonicalPath: canonical, forwardRequest };
    }
    return { ok: true, canonicalPath: canonical, forwardRequest: request };
  }
  return { ok: false, code: "misconfigured", forwardRequest: request };
};

const parseAtomicCookie = (value) => {
  if (!value) return null;
  const parts = value.split("|");
  if (parts[0] !== "1" || parts.length < 4) return null;
  const mode = parts[1];
  const captchaToken = parts[2] || "";
  const payload = parts[3] || "";
  if (!captchaToken || !payload) return null;
  if (mode === "t") return { captchaToken, ticketB64: payload, consumeToken: "" };
  if (mode === "c") return { captchaToken, ticketB64: "", consumeToken: payload };
  return null;
};

const extractAtomicAuth = (request, url, config) => {
  const qTurn = config.ATOMIC_TURN_QUERY.trim();
  const qTicket = config.ATOMIC_TICKET_QUERY.trim();
  const qConsume = config.ATOMIC_CONSUME_QUERY.trim();
  const hTurn = config.ATOMIC_TURN_HEADER.trim();
  const hTicket = config.ATOMIC_TICKET_HEADER.trim();
  const hConsume = config.ATOMIC_CONSUME_HEADER.trim();
  const cookieName = config.ATOMIC_COOKIE_NAME.trim();

  let captchaToken = "";
  let ticketB64 = "";
  let consumeToken = "";
  let fromCookie = false;
  if (cookieName) {
    const cookies = parseCookieHeader(request.headers.get("Cookie"));
    const raw = cookies.get(cookieName) || "";
    const parsed = parseAtomicCookie(raw);
    if (parsed) {
      captchaToken = parsed.captchaToken;
      ticketB64 = parsed.ticketB64;
      consumeToken = parsed.consumeToken;
      fromCookie = true;
    }
  }
  if (!fromCookie) {
    const headerCaptcha = hTurn ? request.headers.get(hTurn) : "";
    if (headerCaptcha) {
      captchaToken = headerCaptcha;
      ticketB64 = hTicket ? request.headers.get(hTicket) || "" : "";
      consumeToken = hConsume ? request.headers.get(hConsume) || "" : "";
    } else {
      captchaToken = qTurn ? url.searchParams.get(qTurn) || "" : "";
      ticketB64 = qTicket ? url.searchParams.get(qTicket) || "" : "";
      consumeToken = qConsume ? url.searchParams.get(qConsume) || "" : "";
    }
  }

  const stripQuery = config.STRIP_ATOMIC_QUERY !== false;
  const stripHeader = config.STRIP_ATOMIC_HEADERS !== false;
  let forwardRequest = request;

  if (stripQuery && (qTurn || qTicket || qConsume)) {
    const nextUrl = new URL(url.toString());
    let changed = false;
    if (qTurn && nextUrl.searchParams.has(qTurn)) {
      nextUrl.searchParams.delete(qTurn);
      changed = true;
    }
    if (qTicket && nextUrl.searchParams.has(qTicket)) {
      nextUrl.searchParams.delete(qTicket);
      changed = true;
    }
    if (qConsume && nextUrl.searchParams.has(qConsume)) {
      nextUrl.searchParams.delete(qConsume);
      changed = true;
    }
    if (changed) {
      forwardRequest = new Request(nextUrl, request);
    }
  }

  if (stripHeader && (hTurn || hTicket || hConsume)) {
    const headers = new Headers(forwardRequest.headers);
    let changed = false;
    if (hTurn && headers.has(hTurn)) {
      headers.delete(hTurn);
      changed = true;
    }
    if (hTicket && headers.has(hTicket)) {
      headers.delete(hTicket);
      changed = true;
    }
    if (hConsume && headers.has(hConsume)) {
      headers.delete(hConsume);
      changed = true;
    }
    if (changed) {
      forwardRequest = new Request(forwardRequest, { headers });
    }
  }

  return { captchaToken, ticketB64, consumeToken, fromCookie, cookieName, forwardRequest };
};

const validateAtomicSnapshot = (atomic) => {
  if (!atomic || typeof atomic !== "object") {
    return { ok: false, status: 400 };
  }
  if (
    typeof atomic.captchaToken !== "string" ||
    typeof atomic.ticketB64 !== "string" ||
    typeof atomic.consumeToken !== "string" ||
    typeof atomic.fromCookie !== "boolean" ||
    typeof atomic.cookieName !== "string"
  ) {
    return { ok: false, status: 400 };
  }

  if (
    atomic.captchaToken.length > ATOMIC_CAPTCHA_MAX_LEN ||
    atomic.ticketB64.length > ATOMIC_TICKET_MAX_LEN ||
    atomic.consumeToken.length > ATOMIC_CONSUME_MAX_LEN ||
    atomic.cookieName.length > ATOMIC_COOKIE_NAME_MAX_LEN
  ) {
    return { ok: false, status: 431 };
  }

  if (
    CONTROL_CHAR_RE.test(atomic.captchaToken) ||
    CONTROL_CHAR_RE.test(atomic.consumeToken) ||
    CONTROL_CHAR_RE.test(atomic.cookieName)
  ) {
    return { ok: false, status: 400 };
  }

  if (atomic.ticketB64 && !BASE64URL_RE.test(atomic.ticketB64)) {
    return { ok: false, status: 400 };
  }

  const preflight =
    atomic.turnstilePreflight && typeof atomic.turnstilePreflight === "object"
      ? atomic.turnstilePreflight
      : null;
  if (!preflight) {
    return { ok: false, status: 400 };
  }
  if (
    typeof preflight.checked !== "boolean" ||
    typeof preflight.ok !== "boolean" ||
    typeof preflight.reason !== "string" ||
    typeof preflight.ticketMac !== "string" ||
    typeof preflight.tokenTag !== "string"
  ) {
    return { ok: false, status: 400 };
  }
  if (
    preflight.reason.length > PREFLIGHT_REASON_MAX_LEN ||
    preflight.ticketMac.length > B64_HASH_MAX_LEN ||
    preflight.tokenTag.length > CAPTCHA_TAG_LEN
  ) {
    return { ok: false, status: 431 };
  }
  if (
    CONTROL_CHAR_RE.test(preflight.reason) ||
    CONTROL_CHAR_RE.test(preflight.ticketMac) ||
    CONTROL_CHAR_RE.test(preflight.tokenTag)
  ) {
    return { ok: false, status: 400 };
  }
  if (preflight.ticketMac && !BASE64URL_RE.test(preflight.ticketMac)) {
    return { ok: false, status: 400 };
  }
  if (preflight.tokenTag && !BASE64URL_RE.test(preflight.tokenTag)) {
    return { ok: false, status: 400 };
  }

  const atomicSize = utf8ToBytes(JSON.stringify(atomic)).length;
  if (atomicSize > ATOMIC_SNAPSHOT_MAX_LEN) {
    return { ok: false, status: 431 };
  }

  return { ok: true };
};

const isPlainObject = (value) => {
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return false;
  return Object.getPrototypeOf(value) === Object.prototype;
};

const reviveRegex = (value) => {
  if (!isPlainObject(value) || !Object.prototype.hasOwnProperty.call(value, "$re")) {
    return value;
  }
  const inner = value.$re;
  if (!isPlainObject(inner) || typeof inner.s !== "string") return value;
  const flags = typeof inner.f === "string" ? inner.f : "";
  try {
    return new RegExp(inner.s, flags);
  } catch {
    return value;
  }
};

const matchValue = (actual, expected, options = {}) => {
  if (expected === null || expected === undefined) return false;
  if (Array.isArray(expected)) {
    let matched = false;
    for (const entry of expected) {
      if (matchValue(actual, entry, options)) matched = true;
    }
    return matched;
  }
  const revived = reviveRegex(expected);
  if (revived instanceof RegExp) {
    const testRegex = (value) => {
      revived.lastIndex = 0;
      return revived.test(String(value));
    };
    if (Array.isArray(actual)) {
      for (const entry of actual) {
        if (testRegex(entry)) return true;
      }
      return false;
    }
    if (actual === null || actual === undefined) return false;
    return testRegex(actual);
  }
  if (typeof revived === "string") {
    const matches = (value) => {
      if (value === null || value === undefined) return false;
      const actualStr = String(value);
      const expectedStr = revived;
      if (options.contains) {
        return actualStr.toLowerCase().includes(expectedStr.toLowerCase());
      }
      if (options.caseSensitive) {
        return actualStr === expectedStr;
      }
      return actualStr.toLowerCase() === expectedStr.toLowerCase();
    };
    if (Array.isArray(actual)) {
      for (const entry of actual) {
        if (matches(entry)) return true;
      }
      return false;
    }
    return matches(actual);
  }
  return false;
};

const matchObject = (container, conditions, options = {}) => {
  if (!conditions || typeof conditions !== "object") return false;
  let matched = true;
  const isExistsCheck = (value) =>
    isPlainObject(value) &&
    Object.keys(value).length === 1 &&
    typeof value.exists === "boolean";
  for (const [key, expected] of Object.entries(conditions)) {
    let exists = false;
    let actual;
    if (container instanceof Headers) {
      exists = container.has(key);
      actual = container.get(key);
    } else if (container instanceof Map) {
      exists = container.has(key);
      actual = container.get(key);
    } else if (container instanceof URLSearchParams) {
      exists = container.has(key);
      const values = container.getAll(key);
      actual = values.length ? values : undefined;
    } else if (container && typeof container === "object") {
      exists = Object.prototype.hasOwnProperty.call(container, key);
      actual = exists ? container[key] : undefined;
    } else {
      matched = false;
      continue;
    }

    if (isExistsCheck(expected)) {
      if (exists !== expected.exists) matched = false;
      continue;
    }
    if (!matchValue(actual, expected, options)) matched = false;
  }
  return matched;
};

const ipInCidr = (ip, cidr) => {
  if (typeof ip !== "string" || typeof cidr !== "string") return false;
  const slash = cidr.indexOf("/");
  if (slash === -1) return false;
  const base = cidr.slice(0, slash);
  const prefixRaw = cidr.slice(slash + 1);
  if (!prefixRaw) return false;
  const prefix = Number(prefixRaw);
  if (!Number.isFinite(prefix)) return false;
  if (isIpv4(base) && isIpv4(ip)) {
    const baseBytes = parseIpv4(base);
    const ipBytes = parseIpv4(ip);
    if (!baseBytes || !ipBytes) return false;
    const p = Math.min(32, Math.max(0, prefix));
    const toInt = (bytes) =>
      ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
    const mask = p === 0 ? 0 : (~0 << (32 - p)) >>> 0;
    return (toInt(ipBytes) & mask) === (toInt(baseBytes) & mask);
  }
  if (isIpv6(base) && isIpv6(ip)) {
    const baseBytes = parseIpv6(base);
    const ipBytes = parseIpv6(ip);
    if (!baseBytes || !ipBytes) return false;
    const p = Math.min(128, Math.max(0, prefix));
    const fullBytes = Math.floor(p / 8);
    const rem = p % 8;
    for (let i = 0; i < fullBytes; i++) {
      if (ipBytes[i] !== baseBytes[i]) return false;
    }
    if (rem === 0) return true;
    const mask = 0xff << (8 - rem);
    return (ipBytes[fullBytes] & mask) === (baseBytes[fullBytes] & mask);
  }
  return false;
};

const matchCidr = (ip, cidr) => {
  if (Array.isArray(cidr)) {
    let matched = false;
    for (const entry of cidr) {
      if (matchCidr(ip, entry)) matched = true;
    }
    return matched;
  }
  if (typeof cidr !== "string") return false;
  if (cidr.includes("/")) return ipInCidr(ip, cidr);
  if (typeof ip !== "string") return false;
  return ip === cidr;
};

const evaluateCondition = (condition, context) => {
  if (condition === null || condition === undefined) return true;
  if (!condition || typeof condition !== "object" || Array.isArray(condition)) {
    return false;
  }
  let matched = true;
  for (const [key, value] of Object.entries(condition)) {
    let result = false;
    switch (key) {
      case "and": {
        if (!Array.isArray(value)) {
          result = false;
          break;
        }
        let all = true;
        for (const entry of value) {
          if (!evaluateCondition(entry, context)) all = false;
        }
        result = all;
        break;
      }
      case "or": {
        if (!Array.isArray(value)) {
          result = false;
          break;
        }
        let any = false;
        for (const entry of value) {
          if (evaluateCondition(entry, context)) any = true;
        }
        result = any;
        break;
      }
      case "not":
        if (!value || typeof value !== "object" || Array.isArray(value)) {
          result = false;
          break;
        }
        result = !evaluateCondition(value, context);
        break;
      case "country":
        result = matchValue(context && context.country, value);
        break;
      case "asn":
        result = matchValue(context && context.asn, value);
        break;
      case "ip":
        result = matchCidr(context && context.ip, value);
        break;
      case "method":
        result = matchValue(context && context.method, value);
        break;
      case "ua":
        result = matchValue(context && context.ua, value, { contains: true });
        break;
      case "path":
        result = matchValue(context && context.path, value, { caseSensitive: true });
        break;
      case "tls":
        result = typeof value === "boolean" && value === (context && context.tls === true);
        break;
      case "header":
        result = matchObject(context && context.header, value);
        break;
      case "cookie":
        result = matchObject(context && context.cookie, value);
        break;
      case "query":
        result = matchObject(context && context.query, value);
        break;
      default:
        result = false;
    }
    if (!result) matched = false;
  }
  return matched;
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
  const ipInt = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
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

const buildEvalContext = (request, url, hostname, path, whenNeeds) => {
  const headers = request && request.headers ? request.headers : new Headers();
  const cf = getRequestCf(request);
  const ua = headers.get("User-Agent") || "";
  const method = request && typeof request.method === "string" ? request.method : "";
  const ip = getClientIP(request);
  const country = normalizeCountry(cf && cf.country);
  const asn = normalizeAsn(cf && cf.asn);
  const tls = Boolean(
    cf && cf.tlsClientExtensionsSha1 && cf.tlsClientCiphersSha1
  );
  const needsCookie = !whenNeeds || whenNeeds.cookie === true;
  const cookie = needsCookie ? parseCookieHeader(headers.get("Cookie")) : null;
  const query = url && url.searchParams ? url.searchParams : new URLSearchParams();
  const host = typeof hostname === "string" ? hostname : "";
  return {
    host,
    ua,
    method,
    path: typeof path === "string" ? path : "",
    ip,
    country,
    asn,
    tls,
    header: headers,
    cookie,
    query,
  };
};

const matchHostFast = (host, rule) => {
  if (!host || !rule) return false;
  if (rule.hostType === "exact") {
    if (typeof rule.hostExact === "string") return host === rule.hostExact;
    if (rule.hostRegex) return rule.hostRegex.test(host);
    return false;
  }
  if (rule.hostType === "wildcard") {
    if (!Array.isArray(rule.hostLabels)) {
      if (rule.hostRegex) return rule.hostRegex.test(host);
      return false;
    }
    const labels = host.split(".");
    const expectedCount =
      typeof rule.hostLabelCount === "number" ? rule.hostLabelCount : rule.hostLabels.length;
    if (labels.length !== expectedCount) return false;
    for (let i = 0; i < expectedCount; i++) {
      const expected = rule.hostLabels[i];
      if (expected === "*") continue;
      if (labels[i] !== expected) return false;
    }
    return true;
  }
  if (rule.hostRegex) return rule.hostRegex.test(host);
  return false;
};

const matchPathFast = (path, rule) => {
  if (!rule) return false;
  if (rule.pathType === "exact") {
    if (typeof rule.pathExact === "string") return path === rule.pathExact;
    if (rule.pathRegex) return rule.pathRegex.test(path);
    return false;
  }
  if (rule.pathType === "prefix") {
    if (typeof rule.pathPrefix !== "string") {
      if (rule.pathRegex) return rule.pathRegex.test(path);
      return false;
    }
    if (rule.pathPrefix === "/") {
      return path.startsWith("/") || (rule.pathRegex ? rule.pathRegex.test(path) : false);
    }
    return path === rule.pathPrefix || path.startsWith(`${rule.pathPrefix}/`);
  }
  if (rule.pathRegex) return rule.pathRegex.test(path);
  return false;
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

const normalizeConfig = (baseConfig) => {
  const merged = { ...DEFAULTS, ...(baseConfig || {}) };
  return {
    ...merged,
    powcheck: normalizeBoolean(merged.powcheck, DEFAULTS.powcheck),
    turncheck: normalizeBoolean(merged.turncheck, DEFAULTS.turncheck),
    recaptchaEnabled: normalizeBoolean(merged.recaptchaEnabled, DEFAULTS.recaptchaEnabled),
    bindPathMode: normalizeString(merged.bindPathMode, DEFAULTS.bindPathMode),
    bindPathQueryName: normalizeString(merged.bindPathQueryName, DEFAULTS.bindPathQueryName),
    bindPathHeaderName: normalizeString(merged.bindPathHeaderName, DEFAULTS.bindPathHeaderName),
    stripBindPathHeader: normalizeBoolean(
      merged.stripBindPathHeader,
      DEFAULTS.stripBindPathHeader
    ),
    POW_VERSION: normalizeNumberClamp(merged.POW_VERSION, DEFAULTS.POW_VERSION, 1, 10),
    POW_API_PREFIX: DEFAULTS.POW_API_PREFIX,
    POW_DIFFICULTY_BASE: normalizeNumberClamp(
      merged.POW_DIFFICULTY_BASE,
      DEFAULTS.POW_DIFFICULTY_BASE,
      1,
      1000000000
    ),
    POW_DIFFICULTY_COEFF: normalizeNumberClamp(
      merged.POW_DIFFICULTY_COEFF,
      DEFAULTS.POW_DIFFICULTY_COEFF,
      0,
      100
    ),
    POW_MIN_STEPS: normalizeNumberClamp(
      merged.POW_MIN_STEPS,
      DEFAULTS.POW_MIN_STEPS,
      1,
      1000000
    ),
    POW_MAX_STEPS: normalizeNumberClamp(
      merged.POW_MAX_STEPS,
      DEFAULTS.POW_MAX_STEPS,
      1,
      1000000
    ),
    POW_HASHCASH_BITS: normalizeNumberClamp(
      merged.POW_HASHCASH_BITS,
      DEFAULTS.POW_HASHCASH_BITS,
      0,
      32
    ),
    POW_SEGMENT_LEN: normalizeSegmentLen(merged.POW_SEGMENT_LEN, DEFAULTS.POW_SEGMENT_LEN),
    POW_SAMPLE_K: normalizeNumberClamp(
      merged.POW_SAMPLE_K,
      DEFAULTS.POW_SAMPLE_K,
      1,
      256
    ),
    POW_SPINE_K: normalizeNumberClamp(
      merged.POW_SPINE_K,
      DEFAULTS.POW_SPINE_K,
      0,
      256
    ),
    POW_CHAL_ROUNDS: normalizeNumberClamp(
      merged.POW_CHAL_ROUNDS,
      DEFAULTS.POW_CHAL_ROUNDS,
      1,
      256
    ),
    POW_OPEN_BATCH: normalizeNumberClamp(
      merged.POW_OPEN_BATCH,
      DEFAULTS.POW_OPEN_BATCH,
      1,
      256
    ),
    POW_FORCE_EDGE_1: normalizeBoolean(merged.POW_FORCE_EDGE_1, DEFAULTS.POW_FORCE_EDGE_1),
    POW_FORCE_EDGE_LAST: normalizeBoolean(
      merged.POW_FORCE_EDGE_LAST,
      DEFAULTS.POW_FORCE_EDGE_LAST
    ),
    POW_COMMIT_TTL_SEC: normalizeNumberClamp(
      merged.POW_COMMIT_TTL_SEC,
      DEFAULTS.POW_COMMIT_TTL_SEC,
      0,
      1000000000
    ),
    POW_TICKET_TTL_SEC: normalizeNumberClamp(
      merged.POW_TICKET_TTL_SEC,
      DEFAULTS.POW_TICKET_TTL_SEC,
      0,
      1000000000
    ),
    PROOF_TTL_SEC: normalizeNumberClamp(
      merged.PROOF_TTL_SEC,
      DEFAULTS.PROOF_TTL_SEC,
      0,
      1000000000
    ),
    PROOF_RENEW_ENABLE: normalizeBoolean(
      merged.PROOF_RENEW_ENABLE,
      DEFAULTS.PROOF_RENEW_ENABLE
    ),
    PROOF_RENEW_MAX: normalizeNumberClamp(
      merged.PROOF_RENEW_MAX,
      DEFAULTS.PROOF_RENEW_MAX,
      0,
      1000
    ),
    PROOF_RENEW_WINDOW_SEC: normalizeNumberClamp(
      merged.PROOF_RENEW_WINDOW_SEC,
      DEFAULTS.PROOF_RENEW_WINDOW_SEC,
      0,
      1000000000
    ),
    PROOF_RENEW_MIN_SEC: normalizeNumberClamp(
      merged.PROOF_RENEW_MIN_SEC,
      DEFAULTS.PROOF_RENEW_MIN_SEC,
      0,
      1000000000
    ),
    ATOMIC_CONSUME: normalizeBoolean(merged.ATOMIC_CONSUME, DEFAULTS.ATOMIC_CONSUME),
    ATOMIC_TURN_QUERY: normalizeString(merged.ATOMIC_TURN_QUERY, DEFAULTS.ATOMIC_TURN_QUERY),
    ATOMIC_TICKET_QUERY: normalizeString(
      merged.ATOMIC_TICKET_QUERY,
      DEFAULTS.ATOMIC_TICKET_QUERY
    ),
    ATOMIC_CONSUME_QUERY: normalizeString(
      merged.ATOMIC_CONSUME_QUERY,
      DEFAULTS.ATOMIC_CONSUME_QUERY
    ),
    ATOMIC_TURN_HEADER: normalizeString(
      merged.ATOMIC_TURN_HEADER,
      DEFAULTS.ATOMIC_TURN_HEADER
    ),
    ATOMIC_TICKET_HEADER: normalizeString(
      merged.ATOMIC_TICKET_HEADER,
      DEFAULTS.ATOMIC_TICKET_HEADER
    ),
    ATOMIC_CONSUME_HEADER: normalizeString(
      merged.ATOMIC_CONSUME_HEADER,
      DEFAULTS.ATOMIC_CONSUME_HEADER
    ),
    ATOMIC_COOKIE_NAME: normalizeString(merged.ATOMIC_COOKIE_NAME, DEFAULTS.ATOMIC_COOKIE_NAME),
    STRIP_ATOMIC_QUERY: normalizeBoolean(
      merged.STRIP_ATOMIC_QUERY,
      DEFAULTS.STRIP_ATOMIC_QUERY
    ),
    STRIP_ATOMIC_HEADERS: normalizeBoolean(
      merged.STRIP_ATOMIC_HEADERS,
      DEFAULTS.STRIP_ATOMIC_HEADERS
    ),
    INNER_AUTH_QUERY_NAME: normalizeString(
      merged.INNER_AUTH_QUERY_NAME,
      DEFAULTS.INNER_AUTH_QUERY_NAME
    ),
    INNER_AUTH_QUERY_VALUE: normalizeString(
      merged.INNER_AUTH_QUERY_VALUE,
      DEFAULTS.INNER_AUTH_QUERY_VALUE
    ),
    INNER_AUTH_HEADER_NAME: normalizeString(
      merged.INNER_AUTH_HEADER_NAME,
      DEFAULTS.INNER_AUTH_HEADER_NAME
    ),
    INNER_AUTH_HEADER_VALUE: normalizeString(
      merged.INNER_AUTH_HEADER_VALUE,
      DEFAULTS.INNER_AUTH_HEADER_VALUE
    ),
    stripInnerAuthQuery: normalizeBoolean(
      merged.stripInnerAuthQuery,
      DEFAULTS.stripInnerAuthQuery
    ),
    stripInnerAuthHeader: normalizeBoolean(
      merged.stripInnerAuthHeader,
      DEFAULTS.stripInnerAuthHeader
    ),
    POW_BIND_PATH: normalizeBoolean(merged.POW_BIND_PATH, DEFAULTS.POW_BIND_PATH),
    POW_BIND_IPRANGE: normalizeBoolean(merged.POW_BIND_IPRANGE, DEFAULTS.POW_BIND_IPRANGE),
    POW_BIND_COUNTRY: normalizeBoolean(merged.POW_BIND_COUNTRY, DEFAULTS.POW_BIND_COUNTRY),
    POW_BIND_ASN: normalizeBoolean(merged.POW_BIND_ASN, DEFAULTS.POW_BIND_ASN),
    POW_BIND_TLS: normalizeBoolean(merged.POW_BIND_TLS, DEFAULTS.POW_BIND_TLS),
    IPV4_PREFIX: normalizeNumberClamp(merged.IPV4_PREFIX, DEFAULTS.IPV4_PREFIX, 0, 32),
    IPV6_PREFIX: normalizeNumberClamp(merged.IPV6_PREFIX, DEFAULTS.IPV6_PREFIX, 0, 128),
    POW_COMMIT_COOKIE: DEFAULTS.POW_COMMIT_COOKIE,
    POW_ESM_URL: normalizeString(merged.POW_ESM_URL, DEFAULTS.POW_ESM_URL),
    POW_GLUE_URL: normalizeString(merged.POW_GLUE_URL, DEFAULTS.POW_GLUE_URL),
    TURNSTILE_SITEKEY: normalizeString(merged.TURNSTILE_SITEKEY, ""),
    TURNSTILE_SECRET: normalizeString(merged.TURNSTILE_SECRET, ""),
    RECAPTCHA_PAIRS: normalizeRecaptchaPairs(merged.RECAPTCHA_PAIRS),
    RECAPTCHA_MIN_SCORE: normalizeNumberClamp(
      merged.RECAPTCHA_MIN_SCORE,
      DEFAULTS.RECAPTCHA_MIN_SCORE,
      0,
      1
    ),
    POW_TOKEN: typeof merged.POW_TOKEN === "string" ? merged.POW_TOKEN : undefined,
  };
};

const stripInnerHeaders = (headers) => {
  for (const key of Array.from(headers.keys())) {
    if (key.toLowerCase().startsWith("x-pow-inner")) {
      headers.delete(key);
    }
  }
  return headers;
};

const writeInnerHeaders = (headers, payload, mac, exp) => {
  if (payload.length <= INNER_CHUNK_SIZE) {
    headers.set(INNER_HEADER, payload);
  } else {
    const count = Math.ceil(payload.length / INNER_CHUNK_SIZE);
    headers.set(INNER_COUNT_HEADER, String(count));
    for (let i = 0; i < count; i += 1) {
      const start = i * INNER_CHUNK_SIZE;
      headers.set(`${INNER_HEADER_PREFIX}${i}`, payload.slice(start, start + INNER_CHUNK_SIZE));
    }
  }
  headers.set(INNER_MAC, mac);
  headers.set(INNER_EXPIRE_HEADER, String(exp));
};

const pickConfigWithId = (request, url, hostname, path) => {
  const host = typeof hostname === "string" ? hostname.toLowerCase() : "";
  const requestPath = typeof path === "string" ? path : "";
  if (!host) return null;
  let context = null;
  for (let i = 0; i < COMPILED_CONFIG.length; i++) {
    const rule = COMPILED_CONFIG[i];
    if (!rule) continue;
    if (!matchHostFast(host, rule)) continue;
    if (rule.pathRegex || rule.pathType) {
      if (!matchPathFast(requestPath, rule)) continue;
    }
    if (rule.when) {
      const needsCookie = !rule.whenNeeds || rule.whenNeeds.cookie === true;
      if (!context) {
        context = buildEvalContext(request, url, host, requestPath, rule.whenNeeds);
      } else if (needsCookie && context.cookie === null) {
        context.cookie = parseCookieHeader(context.header.get("Cookie"));
      }
      if (!evaluateCondition(rule.when, context)) continue;
    }
    return { cfgId: i, config: rule.config || null };
  }
  return null;
};

const setCompiledConfigForTest = (compiled) => {
  const previous = COMPILED_CONFIG;
  COMPILED_CONFIG = Array.isArray(compiled) ? compiled.map(normalizeCompiledEntry) : [];
  return () => {
    COMPILED_CONFIG = previous;
  };
};

const getConfigById = (cfgId) => {
  if (!Number.isInteger(cfgId) || cfgId < 0 || cfgId >= COMPILED_CONFIG.length) {
    return null;
  }
  const entry = COMPILED_CONFIG[cfgId];
  return entry && entry.config ? entry.config : null;
};

const parsePowTicket = (ticketB64) => {
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  const bytes = base64UrlDecodeToBytes(ticketB64);
  if (!bytes) return null;
  const raw = decoder.decode(bytes);
  const parts = raw.split(".");
  if (parts.length !== 6) return null;
  const cfgId = Number.parseInt(parts[4], 10);
  if (!Number.isFinite(cfgId)) return null;
  return { cfgId };
};

const parsePowTicketFull = (ticketB64) => {
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
  if (!Number.isFinite(v) || v <= 0) return null;
  if (!Number.isFinite(e) || e <= 0) return null;
  if (!Number.isFinite(L) || L <= 0) return null;
  if (!Number.isFinite(cfgId) || cfgId < 0) return null;
  if (!isBase64Url(r, 1, B64_HASH_MAX_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { v, e, L, r, cfgId, mac, ticketB64 };
};

const parseConsumeToken = (value) => {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 6 || parts[0] !== "v2") return null;
  const ticketB64 = parts[1] || "";
  const exp = Number.parseInt(parts[2], 10);
  const captchaTag = parts[3] || "";
  const m = Number.parseInt(parts[4], 10);
  const mac = parts[5] || "";
  if (!Number.isFinite(exp) || exp <= 0) return null;
  if (!Number.isFinite(m) || m < 0) return null;
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(captchaTag, CAPTCHA_TAG_LEN, CAPTCHA_TAG_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { ticketB64, exp, captchaTag, m, mac };
};

const makeConsumeMac = async (powSecret, ticketB64, exp, captchaTag, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `U|${ticketB64}|${exp}|${captchaTag}|${m}`);

const verifyConsumeIntegrity = async (consumeToken, powSecret, nowSeconds, requiredMask) => {
  const parsed = parseConsumeToken(consumeToken);
  if (!parsed) return null;
  if (!powSecret) return null;
  if (parsed.exp <= nowSeconds) return null;
  if ((parsed.m & requiredMask) !== requiredMask) return null;
  const expectedMac = await makeConsumeMac(
    powSecret,
    parsed.ticketB64,
    parsed.exp,
    parsed.captchaTag,
    parsed.m
  );
  if (!timingSafeEqual(expectedMac, parsed.mac)) return null;
  return parsed;
};

const computePathHash = async (canonicalPath) =>
  base64UrlEncodeNoPad(await sha256Bytes(canonicalPath));

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
  const country =
    bindCountry && source && typeof source.country === "string" ? source.country : "";
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

const getPowBindingValues = async (canonicalPath, config, derived) => {
  const bindPath = config.POW_BIND_PATH !== false;
  const pathHash = bindPath ? await computePathHash(canonicalPath) : "any";
  return getPowBindingValuesWithPathHash(pathHash, config, derived);
};

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

const verifyTicketMac = async (ticket, hostname, bindingValues, powSecret) => {
  if (!powSecret) return "";
  const bindingString = makePowBindingString(
    ticket,
    hostname,
    bindingValues.pathHash,
    bindingValues.ipScope,
    bindingValues.country,
    bindingValues.asn,
    bindingValues.tlsFingerprint
  );
  const expectedMac = await hmacSha256Base64UrlNoPad(powSecret, bindingString);
  if (!timingSafeEqual(expectedMac, ticket.mac)) return "";
  return bindingString;
};

const readDualCaptchaTokens = (captchaToken) => {
  const readFromObject = (parsed) => {
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const turnstile = typeof parsed.turnstile === "string" ? parsed.turnstile.trim() : "";
    const recaptcha_v3 =
      typeof parsed.recaptcha_v3 === "string" ? parsed.recaptcha_v3.trim() : "";
    return { turnstile, recaptcha_v3 };
  };

  if (typeof captchaToken === "string") {
    const single = captchaToken.trim();
    if (!single || !(single.startsWith("{") && single.endsWith("}"))) return null;
    try {
      return readFromObject(JSON.parse(single));
    } catch {
      return null;
    }
  }

  return readFromObject(captchaToken);
};

const validateTurnToken = (value) => {
  if (!value || typeof value !== "string") return null;
  const token = value.trim();
  if (token.length < TURN_TOKEN_MIN_LEN || token.length > TURN_TOKEN_MAX_LEN) return null;
  if (CONTROL_CHAR_RE.test(token)) return null;
  return token;
};

const captchaTagFromToken = async (token) =>
  base64UrlEncodeNoPad((await sha256Bytes(token)).slice(0, 12));

const verifyTurnstileSiteverify = async (request, secret, token) => {
  if (!secret || !token) return { ok: false, cdata: "" };
  const form = new URLSearchParams();
  form.set("secret", secret);
  form.set("response", token);
  const remoteip = getClientIP(request);
  if (remoteip && remoteip !== "0.0.0.0") {
    form.set("remoteip", remoteip);
  }
  let verifyRes;
  try {
    verifyRes = await fetch(TURNSTILE_SITEVERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    });
  } catch {
    return { ok: false, cdata: "" };
  }
  let parsed;
  try {
    parsed = await verifyRes.json();
  } catch {
    parsed = null;
  }
  if (!parsed || parsed.success !== true) return { ok: false, cdata: "" };
  return { ok: true, cdata: typeof parsed.cdata === "string" ? parsed.cdata : "" };
};

const defaultTurnstilePreflight = () => ({
  checked: false,
  ok: false,
  reason: "not_applicable",
  ticketMac: "",
  tokenTag: "",
});

const shouldRunTurnstilePreflight = (requestPath, config, bind) =>
  config.ATOMIC_CONSUME === true &&
  config.turncheck === true &&
  config.recaptchaEnabled === true &&
  bind.ok === true &&
  !requestPath.startsWith(`${config.POW_API_PREFIX}/`);

const runTurnstilePreflight = async ({
  request,
  requestPath,
  cfgId,
  config,
  bind,
  atomic,
  nowSeconds,
  derived,
}) => {
  const preflight = {
    checked: true,
    ok: false,
    reason: "missing_atomic",
    ticketMac: "",
    tokenTag: "",
  };

  const shouldCheck = shouldRunTurnstilePreflight(requestPath, config, bind);
  if (!shouldCheck) return preflight;

  const tokens = readDualCaptchaTokens(atomic.captchaToken);
  const turnToken = validateTurnToken(tokens && tokens.turnstile);
  const recaptchaToken = validateTurnToken(tokens && tokens.recaptcha_v3);
  if (!turnToken || !recaptchaToken) {
    preflight.reason = "missing_atomic";
    return preflight;
  }

  const requiredMask = (config.powcheck === true ? 1 : 0) | 2 | 4;
  const powSecret = typeof config.POW_TOKEN === "string" ? config.POW_TOKEN : "";
  let ticket = null;
  let nextDerived = derived;
  const canonicalPath = bind.canonicalPath || requestPath;

  if (config.powcheck === true) {
    const consume = await verifyConsumeIntegrity(
      atomic.consumeToken,
      powSecret,
      nowSeconds,
      requiredMask
    );
    if (!consume) {
      preflight.reason = "consume_invalid";
      return preflight;
    }
    ticket = parsePowTicketFull(consume.ticketB64);
    if (!ticket || ticket.cfgId !== cfgId) {
      preflight.reason = "ticket_invalid";
      return preflight;
    }
  } else {
    ticket = parsePowTicketFull(atomic.ticketB64);
    if (!ticket || ticket.cfgId !== cfgId || ticket.e <= nowSeconds) {
      preflight.reason = "ticket_invalid";
      return preflight;
    }
    if (!nextDerived) {
      nextDerived = await buildDerivedBindings(request, config);
    }
    const bindingValues = await getPowBindingValues(canonicalPath, config, nextDerived);
    if (!bindingValues) {
      preflight.reason = "ticket_invalid";
      return preflight;
    }
    const bindingString = await verifyTicketMac(ticket, new URL(request.url).hostname, bindingValues, powSecret);
    if (!bindingString) {
      preflight.reason = "ticket_invalid";
      return preflight;
    }
  }

  const verify = await verifyTurnstileSiteverify(request, config.TURNSTILE_SECRET, turnToken);
  if (!verify.ok || verify.cdata !== ticket.mac) {
    preflight.reason = "turn_verify_failed";
    return preflight;
  }

  preflight.ok = true;
  preflight.reason = "";
  preflight.ticketMac = ticket.mac;
  preflight.tokenTag = await captchaTagFromToken(turnToken);
  return { ...preflight, derived: nextDerived };
};

const parsePowCommitCookie = (value) => {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 9) return null;
  if (parts[0] !== "v4") return null;
  const ticketB64 = parts[1] || "";
  const rootB64 = parts[2] || "";
  const pathHash = parts[3] || "";
  const captchaTag = parts[4] || "";
  const nonce = parts[5] || "";
  const exp = Number.parseInt(parts[6], 10);
  const spineSeed = parts[7] || "";
  const mac = parts[8] || "";
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(rootB64, 1, B64_HASH_MAX_LEN)) return null;
  if (!(pathHash === "any" || isBase64Url(pathHash, 1, B64_HASH_MAX_LEN))) return null;
  if (!(captchaTag === "any" || isBase64Url(captchaTag, CAPTCHA_TAG_LEN, CAPTCHA_TAG_LEN))) {
    return null;
  }
  if (!isBase64Url(nonce, NONCE_MIN_LEN, NONCE_MAX_LEN)) return null;
  if (!isBase64Url(spineSeed, SPINE_SEED_MIN_LEN, SPINE_SEED_MAX_LEN)) {
    return null;
  }
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  if (!Number.isFinite(exp) || exp <= 0) return null;
  return { ticketB64 };
};

const readJsonBody = async (request) => {
  try {
    return await request.json();
  } catch {
    return null;
  }
};

const resolveCfgIdFromPowApi = async (request, requestPath) => {
  if (!requestPath.startsWith(`${DEFAULTS.POW_API_PREFIX}/`)) return null;
  const action = requestPath.slice(DEFAULTS.POW_API_PREFIX.length);
  if (action === "/commit" || action === "/cap") {
    const body = await readJsonBody(request.clone());
    const ticketB64 = body && typeof body.ticketB64 === "string" ? body.ticketB64 : "";
    const ticket = parsePowTicket(ticketB64);
    return ticket ? ticket.cfgId : null;
  }
  if (action === "/challenge" || action === "/open") {
    const cookies = parseCookieHeader(request.headers.get("Cookie"));
    const commitRaw = cookies.get(DEFAULTS.POW_COMMIT_COOKIE) || "";
    const commit = parsePowCommitCookie(commitRaw);
    const ticket = commit ? parsePowTicket(commit.ticketB64) : null;
    return ticket ? ticket.cfgId : null;
  }
  return null;
};

const buildDerivedBindings = async (request, config) => {
  const bindIp = config.POW_BIND_IPRANGE !== false;
  const bindCountry = config.POW_BIND_COUNTRY === true;
  const bindAsn = config.POW_BIND_ASN === true;
  const bindTls = config.POW_BIND_TLS === true;
  const ipScope = bindIp ? computeIpScope(getClientIP(request), config) : "any";
  const cf = getRequestCf(request);
  const country = bindCountry ? normalizeCountry(cf && cf.country) : "any";
  const asn = bindAsn ? normalizeAsn(cf && cf.asn) : "any";
  let tlsFingerprint = "any";
  if (bindTls) {
    tlsFingerprint = await buildTlsFingerprintHash(request);
  }
  return { ipScope, country, asn, tlsFingerprint };
};

const buildSignedInnerPayload = async (
  request,
  cfgId,
  normalizedConfig,
  strategySnapshot,
  derived = null
) => {
  const finalDerived = derived || (await buildDerivedBindings(request, normalizedConfig));
  const payloadObj = {
    v: 1,
    id: cfgId,
    c: normalizedConfig,
    d: finalDerived,
    s: strategySnapshot,
  };
  const payload = base64UrlEncodeNoPad(utf8ToBytes(JSON.stringify(payloadObj)));
  const exp = Math.floor(Date.now() / 1000) + 3;
  const mac = await hmacSha256Base64UrlNoPad(CONFIG_SECRET, `${payload}.${exp}`);
  return { payload, mac, exp };
};

const resolveConfig = async (request, url, requestPath) => {
  const cfgIdFromApi = await resolveCfgIdFromPowApi(request, requestPath);
  if (Number.isInteger(cfgIdFromApi)) {
    const config = getConfigById(cfgIdFromApi);
    if (!config) {
      return { cfgId: -1, config: DEFAULTS };
    }
    return { cfgId: cfgIdFromApi, config };
  }
  const selected = pickConfigWithId(request, url, url.hostname, requestPath);
  if (selected) return { cfgId: selected.cfgId, config: selected.config || DEFAULTS };
  return { cfgId: -1, config: DEFAULTS };
};

export { hmacSha256Base64UrlNoPad };
export const __test = { evaluateCondition, matchCidr, pickConfigWithId, setCompiledConfigForTest };

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const requestPath = normalizePath(url.pathname);
    if (!requestPath) {
      return new Response(null, { status: 400 });
    }

    if (isPlaceholderConfigSecret(CONFIG_SECRET)) {
      return new Response(null, { status: 500 });
    }

    const resolved = await resolveConfig(request, url, requestPath);
    const normalizedConfig = normalizeConfig(resolved.config);

    const bypass = resolveBypassRequest(request, url, normalizedConfig);
    let forwardRequest = bypass.forwardRequest;
    let forwardUrl = new URL(forwardRequest.url);

    const bind = resolveBindPathForPow(forwardRequest, forwardUrl, requestPath, normalizedConfig);
    forwardRequest = bind.forwardRequest;
    forwardUrl = new URL(forwardRequest.url);

    const atomic = extractAtomicAuth(forwardRequest, forwardUrl, normalizedConfig);
    forwardRequest = atomic.forwardRequest;

    const nowSeconds = Math.floor(Date.now() / 1000);
    let derivedBindings = null;
    const preflight = defaultTurnstilePreflight();
    const shouldRunPreflight = shouldRunTurnstilePreflight(requestPath, normalizedConfig, bind);
    if (shouldRunPreflight) {
      const result = await runTurnstilePreflight({
        request: forwardRequest,
        requestPath,
        cfgId: resolved.cfgId,
        config: normalizedConfig,
        bind,
        atomic,
        nowSeconds,
        derived: derivedBindings,
      });
      preflight.checked = result.checked;
      preflight.ok = result.ok;
      preflight.reason = result.reason;
      preflight.ticketMac = result.ticketMac;
      preflight.tokenTag = result.tokenTag;
      if (result.derived && typeof result.derived === "object") {
        derivedBindings = result.derived;
      }
    }

    const strategySnapshot = {
      nav: {},
      bypass: { bypass: bypass.bypass },
      bind: {
        ok: bind.ok,
        code: bind.code || "",
        canonicalPath: bind.canonicalPath || requestPath,
      },
      atomic: {
        captchaToken: atomic.captchaToken,
        ticketB64: atomic.ticketB64,
        consumeToken: atomic.consumeToken,
        fromCookie: atomic.fromCookie,
        cookieName: atomic.cookieName,
        turnstilePreflight: preflight,
      },
    };

    const atomicValidation = validateAtomicSnapshot(strategySnapshot.atomic);
    if (!atomicValidation.ok) {
      return new Response(null, { status: atomicValidation.status });
    }

    const { payload, mac, exp } = await buildSignedInnerPayload(
      forwardRequest,
      resolved.cfgId,
      normalizedConfig,
      strategySnapshot,
      derivedBindings
    );

    const headers = stripInnerHeaders(new Headers(forwardRequest.headers));
    writeInnerHeaders(headers, payload, mac, exp);

    const forward = new Request(forwardRequest, { headers });
    return fetch(forward);
  },
};
