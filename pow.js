// Cloudflare Snippet: stateless PoW (generic L7 WAF)
// Set POW_TOKEN in config to your PoW secret.
const PROOF_COOKIE = "__Host-proof";
const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const INNER_HEADER = "X-Pow-Inner";
const INNER_MAC = "X-Pow-Inner-Mac";
const INNER_EXPIRE_HEADER = "X-Pow-Inner-Expire";
const INNER_COUNT_HEADER = `${INNER_HEADER}-Count`;
const INNER_CHUNK_PREFIX = `${INNER_HEADER}-`;
const INNER_CHUNK_MAX = 64;
const INNER_PAYLOAD_MAX_LEN = 128 * 1024;
const CONFIG_SECRET = "replace-me";
const isPlaceholderConfigSecret = (value) =>
  typeof value !== "string" || !value.trim() || value === "replace-me";

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

const readInnerPayload = async (request) => {
  if (isPlaceholderConfigSecret(CONFIG_SECRET)) return null;
  let payload = request.headers.get(INNER_HEADER) || "";
  const mac = request.headers.get(INNER_MAC) || "";
  const expRaw = request.headers.get(INNER_EXPIRE_HEADER) || "";
  if (!/^[0-9]+$/.test(expRaw)) return null;
  const exp = Number.parseInt(expRaw, 10);
  if (!Number.isSafeInteger(exp)) return null;
  const nowSec = Math.floor(Date.now() / 1000);
  if (exp < nowSec || exp > nowSec + 3) return null;
  if (!payload) {
    const countRaw = request.headers.get(INNER_COUNT_HEADER) || "";
    if (!/^[0-9]+$/.test(countRaw)) return null;
    const count = Number(countRaw);
    if (!Number.isFinite(count) || count <= 0 || count > INNER_CHUNK_MAX) return null;
    let total = 0;
    const parts = [];
    for (let i = 0; i < count; i += 1) {
      const part = request.headers.get(`${INNER_CHUNK_PREFIX}${i}`) || "";
      if (!part) return null;
      total += part.length;
      if (total > INNER_PAYLOAD_MAX_LEN) return null;
      parts.push(part);
    }
    payload = parts.join("");
  }
  if (!payload || !mac) return null;
  const expected = await hmacSha256Base64UrlNoPad(CONFIG_SECRET, `${payload}.${exp}`);
  if (!timingSafeEqual(expected, mac)) return null;
  const bytes = base64UrlDecodeToBytes(payload);
  if (!bytes) return null;
  let parsed;
  try {
    parsed = JSON.parse(decoder.decode(bytes));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  if (parsed.v !== 1) return null;
  const id = Number.isInteger(parsed.id) ? parsed.id : null;
  const config = parsed.c && typeof parsed.c === "object" ? parsed.c : null;
  const derived = parsed.d && typeof parsed.d === "object" ? parsed.d : null;
  if (id === null || !config || !derived) return null;
  return { id, c: config, d: derived };
};

const stripInnerHeaders = (request) => {
  const headers = new Headers(request.headers);
  const keys = Array.from(headers.keys());
  for (const key of keys) {
    if (key.toLowerCase().startsWith("x-pow-inner")) {
      headers.delete(key);
    }
  }
  return new Request(request, { headers });
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


const utf8ToBytes = (value) => encoder.encode(String(value ?? ""));

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

const hmacSha256 = async (secret, data) => {
  const key = await getHmacKey(secret);
  const payload = encoder.encode(data);
  const buf = await crypto.subtle.sign("HMAC", key, payload);
  return new Uint8Array(buf);
};

const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;
const validateTurnToken = (value) => {
  if (!value) return null;
  const token = value.trim();
  if (token.length < TURN_TOKEN_MIN_LEN || token.length > TURN_TOKEN_MAX_LEN) return null;
  if (CONTROL_CHAR_RE.test(token)) return null;
  return token;
};

const normalizeBindPathInput = (raw) => {
  let decoded;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return null;
  }
  const canonical = decoded[0] === "/" ? decoded : `/${decoded}`;
  if (canonical.length > 4096) return null;
  if (CONTROL_CHAR_RE.test(canonical)) return null;
  return canonical;
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
    if (!name) return { ok: false, code: "misconfigured" };
    const raw = url.searchParams.get(name);
    if (!raw) return { ok: false, code: "missing" };
    const canonical = normalizeBindPathInput(raw);
    if (!canonical) return { ok: false, code: "invalid" };
    return { ok: true, canonicalPath: canonical, forwardRequest: request };
  }
  if (mode === "header") {
    const name = config.bindPathHeaderName.trim();
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

const withClearedCookie = (response, name) => {
  if (!name) return response;
  const headers = new Headers(response.headers);
  clearCookie(headers, name);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
};

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

const extractAtomicAuth = (request, url, config) => {
  const qTurn = config.ATOMIC_TURN_QUERY.trim();
  const qTicket = config.ATOMIC_TICKET_QUERY.trim();
  const qConsume = config.ATOMIC_CONSUME_QUERY.trim();
  const hTurn = config.ATOMIC_TURN_HEADER.trim();
  const hTicket = config.ATOMIC_TICKET_HEADER.trim();
  const hConsume = config.ATOMIC_CONSUME_HEADER.trim();
  const cookieName = config.ATOMIC_COOKIE_NAME.trim();

  let turnToken = "";
  let ticketB64 = "";
  let consumeToken = "";
  let fromCookie = false;
  if (cookieName) {
    const cookies = parseCookieHeader(request.headers.get("Cookie"));
    const raw = cookies.get(cookieName) || "";
    const parsed = parseAtomicCookie(raw);
    if (parsed) {
      turnToken = parsed.turnToken;
      ticketB64 = parsed.ticketB64;
      consumeToken = parsed.consumeToken;
      fromCookie = true;
    }
  }
  if (!fromCookie) {
    const headerTurn = hTurn ? request.headers.get(hTurn) : "";
    if (headerTurn) {
      turnToken = headerTurn;
      ticketB64 = hTicket ? request.headers.get(hTicket) || "" : "";
      consumeToken = hConsume ? request.headers.get(hConsume) || "" : "";
    } else {
      turnToken = qTurn ? url.searchParams.get(qTurn) || "" : "";
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

  return { turnToken, ticketB64, consumeToken, forwardRequest, fromCookie, cookieName };
};

const getPowSteps = (config) => {
  const base = config.POW_DIFFICULTY_BASE;
  const coeff = config.POW_DIFFICULTY_COEFF;
  const minSteps = config.POW_MIN_STEPS;
  const maxSteps = config.POW_MAX_STEPS;
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
  const bytes = await hmacSha256(powSecret, `I|${cfgId}|${commitMac}`);
  return base64UrlEncodeNoPad(bytes.slice(0, 12));
};

const derivePowSeedBytes16 = async (powSecret, cfgId, commitMac, sid) => {
  const bytes = await hmacSha256(powSecret, `D|${cfgId}|${commitMac}|${sid}`);
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
    `P|${cfgId}|${commitMac}|${sid}|${cursor}|${batchLen}|${spineSeed}`
  );
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
  if (raw === null || raw === undefined) {
    return null;
  }
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

const getBatchMax = (config) =>
  Math.max(1, Math.min(32, Math.floor(config.POW_OPEN_BATCH)));

const buildPowSample = async (config, powSecret, ticket, commitMac, sid) => {
  const rounds = Math.max(1, Math.floor(config.POW_CHAL_ROUNDS));
  const sampleK = Math.max(0, Math.floor(config.POW_SAMPLE_K));
  const hashcashBits = Math.max(0, Math.floor(config.POW_HASHCASH_BITS));
  const spineK = Math.max(0, Math.floor(config.POW_SPINE_K));
  const segSpec = parseSegmentLenSpec(config.POW_SEGMENT_LEN);
  if (!segSpec) return null;
  const seed16 = await derivePowSeedBytes16(powSecret, ticket.cfgId, commitMac, sid);
  const rng = makeXoshiro128ss(seed16);
  const indices = sampleIndicesDeterministicV2({
    maxIndex: ticket.L,
    extraCount: sampleK * rounds,
    forceEdge1: config.POW_FORCE_EDGE_1 === true,
    forceEdgeLast: config.POW_FORCE_EDGE_LAST === true || hashcashBits > 0,
    rng,
  });
  if (!indices.length) return null;
  const segSeed16 = await deriveSegLenSeed16(powSecret, ticket.cfgId, commitMac, sid);
  const rngSeg = makeXoshiro128ss(segSeed16);
  const segLensAll = computeSegLensForIndices(indices, segSpec, rngSeg);
  return { indices, segLensAll, hashcashBits, spineK };
};

const buildPowBatchResponse = async (
  indices,
  segLensAll,
  spineK,
  ticket,
  commit,
  powSecret,
  sid,
  cursor,
  batchLen
) => {
  const batch = indices.slice(cursor, cursor + batchLen);
  if (!batch.length) return null;
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
  const spinePos = spineK > 0
    ? pickSpinePosForBatch(
      batch,
      segBatch,
      ticket.L,
      spineK,
      makeXoshiro128ss(spineSeed16)
    )
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
  return { done: false, sid, cursor, indices: batch, segs: segBatch, spinePos, token };
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
    `C|${ticketB64}|${rootB64}|${pathHash}|${tb}|${nonce}|${exp}|${spineSeed}`
  );

const makeConsumeMac = async (powSecret, ticketB64, exp, tb, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `U|${ticketB64}|${exp}|${tb}|${m}`);

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
    `S|${cfgId}|${sid}|${commitMac}|${cursor}|${batchLen}|${serializeSpinePos(spinePos)}`
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
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(rootB64, 1, B64_HASH_MAX_LEN)) return null;
  if (!(pathHash === "any" || isBase64Url(pathHash, 1, B64_HASH_MAX_LEN))) return null;
  if (!(tb === "any" || isBase64Url(tb, TB_LEN, TB_LEN))) return null;
  if (!isBase64Url(nonce, NONCE_MIN_LEN, NONCE_MAX_LEN)) return null;
  if (!isBase64Url(spineSeed, SPINE_SEED_MIN_LEN, SPINE_SEED_MAX_LEN)) {
    return null;
  }
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { ticketB64, rootB64, pathHash, tb, nonce, exp, mac, spineSeed };
};

const parseProofCookie = (value) => {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 7 || parts[0] !== "v1") return null;
  const ticketB64 = parts[1] || "";
  const iat = Number.parseInt(parts[2], 10);
  const last = Number.parseInt(parts[3], 10);
  const n = Number.parseInt(parts[4], 10);
  const m = Number.parseInt(parts[5], 10);
  const mac = parts[6] || "";
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { v: 1, ticketB64, iat, last, n, m, mac };
};

const parseConsumeToken = (value) => {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 6 || parts[0] !== "v2") return null;
  const ticketB64 = parts[1] || "";
  const exp = Number.parseInt(parts[2], 10);
  const tb = parts[3] || "";
  const m = Number.parseInt(parts[4], 10);
  const mac = parts[5] || "";
  if (exp <= 0) return null;
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(tb, TB_LEN, TB_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { ticketB64, exp, tb, m, mac };
};

const parseAtomicCookie = (value) => {
  if (!value) return null;
  const parts = value.split("|");
  if (parts[0] !== "1" || parts.length < 4) return null;
  const mode = parts[1];
  const turnToken = parts[2] || "";
  const payload = parts[3] || "";
  if (!turnToken || !payload) return null;
  if (mode === "t") return { turnToken, ticketB64: payload, consumeToken: "" };
  if (mode === "c") return { turnToken, ticketB64: "", consumeToken: payload };
  return null;
};

const makeProofMac = async (powSecret, ticketB64, iat, last, n, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `O|${ticketB64}|${iat}|${last}|${n}|${m}`);

const computePathHash = async (canonicalPath) =>
  base64UrlEncodeNoPad(await sha256Bytes(canonicalPath));

const getPowBindingValuesWithPathHash = async (request, pathHash, config, derived) => {
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
    bindTls && source && typeof source.tlsFingerprint === "string"
      ? source.tlsFingerprint
      : "";
  if (bindTls && !tlsFingerprint) return null;
  return {
    pathHash: normalizedPathHash,
    ipScope: bindIp ? ipScope : "any",
    country: bindCountry ? country : "any",
    asn: bindAsn ? asn : "any",
    tlsFingerprint: bindTls ? tlsFingerprint : "any",
  };
};

const getPowBindingValues = async (request, canonicalPath, config, derived) => {
  const bindPath = config.POW_BIND_PATH !== false;
  const pathHash = bindPath ? await computePathHash(canonicalPath) : "any";
  return getPowBindingValuesWithPathHash(request, pathHash, config, derived);
};

const isFiniteNumber = (value) => typeof value === "number" && Number.isFinite(value);
const isString = (value) => typeof value === "string";
const isNonEmptyString = (value) => isString(value) && value.trim().length > 0;
const isBoolean = (value) => typeof value === "boolean";
const isSegmentLenValue = (value) =>
  (typeof value === "string" && value.trim().length > 0) || isFiniteNumber(value);

const validateConfig = (config) => {
  const stringFields = [
    "bindPathMode",
    "bindPathQueryName",
    "bindPathHeaderName",
    "INNER_AUTH_QUERY_NAME",
    "INNER_AUTH_QUERY_VALUE",
    "INNER_AUTH_HEADER_NAME",
    "INNER_AUTH_HEADER_VALUE",
    "ATOMIC_TURN_QUERY",
    "ATOMIC_TICKET_QUERY",
    "ATOMIC_CONSUME_QUERY",
    "ATOMIC_TURN_HEADER",
    "ATOMIC_TICKET_HEADER",
    "ATOMIC_CONSUME_HEADER",
    "ATOMIC_COOKIE_NAME",
    "POW_API_PREFIX",
    "POW_COMMIT_COOKIE",
    "POW_ESM_URL",
    "POW_GLUE_URL",
  ];
  for (const key of stringFields) {
    if (!isString(config[key])) return false;
  }
  const optionalStringFields = ["POW_TOKEN", "TURNSTILE_SITEKEY", "TURNSTILE_SECRET"];
  for (const key of optionalStringFields) {
    if (key in config && config[key] !== undefined && !isString(config[key])) {
      return false;
    }
  }
  const booleanFields = [
    "powcheck",
    "turncheck",
    "stripBindPathHeader",
    "POW_FORCE_EDGE_1",
    "POW_FORCE_EDGE_LAST",
    "PROOF_RENEW_ENABLE",
    "ATOMIC_CONSUME",
    "STRIP_ATOMIC_QUERY",
    "STRIP_ATOMIC_HEADERS",
    "stripInnerAuthQuery",
    "stripInnerAuthHeader",
    "POW_BIND_PATH",
    "POW_BIND_IPRANGE",
    "POW_BIND_COUNTRY",
    "POW_BIND_ASN",
    "POW_BIND_TLS",
  ];
  for (const key of booleanFields) {
    if (!isBoolean(config[key])) return false;
  }
  const numberFields = [
    "POW_VERSION",
    "POW_DIFFICULTY_BASE",
    "POW_DIFFICULTY_COEFF",
    "POW_MIN_STEPS",
    "POW_MAX_STEPS",
    "POW_HASHCASH_BITS",
    "POW_SAMPLE_K",
    "POW_SPINE_K",
    "POW_CHAL_ROUNDS",
    "POW_OPEN_BATCH",
    "POW_COMMIT_TTL_SEC",
    "POW_TICKET_TTL_SEC",
    "PROOF_TTL_SEC",
    "PROOF_RENEW_MAX",
    "PROOF_RENEW_WINDOW_SEC",
    "PROOF_RENEW_MIN_SEC",
  ];
  for (const key of numberFields) {
    if (!isFiniteNumber(config[key])) return false;
  }
  if (!isSegmentLenValue(config.POW_SEGMENT_LEN)) return false;
  if (!parseSegmentLenSpec(config.POW_SEGMENT_LEN)) return false;
  const modeValues = new Set(["none", "query", "header"]);
  if (!modeValues.has(config.bindPathMode)) return false;
  if (config.bindPathMode === "query" && !isNonEmptyString(config.bindPathQueryName)) {
    return false;
  }
  if (config.bindPathMode === "header" && !isNonEmptyString(config.bindPathHeaderName)) {
    return false;
  }
  if (!isNonEmptyString(config.POW_API_PREFIX)) return false;
  if (!isNonEmptyString(config.POW_COMMIT_COOKIE)) return false;
  if (!isNonEmptyString(config.ATOMIC_TURN_QUERY)) return false;
  if (!isNonEmptyString(config.ATOMIC_TICKET_QUERY)) return false;
  if (!isNonEmptyString(config.ATOMIC_CONSUME_QUERY)) return false;
  if (!isNonEmptyString(config.ATOMIC_TURN_HEADER)) return false;
  if (!isNonEmptyString(config.ATOMIC_TICKET_HEADER)) return false;
  if (!isNonEmptyString(config.ATOMIC_CONSUME_HEADER)) return false;
  if (!isNonEmptyString(config.ATOMIC_COOKIE_NAME)) return false;
  if ((config.powcheck === true || config.turncheck === true) && !isNonEmptyString(config.POW_TOKEN)) {
    return false;
  }
  if ((config.powcheck === true || config.turncheck === true) && !isNonEmptyString(config.POW_GLUE_URL)) {
    return false;
  }
  if (config.powcheck === true && !isNonEmptyString(config.POW_ESM_URL)) {
    return false;
  }
  if (config.turncheck === true) {
    if (
      !isNonEmptyString(config.TURNSTILE_SITEKEY) ||
      !isNonEmptyString(config.TURNSTILE_SECRET)
    ) {
      return false;
    }
  }
  return true;
};

const loadConfigFromInner = (inner) => {
  if (!inner || typeof inner !== "object") return null;
  const baseConfig = inner.c && typeof inner.c === "object" ? inner.c : null;
  if (!baseConfig) return null;
  if (!validateConfig(baseConfig)) return null;
  return {
    config: baseConfig,
    powSecret: getPowSecret(baseConfig),
    derived: inner.d,
    cfgId: inner.id,
  };
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

const getPowVersion = (config) => config.POW_VERSION;

const getTurnSecret = (config) => config.TURNSTILE_SECRET;

const validateTicket = (ticket, config, nowSeconds) => {
  const powVersion = getPowVersion(config);
  if (ticket.v !== powVersion) return 0;
  if (isExpired(ticket.e, nowSeconds)) return 0;
  return powVersion;
};

const verifyCommit = async (commit, ticket, config, powSecret, nowSeconds) => {
  if (config.turncheck === true && !isBase64Url(commit.tb, TB_LEN, TB_LEN)) return 0;
  if (isExpired(commit.exp, nowSeconds)) return 0;
  const powVersion = validateTicket(ticket, config, nowSeconds);
  if (!powVersion) return 0;
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
  if (!timingSafeEqual(commitMac, commit.mac)) return 0;
  return powVersion;
};

const verifyConsumeToken = async (consumeToken, powSecret, nowSeconds, requiredMask) => {
  const parsed = parseConsumeToken(consumeToken);
  if (!parsed) return null;
  if (isExpired(parsed.exp, nowSeconds)) return null;
  if ((parsed.m & requiredMask) !== requiredMask) return null;
  const mac = await makeConsumeMac(
    powSecret,
    parsed.ticketB64,
    parsed.exp,
    parsed.tb,
    parsed.m
  );
  if (!timingSafeEqual(mac, parsed.mac)) return null;
  return parsed;
};

const loadAtomicTicket = async (
  ticketB64,
  request,
  url,
  canonicalPath,
  config,
  powSecret,
  derived,
  cfgId,
  nowSeconds
) => {
  const ticket = parsePowTicket(ticketB64);
  if (!ticket) return null;
  if (ticket.cfgId !== cfgId) return null;
  if (!Number.isFinite(ticket.L) || ticket.L <= 0) return null;
  if (!validateTicket(ticket, config, nowSeconds)) return null;
  const bindingValues = await getPowBindingValues(request, canonicalPath, config, derived);
  if (!bindingValues) return null;
  if (!(await verifyTicketMac(ticket, url, bindingValues, powSecret))) return null;
  return ticket;
};

const normalizePathHash = (pathHash, config) => {
  if (config.POW_BIND_PATH === false) return "any";
  return isBase64Url(pathHash, 1, B64_HASH_MAX_LEN) ? pathHash : "";
};

const verifyTicketMac = async (ticket, url, bindingValues, powSecret) => {
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
  if (!timingSafeEqual(expectedMac, ticket.mac)) return "";
  return bindingString;
};

const verifyTurnstileToken = async (request, turnSecret, turnToken) => {
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
    return null;
  }
  let verify;
  try {
    verify = await verifyRes.json();
  } catch {
    verify = null;
  }
  if (!verify || verify.success !== true) return null;
  return verify;
};

const verifyTurnstileForTicket = async (request, turnSecret, turnToken, ticket) => {
  const verify = await verifyTurnstileToken(request, turnSecret, turnToken);
  if (!verify) return false;
  const cdata = typeof verify.cdata === "string" ? verify.cdata : "";
  return cdata === ticket.mac;
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
  m
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
    bindingValues.tlsFingerprint
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

const verifyProofCookie = async (
  request,
  url,
  canonicalPath,
  nowSeconds,
  config,
  powSecret,
  derived,
  cfgId,
  requiredMask
) => {
  const cookies = parseCookieHeader(request.headers.get("Cookie"));
  const raw = cookies.get(PROOF_COOKIE) || "";
  const proof = parseProofCookie(raw);
  if (!proof) return null;
  const ticket = parsePowTicket(proof.ticketB64);
  if (!ticket) return null;
  const powVersion = getPowVersion(config);
  if (ticket.v !== powVersion) return null;
  if (!Number.isFinite(ticket.e) || ticket.e <= nowSeconds) return null;
  if (!Number.isFinite(ticket.L) || ticket.L <= 0) return null;
  if (ticket.cfgId !== cfgId) return null;
  if (proof.last > ticket.e) return null;
  const bindingValues = await getPowBindingValues(request, canonicalPath, config, derived);
  if (!bindingValues) return null;
  if (!(await verifyTicketMac(ticket, url, bindingValues, powSecret))) return null;
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
    Math.floor(config.PROOF_RENEW_MAX)
  );
  if (!renewMax || proof.n >= renewMax) return response;

  const ttl = Math.max(
    1,
    Math.floor(config.PROOF_TTL_SEC)
  );
  const window = Math.max(
    0,
    Math.floor(config.PROOF_RENEW_WINDOW_SEC)
  );
  const minSinceLast = Math.max(
    0,
    Math.floor(config.PROOF_RENEW_MIN_SEC)
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
  atomicCfg,
}) => __HTML_TEMPLATE__
  .replace('__B__', bindingStringB64)
  .replace('__S__', String(steps))
  .replace('__T__', ticketB64)
  .replace('__P__', pathHash)
  .replace('__H__', String(hashcashBits))
  .replace('__L__', String(segmentLen))
  .replace('__G__', glueUrl)
  .replace('__R__', reloadUrlB64)
  .replace('__A__', apiPrefixB64)
  .replace('__E__', esmUrlB64)
  .replace('__K__', turnSiteKeyB64)
  .replace('__C__', atomicCfg);

const respondPowChallengeHtml = async (
  request,
  url,
  canonicalPath,
  nowSeconds,
  config,
  powSecret,
  derived,
  cfgId,
  requirements
) => {
  const ticketTtl = config.POW_TICKET_TTL_SEC || 0;
  const exp = nowSeconds + Math.max(1, ticketTtl);
  const needPow = requirements && requirements.needPow === true;
  const needTurn = requirements && requirements.needTurn === true;
  const steps = needPow ? getPowSteps(config) : 1;
  const glueSteps = needPow ? steps : 0;
  const hashcashBits = needPow ? Math.max(0, Math.floor(config.POW_HASHCASH_BITS)) : 0;
  const segSpec = needPow
    ? parseSegmentLenSpec(config.POW_SEGMENT_LEN)
    : { mode: "fixed", fixed: 1 };
  if (needPow && !segSpec) return S(500);
  const bindingValues = await getPowBindingValues(request, canonicalPath, config, derived);
  if (!bindingValues) return deny();
  const { pathHash, ipScope, country, asn, tlsFingerprint } = bindingValues;
  const powVersion = getPowVersion(config);
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
  const apiPrefixB64 = base64UrlEncodeNoPad(utf8ToBytes(config.POW_API_PREFIX));
  const esmUrlB64 = needPow ? base64UrlEncodeNoPad(utf8ToBytes(config.POW_ESM_URL)) : "";
  const turnSiteKeyB64 = needTurn
    ? base64UrlEncodeNoPad(utf8ToBytes(config.TURNSTILE_SITEKEY))
    : "";
  const glueUrl = config.POW_GLUE_URL;
  const atomicConsume = config.ATOMIC_CONSUME === true ? "1" : "0";
  const atomicTurnQuery = config.ATOMIC_TURN_QUERY.trim();
  const atomicTicketQuery = config.ATOMIC_TICKET_QUERY.trim();
  const atomicConsumeQuery = config.ATOMIC_CONSUME_QUERY.trim();
  const atomicTurnHeader = config.ATOMIC_TURN_HEADER.trim();
  const atomicTicketHeader = config.ATOMIC_TICKET_HEADER.trim();
  const atomicConsumeHeader = config.ATOMIC_CONSUME_HEADER.trim();
  const atomicCookieName = config.ATOMIC_COOKIE_NAME.trim();
  const atomicCfg = `${atomicConsume}|${atomicTurnQuery}|${atomicTicketQuery}|${atomicConsumeQuery}|${atomicTurnHeader}|${atomicTicketHeader}|${atomicConsumeHeader}|${atomicCookieName}`;
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
    atomicCfg,
  });
  const headers = new Headers();
  headers.set("Content-Type", "text/html");
  headers.set("Cache-Control", "no-store");
  headers.set("Content-Security-Policy", "frame-ancestors 'none'");
  headers.set("X-Frame-Options", "DENY");
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

const getPowSecret = (config) => config.POW_TOKEN;

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
  const token = typeof body.token === "string" ? body.token : "";
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
  if (!ticketMatchesInner(ticket, cfgId)) return deny();
  if (!powSecret) return S(500);
  if (config.powcheck !== true) return S(500);
  const needTurn = config.turncheck === true;
  let turnToken = "";
  if (needTurn) {
    turnToken = validateTurnToken(token);
    if (!turnToken) return S(400);
  }
  const powVersion = validateTicket(ticket, config, nowSeconds);
  if (!powVersion) return deny();
  const normalizedPathHash = normalizePathHash(pathHash, config);
  if (!normalizedPathHash) return S(400);
  const bindingValues = await getPowBindingValuesWithPathHash(
    request,
    normalizedPathHash,
    config,
    derived
  );
  if (!bindingValues) return deny();
  if (!(await verifyTicketMac(ticket, url, bindingValues, powSecret))) return deny();
  const rootBytes = base64UrlDecodeToBytes(rootB64);
  if (!rootBytes || rootBytes.length !== 32) {
    return S(400);
  }
  const ttl = config.POW_COMMIT_TTL_SEC || 0;
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
  setCookie(headers, config.POW_COMMIT_COOKIE, value, ttl);
  return new Response(null, { status: 200, headers });
};

const handleTurn = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId } = innerCtx;
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object") return S(400);
  const ticketB64 = typeof body.ticketB64 === "string" ? body.ticketB64 : "";
  const pathHash = typeof body.pathHash === "string" ? body.pathHash : "";
  const token = typeof body.token === "string" ? body.token : "";
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN) || pathHash.length > B64_HASH_MAX_LEN) {
    return S(400);
  }

  const ticket = parsePowTicket(ticketB64);
  if (!ticket) return deny();
  if (!ticketMatchesInner(ticket, cfgId)) return deny();
  if (!powSecret) return S(500);
  const needPow = config.powcheck === true;
  const needTurn = config.turncheck === true;
  if (!needTurn || needPow || config.ATOMIC_CONSUME === true) return S(404);
  const turnSecret = getTurnSecret(config);
  if (!turnSecret) return S(500);
  const turnToken = validateTurnToken(token);
  if (!turnToken) return S(400);

  const powVersion = validateTicket(ticket, config, nowSeconds);
  if (!powVersion) return deny();

  const normalizedPathHash = normalizePathHash(pathHash, config);
  if (!normalizedPathHash) return S(400);

  const bindingValues = await getPowBindingValuesWithPathHash(
    request,
    normalizedPathHash,
    config,
    derived
  );
  if (!bindingValues) return deny();
  if (!(await verifyTicketMac(ticket, url, bindingValues, powSecret))) return deny();

  if (!(await verifyTurnstileForTicket(request, turnSecret, turnToken, ticket))) {
    return deny();
  }

  const ttl = getProofTtl(ticket, config, nowSeconds);
  if (!ttl) return deny();
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
    2
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
  if (!(await verifyCommit(commit, ticket, config, powSecret, nowSeconds))) return deny();
  if (!Number.isFinite(ticket.L) || ticket.L <= 0) return deny();
  const bindingValues = await getPowBindingValuesWithPathHash(
    request,
    commit.pathHash,
    config,
    derived
  );
  if (!bindingValues) return deny();
  if (!(await verifyTicketMac(ticket, url, bindingValues, powSecret))) return deny();
  const sid = await derivePowSid(powSecret, ticket.cfgId, commit.mac);
  const sample = await buildPowSample(config, powSecret, ticket, commit.mac, sid);
  if (!sample) return deny();
  const { indices, segLensAll, spineK } = sample;
  const batchLen = getBatchMax(config);
  const batchResp = await buildPowBatchResponse(
    indices,
    segLensAll,
    spineK,
    ticket,
    commit,
    powSecret,
    sid,
    0,
    batchLen
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
  const needTurn = config.turncheck === true;
  const powVersion = await verifyCommit(commit, ticket, config, powSecret, nowSeconds);
  if (!powVersion) return deny();
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
  const batchMax = getBatchMax(config);
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
  const sample = await buildPowSample(config, powSecret, ticket, commit.mac, sidExpected);
  if (!sample) return deny();
  const { indices, segLensAll, hashcashBits, spineK } = sample;
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
    config,
    derived
  );
  if (!bindingValues) return deny();
  const bindingString = await verifyTicketMac(ticket, url, bindingValues, powSecret);
  if (!bindingString) return deny();
  const powBindingString = needTurn ? `${bindingString}|${commit.tb}` : bindingString;
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
    const nextResp = await buildPowBatchResponse(
      indices,
      segLensAll,
      spineK,
      ticket,
      commit,
      powSecret,
      sidExpected,
      nextCursor,
      batchMax
    );
    if (!nextResp) return deny();
    return J(nextResp);
  }
  const ttl = getProofTtl(ticket, config, nowSeconds);
  if (!ttl) return deny();

  if (needTurn && config.ATOMIC_CONSUME === true) {
    const finalToken = validateTurnToken(turnToken);
    if (!finalToken) return deny();
    const tb = await tbFromToken(finalToken);
    if (tb !== commit.tb) return deny();
    const exp = nowSeconds + ttl;
    const mac = await makeConsumeMac(powSecret, commit.ticketB64, exp, tb, 3);
    const headers = new Headers();
    clearCookie(headers, config.POW_COMMIT_COOKIE);
    return J({ done: true, consume: `v2.${commit.ticketB64}.${exp}.${tb}.3.${mac}` }, 200, headers);
  }

  if (needTurn) {
    const turnSecret = getTurnSecret(config);
    if (!turnSecret) return S(500);
    const finalToken = validateTurnToken(turnToken);
    if (!finalToken) return deny();
    const tb = await tbFromToken(finalToken);
    if (tb !== commit.tb) return deny();
    if (!(await verifyTurnstileForTicket(request, turnSecret, finalToken, ticket))) {
      return deny();
    }
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
    needTurn ? 3 : 1
  );
  clearCookie(headers, config.POW_COMMIT_COOKIE);
  return J({ done: true }, 200, headers);
};

const handlePowApi = async (request, url, nowSeconds, innerCtx) => {
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
  if (action === "/turn") {
    return handleTurn(request, url, nowSeconds, innerCtx);
  }
  return S(404);
};

export { hmacSha256Base64UrlNoPad };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const nowSeconds = Math.floor(Date.now() / 1000);

    const requestPath = normalizePath(url.pathname);
    if (!requestPath) return S(400);

    const inner = await readInnerPayload(request);
    if (!inner) return S(500);
    const innerCtx = loadConfigFromInner(inner);
    if (!innerCtx) return S(500);
    const { config, powSecret, derived, cfgId } = innerCtx;

    if (request.method === "OPTIONS") {
      return S(204);
    }

    if (requestPath.startsWith(`${config.POW_API_PREFIX}/`)) {
      return handlePowApi(request, url, nowSeconds, innerCtx);
    }

    const needPow = config.powcheck === true;
    const needTurn = config.turncheck === true;
    if (!needPow && !needTurn) {
      return fetch(stripInnerHeaders(request));
    }
    const bypass = resolveBypassRequest(request, url, config);
    if (bypass.bypass) {
      return fetch(stripInnerHeaders(bypass.forwardRequest));
    }

    const bindRes = resolveBindPathForPow(request, url, requestPath, config);
    if (!bindRes.ok) {
      if (bindRes.code === "missing") return S(400);
      if (bindRes.code === "invalid") return S(400);
      return S(500);
    }

    if (!powSecret) return S(500);
    if (needPow && !config.POW_ESM_URL) return S(500);
    if (needTurn) {
      const sitekey = config.TURNSTILE_SITEKEY;
      const secret = getTurnSecret(config);
      if (!sitekey || !secret) return S(500);
    }

    const requiredMask = (needPow ? 1 : 0) | (needTurn ? 2 : 0);
    const allowProof = !(needTurn && config.ATOMIC_CONSUME === true);
    const proofMeta = allowProof
      ? await verifyProofCookie(
          request,
          url,
          bindRes.canonicalPath,
          nowSeconds,
          config,
          powSecret,
          derived,
          cfgId,
          requiredMask
        )
      : null;

    if (proofMeta) {
      let response = await fetch(stripInnerHeaders(bindRes.forwardRequest));
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

    if (needTurn && config.ATOMIC_CONSUME === true) {
      const baseRequest = bindRes.forwardRequest;
      const baseUrl = new URL(baseRequest.url);
      const atomic = extractAtomicAuth(baseRequest, baseUrl, config);
      const fail = async (resp, allowChallenge = true) => {
        if (allowChallenge && isNavigationRequest(request)) {
          const challenge = await respondPowChallengeHtml(
            baseRequest,
            baseUrl,
            bindRes.canonicalPath,
            nowSeconds,
            config,
            powSecret,
            derived,
            cfgId,
            { needPow, needTurn }
          );
          return atomic.fromCookie ? withClearedCookie(challenge, atomic.cookieName) : challenge;
        }
        return atomic.fromCookie ? withClearedCookie(resp, atomic.cookieName) : resp;
      };
      if (atomic.turnToken) {
        const turnToken = validateTurnToken(atomic.turnToken);
        if (!turnToken) return await fail(deny());
        const turnSecret = getTurnSecret(config);
        if (!turnSecret) return await fail(S(500), false);
        if (needPow) {
          const consume = await verifyConsumeToken(
            atomic.consumeToken,
            powSecret,
            nowSeconds,
            requiredMask
          );
          if (!consume) return await fail(deny());
          const tb = await tbFromToken(turnToken);
          if (tb !== consume.tb) return await fail(deny());
          const ticket = await loadAtomicTicket(
            consume.ticketB64,
            baseRequest,
            baseUrl,
            bindRes.canonicalPath,
            config,
            powSecret,
            derived,
            cfgId,
            nowSeconds
          );
          if (!ticket) return await fail(deny());
          if (!(await verifyTurnstileForTicket(baseRequest, turnSecret, turnToken, ticket))) {
            return await fail(deny());
          }
          const response = await fetch(stripInnerHeaders(atomic.forwardRequest));
          return atomic.fromCookie ? withClearedCookie(response, atomic.cookieName) : response;
        }
        const ticket = await loadAtomicTicket(
          atomic.ticketB64,
          baseRequest,
          baseUrl,
          bindRes.canonicalPath,
          config,
          powSecret,
          derived,
          cfgId,
          nowSeconds
        );
        if (!ticket) return await fail(deny());
        if (!(await verifyTurnstileForTicket(baseRequest, turnSecret, turnToken, ticket))) {
          return await fail(deny());
        }
        const response = await fetch(stripInnerHeaders(atomic.forwardRequest));
        return atomic.fromCookie ? withClearedCookie(response, atomic.cookieName) : response;
      }
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
      derived,
      cfgId,
      { needPow, needTurn }
    );
  },
};
