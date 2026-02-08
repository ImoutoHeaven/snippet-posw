// Cloudflare Snippet: stateless PoW (generic L7 WAF)
// Set POW_TOKEN in config to your PoW secret.
const PROOF_COOKIE = "__Host-proof";
const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const RECAPTCHA_SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";
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
  const strategy = parsed.s && typeof parsed.s === "object" ? parsed.s : null;
  if (id === null || !config || !derived || !strategy) return null;
  return { id, c: config, d: derived, s: strategy };
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
const CAPTCHA_TAG_LEN = 16;
const PREFLIGHT_REASON_MAX_LEN = 64;
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

const hmacSha256Base64UrlNoPad = async (secret, data) => {
  const bytes = await hmacSha256(secret, data);
  return base64UrlEncodeNoPad(bytes);
};

const sha256Bytes = async (data) => {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
};
const bytesToHex = (bytes) => Array.from(bytes || [], (b) => b.toString(16).padStart(2, "0")).join("");
const captchaTagFromToken = async (token) =>
  base64UrlEncodeNoPad((await sha256Bytes(token)).slice(0, 12));

const makeRecaptchaAction = async (bindingString, kid) => {
  const binding = typeof bindingString === "string" ? bindingString : "";
  const kidNum = Number.isInteger(kid) && kid >= 0 ? kid : -1;
  if (!binding || kidNum < 0) return "";
  const digest = await sha256Bytes(`act|${binding}|${kidNum}`);
  return `p_${bytesToHex(digest.slice(0, 10))}`;
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
  captchaTag,
  nonce,
  exp,
  spineSeed
) =>
  hmacSha256Base64UrlNoPad(
    powSecret,
    `C|${ticketB64}|${rootB64}|${pathHash}|${captchaTag}|${nonce}|${exp}|${spineSeed}`
  );

const makeConsumeMac = async (powSecret, ticketB64, exp, captchaTag, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `U|${ticketB64}|${exp}|${captchaTag}|${m}`);

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
  return { ticketB64, rootB64, pathHash, captchaTag, nonce, exp, mac, spineSeed };
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
  const captchaTag = parts[3] || "";
  const m = Number.parseInt(parts[4], 10);
  const mac = parts[5] || "";
  if (exp <= 0) return null;
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(captchaTag, CAPTCHA_TAG_LEN, CAPTCHA_TAG_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { ticketB64, exp, captchaTag, m, mac };
};

const makeProofMac = async (powSecret, ticketB64, iat, last, n, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `O|${ticketB64}|${iat}|${last}|${n}|${m}`);

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

const getPowBindingValues = async (canonicalPath, config, derived) => {
  const bindPath = config.POW_BIND_PATH !== false;
  const pathHash = bindPath ? await computePathHash(canonicalPath) : "any";
  return getPowBindingValuesWithPathHash(pathHash, config, derived);
};

const normalizeTurnstilePreflight = (raw) => {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  if (typeof raw.checked !== "boolean") return null;
  if (typeof raw.ok !== "boolean") return null;
  if (typeof raw.reason !== "string") return null;
  if (typeof raw.ticketMac !== "string") return null;
  if (typeof raw.tokenTag !== "string") return null;
  if (
    raw.reason.length > PREFLIGHT_REASON_MAX_LEN ||
    raw.ticketMac.length > B64_HASH_MAX_LEN ||
    raw.tokenTag.length > CAPTCHA_TAG_LEN
  ) {
    return null;
  }
  if (
    CONTROL_CHAR_RE.test(raw.reason) ||
    CONTROL_CHAR_RE.test(raw.ticketMac) ||
    CONTROL_CHAR_RE.test(raw.tokenTag)
  ) {
    return null;
  }
  if (raw.ticketMac && !isBase64Url(raw.ticketMac, 1, B64_HASH_MAX_LEN)) return null;
  if (raw.tokenTag && !isBase64Url(raw.tokenTag, 1, CAPTCHA_TAG_LEN)) return null;
  return {
    checked: raw.checked,
    ok: raw.ok,
    reason: raw.reason,
    ticketMac: raw.ticketMac,
    tokenTag: raw.tokenTag,
  };
};

const normalizeInnerStrategy = (snapshot) => {
  if (!snapshot || typeof snapshot !== "object") return null;
  const nav = snapshot.nav && typeof snapshot.nav === "object" ? snapshot.nav : null;
  const bypassRaw = snapshot.bypass && typeof snapshot.bypass === "object" ? snapshot.bypass : null;
  const bindRaw = snapshot.bind && typeof snapshot.bind === "object" ? snapshot.bind : null;
  const atomicRaw = snapshot.atomic && typeof snapshot.atomic === "object" ? snapshot.atomic : null;
  if (!nav || !bypassRaw || !bindRaw || !atomicRaw) return null;
  if (typeof bypassRaw.bypass !== "boolean") return null;
  if (typeof bindRaw.ok !== "boolean") return null;
  if (typeof bindRaw.code !== "string") return null;
  if (typeof bindRaw.canonicalPath !== "string") return null;
  if (typeof atomicRaw.captchaToken !== "string") return null;
  if (typeof atomicRaw.ticketB64 !== "string") return null;
  if (typeof atomicRaw.consumeToken !== "string") return null;
  if (typeof atomicRaw.fromCookie !== "boolean") return null;
  if (typeof atomicRaw.cookieName !== "string") return null;
  const normalizedPreflight = normalizeTurnstilePreflight(atomicRaw.turnstilePreflight);
  return {
    nav,
    bypass: { bypass: bypassRaw.bypass },
    bind: {
      ok: bindRaw.ok,
      code: bindRaw.code,
      canonicalPath: bindRaw.canonicalPath,
    },
    atomic: {
      captchaToken: atomicRaw.captchaToken,
      ticketB64: atomicRaw.ticketB64,
      consumeToken: atomicRaw.consumeToken,
      fromCookie: atomicRaw.fromCookie,
      cookieName: atomicRaw.cookieName,
      turnstilePreflight: normalizedPreflight,
    },
  };
};

const loadConfigFromInner = (inner) => {
  if (!inner || typeof inner !== "object") return null;
  const baseConfig = inner.c && typeof inner.c === "object" ? inner.c : null;
  const strategy = normalizeInnerStrategy(inner.s);
  if (!baseConfig) return null;
  if (!strategy) return null;
  return {
    config: baseConfig,
    powSecret: getPowSecret(baseConfig),
    derived: inner.d,
    cfgId: inner.id,
    strategy,
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

const validateTicket = (ticket, config, nowSeconds) => {
  const powVersion = config.POW_VERSION;
  if (ticket.v !== powVersion) return 0;
  if (isExpired(ticket.e, nowSeconds)) return 0;
  return powVersion;
};

const verifyCommit = async (commit, ticket, config, powSecret, nowSeconds) => {
  if (config.turncheck === true && !isBase64Url(commit.captchaTag, CAPTCHA_TAG_LEN, CAPTCHA_TAG_LEN)) {
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
    parsed.captchaTag,
    parsed.m
  );
  if (!timingSafeEqual(mac, parsed.mac)) return null;
  return parsed;
};

const loadAtomicTicket = async (
  ticketB64,
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
  const bindingValues = await getPowBindingValues(canonicalPath, config, derived);
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

const pickRecaptchaPair = async (ticketMac, pairs) => {
  if (!Array.isArray(pairs) || pairs.length === 0) return null;
  const digest = await sha256Bytes(`kid|${typeof ticketMac === "string" ? ticketMac : ""}`);
  const number =
    ((digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]) >>> 0;
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
  { provider, secret, token, ticketMac, bindingString = "", kid = -1, minScore = 0 }
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
    const expectedAction = await makeRecaptchaAction(bindingString, kid);
    if (!expectedAction || verify.action !== expectedAction) return false;
    return true;
  }
  return false;
};

const readCaptchaTokens = (captchaToken, needTurn, needRecaptcha) => {
  if (typeof captchaToken === "string") {
    const single = captchaToken.trim();
    if (!single) return null;
    if (single.startsWith("{") && single.endsWith("}")) {
      try {
        const parsed = JSON.parse(single);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          const turnstile = typeof parsed.turnstile === "string" ? parsed.turnstile.trim() : "";
          const recaptcha_v3 =
            typeof parsed.recaptcha_v3 === "string" ? parsed.recaptcha_v3.trim() : "";
          return { turnstile, recaptcha_v3 };
        }
      } catch {
        return null;
      }
      return null;
    }
    if (needTurn && !needRecaptcha) return { turnstile: single, recaptcha_v3: "" };
    if (needRecaptcha && !needTurn) return { turnstile: "", recaptcha_v3: single };
    return null;
  }
  if (!captchaToken || typeof captchaToken !== "object" || Array.isArray(captchaToken)) {
    return null;
  }
  const turnstile = typeof captchaToken.turnstile === "string" ? captchaToken.turnstile.trim() : "";
  const recaptcha_v3 =
    typeof captchaToken.recaptcha_v3 === "string" ? captchaToken.recaptcha_v3.trim() : "";
  return { turnstile, recaptcha_v3 };
};

const verifyRequiredCaptchaForTicket = async (
  request,
  config,
  ticket,
  bindingString,
  captchaToken,
  options = {}
) => {
  const opts = options && typeof options === "object" ? options : {};
  const requireTurnPreflight = opts.requireTurnPreflight === true;
  const turnstilePreflight = normalizeTurnstilePreflight(opts.turnstilePreflight);
  const needTurn = config.turncheck === true;
  const needRecaptcha = config.recaptchaEnabled === true;
  if (!needTurn && !needRecaptcha) return { ok: true, captchaTag: "any" };
  const tokens = readCaptchaTokens(captchaToken, needTurn, needRecaptcha);
  if (!tokens) return { ok: false, captchaTag: "" };
  let turnToken = "";
  let recaptchaToken = "";

  if (needTurn) {
    turnToken = validateTurnToken(tokens.turnstile);
    if (!turnToken) return { ok: false, captchaTag: "" };
    if (requireTurnPreflight) {
      if (!turnstilePreflight || !turnstilePreflight.checked || !turnstilePreflight.ok) {
        return { ok: false, captchaTag: "" };
      }
      if (!timingSafeEqual(turnstilePreflight.ticketMac, ticket.mac)) {
        return { ok: false, captchaTag: "" };
      }
      const expectedTokenTag = await captchaTagFromToken(turnToken);
      if (!timingSafeEqual(turnstilePreflight.tokenTag, expectedTokenTag)) {
        return { ok: false, captchaTag: "" };
      }
    } else {
      const turnSecret = config.TURNSTILE_SECRET;
      if (!turnSecret) return { ok: false, captchaTag: "" };
      const turnOk = await verifyCaptchaForTicket(request, {
        provider: "turnstile",
        secret: turnSecret,
        token: turnToken,
        ticketMac: ticket.mac,
      });
      if (!turnOk) return { ok: false, captchaTag: "" };
    }
  }

  if (needRecaptcha) {
    const pairs = Array.isArray(config.RECAPTCHA_PAIRS) ? config.RECAPTCHA_PAIRS : [];
    const picked = await pickRecaptchaPair(ticket.mac, pairs);
    if (!picked || !picked.pair || !picked.pair.secret) return { ok: false, captchaTag: "" };
    recaptchaToken = validateTurnToken(tokens.recaptcha_v3);
    if (!recaptchaToken) return { ok: false, captchaTag: "" };
    const minScore = Number.isFinite(config.RECAPTCHA_MIN_SCORE)
      ? config.RECAPTCHA_MIN_SCORE
      : 0.5;
    const recapOk = await verifyCaptchaForTicket(request, {
      provider: "recaptcha_v3",
      secret: picked.pair.secret,
      token: recaptchaToken,
      ticketMac: ticket.mac,
      bindingString,
      kid: picked.kid,
      minScore,
    });
    if (!recapOk) return { ok: false, captchaTag: "" };
  }

  const activeCaptchaMaterial = turnToken || recaptchaToken;
  const captchaTag = activeCaptchaMaterial ? await captchaTagFromToken(activeCaptchaMaterial) : "any";
  return { ok: true, captchaTag };
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
  const powVersion = config.POW_VERSION;
  if (ticket.v !== powVersion) return null;
  if (!Number.isFinite(ticket.e) || ticket.e <= nowSeconds) return null;
  if (!Number.isFinite(ticket.L) || ticket.L <= 0) return null;
  if (ticket.cfgId !== cfgId) return null;
  if (proof.last > ticket.e) return null;
  const bindingValues = await getPowBindingValues(canonicalPath, config, derived);
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
  captchaCfgB64,
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
  .replace('__K__', captchaCfgB64)
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
  const needRecaptcha = requirements && requirements.needRecaptcha === true;
  const steps = needPow ? getPowSteps(config) : 1;
  const glueSteps = needPow ? steps : 0;
  const hashcashBits = needPow ? Math.max(0, Math.floor(config.POW_HASHCASH_BITS)) : 0;
  const segSpec = needPow
    ? parseSegmentLenSpec(config.POW_SEGMENT_LEN)
    : { mode: "fixed", fixed: 1 };
  if (needPow && !segSpec) return S(500);
  const bindingValues = await getPowBindingValues(canonicalPath, config, derived);
  if (!bindingValues) return deny();
  const { pathHash, ipScope, country, asn, tlsFingerprint } = bindingValues;
  const powVersion = config.POW_VERSION;
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
  const captchaCfg = {};
  if (needTurn) {
    captchaCfg.turnstile = { sitekey: config.TURNSTILE_SITEKEY };
  }
  if (needRecaptcha) {
    const pairs = Array.isArray(config.RECAPTCHA_PAIRS) ? config.RECAPTCHA_PAIRS : [];
    const picked = await pickRecaptchaPair(ticket.mac, pairs);
    if (!picked || !picked.pair || !picked.pair.sitekey) return S(500);
    const action = await makeRecaptchaAction(bindingString, picked.kid);
    if (!action) return S(500);
    captchaCfg.recaptcha_v3 = { sitekey: picked.pair.sitekey, action };
  }
  const captchaCfgB64 = base64UrlEncodeNoPad(utf8ToBytes(JSON.stringify(captchaCfg)));
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
    captchaCfgB64,
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
  if (!ticket) return deny();
  if (!ticketMatchesInner(ticket, cfgId)) return deny();
  if (!powSecret) return S(500);
  if (config.powcheck !== true) return S(500);
  const needTurn = config.turncheck === true;
  const needRecaptcha = config.recaptchaEnabled === true;
  const powVersion = validateTicket(ticket, config, nowSeconds);
  if (!powVersion) return deny();
  const normalizedPathHash = normalizePathHash(pathHash, config);
  if (!normalizedPathHash) return S(400);
  const bindingValues = await getPowBindingValuesWithPathHash(normalizedPathHash, config, derived);
  if (!bindingValues) return deny();
  const bindingString = await verifyTicketMac(ticket, url, bindingValues, powSecret);
  if (!bindingString) return deny();
  const rootBytes = base64UrlDecodeToBytes(rootB64);
  if (!rootBytes || rootBytes.length !== 32) {
    return S(400);
  }
  const ttl = config.POW_COMMIT_TTL_SEC || 0;
  const exp = nowSeconds + Math.max(1, ttl);
  const spineSeed = randomBase64Url(16);
  let captchaTag = "any";
  if (needTurn || needRecaptcha) {
    const verifiedCaptcha = await verifyRequiredCaptchaForTicket(
      request,
      config,
      ticket,
      bindingString,
      captchaToken
    );
    if (!verifiedCaptcha.ok) return deny();
    captchaTag = verifiedCaptcha.captchaTag;
  }
  const mac = await makePowCommitMac(
    powSecret,
    ticketB64,
    rootB64,
    bindingValues.pathHash,
    captchaTag,
    nonce,
    exp,
    spineSeed
  );
  const value = `v4.${ticketB64}.${rootB64}.${bindingValues.pathHash}.${captchaTag}.${nonce}.${exp}.${spineSeed}.${mac}`;
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
  const needTurn = config.turncheck === true;
  const needRecaptcha = config.recaptchaEnabled === true;
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

  const verifiedCaptcha = await verifyRequiredCaptchaForTicket(
    request,
    config,
    ticket,
    bindingString,
    captchaToken
  );
  if (!verifiedCaptcha.ok) {
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
    requiredMask
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
  const bindingValues = await getPowBindingValuesWithPathHash(commit.pathHash, config, derived);
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
  const needRecaptcha = config.recaptchaEnabled === true;
  const requiredMask = 1 | (needTurn ? 2 : 0) | (needRecaptcha ? 4 : 0);
  const powVersion = await verifyCommit(commit, ticket, config, powSecret, nowSeconds);
  if (!powVersion) return deny();
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object") {
    return S(400);
  }
  const sid = typeof body.sid === "string" ? body.sid : "";
  const cursor = Number.parseInt(body.cursor, 10);
  const stateToken = typeof body.token === "string" ? body.token : "";
  const captchaToken = body.captchaToken;
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
  const bindingValues = await getPowBindingValuesWithPathHash(commit.pathHash, config, derived);
  if (!bindingValues) return deny();
  const bindingString = await verifyTicketMac(ticket, url, bindingValues, powSecret);
  if (!bindingString) return deny();
  const powBindingString = needTurn || needRecaptcha
    ? `${bindingString}|${commit.captchaTag}`
    : bindingString;
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

  if ((needTurn || needRecaptcha) && config.ATOMIC_CONSUME === true) {
    const verifiedCaptcha = await verifyRequiredCaptchaForTicket(
      request,
      config,
      ticket,
      bindingString,
      captchaToken
    );
    if (!verifiedCaptcha.ok || verifiedCaptcha.captchaTag !== commit.captchaTag) return deny();
    const exp = nowSeconds + ttl;
    const mac = await makeConsumeMac(
      powSecret,
      commit.ticketB64,
      exp,
      verifiedCaptcha.captchaTag,
      requiredMask
    );
    const headers = new Headers();
    clearCookie(headers, config.POW_COMMIT_COOKIE);
    return J(
      {
        done: true,
        consume: `v2.${commit.ticketB64}.${exp}.${verifiedCaptcha.captchaTag}.${requiredMask}.${mac}`,
      },
      200,
      headers
    );
  }

  if (needTurn || needRecaptcha) {
    const verifiedCaptcha = await verifyRequiredCaptchaForTicket(
      request,
      config,
      ticket,
      bindingString,
      captchaToken
    );
    if (!verifiedCaptcha.ok || verifiedCaptcha.captchaTag !== commit.captchaTag) return deny();
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
    requiredMask
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
  if (action === "/cap") {
    return handleCap(request, url, nowSeconds, innerCtx);
  }
  return S(404);
};

export { hmacSha256Base64UrlNoPad };
export const __captchaTesting = {
  pickRecaptchaPair,
  makeRecaptchaAction,
  verifyCaptchaSiteverify,
  verifyCaptchaForTicket,
};

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
    const { config, powSecret, derived, cfgId, strategy } = innerCtx;

    if (request.method === "OPTIONS") {
      return S(204);
    }

    if (requestPath.startsWith(`${config.POW_API_PREFIX}/`)) {
      return handlePowApi(request, url, nowSeconds, innerCtx);
    }

    const needPow = config.powcheck === true;
    const needTurn = config.turncheck === true;
    const needRecaptcha = config.recaptchaEnabled === true;
    if (!needPow && !needTurn && !needRecaptcha) {
      return fetch(stripInnerHeaders(request));
    }
    if (strategy.bypass.bypass) {
      return fetch(stripInnerHeaders(request));
    }

    const bindRes = strategy.bind;
    if (!bindRes.ok) {
      if (bindRes.code === "missing") return S(400);
      if (bindRes.code === "invalid") return S(400);
      return S(500);
    }

    if (!powSecret) return S(500);
    if (needPow && !config.POW_ESM_URL) return S(500);
    if (needTurn) {
      const sitekey = config.TURNSTILE_SITEKEY;
      const secret = config.TURNSTILE_SECRET;
      if (!sitekey || !secret) return S(500);
    }

    const requiredMask = (needPow ? 1 : 0) | (needTurn ? 2 : 0) | (needRecaptcha ? 4 : 0);
    const allowProof = !((needTurn || needRecaptcha) && config.ATOMIC_CONSUME === true);
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
      let response = await fetch(stripInnerHeaders(request));
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

    if ((needTurn || needRecaptcha) && config.ATOMIC_CONSUME === true) {
      const baseRequest = request;
      const baseUrl = url;
      const atomic = strategy.atomic;
      const requireTurnPreflight = needTurn && needRecaptcha;
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
            { needPow, needTurn, needRecaptcha }
          );
          return atomic.fromCookie ? withClearedCookie(challenge, atomic.cookieName) : challenge;
        }
        return atomic.fromCookie ? withClearedCookie(resp, atomic.cookieName) : resp;
      };
      if (atomic.captchaToken) {
        if (
          requireTurnPreflight &&
          (!atomic.turnstilePreflight ||
            atomic.turnstilePreflight.checked !== true ||
            atomic.turnstilePreflight.ok !== true)
        ) {
          return await fail(deny());
        }
        const tokenMap = readCaptchaTokens(atomic.captchaToken, needTurn, needRecaptcha);
        if (!tokenMap) return await fail(deny());
        const turnToken = needTurn ? validateTurnToken(tokenMap.turnstile) : "";
        if (needTurn && !turnToken) return await fail(deny());
        if (needPow) {
          const consume = await verifyConsumeToken(
            atomic.consumeToken,
            powSecret,
            nowSeconds,
            requiredMask
          );
          if (!consume) return await fail(deny());
          const ticket = await loadAtomicTicket(
            consume.ticketB64,
            baseUrl,
            bindRes.canonicalPath,
            config,
            powSecret,
            derived,
            cfgId,
            nowSeconds
          );
          if (!ticket) return await fail(deny());
          const bindingValues = await getPowBindingValues(bindRes.canonicalPath, config, derived);
          if (!bindingValues) return await fail(deny());
          const atomicBinding = await verifyTicketMac(ticket, baseUrl, bindingValues, powSecret);
          if (!atomicBinding) return await fail(deny());
          const verifiedCaptcha = await verifyRequiredCaptchaForTicket(
            baseRequest,
            config,
            ticket,
            atomicBinding,
            atomic.captchaToken,
            {
              requireTurnPreflight,
              turnstilePreflight: atomic.turnstilePreflight,
            }
          );
          if (!verifiedCaptcha.ok || verifiedCaptcha.captchaTag !== consume.captchaTag) {
            return await fail(deny());
          }
          const response = await fetch(stripInnerHeaders(baseRequest));
          return atomic.fromCookie ? withClearedCookie(response, atomic.cookieName) : response;
        }
        const ticket = await loadAtomicTicket(
          atomic.ticketB64,
          baseUrl,
          bindRes.canonicalPath,
          config,
          powSecret,
          derived,
          cfgId,
          nowSeconds
        );
        if (!ticket) return await fail(deny());
        const bindingValues = await getPowBindingValues(bindRes.canonicalPath, config, derived);
        if (!bindingValues) return await fail(deny());
        const atomicBinding = await verifyTicketMac(ticket, baseUrl, bindingValues, powSecret);
        if (!atomicBinding) return await fail(deny());
        const verifiedCaptcha = await verifyRequiredCaptchaForTicket(
          baseRequest,
          config,
          ticket,
          atomicBinding,
          atomic.captchaToken,
          {
            requireTurnPreflight,
            turnstilePreflight: atomic.turnstilePreflight,
          }
        );
        if (!verifiedCaptcha.ok) {
          return await fail(deny());
        }
        const response = await fetch(stripInnerHeaders(baseRequest));
        return atomic.fromCookie ? withClearedCookie(response, atomic.cookieName) : response;
      }
    }

    if (!isNavigationRequest(request)) {
      const code = needPow ? "pow_required" : "captcha_required";
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
      { needPow, needTurn, needRecaptcha }
    );
  },
};
