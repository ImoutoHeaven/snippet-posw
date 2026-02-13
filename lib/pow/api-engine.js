import { verifyOpenBatchVector } from "../mhg/verify.js";
import { verifyViaSiteverifyAggregator } from "./siteverify-client.js";

const PROOF_COOKIE = "__Host-proof";

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

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hmacKeyCache = new Map();

const HASHCASH_PREFIX = encoder.encode("hashcash|v4|");

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
    const fixed = clampInt(raw, 1, 16);
    return { mode: "fixed", fixed };
  }
  if (isNumericString) {
    const fixed = clampInt(raw, 1, 16);
    return { mode: "fixed", fixed };
  }
  if (typeof raw === "string") {
    const match = raw.trim().match(/^(\d+)\s*-\s*(\d+)$/);
    if (match) {
      const min = clampInt(match[1], 1, 16);
      const max = clampInt(match[2], 1, 16);
      if (min <= max && max - min <= 15) {
        return { mode: "range", min, max };
      }
    }
  }
  return null;
};

const computeSegLensForIndices = (indices, segSpec, rngSeg) => {
  if (!segSpec || segSpec.mode !== "range") {
    const fixed = clampInt(segSpec && segSpec.fixed, 1, 16);
    return indices.map(() => fixed);
  }
  const span = Math.max(1, Math.floor(segSpec.max - segSpec.min + 1));
  return indices.map(() => segSpec.min + rngSeg.randInt(span));
};

const getBatchMax = (config) => Math.max(1, Math.min(32, Math.floor(config.POW_OPEN_BATCH)));

const normalizeNumberClamp = (value, fallback, min, max) => {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
};

const getPowMaxGenTimeSec = (config) =>
  Math.floor(normalizeNumberClamp(config?.POW_MAX_GEN_TIME_SEC, 300, 1, 1000000000));

const isPowAbsoluteLifecycleExpired = (ticket, config, nowSeconds) => {
  const issuedAt = Number(ticket?.issuedAt);
  const maxGen = getPowMaxGenTimeSec(config);
  const commitTtl = Math.max(1, Math.floor(Number(config?.POW_COMMIT_TTL_SEC) || 0));
  const absoluteDeadline = issuedAt + maxGen + commitTtl;
  return !Number.isFinite(issuedAt) || issuedAt <= 0 || nowSeconds > absoluteDeadline;
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

const getPowDifficultyBinding = (config) => ({
  pageBytes: (() => {
    const raw = Number(config?.POW_PAGE_BYTES);
    if (!Number.isFinite(raw)) return 16384;
    const pageBytes = Math.floor(raw);
    if (pageBytes < 16) return 16384;
    return Math.floor(pageBytes / 16) * 16;
  })(),
  mixRounds: (() => {
    const raw = Number(config?.POW_MIX_ROUNDS);
    if (!Number.isFinite(raw)) return 2;
    return Math.max(1, Math.min(4, Math.floor(raw)));
  })(),
});

const makePowBindingString = (
  ticket,
  hostname,
  pathHash,
  ipScope,
  country,
  asn,
  tlsFingerprint,
  pageBytes,
  mixRounds,
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
    tlsFingerprint +
    "|" +
    pageBytes +
    "|" +
    mixRounds +
    "|" +
    ticket.issuedAt
  );
};

const hashcashRootLast = async (rootBytes, lastBytes) =>
  sha256Bytes(concatBytes(HASHCASH_PREFIX, rootBytes, lastBytes));

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
  if (!Number.isFinite(ticket.issuedAt) || ticket.issuedAt <= 0) {
    throw new Error("invalid ticket issuedAt");
  }
  const raw = `${ticket.v}.${ticket.e}.${ticket.L}.${ticket.r}.${ticket.cfgId}.${ticket.issuedAt}.${ticket.mac}`;
  return base64UrlEncodeNoPad(encoder.encode(raw));
};

const parsePowTicket = (ticketB64) => {
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  const bytes = base64UrlDecodeToBytes(ticketB64);
  if (!bytes) return null;
  const raw = decoder.decode(bytes);
  const parts = raw.split(".");
  if (parts.length !== 7) return null;
  const v = Number.parseInt(parts[0], 10);
  const e = Number.parseInt(parts[1], 10);
  const L = Number.parseInt(parts[2], 10);
  const r = parts[3] || "";
  const cfgId = Number.parseInt(parts[4], 10);
  const issuedAt = Number.parseInt(parts[5], 10);
  const mac = parts[6] || "";
  if (!Number.isFinite(issuedAt) || issuedAt <= 0) return null;
  if (!isBase64Url(r, 1, B64_HASH_MAX_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { v, e, L, r, cfgId, issuedAt, mac };
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
  const needTurn = config.turncheck === true;
  return { needTurn };
};

const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;

const validateTurnToken = (value) => {
  if (!value) return null;
  const token = String(value).trim();
  if (token.length < TURN_TOKEN_MIN_LEN || token.length > TURN_TOKEN_MAX_LEN) return null;
  if (CONTROL_CHAR_RE.test(token)) return null;
  return token;
};

const captchaTagV1 = async (turnToken) => {
  const turn = typeof turnToken === "string" ? turnToken : "";
  const material = `ctag|v1|t=${turn}`;
  return base64UrlEncodeNoPad((await sha256Bytes(material)).slice(0, 12));
};

const parseCanonicalCaptchaTokens = (captchaToken, needTurn) => {
  if (!needTurn) {
    return { ok: true, malformed: false, tokens: { turnstile: "" } };
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
    if (key !== "turnstile") {
      return { ok: false, malformed: true, tokens: null };
    }
    if (typeof envelope[key] !== "string") {
      return { ok: false, malformed: true, tokens: null };
    }
  }

  const turnRaw = typeof envelope.turnstile === "string" ? envelope.turnstile : "";
  const turnstile = needTurn ? validateTurnToken(turnRaw) : "";
  if (needTurn && !turnstile) {
    return { ok: false, malformed: true, tokens: null };
  }
  return { ok: true, malformed: false, tokens: { turnstile } };
};

const deriveLocalCaptchaTag = async (config, captchaToken) => {
  const { needTurn } = resolveCaptchaRequirements(config);
  if (!needTurn) return { ok: true, malformed: false, captchaTag: "any" };
  const parsed = parseCanonicalCaptchaTokens(captchaToken, needTurn);
  if (!parsed.ok) return { ok: false, malformed: parsed.malformed, captchaTag: "" };
  return {
    ok: true,
    malformed: false,
    captchaTag: await captchaTagV1(parsed.tokens.turnstile),
  };
};

const verifyRequiredCaptchaForTicket = async (request, config, ticket, captchaToken) => {
  const { needTurn } = resolveCaptchaRequirements(config);
  const aggregatorPowAtomic = config.AGGREGATOR_POW_ATOMIC_CONSUME === true;
  if (!needTurn && !aggregatorPowAtomic) {
    return { ok: true, malformed: false, captchaTag: "any" };
  }
  const parsed = parseCanonicalCaptchaTokens(captchaToken, needTurn);
  if (!parsed.ok) return { ok: false, malformed: parsed.malformed, captchaTag: "" };
  const turnToken = parsed.tokens.turnstile;
  const payload = {
    ticketMac: ticket.mac,
    remoteip: request.headers.get("CF-Connecting-IP") || request.headers.get("cf-connecting-ip") || "",
    token: {},
    providers: {},
    checks: {},
  };

  if (needTurn) {
    const turnSecret = config.TURNSTILE_SECRET;
    if (!turnSecret) return { ok: false, malformed: false, captchaTag: "" };
    payload.token.turnstile = turnToken;
    payload.providers.turnstile = { secret: turnSecret };
  }

  const verifyResult = await verifyViaSiteverifyAggregator({
    config,
    payload,
    powConsume: {
      cfgId: ticket.cfgId,
      ticketMac: ticket.mac,
      expireAt: ticket.e,
    },
  });
  if (!verifyResult || verifyResult.ok !== true) {
    return { ok: false, malformed: false, captchaTag: "" };
  }

  const captchaTag = needTurn ? await captchaTagV1(turnToken) : "any";
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
  const { needTurn } = resolveCaptchaRequirements(config);
  if (needTurn && !isBase64Url(commit.captchaTag, CAPTCHA_TAG_LEN, CAPTCHA_TAG_LEN)) {
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

const verifyTicketMac = async (ticket, url, bindingValues, config, powSecret) => {
  const difficultyBinding = getPowDifficultyBinding(config);
  const bindingString = makePowBindingString(
    ticket,
    url.hostname,
    bindingValues.pathHash,
    bindingValues.ipScope,
    bindingValues.country,
    bindingValues.asn,
    bindingValues.tlsFingerprint,
    difficultyBinding.pageBytes,
    difficultyBinding.mixRounds,
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
  config,
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
    issuedAt: ticket.issuedAt,
    mac: "",
  };
  const difficultyBinding = getPowDifficultyBinding(config);
  const proofBindingString = makePowBindingString(
    proofTicket,
    url.hostname,
    bindingValues.pathHash,
    bindingValues.ipScope,
    bindingValues.country,
    bindingValues.asn,
    bindingValues.tlsFingerprint,
    difficultyBinding.pageBytes,
    difficultyBinding.mixRounds,
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
  pageBytes,
  mixRounds,
) => {
  const batch = indices.slice(cursor, cursor + batchLen);
  if (!batch.length) return null;
  const segBatch = segLensAll.slice(cursor, cursor + batchLen);
  const token = await makePowStateToken(powSecret, ticket.cfgId, sid, commit.mac, cursor, batchLen);
  return {
    done: false,
    sid,
    cursor,
    indices: batch,
    segs: segBatch,
    pageBytes,
    mixRounds,
    token,
  };
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
  const { needTurn } = resolveCaptchaRequirements(config);
  const powVersion = validateTicket(ticket, config, nowSeconds);
  if (!powVersion) return denyStale();
  const normalizedPathHash = normalizePathHash(pathHash, config);
  if (!normalizedPathHash) return S(400);
  const bindingValues = await getPowBindingValuesWithPathHash(normalizedPathHash, config, derived);
  if (!bindingValues) return denyStale();
  const bindingString = await verifyTicketMac(ticket, url, bindingValues, config, powSecret);
  if (!bindingString) return denyStale();
  const pageAge = nowSeconds - ticket.issuedAt;
  if (!Number.isFinite(pageAge) || pageAge < 0 || pageAge > getPowMaxGenTimeSec(config)) {
    return denyStale();
  }
  const rootBytes = base64UrlDecodeToBytes(rootB64);
  if (!rootBytes || rootBytes.length !== 32) {
    return S(400);
  }
  const ttl = config.POW_COMMIT_TTL_SEC || 0;
  const exp = nowSeconds + Math.max(1, ttl);
  let captchaTag = "any";
  if (needTurn) {
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
  const { needTurn } = resolveCaptchaRequirements(config);
  const requiredMask = (needPow ? 1 : 0) | (needTurn ? 2 : 0);
  if (needPow || !needTurn || config.ATOMIC_CONSUME === true) return S(404);

  const powVersion = validateTicket(ticket, config, nowSeconds);
  if (!powVersion) return deny();

  const normalizedPathHash = normalizePathHash(pathHash, config);
  if (!normalizedPathHash) return S(400);

  const bindingValues = await getPowBindingValuesWithPathHash(normalizedPathHash, config, derived);
  if (!bindingValues) return deny();
  const bindingString = await verifyTicketMac(ticket, url, bindingValues, config, powSecret);
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
    config,
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
  if (isPowAbsoluteLifecycleExpired(ticket, config, nowSeconds)) return denyStale();
  if (!Number.isFinite(ticket.L) || ticket.L <= 0) return deny();
  const bindingValues = await getPowBindingValuesWithPathHash(commit.pathHash, config, derived);
  if (!bindingValues) return deny();
  if (!(await verifyTicketMac(ticket, url, bindingValues, config, powSecret))) return deny();
  const sid = await derivePowSid(powSecret, ticket.cfgId, commit.mac);
  const sample = await buildPowSample(config, powSecret, ticket, commit.mac, sid);
  if (!sample) return deny();
  const { indices, segLensAll } = sample;
  const difficultyBinding = getPowDifficultyBinding(config);
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
    difficultyBinding.pageBytes,
    difficultyBinding.mixRounds,
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
  const { needTurn } = resolveCaptchaRequirements(config);
  const requiredMask = 1 | (needTurn ? 2 : 0);
  if (isExpired(ticket.e, nowSeconds) || isExpired(commit.exp, nowSeconds)) return denyStale();
  const powVersion = await verifyCommit(commit, ticket, config, powSecret, nowSeconds);
  if (!powVersion) return denyCheat();
  if (isPowAbsoluteLifecycleExpired(ticket, config, nowSeconds)) return denyStale();
  const bindingValues = await getPowBindingValuesWithPathHash(commit.pathHash, config, derived);
  if (!bindingValues) return deny();
  if (!(await verifyTicketMac(ticket, url, bindingValues, config, powSecret))) return deny();
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object") {
    return S(400);
  }
  const cursor = Number.parseInt(body.cursor, 10);
  const sid = typeof body.sid === "string" ? body.sid : "";
  const stateToken = typeof body.token === "string" ? body.token : "";
  const captchaToken = body.captchaToken;
  const opens = Array.isArray(body.opens) ? body.opens : null;
  if (!sid || !stateToken || !opens || !Number.isFinite(cursor) || cursor < 0) {
    return S(400);
  }
  if (!isBase64Url(stateToken, TOKEN_MIN_LEN, TOKEN_MAX_LEN)) {
    return S(400);
  }
  const batchMax = getBatchMax(config);
  if (batchMax <= 0) return S(500);
  const sidExpected = await derivePowSid(powSecret, ticket.cfgId, commit.mac);
  if (!timingSafeEqual(sid, sidExpected)) return denyCheat();
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
  const difficultyBinding = getPowDifficultyBinding(config);
  if (hashcashBits > 0 && !indices.includes(ticket.L)) return denyCheat();
  const expectedBatch = indices.slice(cursor, cursor + batchMax);
  if (!expectedBatch.length) return denyCheat();
  const segBatch = segLensAll.slice(cursor, cursor + batchMax);
  const batchSize = opens.length;
  if (batchSize !== expectedBatch.length) {
    return denyCheat();
  }
  for (let i = 0; i < batchSize; i += 1) {
    const open = opens[i];
    if (!open || typeof open !== "object" || Array.isArray(open)) return S(400);
    const idx = Number.parseInt(open.i, 10);
    const seg = Number.parseInt(open.seg, 10);
    if (!Number.isFinite(idx) || idx < 1 || idx > ticket.L) {
      return S(400);
    }
    if (!Number.isFinite(seg)) {
      return S(400);
    }
    const expectedIdx = expectedBatch[i];
    if (idx !== expectedIdx) return denyCheat();
    const segLen = segBatch[i];
    if (!Number.isFinite(segLen) || segLen <= 0) {
      return denyCheat();
    }
    if (seg !== segLen) return denyCheat();
  }

  const rootBytes = base64UrlDecodeToBytes(commit.rootB64);
  if (!rootBytes || rootBytes.length !== 32) return denyCheat();
  const graphSeed = await deriveMhgGraphSeed16(commit.ticketB64, commit.nonce);
  const nonce16 = await deriveMhgNonce16(commit.nonce);
  if (!nonce16) return denyCheat();
  const vectorVerify = await verifyOpenBatchVector({
    root: rootBytes,
    leafCount: ticket.L + 1,
    graphSeed,
    nonce: nonce16,
    pageBytes: difficultyBinding.pageBytes,
    mixRounds: difficultyBinding.mixRounds,
    opens,
  });
  if (!vectorVerify.ok) {
    if (vectorVerify.reason === "bad_vector" || vectorVerify.reason === "bad_open") {
      return S(400);
    }
    return denyCheat();
  }
  if (hashcashBits > 0 && expectedBatch.includes(ticket.L)) {
    const finalOpen = opens.find((entry) => Number.parseInt(entry && entry.i, 10) === ticket.L);
    if (!finalOpen || !finalOpen.nodes || typeof finalOpen.nodes !== "object") return denyCheat();
    const finalNode = finalOpen.nodes[String(ticket.L)] ?? finalOpen.nodes[ticket.L];
    if (!finalNode || typeof finalNode.pageB64 !== "string") return denyCheat();
    const finalPage = base64UrlDecodeToBytes(finalNode.pageB64);
    if (!(finalPage instanceof Uint8Array)) return denyCheat();
    const digest = await hashcashRootLast(rootBytes, finalPage);
    if (leadingZeroBits(digest) < hashcashBits) return denyCheat();
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
      difficultyBinding.pageBytes,
      difficultyBinding.mixRounds,
    );
    if (!nextResp) return denyCheat();
    return J(nextResp);
  }
  const ttl = getProofTtl(ticket, config, nowSeconds);
  if (!ttl) return deny();

  const atomicConsumeEnabled =
    config.ATOMIC_CONSUME === true && (needTurn || config.AGGREGATOR_POW_ATOMIC_CONSUME === true);
  if (atomicConsumeEnabled) {
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

  const aggregatorPowAtomic = config.AGGREGATOR_POW_ATOMIC_CONSUME === true;
  if (needTurn || aggregatorPowAtomic) {
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
    config,
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
