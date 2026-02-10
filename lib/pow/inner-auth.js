const INNER_HEADER = "X-Pow-Inner";
const INNER_MAC_HEADER = "X-Pow-Inner-Mac";
const INNER_EXPIRE_HEADER = "X-Pow-Inner-Expire";
const INNER_COUNT_HEADER = `${INNER_HEADER}-Count`;
const INNER_CHUNK_PREFIX = `${INNER_HEADER}-`;
const INNER_CHUNK_MAX = 64;
const INNER_PAYLOAD_MAX_LEN = 128 * 1024;
const INNER_MAX_SKEW_SEC = 3;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hmacKeyCache = new Map();

const isPlaceholderConfigSecret = (value) =>
  typeof value !== "string" || !value.trim() || value === "replace-me";

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
    for (let i = 0; i < bin.length; i += 1) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
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

const hmacSha256Base64UrlNoPad = async (secret, data) => {
  const key = await getHmacKey(secret);
  const payload = encoder.encode(data);
  const buffer = await crypto.subtle.sign("HMAC", key, payload);
  return base64UrlEncodeNoPad(new Uint8Array(buffer));
};

export const readInnerPayload = async (request, secret) => {
  if (isPlaceholderConfigSecret(secret)) return null;

  let payload = request.headers.get(INNER_HEADER) || "";
  const mac = request.headers.get(INNER_MAC_HEADER) || "";
  const expRaw = request.headers.get(INNER_EXPIRE_HEADER) || "";

  if (!/^\d+$/u.test(expRaw)) return null;
  const exp = Number.parseInt(expRaw, 10);
  if (!Number.isSafeInteger(exp)) return null;

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (exp < nowSeconds || exp > nowSeconds + INNER_MAX_SKEW_SEC) return null;

  if (!payload) {
    const countRaw = request.headers.get(INNER_COUNT_HEADER) || "";
    if (!/^\d+$/u.test(countRaw)) return null;
    const count = Number.parseInt(countRaw, 10);
    if (!Number.isSafeInteger(count) || count <= 0 || count > INNER_CHUNK_MAX) return null;

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
  } else if (payload.length > INNER_PAYLOAD_MAX_LEN) {
    return null;
  }

  if (!payload || !mac) return null;

  const expected = await hmacSha256Base64UrlNoPad(secret, `${payload}.${exp}`);
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
