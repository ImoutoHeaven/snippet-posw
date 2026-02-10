const TRANSIT_HEADER = "X-Pow-Transit";
const TRANSIT_MAC_HEADER = "X-Pow-Transit-Mac";
const TRANSIT_EXPIRE_HEADER = "X-Pow-Transit-Expire";
const TRANSIT_API_PREFIX_HEADER = "X-Pow-Transit-Api-Prefix";
const TRANSIT_HEADER_PREFIX = "x-pow-transit";
const TRANSIT_TTL_SEC = 3;

const encoder = new TextEncoder();
const hmacKeyCache = new Map();

const TRANSIT_KINDS = new Set(["api", "biz"]);

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

const normalizeMethod = (value) => {
  const method = typeof value === "string" && value ? value : "GET";
  return method.toUpperCase();
};

const normalizePathname = (value) => {
  if (typeof value !== "string") return "/";
  if (!value) return "/";
  return value.startsWith("/") ? value : `/${value}`;
};

const normalizeApiPrefix = (value) => {
  if (typeof value !== "string") return "/__pow";
  const trimmed = value.trim();
  if (!trimmed) return "/__pow";
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  const normalized = withSlash.replace(/\/+$/u, "");
  return normalized || "/__pow";
};

const transitMacInput = ({ exp, kind, method, pathname, apiPrefix }) =>
  `v1|${exp}|${kind}|${normalizeMethod(method)}|${normalizePathname(pathname)}|${normalizeApiPrefix(apiPrefix)}`;

export const makeTransitMac = async (secret, data) => hmacSha256Base64UrlNoPad(secret, data);

export const issueTransit = async ({
  secret,
  method,
  pathname,
  kind,
  apiPrefix,
  ttlSec = TRANSIT_TTL_SEC,
  nowSeconds = Math.floor(Date.now() / 1000),
}) => {
  if (isPlaceholderConfigSecret(secret)) return null;
  if (!TRANSIT_KINDS.has(kind)) return null;
  const ttl = Math.max(1, Math.floor(Number(ttlSec) || TRANSIT_TTL_SEC));
  const exp = nowSeconds + ttl;
  const normalizedApiPrefix = normalizeApiPrefix(apiPrefix);
  const macData = transitMacInput({ exp, kind, method, pathname, apiPrefix: normalizedApiPrefix });
  const mac = await makeTransitMac(secret, macData);
  return {
    kind,
    exp,
    apiPrefix: normalizedApiPrefix,
    mac,
    headers: {
      [TRANSIT_HEADER]: kind,
      [TRANSIT_MAC_HEADER]: mac,
      [TRANSIT_EXPIRE_HEADER]: String(exp),
      [TRANSIT_API_PREFIX_HEADER]: normalizedApiPrefix,
    },
  };
};

export const stripTransitHeaders = (request) => {
  const headers = new Headers(request.headers);
  const keys = Array.from(headers.keys());
  for (const key of keys) {
    if (key.toLowerCase().startsWith(TRANSIT_HEADER_PREFIX)) {
      headers.delete(key);
    }
  }
  return new Request(request, { headers });
};

export const verifyTransit = async ({
  request,
  secret,
  method,
  pathname,
  allowedKind,
  maxSkewSec = TRANSIT_TTL_SEC,
  nowSeconds = Math.floor(Date.now() / 1000),
}) => {
  if (isPlaceholderConfigSecret(secret)) return null;
  const kind = request.headers.get(TRANSIT_HEADER) || "";
  const mac = request.headers.get(TRANSIT_MAC_HEADER) || "";
  const expRaw = request.headers.get(TRANSIT_EXPIRE_HEADER) || "";
  const apiPrefix = normalizeApiPrefix(request.headers.get(TRANSIT_API_PREFIX_HEADER));

  if (!kind || !mac || !expRaw) return null;
  if (!TRANSIT_KINDS.has(kind)) return null;
  if (allowedKind && kind !== allowedKind) return null;
  if (!/^\d+$/u.test(expRaw)) return null;

  const exp = Number.parseInt(expRaw, 10);
  if (!Number.isSafeInteger(exp)) return null;
  if (exp <= nowSeconds) return null;
  if (exp > nowSeconds + Math.max(1, Math.floor(Number(maxSkewSec) || TRANSIT_TTL_SEC))) {
    return null;
  }

  const macData = transitMacInput({ exp, kind, method, pathname, apiPrefix });
  const expectedMac = await makeTransitMac(secret, macData);
  if (!timingSafeEqual(expectedMac, mac)) return null;

  return { kind, exp, apiPrefix };
};

export {
  TRANSIT_HEADER,
  TRANSIT_MAC_HEADER,
  TRANSIT_EXPIRE_HEADER,
  TRANSIT_API_PREFIX_HEADER,
};
