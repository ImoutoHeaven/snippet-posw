import { stripPowInternalHeaders } from "./internal-headers.js";

const PROOF_COOKIE = "__Host-proof";
const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const RECAPTCHA_SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const B64_HASH_MAX_LEN = 64;
const B64_TICKET_MAX_LEN = 256;
const NONCE_MIN_LEN = 16;
const NONCE_MAX_LEN = 64;
const CAPTCHA_TAG_LEN = 16;
const TURN_TOKEN_MIN_LEN = 20;
const TURN_TOKEN_MAX_LEN = 4096;
const PREFLIGHT_REASON_MAX_LEN = 64;

const encoder = new TextEncoder();
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
        ["sign"],
      ),
    );
  }
  return hmacKeyCache.get(key);
};

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

const isBase64Url = (value, minLen, maxLen) => {
  if (typeof value !== "string") return false;
  const len = value.length;
  if (len < minLen || len > maxLen) return false;
  return BASE64URL_RE.test(value);
};

const isExpired = (expire, nowSeconds) => expire > 0 && expire < nowSeconds;

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

const makeConsumeMac = async (powSecret, ticketB64, exp, captchaTag, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `U|${ticketB64}|${exp}|${captchaTag}|${m}`);

const makeProofMac = async (powSecret, ticketB64, iat, last, n, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `O|${ticketB64}|${iat}|${last}|${n}|${m}`);

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

const encodePowTicket = (ticket) => {
  const raw = `${ticket.v}.${ticket.e}.${ticket.L}.${ticket.r}.${ticket.cfgId}.${ticket.mac}`;
  return base64UrlEncodeNoPad(encoder.encode(raw));
};

const parsePowTicket = (ticketB64) => {
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  const bytes = base64UrlDecodeToBytes(ticketB64);
  if (!bytes) return null;
  const raw = new TextDecoder().decode(bytes);
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

const getPowBindingValues = async (canonicalPath, config, derived) => {
  const bindPath = config.POW_BIND_PATH !== false;
  const pathHash = bindPath ? await computePathHash(canonicalPath) : "any";
  return getPowBindingValuesWithPathHash(pathHash, config, derived);
};

const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;

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

const validateTurnToken = (value) => {
  if (!value) return null;
  const token = value.trim();
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

const verifyRequiredCaptchaForTicket = async (
  request,
  config,
  ticket,
  captchaToken,
  options = {},
) => {
  const opts = options && typeof options === "object" ? options : {};
  const requireTurnPreflight = opts.requireTurnPreflight === true;
  const turnstilePreflight = normalizeTurnstilePreflight(opts.turnstilePreflight);
  const { needTurn, needRecaptcha } = resolveCaptchaRequirements(config);
  if (!needTurn && !needRecaptcha) return { ok: true, malformed: false, captchaTag: "any" };
  const parsed = parseCanonicalCaptchaTokens(captchaToken, needTurn, needRecaptcha);
  if (!parsed.ok) return { ok: false, malformed: parsed.malformed, captchaTag: "" };
  const turnToken = parsed.tokens.turnstile;
  const recaptchaToken = parsed.tokens.recaptcha_v3;

  if (needTurn) {
    if (requireTurnPreflight) {
      if (!turnstilePreflight || !turnstilePreflight.checked || !turnstilePreflight.ok) {
        return { ok: false, malformed: false, captchaTag: "" };
      }
      if (!timingSafeEqual(turnstilePreflight.ticketMac, ticket.mac)) {
        return { ok: false, malformed: false, captchaTag: "" };
      }
      const expectedTokenTag = await captchaTagV1(turnToken, recaptchaToken);
      if (!timingSafeEqual(turnstilePreflight.tokenTag, expectedTokenTag)) {
        return { ok: false, malformed: false, captchaTag: "" };
      }
    } else {
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
    powSecret: baseConfig.POW_TOKEN,
    derived: inner.d,
    cfgId: inner.id,
    strategy,
  };
};

const validateTicket = (ticket, config, nowSeconds) => {
  const powVersion = config.POW_VERSION;
  if (ticket.v !== powVersion) return 0;
  if (isExpired(ticket.e, nowSeconds)) return 0;
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
    parsed.m,
  );
  if (!timingSafeEqual(mac, parsed.mac)) return null;
  return parsed;
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

const loadAtomicTicket = async (
  ticketB64,
  url,
  canonicalPath,
  config,
  powSecret,
  derived,
  cfgId,
  nowSeconds,
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

const verifyProofCookie = async (
  request,
  url,
  canonicalPath,
  nowSeconds,
  config,
  powSecret,
  derived,
  cfgId,
  requiredMask,
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
    proof.m,
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
  response,
) => {
  if (!meta || !meta.proof || !meta.bindingValues || !response) return response;
  if (config.PROOF_RENEW_ENABLE !== true) return response;
  if (!isNavigationRequest(request)) return response;

  const proof = meta.proof;
  const renewMax = Math.max(0, Math.floor(config.PROOF_RENEW_MAX));
  if (!renewMax || proof.n >= renewMax) return response;

  const ttl = Math.max(1, Math.floor(config.PROOF_TTL_SEC));
  const window = Math.max(0, Math.floor(config.PROOF_RENEW_WINDOW_SEC));
  const minSinceLast = Math.max(0, Math.floor(config.PROOF_RENEW_MIN_SEC));
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
    b.tlsFingerprint,
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
  requirements,
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
    tlsFingerprint,
  );
  ticket.mac = await hmacSha256Base64UrlNoPad(powSecret, bindingString);
  const ticketB64 = encodePowTicket(ticket);
  const bindingStringB64 = base64UrlEncodeNoPad(encoder.encode(bindingString));
  const reloadUrlB64 = base64UrlEncodeNoPad(encoder.encode(url.toString()));
  const apiPrefixB64 = base64UrlEncodeNoPad(encoder.encode(config.POW_API_PREFIX));
  const esmUrlB64 = needPow ? base64UrlEncodeNoPad(encoder.encode(config.POW_ESM_URL)) : "";
  const captchaCfg = {};
  if (needTurn) {
    captchaCfg.turnstile = { sitekey: config.TURNSTILE_SITEKEY };
  }
  if (needRecaptcha) {
    const pairs = Array.isArray(config.RECAPTCHA_PAIRS) ? config.RECAPTCHA_PAIRS : [];
    const picked = await pickRecaptchaPair(ticket.mac, pairs);
    if (!picked || !picked.pair || !picked.pair.sitekey) return S(500);
    captchaCfg.recaptcha_v3 = {
      sitekey: picked.pair.sitekey,
      action: resolveRecaptchaAction(config),
    };
  }
  const captchaCfgB64 = base64UrlEncodeNoPad(encoder.encode(JSON.stringify(captchaCfg)));
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
    Math.min(steps, Math.floor(segSpec.mode === "fixed" ? segSpec.fixed : segSpec.min)),
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

export const handleBusinessGate = async ({ request, url, nowSeconds, inner, forward }) => {
  if (typeof forward !== "function") return S(500);

  const innerCtx = loadConfigFromInner(inner);
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId, strategy } = innerCtx;

  const needPow = config.powcheck === true;
  const { needTurn, needRecaptcha } = resolveCaptchaRequirements(config);
  if (!needPow && !needTurn && !needRecaptcha) {
    return forward(stripPowInternalHeaders(request));
  }
  if (strategy.bypass.bypass) {
    return forward(stripPowInternalHeaders(request));
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
        requiredMask,
      )
    : null;

  if (proofMeta) {
    let response = await forward(stripPowInternalHeaders(request));
    response = await maybeRenewProof(
      request,
      url,
      nowSeconds,
      config,
      powSecret,
      cfgId,
      proofMeta,
      response,
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
          { needPow, needTurn, needRecaptcha },
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
        const preflightReason =
          atomic.turnstilePreflight && typeof atomic.turnstilePreflight.reason === "string"
            ? atomic.turnstilePreflight.reason
            : "";
        return fail(preflightReason === "consume_stale" ? denyStale() : deny());
      }
      const parsedAtomicCaptcha = parseCanonicalCaptchaTokens(
        atomic.captchaToken,
        needTurn,
        needRecaptcha,
      );
      if (!parsedAtomicCaptcha.ok) {
        return fail(parsedAtomicCaptcha.malformed ? S(400) : deny(), false);
      }
      if (needPow) {
        const consume = await verifyConsumeToken(
          atomic.consumeToken,
          powSecret,
          nowSeconds,
          requiredMask,
        );
        if (!consume) return fail(deny());
        const ticket = await loadAtomicTicket(
          consume.ticketB64,
          baseUrl,
          bindRes.canonicalPath,
          config,
          powSecret,
          derived,
          cfgId,
          nowSeconds,
        );
        if (!ticket) return fail(deny());
        const bindingValues = await getPowBindingValues(bindRes.canonicalPath, config, derived);
        if (!bindingValues) return fail(deny());
        const atomicBinding = await verifyTicketMac(ticket, baseUrl, bindingValues, powSecret);
        if (!atomicBinding) return fail(deny());
        const verifiedCaptcha = await verifyRequiredCaptchaForTicket(
          baseRequest,
          config,
          ticket,
          atomic.captchaToken,
          {
            requireTurnPreflight,
            turnstilePreflight: atomic.turnstilePreflight,
          },
        );
        if (!verifiedCaptcha.ok || verifiedCaptcha.captchaTag !== consume.captchaTag) {
          if (!verifiedCaptcha.ok && verifiedCaptcha.malformed) {
            return fail(S(400), false);
          }
          return fail(deny());
        }
        const response = await forward(stripPowInternalHeaders(baseRequest));
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
        nowSeconds,
      );
      if (!ticket) return fail(deny());
      const bindingValues = await getPowBindingValues(bindRes.canonicalPath, config, derived);
      if (!bindingValues) return fail(deny());
      const atomicBinding = await verifyTicketMac(ticket, baseUrl, bindingValues, powSecret);
      if (!atomicBinding) return fail(deny());
      const verifiedCaptcha = await verifyRequiredCaptchaForTicket(
        baseRequest,
        config,
        ticket,
        atomic.captchaToken,
        {
          requireTurnPreflight,
          turnstilePreflight: atomic.turnstilePreflight,
        },
      );
      if (!verifiedCaptcha.ok) {
        if (verifiedCaptcha.malformed) return fail(S(400), false);
        return fail(deny());
      }
      const response = await forward(stripPowInternalHeaders(baseRequest));
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
    { needPow, needTurn, needRecaptcha },
  );
};
