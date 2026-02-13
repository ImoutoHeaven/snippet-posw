const AUTH_WINDOW_SEC = 10;
const MAX_BODY_BYTES = 256 * 1024;
const D1_BINDING = "POW_NONCE_DB";
const LEDGER_CLEANUP_SAMPLE_RATE = 0.01;
const INIT_TABLES = false;
const SHARED_SECRETS = Object.freeze({
  v1: "replace-me",
});
const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const INIT_SQL = `
CREATE TABLE IF NOT EXISTS pow_nonce_ledger (
  consume_key TEXT PRIMARY KEY,
  expire_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
`;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const hexFromBytes = (bytes) =>
  Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");

const jsonResponse = (payload) =>
  new Response(JSON.stringify(payload), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
    },
  });

const baseContract = (overrides = {}) => ({
  ok: false,
  reason: "provider_failed",
  checks: {},
  providers: {},
  ...overrides,
});

const canonical = ({ method, path, kid, exp, nonce, bodySha256 }) =>
  ["SV1", method, path, kid, String(exp), nonce, bodySha256].join("\n");

const parseAuthorization = (headerValue) => {
  if (typeof headerValue !== "string") {
    return null;
  }

  const trimmed = headerValue.trim();
  if (!trimmed.startsWith("SV1 ")) {
    return null;
  }

  const rawPairs = trimmed.slice(4).split(",");
  const pairs = {};

  for (const rawPair of rawPairs) {
    const segment = rawPair.trim();
    if (!segment) {
      return null;
    }

    const separatorIdx = segment.indexOf("=");
    if (separatorIdx <= 0) {
      return null;
    }

    const key = segment.slice(0, separatorIdx).trim();
    const value = segment.slice(separatorIdx + 1).trim();

    if (!key || !value || key in pairs) {
      return null;
    }

    pairs[key] = value;
  }

  const requiredKeys = ["kid", "exp", "nonce", "sig"];
  if (Object.keys(pairs).length !== requiredKeys.length) {
    return null;
  }

  for (const key of requiredKeys) {
    if (!(key in pairs)) {
      return null;
    }
  }

  return pairs;
};

const isHexDigest = (value) => /^[a-f0-9]{64}$/u.test(value);

const secureEqual = (left, right) => {
  if (left.length !== right.length) {
    return false;
  }

  let mismatch = 0;
  for (let idx = 0; idx < left.length; idx += 1) {
    mismatch |= left.charCodeAt(idx) ^ right.charCodeAt(idx);
  }

  return mismatch === 0;
};

const sha256Hex = async (bytes) => {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return hexFromBytes(new Uint8Array(digest));
};

const hmacSha256Hex = async (secret, message) => {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return hexFromBytes(new Uint8Array(signature));
};

const isWithinExpWindow = (exp) => {
  const nowSec = Math.floor(Date.now() / 1000);
  return Math.abs(exp - nowSec) <= AUTH_WINDOW_SEC;
};

const isValidNonce = (nonce) => /^[A-Za-z0-9._~-]{1,128}$/u.test(nonce);

const parseAuthContext = (request) => {
  const parsedAuth = parseAuthorization(request.headers.get("authorization"));
  if (!parsedAuth) {
    return null;
  }

  const { kid, exp: expText, nonce, sig } = parsedAuth;
  if (!isValidNonce(nonce)) {
    return null;
  }

  const exp = Number.parseInt(expText, 10);
  if (!Number.isSafeInteger(exp) || String(exp) !== expText || !isWithinExpWindow(exp)) {
    return null;
  }

  const secret = SHARED_SECRETS[kid];
  if (typeof secret !== "string" || secret.length === 0) {
    return null;
  }

  const bodyHashHeader = request.headers.get("x-sv-body-sha256");
  if (!bodyHashHeader || !isHexDigest(bodyHashHeader)) {
    return null;
  }

  if (!isHexDigest(sig)) {
    return null;
  }

  const url = new URL(request.url);
  return {
    method: request.method.toUpperCase(),
    path: url.pathname,
    kid,
    exp,
    nonce,
    sig,
    secret,
    bodyHashHeader,
  };
};

const concatChunks = (chunks, totalBytes) => {
  const out = new Uint8Array(totalBytes);
  let offset = 0;

  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return out;
};

const readBodyWithLimit = async (request) => {
  if (!request.body) {
    return { tooLarge: false, bodyBytes: new Uint8Array(0) };
  }

  const reader = request.body.getReader();
  const chunks = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }

      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      totalBytes += chunk.byteLength;
      if (totalBytes > MAX_BODY_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // no-op
        }
        return { tooLarge: true, bodyBytes: null };
      }

      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }

  return { tooLarge: false, bodyBytes: concatChunks(chunks, totalBytes) };
};

const isHeaderSignatureValid = async (authContext) => {
  const canonicalInput = canonical({
    method: authContext.method,
    path: authContext.path,
    kid: authContext.kid,
    exp: authContext.exp,
    nonce: authContext.nonce,
    bodySha256: authContext.bodyHashHeader,
  });

  const expectedSig = await hmacSha256Hex(authContext.secret, canonicalInput);
  return secureEqual(authContext.sig, expectedSig);
};

const isBodyHashValid = async (authContext, bodyBytes) => {
  const computedBodyHash = await sha256Hex(bodyBytes);
  return secureEqual(authContext.bodyHashHeader, computedBodyHash);
};

const getClientIP = (request, fallback = "") => {
  const directHeaders = ["cf-connecting-ip", "x-real-ip", "x-client-ip"];
  for (const header of directHeaders) {
    const raw = request.headers.get(header);
    if (typeof raw === "string") {
      const trimmed = raw.trim();
      if (trimmed) return trimmed;
    }
  }

  const forwarded = request.headers.get("x-forwarded-for");
  if (typeof forwarded === "string") {
    const first = forwarded
      .split(",")
      .map((part) => part.trim())
      .find(Boolean);
    if (first) return first;
  }

  return typeof fallback === "string" ? fallback : "";
};

const parseJsonObject = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value;
};

const parseStrictPositiveInteger = (value) => {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value > 0 ? value : null;
  }
  if (typeof value !== "string" || !/^\d+$/u.test(value)) {
    return null;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
};

const shouldInitTables = (env) => INIT_TABLES === true || env?.INIT_TABLES === true;

const parseProviderRequest = (body) => {
  const root = parseJsonObject(body);
  if (!root) return null;

  const providers = parseJsonObject(root.providers) ?? {};
  const tokens = parseJsonObject(root.token) ?? {};
  const powConsume = parseJsonObject(root.powConsume);

  const parsed = {
    ticketMac: typeof root.ticketMac === "string" ? root.ticketMac : "",
    remoteip: typeof root.remoteip === "string" ? root.remoteip : "",
    turnstile: null,
    powConsume: null,
  };

  const turnstileProvider = parseJsonObject(providers.turnstile);
  if (turnstileProvider) {
    parsed.turnstile = {
      secret: typeof turnstileProvider.secret === "string" ? turnstileProvider.secret : "",
      token: typeof tokens.turnstile === "string" ? tokens.turnstile : "",
    };
  }

  if (powConsume) {
    const consumeKey = typeof powConsume.consumeKey === "string" ? powConsume.consumeKey.trim() : "";
    const expireAt = parseStrictPositiveInteger(powConsume.expireAt);
    if (!consumeKey || expireAt === null) {
      return null;
    }
    parsed.powConsume = {
      consumeKey,
      expireAt,
    };
  }

  return parsed;
};

const verifyTurnstile = async ({ provider, remoteip, ticketMac }) => {
  if (!provider || !provider.secret || !provider.token) {
    return {
      provider: "turnstile",
      ok: false,
      httpStatus: 400,
      normalized: null,
      rawResponse: "missing turnstile provider input",
    };
  }

  const form = new URLSearchParams();
  form.set("secret", provider.secret);
  form.set("response", provider.token);
  if (remoteip) form.set("remoteip", remoteip);

  try {
    const verifyRes = await fetch(TURNSTILE_SITEVERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    });

    let rawResponse;
    try {
      rawResponse = await verifyRes.json();
    } catch {
      rawResponse = "invalid_json_response";
    }

    const success = rawResponse && typeof rawResponse === "object" && rawResponse.success === true;
    const cdata =
      rawResponse && typeof rawResponse === "object" && typeof rawResponse.cdata === "string"
        ? rawResponse.cdata
        : "";

    return {
      provider: "turnstile",
      ok: success && cdata === ticketMac,
      httpStatus: verifyRes.status,
      normalized: {
        success,
        cdata,
      },
      rawResponse,
    };
  } catch (error) {
    return {
      provider: "turnstile",
      ok: false,
      httpStatus: 502,
      normalized: null,
      rawResponse: error instanceof Error ? error.message : String(error),
    };
  }
};

const maybeInitConsumeLedger = async (env, db) => {
  // Schema init is explicitly opt-in; only literal true enables it.
  if (!db || !shouldInitTables(env)) {
    return;
  }
  await db.prepare(INIT_SQL).run();
};

const consumePowKey = async (db, consumeKey, expireAt, nowSec) => {
  if (expireAt <= nowSec) {
    return { ok: false, reason: "stale", attemptedInsert: false };
  }

  const result = await db
    .prepare(
      "INSERT INTO pow_nonce_ledger (consume_key, expire_at, created_at) VALUES (?1, ?2, ?3) ON CONFLICT(consume_key) DO UPDATE SET expire_at = excluded.expire_at, created_at = excluded.created_at WHERE pow_nonce_ledger.expire_at <= ?4",
    )
    .bind(consumeKey, expireAt, nowSec, nowSec)
    .run();
  const changes = Number(result?.meta?.changes ?? result?.changes ?? 0);
  if (changes === 1) {
    return { ok: true, reason: "ok", attemptedInsert: true };
  }
  return { ok: false, reason: "duplicate", attemptedInsert: true };
};

const cleanupExpiredConsumeRows = async (db, nowSec) => {
  await db.prepare("DELETE FROM pow_nonce_ledger WHERE expire_at < ?1").bind(nowSec).run();
};

const maybeScheduleLedgerCleanup = (ctx, db, nowSec) => {
  if (!ctx || typeof ctx.waitUntil !== "function") return;
  if (Math.random() >= LEDGER_CLEANUP_SAMPLE_RATE) return;
  ctx.waitUntil(
    cleanupExpiredConsumeRows(db, nowSec).catch(() => {
      // Best-effort background cleanup; never fail the request path.
    }),
  );
};

const runProviders = async (request, parsed) => {
  const remoteip = getClientIP(request, parsed.remoteip);
  const jobs = [];

  if (parsed.turnstile) {
    jobs.push(
      verifyTurnstile({
        provider: parsed.turnstile,
        remoteip,
        ticketMac: parsed.ticketMac,
      }),
    );
  }

  const providerResults = await Promise.all(jobs);
  const providers = {};
  const hasConsumeOnlySuccess = parsed.powConsume !== null && providerResults.length === 0;
  let allOk = providerResults.length > 0 || hasConsumeOnlySuccess;

  for (const result of providerResults) {
    const entry = {
      ok: result.ok,
      httpStatus: result.httpStatus,
      normalized: result.normalized,
      rawResponse: result.rawResponse,
    };

    providers[result.provider] = entry;
    if (!result.ok) allOk = false;
  }

  return {
    ok: allOk,
    reason: allOk ? "ok" : "provider_failed",
    checks: {},
    providers,
  };
};

export default {
  async fetch(request, env = {}, ctx = {}) {
    const authContext = parseAuthContext(request);
    if (!authContext) {
      return new Response(null, { status: 404 });
    }

    const headerSignatureValid = await isHeaderSignatureValid(authContext);
    if (!headerSignatureValid) {
      return new Response(null, { status: 404 });
    }

    const { tooLarge, bodyBytes } = await readBodyWithLimit(request);
    if (tooLarge) {
      return jsonResponse(baseContract({ reason: "bad_request" }));
    }

    const bodyHashValid = await isBodyHashValid(authContext, bodyBytes);
    if (!bodyHashValid) {
      return new Response(null, { status: 404 });
    }

    let parsedBody;
    try {
      parsedBody = JSON.parse(decoder.decode(bodyBytes));
    } catch {
      return jsonResponse(baseContract({ reason: "bad_request" }));
    }

    const providerRequest = parseProviderRequest(parsedBody);
    if (!providerRequest) {
      return jsonResponse(baseContract({ reason: "bad_request" }));
    }

    if (providerRequest.powConsume) {
      const db = env?.[D1_BINDING];
      if (!db) {
        return jsonResponse(baseContract({ reason: "pow_nonce_db_missing" }));
      }
      try {
        await maybeInitConsumeLedger(env, db);
        const nowSec = Math.floor(Date.now() / 1000);
        const consumeResult = await consumePowKey(
          db,
          providerRequest.powConsume.consumeKey,
          providerRequest.powConsume.expireAt,
          nowSec,
        );
        if (consumeResult.attemptedInsert) {
          maybeScheduleLedgerCleanup(ctx, db, nowSec);
        }
        if (!consumeResult.ok) {
          return jsonResponse(baseContract({ reason: consumeResult.reason }));
        }
      } catch {
        return jsonResponse(baseContract({ reason: "provider_failed" }));
      }
    }

    const result = await runProviders(request, providerRequest);
    return jsonResponse(baseContract(result));
  },
};
