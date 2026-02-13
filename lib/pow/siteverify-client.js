const encoder = new TextEncoder();

const INVALID_AGGREGATOR_RESPONSE = {
  ok: false,
  reason: "invalid_aggregator_response",
};

const toHex = (bytes) =>
  Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");

const isPlainObject = (value) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const sha256Hex = async (value) => {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return toHex(new Uint8Array(digest));
};

const hmacSha256Hex = async (secret, value) => {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return toHex(new Uint8Array(signature));
};

const randomNonce = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
};

const normalizePowConsume = (powConsume) => {
  if (!isPlainObject(powConsume)) return null;
  const cfgId = Number.parseInt(powConsume.cfgId, 10);
  const ticketMac = typeof powConsume.ticketMac === "string" ? powConsume.ticketMac : "";
  const expireAt = Number.parseInt(powConsume.expireAt, 10);
  if (!Number.isFinite(cfgId) || cfgId < 0) return null;
  if (!ticketMac) return null;
  if (!Number.isFinite(expireAt) || expireAt <= 0) return null;
  return { cfgId, ticketMac, expireAt };
};

const buildPayloadWithPowConsume = async ({ config, payload, powConsume }) => {
  const outbound = isPlainObject(payload) ? { ...payload } : {};
  if (config.AGGREGATOR_POW_ATOMIC_CONSUME !== true) return outbound;
  const consumeInput = normalizePowConsume(powConsume);
  if (!consumeInput) return outbound;
  outbound.powConsume = {
    consumeKey: await sha256Hex(`${consumeInput.cfgId}|${consumeInput.ticketMac}`),
    expireAt: consumeInput.expireAt,
  };
  return outbound;
};

const parseAggregatorResponse = (value) => {
  if (!isPlainObject(value)) return null;

  if (
    typeof value.ok !== "boolean" ||
    typeof value.reason !== "string" ||
    !Object.prototype.hasOwnProperty.call(value, "checks") ||
    !Object.prototype.hasOwnProperty.call(value, "providers") ||
    !isPlainObject(value.checks) ||
    !isPlainObject(value.providers)
  ) {
    return null;
  }

  return {
    ok: value.ok,
    reason: value.reason,
    checks: value.checks,
    providers: value.providers,
  };
};

const collectSiteverifyUrls = (config) => {
  if (!isPlainObject(config)) return [];

  const deduped = [];
  const seen = new Set();
  const pushUrl = (value) => {
    if (typeof value !== "string") return;
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) return;
    seen.add(trimmed);
    deduped.push(trimmed);
  };

  if (Array.isArray(config.SITEVERIFY_URLS)) {
    for (const value of config.SITEVERIFY_URLS) {
      pushUrl(value);
    }
  }

  return deduped;
};

const pickDeterministicSiteverifyUrl = async ({ urls, payload, powConsume }) => {
  if (!Array.isArray(urls) || urls.length === 0) return "";
  if (urls.length === 1) return urls[0];

  const payloadTicketMac = isPlainObject(payload) && typeof payload.ticketMac === "string" ? payload.ticketMac : "";
  const consumeTicketMac =
    isPlainObject(powConsume) && typeof powConsume.ticketMac === "string" ? powConsume.ticketMac : "";
  const ticketMac = payloadTicketMac || consumeTicketMac;
  if (!ticketMac) return urls[0];

  const digest = await sha256Hex(`siteverify|${ticketMac}`);
  const bucket = Number.parseInt(digest.slice(0, 8), 16);
  if (!Number.isFinite(bucket)) return urls[0];
  return urls[bucket % urls.length];
};

export const verifyViaSiteverifyAggregator = async ({ config, payload, powConsume }) => {
  const siteverifyUrls = collectSiteverifyUrls(config);
  const siteverifyUrl = await pickDeterministicSiteverifyUrl({
    urls: siteverifyUrls,
    payload,
    powConsume,
  });
  const authKid =
    config && typeof config.SITEVERIFY_AUTH_KID === "string"
      ? config.SITEVERIFY_AUTH_KID.trim()
      : "";
  const authSecret =
    config && typeof config.SITEVERIFY_AUTH_SECRET === "string" ? config.SITEVERIFY_AUTH_SECRET : "";

  if (!siteverifyUrl || !authKid || !authSecret) {
    return INVALID_AGGREGATOR_RESPONSE;
  }

  let targetUrl;
  try {
    targetUrl = new URL(siteverifyUrl);
  } catch {
    return INVALID_AGGREGATOR_RESPONSE;
  }

  const requestPayload = await buildPayloadWithPowConsume({ config, payload, powConsume });
  const requestBody = JSON.stringify(requestPayload);
  const bodySha256 = await sha256Hex(requestBody);
  const exp = Math.floor(Date.now() / 1000) + 5;
  const nonce = randomNonce();
  const canonical = ["SV1", "POST", targetUrl.pathname, authKid, String(exp), nonce, bodySha256].join(
    "\n",
  );
  const signature = await hmacSha256Hex(authSecret, canonical);

  let response;
  try {
    response = await fetch(targetUrl.toString(), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `SV1 kid=${authKid},exp=${exp},nonce=${nonce},sig=${signature}`,
        "x-sv-body-sha256": bodySha256,
      },
      body: requestBody,
    });
  } catch {
    return INVALID_AGGREGATOR_RESPONSE;
  }

  if (!response || response.status !== 200 || !response.ok) {
    return INVALID_AGGREGATOR_RESPONSE;
  }

  let parsed;
  try {
    parsed = await response.json();
  } catch {
    return INVALID_AGGREGATOR_RESPONSE;
  }

  return parseAggregatorResponse(parsed) ?? INVALID_AGGREGATOR_RESPONSE;
};
