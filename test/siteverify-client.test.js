import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { verifyViaSiteverifyAggregator } from "../lib/pow/siteverify-client.js";

const ensureGlobals = () => {
  const priorCrypto = globalThis.crypto;
  const priorBtoa = globalThis.btoa;
  const priorAtob = globalThis.atob;
  const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  const canAssignCrypto =
    !cryptoDescriptor || cryptoDescriptor.writable || typeof cryptoDescriptor.set === "function";
  const didSetCrypto = !globalThis.crypto && canAssignCrypto;
  const didSetBtoa = !globalThis.btoa;
  const didSetAtob = !globalThis.atob;

  if (didSetCrypto) {
    globalThis.crypto = crypto.webcrypto;
  }
  if (didSetBtoa) {
    globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
  }
  if (didSetAtob) {
    globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
  }

  return () => {
    if (didSetCrypto) {
      if (typeof priorCrypto === "undefined") {
        delete globalThis.crypto;
      } else {
        globalThis.crypto = priorCrypto;
      }
    }

    if (didSetBtoa) {
      if (typeof priorBtoa === "undefined") {
        delete globalThis.btoa;
      } else {
        globalThis.btoa = priorBtoa;
      }
    }

    if (didSetAtob) {
      if (typeof priorAtob === "undefined") {
        delete globalThis.atob;
      } else {
        globalThis.atob = priorAtob;
      }
    }
  };
};

const sha256Hex = (value) => crypto.createHash("sha256").update(value).digest("hex");
const hmacSha256Hex = (secret, value) =>
  crypto.createHmac("sha256", secret).update(value).digest("hex");
const pickShardUrl = (urls, ticketMac) => {
  const digest = sha256Hex(`siteverify|${ticketMac}`);
  const bucket = Number.parseInt(digest.slice(0, 8), 16);
  return urls[bucket % urls.length];
};

const baseConfig = {
  SITEVERIFY_URLS: ["https://sv.example/siteverify"],
  SITEVERIFY_AUTH_KID: "v1",
  SITEVERIFY_AUTH_SECRET: "siteverify-secret",
};

const basePayload = {
  ticketMac: "ticket-mac",
  token: {
    turnstile: "turnstile-token",
  },
  providers: {
    turnstile: {
      secret: "turnstile-secret",
    },
  },
  checks: {},
};

test("client sends SV1 authorization and body hash headers", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;

  let capturedRequest = null;
  let capturedBody = "";

  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    capturedRequest = request;
    capturedBody = await request.text();
    return new Response(
      JSON.stringify({
        ok: true,
        reason: "ok",
        checks: {},
        providers: {},
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    );
  };

  try {
    const result = await verifyViaSiteverifyAggregator({
      config: baseConfig,
      payload: basePayload,
    });

    assert.equal(result.ok, true);
    assert.ok(capturedRequest, "captures outbound request");
    assert.equal(capturedRequest.method, "POST");
    assert.equal(capturedRequest.url, baseConfig.SITEVERIFY_URLS[0]);

    const authHeader = capturedRequest.headers.get("authorization") || "";
    const bodyHashHeader = capturedRequest.headers.get("x-sv-body-sha256") || "";

    assert.match(authHeader, /^SV1 /u);
    assert.equal(bodyHashHeader, sha256Hex(capturedBody));

    const authKv = Object.fromEntries(
      authHeader
        .slice(4)
        .split(",")
        .map((entry) => {
          const separator = entry.indexOf("=");
          return [entry.slice(0, separator).trim(), entry.slice(separator + 1).trim()];
        }),
    );

    assert.equal(authKv.kid, baseConfig.SITEVERIFY_AUTH_KID);
    assert.ok(/^\d+$/u.test(authKv.exp));
    assert.ok(typeof authKv.nonce === "string" && authKv.nonce.length > 0);
    assert.ok(/^[a-f0-9]{64}$/u.test(authKv.sig));

    const canonical = [
      "SV1",
      "POST",
      new URL(baseConfig.SITEVERIFY_URLS[0]).pathname,
      authKv.kid,
      authKv.exp,
      authKv.nonce,
      bodyHashHeader,
    ].join("\n");

    assert.equal(authKv.sig, hmacSha256Hex(baseConfig.SITEVERIFY_AUTH_SECRET, canonical));
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("client rejects legacy SITEVERIFY_URL-only config", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;

  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    return new Response(
      JSON.stringify({
        ok: true,
        reason: "ok",
        checks: {},
        providers: {},
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    );
  };

  try {
    const result = await verifyViaSiteverifyAggregator({
      config: {
        SITEVERIFY_URL: "https://legacy.example/siteverify",
        SITEVERIFY_AUTH_KID: "v1",
        SITEVERIFY_AUTH_SECRET: "siteverify-secret",
      },
      payload: basePayload,
    });

    assert.deepEqual(result, {
      ok: false,
      reason: "invalid_aggregator_response",
    });
    assert.equal(fetchCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("client deterministically shards requests across siteverify aggregators", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  const shardUrls = [
    "https://sv-1.example/siteverify",
    "https://sv-2.example/siteverify",
    "https://sv-3.example/siteverify",
  ];
  const observedUrls = [];

  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    observedUrls.push(request.url);
    return new Response(
      JSON.stringify({
        ok: true,
        reason: "ok",
        checks: {},
        providers: {},
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    );
  };

  try {
    const config = {
      SITEVERIFY_URLS: shardUrls,
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "siteverify-secret",
    };

    const ticketMacA = "ticket-mac-alpha";
    const ticketMacB = "ticket-mac-beta";

    const resultA1 = await verifyViaSiteverifyAggregator({
      config,
      payload: { ...basePayload, ticketMac: ticketMacA },
    });
    const resultA2 = await verifyViaSiteverifyAggregator({
      config,
      payload: { ...basePayload, ticketMac: ticketMacA },
    });
    const resultB = await verifyViaSiteverifyAggregator({
      config,
      payload: { ...basePayload, ticketMac: ticketMacB },
    });

    assert.equal(resultA1.ok, true);
    assert.equal(resultA2.ok, true);
    assert.equal(resultB.ok, true);
    assert.deepEqual(observedUrls, [
      pickShardUrl(shardUrls, ticketMacA),
      pickShardUrl(shardUrls, ticketMacA),
      pickShardUrl(shardUrls, ticketMacB),
    ]);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("client rejects non-json or malformed response", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;

  const responses = [
    new Response("not json", {
      status: 200,
      headers: { "content-type": "text/plain" },
    }),
    new Response(
      JSON.stringify({
        ok: true,
        reason: "ok",
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    ),
  ];

  globalThis.fetch = async () => responses.shift();

  try {
    const nonJson = await verifyViaSiteverifyAggregator({
      config: baseConfig,
      payload: basePayload,
    });
    assert.deepEqual(nonJson, {
      ok: false,
      reason: "invalid_aggregator_response",
    });

    const malformed = await verifyViaSiteverifyAggregator({
      config: baseConfig,
      payload: basePayload,
    });
    assert.deepEqual(malformed, {
      ok: false,
      reason: "invalid_aggregator_response",
    });
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("client rejects non-200 response", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        ok: true,
        reason: "ok",
        checks: {},
        providers: {},
      }),
      {
        status: 502,
        headers: { "content-type": "application/json" },
      },
    );

  try {
    const result = await verifyViaSiteverifyAggregator({
      config: baseConfig,
      payload: basePayload,
    });
    assert.deepEqual(result, {
      ok: false,
      reason: "invalid_aggregator_response",
    });
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("client accepts provider_failed contract with checks and providers", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        ok: false,
        reason: "provider_failed",
        checks: {},
        providers: {
          turnstile: {
            ok: false,
            httpStatus: 200,
            normalized: { success: false, cdata: "" },
            rawResponse: { success: false },
          },
        },
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    );

  try {
    const result = await verifyViaSiteverifyAggregator({
      config: baseConfig,
      payload: basePayload,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "provider_failed");
    assert.deepEqual(result.checks, {});
    assert.ok(result.providers && typeof result.providers === "object");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("client emits powConsume contract when aggregator consume is enabled", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;

  let capturedBody = "";
  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    capturedBody = await request.text();
    return new Response(
      JSON.stringify({
        ok: true,
        reason: "ok",
        checks: {},
        providers: {},
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    );
  };

  try {
    const cfgId = 42;
    const ticketMac = "ticket-mac-for-consume";
    const expireAt = 1900000000;
    const result = await verifyViaSiteverifyAggregator({
      config: {
        ...baseConfig,
        AGGREGATOR_POW_ATOMIC_CONSUME: true,
      },
      payload: basePayload,
      powConsume: {
        cfgId,
        ticketMac,
        expireAt,
      },
    });

    assert.equal(result.ok, true);
    const outbound = JSON.parse(capturedBody);
    assert.equal(typeof outbound.powConsume.consumeKey, "string");
    assert.equal(outbound.powConsume.consumeKey, sha256Hex(`${cfgId}|${ticketMac}`));
    assert.equal(outbound.powConsume.expireAt, expireAt);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("client omits powConsume when aggregator consume is disabled", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;

  let capturedBody = "";
  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    capturedBody = await request.text();
    return new Response(
      JSON.stringify({
        ok: true,
        reason: "ok",
        checks: {},
        providers: {},
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    );
  };

  try {
    const result = await verifyViaSiteverifyAggregator({
      config: {
        ...baseConfig,
        AGGREGATOR_POW_ATOMIC_CONSUME: false,
      },
      payload: basePayload,
      powConsume: {
        cfgId: 42,
        ticketMac: "ticket-mac-for-consume",
        expireAt: 1900000000,
      },
    });

    assert.equal(result.ok, true);
    const outbound = JSON.parse(capturedBody);
    assert.equal("powConsume" in outbound, false);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
