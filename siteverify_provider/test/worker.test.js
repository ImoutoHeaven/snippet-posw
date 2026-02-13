import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";

const KID = "v1";
const SHARED_SECRET = "replace-me";
const MAX_BODY_BYTES = 256 * 1024;
const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const testEncoder = new TextEncoder();

const toHex = (bytes) =>
  Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");

const sha256Hex = async (value) => {
  const bytes = typeof value === "string" ? testEncoder.encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return toHex(new Uint8Array(digest));
};

const hmacSha256Hex = async (secret, message) => {
  const key = await crypto.subtle.importKey(
    "raw",
    testEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, testEncoder.encode(message));
  return toHex(new Uint8Array(sig));
};

const buildCanonical = ({ method, path, kid, exp, nonce, bodySha256 }) =>
  ["SV1", method, path, kid, String(exp), nonce, bodySha256].join("\n");

const buildAuthorizedRequest = async ({
  body = JSON.stringify({ token: "test-token" }),
  bodyForHash = body,
  bodyInit = body,
  exp = Math.floor(Date.now() / 1000) + 5,
  nonce = "nonce-1",
  sig,
} = {}) => {
  const method = "POST";
  const path = "/siteverify";
  const bodySha256 = await sha256Hex(bodyForHash);
  const canonical = buildCanonical({ method, path, kid: KID, exp, nonce, bodySha256 });
  const signature = sig ?? (await hmacSha256Hex(SHARED_SECRET, canonical));
  const requestInit = {
    method,
    headers: {
      authorization: `SV1 kid=${KID},exp=${exp},nonce=${nonce},sig=${signature}`,
      "x-sv-body-sha256": bodySha256,
      "content-type": "application/json",
    },
    body: bodyInit,
  };

  if (typeof ReadableStream !== "undefined" && bodyInit instanceof ReadableStream) {
    requestInit.duplex = "half";
  }

  return new Request(`https://sv.example${path}`, requestInit);
};

const createDeferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

const buildProviderPayload = () => ({
  token: {
    turnstile: "turn-token",
  },
  remoteip: "203.0.113.10",
  ticketMac: "ticket-mac",
  providers: {
    turnstile: {
      secret: "turn-secret",
    },
  },
});

const jsonFetchResponse = (payload, status = 200) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json",
    },
  });

const createPowNonceDb = () => {
  const rows = new Map();
  let initRuns = 0;
  let lastInsertBindValues = null;

  const db = {
    prepare(sql) {
      return {
        bind(...values) {
          return {
            async first() {
              if (!/SELECT expire_at FROM pow_nonce_ledger/u.test(sql)) {
                throw new Error(`unexpected first() SQL: ${sql}`);
              }
              const row = rows.get(values[0]);
              return row ? { expire_at: row.expire_at } : null;
            },
            async run() {
              if (/CREATE TABLE IF NOT EXISTS pow_nonce_ledger/u.test(sql)) {
                initRuns += 1;
                return { success: true };
              }
              if (/INSERT INTO pow_nonce_ledger/u.test(sql)) {
                const consumeKey = values[0];
                const expireAt = Number(values[1]);
                const createdAt = Number(values[2]);
                const nowSec = Number(values[3]);
                const existing = rows.get(consumeKey);
                if (existing && Number(existing.expire_at) > nowSec) {
                  lastInsertBindValues = [...values];
                  return { success: true, meta: { changes: 0 } };
                }
                lastInsertBindValues = [...values];
                rows.set(consumeKey, {
                  expire_at: expireAt,
                  created_at: createdAt,
                });
                return { success: true, meta: { changes: 1 } };
              }
              throw new Error(`unexpected run() SQL: ${sql}`);
            },
          };
        },
        async run() {
          if (/CREATE TABLE IF NOT EXISTS pow_nonce_ledger/u.test(sql)) {
            initRuns += 1;
            return { success: true };
          }
          throw new Error(`unexpected run() SQL: ${sql}`);
        },
      };
    },
  };

  return {
    db,
    rows,
    getInitRuns: () => initRuns,
    getLastInsertBindValues: () => lastInsertBindValues,
  };
};

const createAtomicConsumeOnlyDb = () => {
  const rows = new Map();

  return {
    prepare(sql) {
      return {
        bind(...values) {
          return {
            async first() {
              throw new Error(`unexpected first() SQL in atomic mode: ${sql}`);
            },
            async run() {
              if (!/INSERT INTO pow_nonce_ledger/u.test(sql)) {
                throw new Error(`unexpected run() SQL in atomic mode: ${sql}`);
              }
              const consumeKey = values[0];
              const expireAt = Number(values[1]);
              const createdAt = Number(values[2]);
              const nowSec = Number(values[3]);
              const existing = rows.get(consumeKey);
              if (existing && Number(existing.expire_at) > nowSec) {
                return { success: true, meta: { changes: 0 } };
              }
              rows.set(consumeKey, {
                expire_at: expireAt,
                created_at: createdAt,
              });
              return { success: true, meta: { changes: 1 } };
            },
          };
        },
        async run() {
          if (/CREATE TABLE IF NOT EXISTS pow_nonce_ledger/u.test(sql)) {
            return { success: true };
          }
          throw new Error(`unexpected run() SQL in atomic mode: ${sql}`);
        },
      };
    },
  };
};

test("worker returns 404 for missing authorization", async () => {
  const res = await worker.fetch(
    new Request("https://sv.example/siteverify", {
      method: "POST",
      body: "{}",
    })
  );

  assert.equal(res.status, 404);
});

test("valid SV1 authorization is accepted", async () => {
  const req = await buildAuthorizedRequest();
  const res = await worker.fetch(req);

  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /application\/json/u);
  const payload = await res.json();
  assert.equal(payload.ok, false);
  assert.equal(payload.reason, "provider_failed");
  assert.deepEqual(payload.providers, {});
});

test("invalid signature returns 404", async () => {
  const req = await buildAuthorizedRequest({ sig: "f".repeat(64) });
  const res = await worker.fetch(req);

  assert.equal(res.status, 404);
});

test("invalid signature is rejected before consuming stream body", async () => {
  const streamBody = new ReadableStream({
    pull() {
      throw new Error("stream should not be read for invalid signature");
    },
  });

  const req = await buildAuthorizedRequest({
    bodyForHash: JSON.stringify({ token: "stream-test" }),
    bodyInit: streamBody,
    sig: "f".repeat(64),
  });

  const res = await worker.fetch(req);
  assert.equal(res.status, 404);
});

test("oversized body with invalid signature still returns 404", async () => {
  const oversizedBody = JSON.stringify({ token: "c".repeat(256 * 1024) });
  assert.ok(testEncoder.encode(oversizedBody).byteLength > MAX_BODY_BYTES);

  const req = await buildAuthorizedRequest({
    body: oversizedBody,
    sig: "f".repeat(64),
  });
  const res = await worker.fetch(req);

  assert.equal(res.status, 404);
});

test("body > 256KB returns bad_request payload", async () => {
  const oversizedBody = JSON.stringify({ token: "a".repeat(256 * 1024) });
  assert.ok(testEncoder.encode(oversizedBody).byteLength > MAX_BODY_BYTES);

  const req = await buildAuthorizedRequest({ body: oversizedBody });
  const res = await worker.fetch(req);

  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), {
    ok: false,
    reason: "bad_request",
    checks: {},
    providers: {},
  });
});

test("oversized stream is rejected before reading further chunks", async () => {
  const oversizedBody = JSON.stringify({ token: "b".repeat(256 * 1024) });
  const firstChunk = testEncoder.encode(oversizedBody);
  assert.ok(firstChunk.byteLength > MAX_BODY_BYTES);

  let emittedFirstChunk = false;
  const streamBody = new ReadableStream({
    pull(controller) {
      if (!emittedFirstChunk) {
        emittedFirstChunk = true;
        controller.enqueue(firstChunk);
        return;
      }

      throw new Error("stream consumed past limit");
    },
  });

  const req = await buildAuthorizedRequest({
    bodyForHash: oversizedBody,
    bodyInit: streamBody,
  });

  const res = await worker.fetch(req);

  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), {
    ok: false,
    reason: "bad_request",
    checks: {},
    providers: {},
  });
});

test("invalid json under size limit returns bad_request payload", async () => {
  const invalidJsonBody = "{\"token\":";
  assert.ok(testEncoder.encode(invalidJsonBody).byteLength < MAX_BODY_BYTES);

  const req = await buildAuthorizedRequest({ body: invalidJsonBody });
  const res = await worker.fetch(req);

  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), {
    ok: false,
    reason: "bad_request",
    checks: {},
    providers: {},
  });
});

test("runs turnstile verification and returns provider results", async () => {
  const payload = buildProviderPayload();
  const body = JSON.stringify(payload);
  const req = await buildAuthorizedRequest({ body });

  const turnstileDeferred = createDeferred();
  const fetchCalls = [];
  const originalFetch = globalThis.fetch;

  globalThis.fetch = (url) => {
    const reqUrl = String(url);
    fetchCalls.push(reqUrl);
    if (reqUrl === TURNSTILE_SITEVERIFY_URL) return turnstileDeferred.promise;
    throw new Error(`unexpected url: ${reqUrl}`);
  };

  try {
    const responsePromise = worker.fetch(req);

    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.equal(
      fetchCalls.filter((entry) => entry === TURNSTILE_SITEVERIFY_URL).length,
      1,
    );
    turnstileDeferred.resolve(
      jsonFetchResponse({
        success: true,
        cdata: payload.ticketMac,
      }),
    );

    const res = await responsePromise;
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.providers.turnstile.rawResponse.success, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("provider network failure maps provider httpStatus=502", async () => {
  const payload = buildProviderPayload();
  const req = await buildAuthorizedRequest({ body: JSON.stringify(payload) });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (url) => {
    const reqUrl = String(url);
    if (reqUrl === TURNSTILE_SITEVERIFY_URL) {
      throw new Error("turnstile network down");
    }
    throw new Error(`unexpected url: ${reqUrl}`);
  };

  try {
    const res = await worker.fetch(req);
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.providers.turnstile.httpStatus, 502);
    assert.equal(typeof body.providers.turnstile.rawResponse, "string");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("pow consume key is single-use until expireAt", async () => {
  const payload = buildProviderPayload();
  payload.powConsume = {
    consumeKey: "consume-key-single-use",
    expireAt: Math.floor(Date.now() / 1000) + 60,
  };
  const body = JSON.stringify(payload);
  const dbMock = createPowNonceDb();

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (url) => {
    const reqUrl = String(url);
    if (reqUrl === TURNSTILE_SITEVERIFY_URL) {
      return jsonFetchResponse({
        success: true,
        cdata: payload.ticketMac,
      });
    }
    throw new Error(`unexpected url: ${reqUrl}`);
  };

  try {
    const firstReq = await buildAuthorizedRequest({ body });
    const first = await worker.fetch(firstReq, { POW_NONCE_DB: dbMock.db });
    assert.equal(first.status, 200);
    assert.equal((await first.json()).ok, true);

    const secondReq = await buildAuthorizedRequest({ body, nonce: "nonce-2" });
    const second = await worker.fetch(secondReq, { POW_NONCE_DB: dbMock.db });
    assert.equal(second.status, 200);
    const secondBody = await second.json();
    assert.equal(secondBody.ok, false);
    assert.equal(secondBody.reason, "duplicate");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("consume-only request succeeds once then returns duplicate", async () => {
  const payload = {
    powConsume: {
      consumeKey: "consume-only-key",
      expireAt: Math.floor(Date.now() / 1000) + 60,
    },
  };
  const body = JSON.stringify(payload);
  const dbMock = createPowNonceDb();

  const firstReq = await buildAuthorizedRequest({ body, nonce: "nonce-consume-only-1" });
  const first = await worker.fetch(firstReq, { POW_NONCE_DB: dbMock.db });
  assert.equal(first.status, 200);
  const firstBody = await first.json();
  assert.equal(firstBody.ok, true);
  assert.equal(firstBody.reason, "ok");
  assert.deepEqual(firstBody.providers, {});

  const secondReq = await buildAuthorizedRequest({ body, nonce: "nonce-consume-only-2" });
  const second = await worker.fetch(secondReq, { POW_NONCE_DB: dbMock.db });
  assert.equal(second.status, 200);
  const secondBody = await second.json();
  assert.equal(secondBody.ok, false);
  assert.equal(secondBody.reason, "duplicate");
});

test("pow consume request without POW_NONCE_DB returns explicit reason", async () => {
  const payload = buildProviderPayload();
  payload.powConsume = {
    consumeKey: "consume-key-missing-db",
    expireAt: Math.floor(Date.now() / 1000) + 60,
  };
  const req = await buildAuthorizedRequest({ body: JSON.stringify(payload) });

  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = () => {
    fetchCalls += 1;
    throw new Error("unexpected turnstile fetch when db binding missing");
  };

  try {
    const res = await worker.fetch(req, {});
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, false);
    assert.equal(body.reason, "pow_nonce_db_missing");
    assert.equal(fetchCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("concurrent duplicate consumes allow exactly one ok result", async () => {
  const payload = buildProviderPayload();
  payload.powConsume = {
    consumeKey: "consume-key-concurrent",
    expireAt: Math.floor(Date.now() / 1000) + 60,
  };
  const body = JSON.stringify(payload);
  const db = createAtomicConsumeOnlyDb();

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (url) => {
    const reqUrl = String(url);
    if (reqUrl === TURNSTILE_SITEVERIFY_URL) {
      return jsonFetchResponse({
        success: true,
        cdata: payload.ticketMac,
      });
    }
    throw new Error(`unexpected url: ${reqUrl}`);
  };

  try {
    const req1 = await buildAuthorizedRequest({ body, nonce: "nonce-concurrency-1" });
    const req2 = await buildAuthorizedRequest({ body, nonce: "nonce-concurrency-2" });
    const [res1, res2] = await Promise.all([
      worker.fetch(req1, { POW_NONCE_DB: db }),
      worker.fetch(req2, { POW_NONCE_DB: db }),
    ]);

    const result1 = await res1.json();
    const result2 = await res2.json();
    const reasons = [result1.reason, result2.reason].sort();
    assert.deepEqual(reasons, ["duplicate", "ok"]);
    assert.equal([result1.ok, result2.ok].filter(Boolean).length, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("expired existing consume key can be reused", async () => {
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = buildProviderPayload();
  payload.powConsume = {
    consumeKey: "consume-key-reuse-after-expiry",
    expireAt: nowSec + 60,
  };
  const req = await buildAuthorizedRequest({ body: JSON.stringify(payload) });
  const dbMock = createPowNonceDb();
  dbMock.rows.set(payload.powConsume.consumeKey, {
    expire_at: nowSec - 1,
    created_at: nowSec - 120,
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (url) => {
    const reqUrl = String(url);
    if (reqUrl === TURNSTILE_SITEVERIFY_URL) {
      return jsonFetchResponse({
        success: true,
        cdata: payload.ticketMac,
      });
    }
    throw new Error(`unexpected url: ${reqUrl}`);
  };

  try {
    const res = await worker.fetch(req, { POW_NONCE_DB: dbMock.db });
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.ok, true);
    assert.equal(body.reason, "ok");
    assert.equal(dbMock.rows.get(payload.powConsume.consumeKey)?.expire_at, payload.powConsume.expireAt);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("stale pow consume key returns stale without calling providers", async () => {
  const payload = buildProviderPayload();
  payload.powConsume = {
    consumeKey: "consume-key-stale",
    expireAt: Math.floor(Date.now() / 1000) - 1,
    powNonce: "do-not-persist",
  };
  const req = await buildAuthorizedRequest({ body: JSON.stringify(payload) });
  const dbMock = createPowNonceDb();

  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = (url) => {
    fetchCalls += 1;
    throw new Error(`unexpected url: ${String(url)}`);
  };

  try {
    const res = await worker.fetch(req, { POW_NONCE_DB: dbMock.db });
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.ok, false);
    assert.equal(body.reason, "stale");
    assert.equal(fetchCalls, 0);
    assert.equal(dbMock.rows.size, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("malformed powConsume.expireAt returns bad_request", async () => {
  const future = Math.floor(Date.now() / 1000) + 60;
  const payload = buildProviderPayload();
  payload.powConsume = {
    consumeKey: "consume-key-malformed-expire",
    expireAt: `${future}abc`,
  };
  const req = await buildAuthorizedRequest({ body: JSON.stringify(payload) });
  const dbMock = createPowNonceDb();

  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = (url) => {
    fetchCalls += 1;
    throw new Error(`unexpected url: ${String(url)}`);
  };

  try {
    const res = await worker.fetch(req, { POW_NONCE_DB: dbMock.db });
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.ok, false);
    assert.equal(body.reason, "bad_request");
    assert.equal(fetchCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("INIT_TABLES initializes consume ledger and does not persist powNonce", async () => {
  const payload = buildProviderPayload();
  payload.powConsume = {
    consumeKey: "consume-key-init",
    expireAt: Math.floor(Date.now() / 1000) + 60,
    powNonce: "pow-nonce-should-not-be-stored",
  };
  const req = await buildAuthorizedRequest({ body: JSON.stringify(payload) });
  const dbMock = createPowNonceDb();

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (url) => {
    const reqUrl = String(url);
    if (reqUrl === TURNSTILE_SITEVERIFY_URL) {
      return jsonFetchResponse({
        success: true,
        cdata: payload.ticketMac,
      });
    }
    throw new Error(`unexpected url: ${reqUrl}`);
  };

  try {
    const res = await worker.fetch(req, {
      POW_NONCE_DB: dbMock.db,
      INIT_TABLES: true,
    });
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.ok, true);
    assert.equal(dbMock.getInitRuns() > 0, true);
    const bindValues = dbMock.getLastInsertBindValues();
    assert.equal(bindValues?.length, 4);
    assert.equal(bindValues?.[0], payload.powConsume.consumeKey);
    assert.equal(bindValues?.[1], payload.powConsume.expireAt);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("INIT_TABLES remains off unless explicitly enabled", async () => {
  const payload = buildProviderPayload();
  payload.powConsume = {
    consumeKey: "consume-key-no-init",
    expireAt: Math.floor(Date.now() / 1000) + 60,
  };
  const req = await buildAuthorizedRequest({ body: JSON.stringify(payload), nonce: "nonce-no-init" });
  const dbMock = createPowNonceDb();

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (url) => {
    const reqUrl = String(url);
    if (reqUrl === TURNSTILE_SITEVERIFY_URL) {
      return jsonFetchResponse({
        success: true,
        cdata: payload.ticketMac,
      });
    }
    throw new Error(`unexpected url: ${reqUrl}`);
  };

  try {
    const res = await worker.fetch(req, { POW_NONCE_DB: dbMock.db });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.reason, "ok");
    assert.equal(dbMock.getInitRuns(), 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
