import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

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

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const buildInnerHeaders = (payloadObj, secret, expOverride) => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const exp = Number.isFinite(expOverride)
    ? expOverride
    : Math.floor(Date.now() / 1000) + 3;
  const macInput = `${payload}.${exp}`;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(macInput).digest());
  return { payload, mac, exp };
};

const decodeTicket = (ticketB64) => {
  const raw = Buffer.from(String(ticketB64 || "").replace(/-/g, "+").replace(/_/g, "/"), "base64")
    .toString("utf8");
  const parts = raw.split(".");
  if (parts.length !== 6) return null;
  return {
    v: Number.parseInt(parts[0], 10),
    e: Number.parseInt(parts[1], 10),
    L: Number.parseInt(parts[2], 10),
    r: parts[3] || "",
    cfgId: Number.parseInt(parts[4], 10),
    mac: parts[5] || "",
  };
};

const extractChallengeArgs = (html) => {
  const match = html.match(/g\("([^"]+)",\s*(\d+),\s*"([^"]+)",\s*"([^"]+)"/u);
  if (!match) return null;
  return {
    bindingB64: match[1],
    steps: Number.parseInt(match[2], 10),
    ticketB64: match[3],
    pathHash: match[4],
  };
};

const decodeB64UrlUtf8 = (value) => {
  let b64 = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return Buffer.from(b64, "base64").toString("utf8");
};

const sha256Bytes = async (value) => {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const digest = await crypto.webcrypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
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
  const v = Number(value) >>> 0;
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  return out;
};

const captchaTagFromToken = async (token) => {
  const digest = await sha256Bytes(String(token || ""));
  return base64Url(digest.slice(0, 12));
};

const makeConsumeToken = ({ powSecret, ticketB64, exp, captchaTag, mask }) => {
  const payload = `U|${ticketB64}|${exp}|${captchaTag}|${mask}`;
  const mac = base64Url(crypto.createHmac("sha256", powSecret).update(payload).digest());
  return `v2.${ticketB64}.${exp}.${captchaTag}.${mask}.${mac}`;
};

const buildPowModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  const template = await readFile(join(repoRoot, "template.html"), "utf8");
  const injected = powSource.replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template));
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-chain-"));
  const tmpPath = join(tmpDir, "pow.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

const buildConfigModule = async (secret = "config-secret", options = {}) => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powConfigSource = await readFile(join(repoRoot, "pow-config.js"), "utf8");
  const gluePadding = options.longGlue ? "x".repeat(12000) : "";
  const configOverrides = options.configOverrides || {};
  const compiledConfig = JSON.stringify([
    {
      host: { s: "^example\\.com$", f: "" },
      path: null,
      config: {
        POW_TOKEN: "pow-secret",
        powcheck: false,
        turncheck: false,
        POW_BIND_TLS: false,
        POW_BIND_COUNTRY: false,
        POW_BIND_ASN: false,
        POW_GLUE_URL: `https://example.com/glue${gluePadding}`,
        ...configOverrides,
      },
    },
  ]);
  const injected = powConfigSource.replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-config-chain-"));
  const tmpPath = join(tmpDir, "pow-config.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

test("pow-config -> pow.js strips inner headers before origin fetch", async () => {
  const restoreGlobals = ensureGlobals();
  const powPath = await buildPowModule();
  const configPath = await buildConfigModule();
  const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configPath).href}?v=${Date.now()}`);
  const powHandler = powMod.default.fetch;
  const configHandler = configMod.default.fetch;

  let innerRequest = null;
  let originRequest = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) {
        innerRequest = request;
        return powHandler(request);
      }
      originRequest = request;
      return new Response("ok", { status: 200 });
    };

    const clientIp = "1.2.3.4";
    const res = await configHandler(
      new Request("https://example.com/protected", {
        headers: {
          "CF-Connecting-IP": clientIp,
        },
      })
    );
    assert.equal(res.status, 200);
    assert.ok(innerRequest, "pow-config forwards to pow.js");
    const innerPayload = innerRequest.headers.get("X-Pow-Inner");
    const innerCount = innerRequest.headers.get("X-Pow-Inner-Count");
    assert.ok(innerPayload || innerCount, "inner header set");
    assert.ok(innerRequest.headers.get("X-Pow-Inner-Mac"), "inner mac set");
    assert.ok(innerRequest.headers.get("X-Pow-Inner-Expire"), "inner expire set");
    assert.equal(innerRequest.headers.get("CF-Connecting-IP"), clientIp);
    assert.ok(originRequest, "origin fetch called");
    assert.equal(originRequest.headers.get("X-Pow-Inner"), null);
    assert.equal(originRequest.headers.get("X-Pow-Inner-Mac"), null);
    assert.equal(originRequest.headers.get("X-Pow-Inner-Expire"), null);
    assert.equal(originRequest.headers.get("CF-Connecting-IP"), clientIp);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config -> pow.js strips chunked inner headers", async () => {
  const restoreGlobals = ensureGlobals();
  const powPath = await buildPowModule();
  const configPath = await buildConfigModule("config-secret", { longGlue: true });
  const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configPath).href}?v=${Date.now()}`);
  const powHandler = powMod.default.fetch;
  const configHandler = configMod.default.fetch;

  let innerRequest = null;
  let originRequest = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) {
        innerRequest = request;
        return powHandler(request);
      }
      originRequest = request;
      return new Response("ok", { status: 200 });
    };

    const res = await configHandler(new Request("https://example.com/protected"));
    assert.equal(res.status, 200);
    assert.ok(innerRequest, "pow-config forwards to pow.js");
    assert.ok(innerRequest.headers.get("X-Pow-Inner-Count"), "chunked headers set");
    assert.ok(innerRequest.headers.get("X-Pow-Inner-Expire"), "inner expire set");
    assert.equal(innerRequest.headers.get("X-Pow-Inner"), null);
    assert.ok(originRequest, "origin fetch called");
    for (const key of originRequest.headers.keys()) {
      assert.ok(!key.toLowerCase().startsWith("x-pow-inner"), `origin strips ${key}`);
    }
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config strips atomic query/header before pow.js handoff", async () => {
  const restoreGlobals = ensureGlobals();
  const powPath = await buildPowModule();
  const configPath = await buildConfigModule();
  const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configPath).href}?v=${Date.now()}`);
  const powHandler = powMod.default.fetch;
  const configHandler = configMod.default.fetch;

  let innerRequest = null;
  let originRequest = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) {
        innerRequest = request;
        return powHandler(request);
      }
      originRequest = request;
      return new Response("ok", { status: 200 });
    };

    const res = await configHandler(
      new Request("https://example.com/protected?__ts=q-turn&__tt=q-ticket&__ct=1&keep=1", {
        headers: {
          "x-turnstile": "h-turn",
          "x-ticket": "h-ticket",
          "x-consume": "1",
        },
      })
    );
    assert.equal(res.status, 200);
    assert.ok(innerRequest, "pow-config forwards to pow.js");
    assert.equal(innerRequest.headers.get("x-turnstile"), null);
    assert.equal(innerRequest.headers.get("x-ticket"), null);
    assert.equal(innerRequest.headers.get("x-consume"), null);
    const innerUrl = new URL(innerRequest.url);
    assert.equal(innerUrl.searchParams.get("__ts"), null);
    assert.equal(innerUrl.searchParams.get("__tt"), null);
    assert.equal(innerUrl.searchParams.get("__ct"), null);
    assert.equal(innerUrl.searchParams.get("keep"), "1");
    assert.ok(originRequest, "origin fetch called");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow.js consumes atomic only from inner.s (no request fallback)", async () => {
  const restoreGlobals = ensureGlobals();
  const powPath = await buildPowModule();
  const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
  const powHandler = powMod.default.fetch;

  const config = {
    powcheck: false,
    turncheck: true,
    bindPathMode: "none",
    bindPathQueryName: "path",
    bindPathHeaderName: "",
    stripBindPathHeader: false,
    POW_VERSION: 3,
    POW_API_PREFIX: "/__pow",
    POW_DIFFICULTY_BASE: 8192,
    POW_DIFFICULTY_COEFF: 1,
    POW_MIN_STEPS: 1,
    POW_MAX_STEPS: 8192,
    POW_HASHCASH_BITS: 0,
    POW_SEGMENT_LEN: 32,
    POW_SAMPLE_K: 1,
    POW_SPINE_K: 0,
    POW_CHAL_ROUNDS: 1,
    POW_OPEN_BATCH: 1,
    POW_FORCE_EDGE_1: true,
    POW_FORCE_EDGE_LAST: true,
    POW_COMMIT_TTL_SEC: 120,
    POW_TICKET_TTL_SEC: 600,
    PROOF_TTL_SEC: 600,
    PROOF_RENEW_ENABLE: false,
    PROOF_RENEW_MAX: 2,
    PROOF_RENEW_WINDOW_SEC: 90,
    PROOF_RENEW_MIN_SEC: 30,
    ATOMIC_CONSUME: true,
    ATOMIC_TURN_QUERY: "__ts",
    ATOMIC_TICKET_QUERY: "__tt",
    ATOMIC_CONSUME_QUERY: "__ct",
    ATOMIC_TURN_HEADER: "x-turnstile",
    ATOMIC_TICKET_HEADER: "x-ticket",
    ATOMIC_CONSUME_HEADER: "x-consume",
    ATOMIC_COOKIE_NAME: "__Secure-pow_a",
    STRIP_ATOMIC_QUERY: true,
    STRIP_ATOMIC_HEADERS: true,
    INNER_AUTH_QUERY_NAME: "",
    INNER_AUTH_QUERY_VALUE: "",
    INNER_AUTH_HEADER_NAME: "",
    INNER_AUTH_HEADER_VALUE: "",
    stripInnerAuthQuery: false,
    stripInnerAuthHeader: false,
    POW_BIND_PATH: true,
    POW_BIND_IPRANGE: true,
    POW_BIND_COUNTRY: false,
    POW_BIND_ASN: false,
    POW_BIND_TLS: false,
    POW_TOKEN: "pow-secret",
    TURNSTILE_SITEKEY: "sitekey",
    TURNSTILE_SECRET: "turn-secret",
    POW_COMMIT_COOKIE: "__Host-pow_commit",
    POW_ESM_URL: "https://example.com/esm",
    POW_GLUE_URL: "https://example.com/glue",
  };

  const { payload, mac, exp } = buildInnerHeaders(
    {
      v: 1,
      id: 7,
      c: config,
      d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    },
    "config-secret"
  );

  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const res = await powHandler(
      new Request("https://example.com/protected?__ts=q-turn&__tt=q-ticket&__ct=1", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "x-turnstile": "header-turn-token",
          "x-ticket": "header-ticket",
          "x-consume": "1",
          Cookie: "__Secure-pow_a=1%7Ct%7Ccookie-turn%7Ccookie-ticket",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );

    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { code: "captcha_required" });
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow.js returns captcha_required when recaptcha is enabled", async () => {
  const restoreGlobals = ensureGlobals();
  const powPath = await buildPowModule();
  const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
  const powHandler = powMod.default.fetch;

  const config = {
    powcheck: false,
    turncheck: false,
    recaptchaEnabled: true,
    bindPathMode: "none",
    bindPathQueryName: "path",
    bindPathHeaderName: "",
    stripBindPathHeader: false,
    POW_VERSION: 3,
    POW_API_PREFIX: "/__pow",
    POW_DIFFICULTY_BASE: 8192,
    POW_DIFFICULTY_COEFF: 1,
    POW_MIN_STEPS: 1,
    POW_MAX_STEPS: 8192,
    POW_HASHCASH_BITS: 0,
    POW_SEGMENT_LEN: 32,
    POW_SAMPLE_K: 1,
    POW_SPINE_K: 0,
    POW_CHAL_ROUNDS: 1,
    POW_OPEN_BATCH: 1,
    POW_FORCE_EDGE_1: true,
    POW_FORCE_EDGE_LAST: true,
    POW_COMMIT_TTL_SEC: 120,
    POW_TICKET_TTL_SEC: 600,
    PROOF_TTL_SEC: 600,
    PROOF_RENEW_ENABLE: false,
    PROOF_RENEW_MAX: 2,
    PROOF_RENEW_WINDOW_SEC: 90,
    PROOF_RENEW_MIN_SEC: 30,
    ATOMIC_CONSUME: false,
    ATOMIC_TURN_QUERY: "__ts",
    ATOMIC_TICKET_QUERY: "__tt",
    ATOMIC_CONSUME_QUERY: "__ct",
    ATOMIC_TURN_HEADER: "x-turnstile",
    ATOMIC_TICKET_HEADER: "x-ticket",
    ATOMIC_CONSUME_HEADER: "x-consume",
    ATOMIC_COOKIE_NAME: "__Secure-pow_a",
    STRIP_ATOMIC_QUERY: true,
    STRIP_ATOMIC_HEADERS: true,
    INNER_AUTH_QUERY_NAME: "",
    INNER_AUTH_QUERY_VALUE: "",
    INNER_AUTH_HEADER_NAME: "",
    INNER_AUTH_HEADER_VALUE: "",
    stripInnerAuthQuery: false,
    stripInnerAuthHeader: false,
    POW_BIND_PATH: true,
    POW_BIND_IPRANGE: true,
    POW_BIND_COUNTRY: false,
    POW_BIND_ASN: false,
    POW_BIND_TLS: false,
    POW_TOKEN: "pow-secret",
    TURNSTILE_SITEKEY: "sitekey",
    TURNSTILE_SECRET: "turn-secret",
    RECAPTCHA_PAIRS: [{ sitekey: "rk", secret: "rs" }],
    RECAPTCHA_MIN_SCORE: 0.5,
    POW_COMMIT_COOKIE: "__Host-pow_commit",
    POW_ESM_URL: "https://example.com/esm",
    POW_GLUE_URL: "https://example.com/glue",
  };

  const { payload, mac, exp } = buildInnerHeaders(
    {
      v: 1,
      id: 10,
      c: config,
      d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    },
    "config-secret"
  );

  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("ok", { status: 200 });
    const res = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );

    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { code: "captcha_required" });
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow api uses /cap and rejects /turn", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const powPath = await buildPowModule();
    const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;

    const config = {
      powcheck: false,
      turncheck: true,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 8192,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 8192,
      POW_HASHCASH_BITS: 0,
      POW_SEGMENT_LEN: 32,
      POW_SAMPLE_K: 1,
      POW_SPINE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_FORCE_EDGE_1: true,
      POW_FORCE_EDGE_LAST: true,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: false,
      ATOMIC_TURN_QUERY: "__ts",
      ATOMIC_TICKET_QUERY: "__tt",
      ATOMIC_CONSUME_QUERY: "__ct",
      ATOMIC_TURN_HEADER: "x-turnstile",
      ATOMIC_TICKET_HEADER: "x-ticket",
      ATOMIC_CONSUME_HEADER: "x-consume",
      ATOMIC_COOKIE_NAME: "__Secure-pow_a",
      STRIP_ATOMIC_QUERY: true,
      STRIP_ATOMIC_HEADERS: true,
      INNER_AUTH_QUERY_NAME: "",
      INNER_AUTH_QUERY_VALUE: "",
      INNER_AUTH_HEADER_NAME: "",
      INNER_AUTH_HEADER_VALUE: "",
      stripInnerAuthQuery: false,
      stripInnerAuthHeader: false,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 9,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    const capRes = await powHandler(
      new Request("https://example.com/__pow/cap", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({}),
      })
    );
    assert.notEqual(capRes.status, 404);

    const turnRes = await powHandler(
      new Request("https://example.com/__pow/turn", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(turnRes.status, 404);
  } finally {
    restoreGlobals();
  }
});

test("/cap works for no-pow turnstile flow and issues proof", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const powPath = await buildPowModule();
    const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;

    const config = {
      powcheck: false,
      turncheck: true,
      recaptchaEnabled: false,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 8192,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 8192,
      POW_HASHCASH_BITS: 0,
      POW_SEGMENT_LEN: 32,
      POW_SAMPLE_K: 1,
      POW_SPINE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_FORCE_EDGE_1: true,
      POW_FORCE_EDGE_LAST: true,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: false,
      ATOMIC_TURN_QUERY: "__ts",
      ATOMIC_TICKET_QUERY: "__tt",
      ATOMIC_CONSUME_QUERY: "__ct",
      ATOMIC_TURN_HEADER: "x-turnstile",
      ATOMIC_TICKET_HEADER: "x-ticket",
      ATOMIC_CONSUME_HEADER: "x-consume",
      ATOMIC_COOKIE_NAME: "__Secure-pow_a",
      STRIP_ATOMIC_QUERY: true,
      STRIP_ATOMIC_HEADERS: true,
      INNER_AUTH_QUERY_NAME: "",
      INNER_AUTH_QUERY_VALUE: "",
      INNER_AUTH_HEADER_NAME: "",
      INNER_AUTH_HEADER_VALUE: "",
      stripInnerAuthQuery: false,
      stripInnerAuthHeader: false,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 11,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    globalThis.fetch = async (url) => {
      if (String(url) === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        return new Response(JSON.stringify({ success: true, cdata: ticket.mac }), { status: 200 });
      }
      return new Response("ok", { status: 200 });
    };

    const pageRes = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");

    const capRes = await powHandler(
      new Request("https://example.com/__pow/cap", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          pathHash: args.pathHash,
          captchaToken: "turnstile-token-value-1234567890",
        }),
      })
    );

    assert.equal(capRes.status, 200);
    const proofCookie = capRes.headers.get("Set-Cookie") || "";
    assert.match(proofCookie, /__Host-proof=/u);
    assert.match(proofCookie, /\.2\./u);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("/cap works for no-pow recaptcha flow and issues proof", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const powPath = await buildPowModule();
    const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;
    const testing = powMod.__captchaTesting;

    const recaptchaPairs = [{ sitekey: "rk-1", secret: "rs-1" }];
    const config = {
      powcheck: false,
      turncheck: false,
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: recaptchaPairs,
      RECAPTCHA_MIN_SCORE: 0.5,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 8192,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 8192,
      POW_HASHCASH_BITS: 0,
      POW_SEGMENT_LEN: 32,
      POW_SAMPLE_K: 1,
      POW_SPINE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_FORCE_EDGE_1: true,
      POW_FORCE_EDGE_LAST: true,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: false,
      ATOMIC_TURN_QUERY: "__ts",
      ATOMIC_TICKET_QUERY: "__tt",
      ATOMIC_CONSUME_QUERY: "__ct",
      ATOMIC_TURN_HEADER: "x-turnstile",
      ATOMIC_TICKET_HEADER: "x-ticket",
      ATOMIC_CONSUME_HEADER: "x-consume",
      ATOMIC_COOKIE_NAME: "__Secure-pow_a",
      STRIP_ATOMIC_QUERY: true,
      STRIP_ATOMIC_HEADERS: true,
      INNER_AUTH_QUERY_NAME: "",
      INNER_AUTH_QUERY_VALUE: "",
      INNER_AUTH_HEADER_NAME: "",
      INNER_AUTH_HEADER_VALUE: "",
      stripInnerAuthQuery: false,
      stripInnerAuthHeader: false,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 12,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    const pageRes = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");
    const pair = await testing.pickRecaptchaPair(ticket.mac, recaptchaPairs);
    const bindingString = `${ticket.v}|${ticket.e}|${ticket.L}|${ticket.r}|${ticket.cfgId}|example.com|${args.pathHash}|1.2.3.4/32|any|any|any`;
    const expectedAction = await testing.makeRecaptchaAction(bindingString, pair.kid);

    globalThis.fetch = async (url) => {
      if (String(url) === "https://www.google.com/recaptcha/api/siteverify") {
        return new Response(
          JSON.stringify({
            success: true,
            hostname: "example.com",
            remoteip: "1.2.3.4",
            score: 0.9,
            action: expectedAction,
          }),
          { status: 200 }
        );
      }
      return new Response("ok", { status: 200 });
    };

    const capRes = await powHandler(
      new Request("https://example.com/__pow/cap", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          pathHash: args.pathHash,
          captchaToken: "recaptcha-token-value-1234567890",
        }),
      })
    );

    assert.equal(capRes.status, 200);
    const proofCookie = capRes.headers.get("Set-Cookie") || "";
    assert.match(proofCookie, /__Host-proof=/u);
    assert.match(proofCookie, /\.4\./u);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("combined pow+captcha /open uses captchaToken and enforces verification", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const powPath = await buildPowModule();
    const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;

    const config = {
      powcheck: true,
      turncheck: true,
      recaptchaEnabled: false,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_SPINE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_FORCE_EDGE_1: true,
      POW_FORCE_EDGE_LAST: true,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: false,
      ATOMIC_TURN_QUERY: "__ts",
      ATOMIC_TICKET_QUERY: "__tt",
      ATOMIC_CONSUME_QUERY: "__ct",
      ATOMIC_TURN_HEADER: "x-turnstile",
      ATOMIC_TICKET_HEADER: "x-ticket",
      ATOMIC_CONSUME_HEADER: "x-consume",
      ATOMIC_COOKIE_NAME: "__Secure-pow_a",
      STRIP_ATOMIC_QUERY: true,
      STRIP_ATOMIC_HEADERS: true,
      INNER_AUTH_QUERY_NAME: "",
      INNER_AUTH_QUERY_VALUE: "",
      INNER_AUTH_HEADER_NAME: "",
      INNER_AUTH_HEADER_VALUE: "",
      stripInnerAuthQuery: false,
      stripInnerAuthHeader: false,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 13,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    const goodToken = "turnstile-open-token-value-1234567890";
    const badToken = "turnstile-open-token-value-bad-1234567890";

    const pageRes = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");

    const bindingString = decodeB64UrlUtf8(args.bindingB64);
    const nonce = base64Url(crypto.randomBytes(12));
    const commitCaptchaTag = await captchaTagFromToken(goodToken);
    const powBinding = `${bindingString}|${commitCaptchaTag}`;
    const seedPrefix = new TextEncoder().encode("posw|seed|");
    const stepPrefix = new TextEncoder().encode("posw|step|");
    const leafPrefix = new TextEncoder().encode("leaf|");
    const nodePrefix = new TextEncoder().encode("node|");
    const pipe = new TextEncoder().encode("|");

    const seedHash = await sha256Bytes(
      concatBytes(seedPrefix, new TextEncoder().encode(powBinding), pipe, new TextEncoder().encode(nonce))
    );
    const hCurr = await sha256Bytes(concatBytes(stepPrefix, encodeUint32BE(1), seedHash));
    const leaf0 = await sha256Bytes(concatBytes(leafPrefix, encodeUint32BE(0), seedHash));
    const leaf1 = await sha256Bytes(concatBytes(leafPrefix, encodeUint32BE(1), hCurr));
    const root = await sha256Bytes(concatBytes(nodePrefix, leaf0, leaf1));
    const rootB64 = base64Url(root);

    globalThis.fetch = async (url) => {
      if (String(url) === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        return new Response(JSON.stringify({ success: true, cdata: ticket.mac }), { status: 200 });
      }
      return new Response("ok", { status: 200 });
    };

    const commitRes = await powHandler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64,
          pathHash: args.pathHash,
          nonce,
          captchaToken: goodToken,
        }),
      })
    );
    assert.equal(commitRes.status, 200);
    const commitCookie = (commitRes.headers.get("Set-Cookie") || "").split(";")[0];
    assert.ok(commitCookie, "commit cookie issued");

    const challengeRes = await powHandler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(challengeRes.status, 200);
    const challenge = await challengeRes.json();
    assert.deepEqual(challenge.indices, [1]);
    assert.deepEqual(challenge.segs, [1]);
    assert.deepEqual(challenge.spinePos, []);

    const openBody = {
      sid: challenge.sid,
      cursor: challenge.cursor,
      token: challenge.token,
      spinePos: challenge.spinePos,
      opens: [
        {
          i: 1,
          hPrev: base64Url(seedHash),
          hCurr: base64Url(hCurr),
          proofPrev: { sibs: [base64Url(leaf1)] },
          proofCurr: { sibs: [base64Url(leaf0)] },
        },
      ],
    };

    const rejectOpen = await powHandler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({ ...openBody, captchaToken: badToken }),
      })
    );
    assert.equal(rejectOpen.status, 403);

    const passOpen = await powHandler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({ ...openBody, captchaToken: goodToken }),
      })
    );
    assert.equal(passOpen.status, 200);
    assert.deepEqual(await passOpen.json(), { done: true });
    const proofCookie = passOpen.headers.get("Set-Cookie") || "";
    assert.match(proofCookie, /__Host-proof=/u);
    assert.match(proofCookie, /\.3\./u);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow+recaptcha /open enforces commit captchaTag binding", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const powPath = await buildPowModule();
    const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;
    const testing = powMod.__captchaTesting;

    const recaptchaPairs = [{ sitekey: "rk-1", secret: "rs-1" }];
    const goodToken = "recaptcha-token-good-1234567890";
    const badToken = "recaptcha-token-bad-1234567890";
    const config = {
      powcheck: true,
      turncheck: false,
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: recaptchaPairs,
      RECAPTCHA_MIN_SCORE: 0.5,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_SPINE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_FORCE_EDGE_1: true,
      POW_FORCE_EDGE_LAST: true,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: false,
      ATOMIC_TURN_QUERY: "__ts",
      ATOMIC_TICKET_QUERY: "__tt",
      ATOMIC_CONSUME_QUERY: "__ct",
      ATOMIC_TURN_HEADER: "x-turnstile",
      ATOMIC_TICKET_HEADER: "x-ticket",
      ATOMIC_CONSUME_HEADER: "x-consume",
      ATOMIC_COOKIE_NAME: "__Secure-pow_a",
      STRIP_ATOMIC_QUERY: true,
      STRIP_ATOMIC_HEADERS: true,
      INNER_AUTH_QUERY_NAME: "",
      INNER_AUTH_QUERY_VALUE: "",
      INNER_AUTH_HEADER_NAME: "",
      INNER_AUTH_HEADER_VALUE: "",
      stripInnerAuthQuery: false,
      stripInnerAuthHeader: false,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 18,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    const pageRes = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");

    const pair = await testing.pickRecaptchaPair(ticket.mac, recaptchaPairs);
    const bindingString = decodeB64UrlUtf8(args.bindingB64);
    const expectedAction = await testing.makeRecaptchaAction(bindingString, pair.kid);

    const nonce = base64Url(crypto.randomBytes(12));
    const seedPrefix = new TextEncoder().encode("posw|seed|");
    const stepPrefix = new TextEncoder().encode("posw|step|");
    const leafPrefix = new TextEncoder().encode("leaf|");
    const nodePrefix = new TextEncoder().encode("node|");
    const pipe = new TextEncoder().encode("|");
    const buildOpenProof = async (powBinding) => {
      const seedHash = await sha256Bytes(
        concatBytes(seedPrefix, new TextEncoder().encode(powBinding), pipe, new TextEncoder().encode(nonce))
      );
      const hCurr = await sha256Bytes(concatBytes(stepPrefix, encodeUint32BE(1), seedHash));
      const leaf0 = await sha256Bytes(concatBytes(leafPrefix, encodeUint32BE(0), seedHash));
      const leaf1 = await sha256Bytes(concatBytes(leafPrefix, encodeUint32BE(1), hCurr));
      const root = await sha256Bytes(concatBytes(nodePrefix, leaf0, leaf1));
      const rootB64 = base64Url(root);
      const opens = [
        {
          i: 1,
          hPrev: base64Url(seedHash),
          hCurr: base64Url(hCurr),
          proofPrev: { sibs: [base64Url(leaf1)] },
          proofCurr: { sibs: [base64Url(leaf0)] },
        },
      ];
      return { rootB64, opens };
    };
    const untaggedProof = await buildOpenProof(bindingString);
    const taggedBinding = `${bindingString}|${await captchaTagFromToken(goodToken)}`;
    const taggedProof = await buildOpenProof(taggedBinding);

    globalThis.fetch = async (url) => {
      if (String(url) === "https://www.google.com/recaptcha/api/siteverify") {
        return new Response(
          JSON.stringify({
            success: true,
            hostname: "example.com",
            remoteip: "1.2.3.4",
            score: 0.9,
            action: expectedAction,
          }),
          { status: 200 }
        );
      }
      return new Response("ok", { status: 200 });
    };

    const commitRes = await powHandler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64: taggedProof.rootB64,
          pathHash: args.pathHash,
          nonce,
          captchaToken: goodToken,
        }),
      })
    );
    assert.equal(commitRes.status, 200);
    const commitCookie = (commitRes.headers.get("Set-Cookie") || "").split(";")[0];
    assert.ok(commitCookie, "commit cookie issued");

    const challengeRes = await powHandler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(challengeRes.status, 200);
    const challenge = await challengeRes.json();

    const openBody = {
      sid: challenge.sid,
      cursor: challenge.cursor,
      token: challenge.token,
      spinePos: challenge.spinePos,
      opens: untaggedProof.opens,
    };

    const rejectUntaggedOpen = await powHandler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({ ...openBody, captchaToken: goodToken }),
      })
    );
    assert.equal(rejectUntaggedOpen.status, 403);

    const rejectOpen = await powHandler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({ ...openBody, captchaToken: badToken }),
      })
    );
    assert.equal(rejectOpen.status, 403);

    const passOpen = await powHandler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({ ...openBody, opens: taggedProof.opens, captchaToken: goodToken }),
      })
    );
    assert.equal(passOpen.status, 200);
    assert.deepEqual(await passOpen.json(), { done: true });
    const proofCookie = passOpen.headers.get("Set-Cookie") || "";
    assert.match(proofCookie, /__Host-proof=/u);
    assert.match(proofCookie, /\.5\./u);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("atomic recaptcha fast-path verifies and forwards without proof", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const powPath = await buildPowModule();
    const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;
    const testing = powMod.__captchaTesting;

    const recaptchaPairs = [{ sitekey: "rk-1", secret: "rs-1" }];
    const recaptchaToken = "atomic-recaptcha-token-1234567890";
    const config = {
      powcheck: false,
      turncheck: false,
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: recaptchaPairs,
      RECAPTCHA_MIN_SCORE: 0.5,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 8192,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 8192,
      POW_HASHCASH_BITS: 0,
      POW_SEGMENT_LEN: 32,
      POW_SAMPLE_K: 1,
      POW_SPINE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_FORCE_EDGE_1: true,
      POW_FORCE_EDGE_LAST: true,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: true,
      ATOMIC_TURN_QUERY: "__ts",
      ATOMIC_TICKET_QUERY: "__tt",
      ATOMIC_CONSUME_QUERY: "__ct",
      ATOMIC_TURN_HEADER: "x-turnstile",
      ATOMIC_TICKET_HEADER: "x-ticket",
      ATOMIC_CONSUME_HEADER: "x-consume",
      ATOMIC_COOKIE_NAME: "__Secure-pow_a",
      STRIP_ATOMIC_QUERY: true,
      STRIP_ATOMIC_HEADERS: true,
      INNER_AUTH_QUERY_NAME: "",
      INNER_AUTH_QUERY_VALUE: "",
      INNER_AUTH_HEADER_NAME: "",
      INNER_AUTH_HEADER_VALUE: "",
      stripInnerAuthQuery: false,
      stripInnerAuthHeader: false,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const baseInner = {
      v: 1,
      id: 31,
      c: config,
      d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    };

    const stage1 = buildInnerHeaders(baseInner, "config-secret");
    const pageRes = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage1.payload,
          "X-Pow-Inner-Mac": stage1.mac,
          "X-Pow-Inner-Expire": String(stage1.exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");
    const pair = await testing.pickRecaptchaPair(ticket.mac, recaptchaPairs);
    const bindingString = decodeB64UrlUtf8(args.bindingB64);
    const expectedAction = await testing.makeRecaptchaAction(bindingString, pair.kid);

    const innerWithAtomic = {
      ...baseInner,
      s: {
        ...baseInner.s,
        atomic: {
          ...baseInner.s.atomic,
          captchaToken: recaptchaToken,
          ticketB64: args.ticketB64,
        },
      },
    };
    const stage2 = buildInnerHeaders(innerWithAtomic, "config-secret");
    let originCalls = 0;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://www.google.com/recaptcha/api/siteverify") {
        return new Response(
          JSON.stringify({
            success: true,
            hostname: "example.com",
            remoteip: "1.2.3.4",
            score: 0.9,
            action: expectedAction,
          }),
          { status: 200 }
        );
      }
      originCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const res = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage2.payload,
          "X-Pow-Inner-Mac": stage2.mac,
          "X-Pow-Inner-Expire": String(stage2.exp),
        },
      })
    );
    assert.equal(res.status, 200);
    assert.equal(originCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("atomic recaptcha+pow rejects consume token with mismatched captchaTag", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const powPath = await buildPowModule();
    const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;
    const testing = powMod.__captchaTesting;

    const recaptchaPairs = [{ sitekey: "rk-1", secret: "rs-1" }];
    const recaptchaToken = "atomic-recaptcha-token-1234567890";
    const wrongToken = "different-recaptcha-token-1234567890";
    const config = {
      powcheck: true,
      turncheck: false,
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: recaptchaPairs,
      RECAPTCHA_MIN_SCORE: 0.5,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_SPINE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_FORCE_EDGE_1: true,
      POW_FORCE_EDGE_LAST: true,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: true,
      ATOMIC_TURN_QUERY: "__ts",
      ATOMIC_TICKET_QUERY: "__tt",
      ATOMIC_CONSUME_QUERY: "__ct",
      ATOMIC_TURN_HEADER: "x-turnstile",
      ATOMIC_TICKET_HEADER: "x-ticket",
      ATOMIC_CONSUME_HEADER: "x-consume",
      ATOMIC_COOKIE_NAME: "__Secure-pow_a",
      STRIP_ATOMIC_QUERY: true,
      STRIP_ATOMIC_HEADERS: true,
      INNER_AUTH_QUERY_NAME: "",
      INNER_AUTH_QUERY_VALUE: "",
      INNER_AUTH_HEADER_NAME: "",
      INNER_AUTH_HEADER_VALUE: "",
      stripInnerAuthQuery: false,
      stripInnerAuthHeader: false,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const baseInner = {
      v: 1,
      id: 35,
      c: config,
      d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    };

    const stage1 = buildInnerHeaders(baseInner, "config-secret");
    const pageRes = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage1.payload,
          "X-Pow-Inner-Mac": stage1.mac,
          "X-Pow-Inner-Expire": String(stage1.exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");
    const pair = await testing.pickRecaptchaPair(ticket.mac, recaptchaPairs);
    const bindingString = decodeB64UrlUtf8(args.bindingB64);
    const expectedAction = await testing.makeRecaptchaAction(bindingString, pair.kid);

    const wrongCaptchaTag = await captchaTagFromToken(wrongToken);
    const exp = Math.floor(Date.now() / 1000) + 120;
    const consumeToken = makeConsumeToken({
      powSecret: "pow-secret",
      ticketB64: args.ticketB64,
      exp,
      captchaTag: wrongCaptchaTag,
      mask: 5,
    });

    const innerWithAtomic = {
      ...baseInner,
      s: {
        ...baseInner.s,
        atomic: {
          ...baseInner.s.atomic,
          captchaToken: recaptchaToken,
          ticketB64: args.ticketB64,
          consumeToken,
        },
      },
    };
    const stage2 = buildInnerHeaders(innerWithAtomic, "config-secret");
    let originCalls = 0;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://www.google.com/recaptcha/api/siteverify") {
        return new Response(
          JSON.stringify({
            success: true,
            hostname: "example.com",
            remoteip: "1.2.3.4",
            score: 0.9,
            action: expectedAction,
          }),
          { status: 200 }
        );
      }
      originCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const res = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage2.payload,
          "X-Pow-Inner-Mac": stage2.mac,
          "X-Pow-Inner-Expire": String(stage2.exp),
        },
      })
    );
    assert.equal(res.status, 403);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("atomic combined mode accepts turn+recaptcha token envelope", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const powPath = await buildPowModule();
    const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;
    const testing = powMod.__captchaTesting;

    const turnToken = "atomic-turn-token-1234567890";
    const recaptchaToken = "atomic-recaptcha-token-1234567890";
    const recaptchaPairs = [{ sitekey: "rk-1", secret: "rs-1" }];
    const config = {
      powcheck: false,
      turncheck: true,
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: recaptchaPairs,
      RECAPTCHA_MIN_SCORE: 0.5,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 8192,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 8192,
      POW_HASHCASH_BITS: 0,
      POW_SEGMENT_LEN: 32,
      POW_SAMPLE_K: 1,
      POW_SPINE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_FORCE_EDGE_1: true,
      POW_FORCE_EDGE_LAST: true,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: true,
      ATOMIC_TURN_QUERY: "__ts",
      ATOMIC_TICKET_QUERY: "__tt",
      ATOMIC_CONSUME_QUERY: "__ct",
      ATOMIC_TURN_HEADER: "x-turnstile",
      ATOMIC_TICKET_HEADER: "x-ticket",
      ATOMIC_CONSUME_HEADER: "x-consume",
      ATOMIC_COOKIE_NAME: "__Secure-pow_a",
      STRIP_ATOMIC_QUERY: true,
      STRIP_ATOMIC_HEADERS: true,
      INNER_AUTH_QUERY_NAME: "",
      INNER_AUTH_QUERY_VALUE: "",
      INNER_AUTH_HEADER_NAME: "",
      INNER_AUTH_HEADER_VALUE: "",
      stripInnerAuthQuery: false,
      stripInnerAuthHeader: false,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const baseInner = {
      v: 1,
      id: 33,
      c: config,
      d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    };

    const stage1 = buildInnerHeaders(baseInner, "config-secret");
    const pageRes = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage1.payload,
          "X-Pow-Inner-Mac": stage1.mac,
          "X-Pow-Inner-Expire": String(stage1.exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");
    const pair = await testing.pickRecaptchaPair(ticket.mac, recaptchaPairs);
    const bindingString = decodeB64UrlUtf8(args.bindingB64);
    const expectedAction = await testing.makeRecaptchaAction(bindingString, pair.kid);

    const innerWithAtomic = {
      ...baseInner,
      s: {
        ...baseInner.s,
        atomic: {
          ...baseInner.s.atomic,
          captchaToken: JSON.stringify({ turnstile: turnToken, recaptcha_v3: recaptchaToken }),
          ticketB64: args.ticketB64,
          turnstilePreflight: {
            checked: true,
            ok: true,
            reason: "",
            ticketMac: ticket.mac,
            tokenTag: await captchaTagFromToken(turnToken),
          },
        },
      },
    };
    const stage2 = buildInnerHeaders(innerWithAtomic, "config-secret");
    let turnstileCalls = 0;
    let recaptchaCalls = 0;
    let originCalls = 0;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        turnstileCalls += 1;
        return new Response(JSON.stringify({ success: true, cdata: ticket.mac }), { status: 200 });
      }
      if (String(url) === "https://www.google.com/recaptcha/api/siteverify") {
        recaptchaCalls += 1;
        return new Response(
          JSON.stringify({
            success: true,
            hostname: "example.com",
            remoteip: "1.2.3.4",
            score: 0.9,
            action: expectedAction,
          }),
          { status: 200 }
        );
      }
      originCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const res = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage2.payload,
          "X-Pow-Inner-Mac": stage2.mac,
          "X-Pow-Inner-Expire": String(stage2.exp),
        },
      })
    );
    assert.equal(res.status, 200);
    assert.equal(turnstileCalls, 0);
    assert.equal(recaptchaCalls, 1);
    assert.equal(originCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("atomic dual-provider request without turnstilePreflight is denied", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const powPath = await buildPowModule();
    const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;

    const config = {
      powcheck: false,
      turncheck: true,
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: [{ sitekey: "rk-1", secret: "rs-1" }],
      RECAPTCHA_MIN_SCORE: 0.5,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 8192,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 8192,
      POW_HASHCASH_BITS: 0,
      POW_SEGMENT_LEN: 32,
      POW_SAMPLE_K: 1,
      POW_SPINE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_FORCE_EDGE_1: true,
      POW_FORCE_EDGE_LAST: true,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: true,
      ATOMIC_TURN_QUERY: "__ts",
      ATOMIC_TICKET_QUERY: "__tt",
      ATOMIC_CONSUME_QUERY: "__ct",
      ATOMIC_TURN_HEADER: "x-turnstile",
      ATOMIC_TICKET_HEADER: "x-ticket",
      ATOMIC_CONSUME_HEADER: "x-consume",
      ATOMIC_COOKIE_NAME: "__Secure-pow_a",
      STRIP_ATOMIC_QUERY: true,
      STRIP_ATOMIC_HEADERS: true,
      INNER_AUTH_QUERY_NAME: "",
      INNER_AUTH_QUERY_VALUE: "",
      INNER_AUTH_HEADER_NAME: "",
      INNER_AUTH_HEADER_VALUE: "",
      stripInnerAuthQuery: false,
      stripInnerAuthHeader: false,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const baseInner = {
      v: 1,
      id: 34,
      c: config,
      d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    };

    const stage1 = buildInnerHeaders(baseInner, "config-secret");
    const pageRes = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage1.payload,
          "X-Pow-Inner-Mac": stage1.mac,
          "X-Pow-Inner-Expire": String(stage1.exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");

    const innerWithAtomic = {
      ...baseInner,
      s: {
        ...baseInner.s,
        atomic: {
          ...baseInner.s.atomic,
          captchaToken: JSON.stringify({
            turnstile: "atomic-turn-token-1234567890",
            recaptcha_v3: "atomic-recaptcha-token-1234567890",
          }),
          ticketB64: args.ticketB64,
        },
      },
    };
    const stage2 = buildInnerHeaders(innerWithAtomic, "config-secret");
    let turnstileCalls = 0;
    let recaptchaCalls = 0;
    let originCalls = 0;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        turnstileCalls += 1;
      } else if (String(url) === "https://www.google.com/recaptcha/api/siteverify") {
        recaptchaCalls += 1;
      } else {
        originCalls += 1;
      }
      return new Response("ok", { status: 200 });
    };

    const res = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage2.payload,
          "X-Pow-Inner-Mac": stage2.mac,
          "X-Pow-Inner-Expire": String(stage2.exp),
        },
      })
    );
    assert.equal(res.status, 403);
    assert.equal(turnstileCalls, 0);
    assert.equal(recaptchaCalls, 0);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("atomic dual-provider request with mismatched preflight evidence is denied", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const powPath = await buildPowModule();
    const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;

    const turnToken = "atomic-turn-token-1234567890";
    const config = {
      powcheck: false,
      turncheck: true,
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: [{ sitekey: "rk-1", secret: "rs-1" }],
      RECAPTCHA_MIN_SCORE: 0.5,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 8192,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 8192,
      POW_HASHCASH_BITS: 0,
      POW_SEGMENT_LEN: 32,
      POW_SAMPLE_K: 1,
      POW_SPINE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_FORCE_EDGE_1: true,
      POW_FORCE_EDGE_LAST: true,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: true,
      ATOMIC_TURN_QUERY: "__ts",
      ATOMIC_TICKET_QUERY: "__tt",
      ATOMIC_CONSUME_QUERY: "__ct",
      ATOMIC_TURN_HEADER: "x-turnstile",
      ATOMIC_TICKET_HEADER: "x-ticket",
      ATOMIC_CONSUME_HEADER: "x-consume",
      ATOMIC_COOKIE_NAME: "__Secure-pow_a",
      STRIP_ATOMIC_QUERY: true,
      STRIP_ATOMIC_HEADERS: true,
      INNER_AUTH_QUERY_NAME: "",
      INNER_AUTH_QUERY_VALUE: "",
      INNER_AUTH_HEADER_NAME: "",
      INNER_AUTH_HEADER_VALUE: "",
      stripInnerAuthQuery: false,
      stripInnerAuthHeader: false,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const baseInner = {
      v: 1,
      id: 35,
      c: config,
      d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    };

    const stage1 = buildInnerHeaders(baseInner, "config-secret");
    const pageRes = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage1.payload,
          "X-Pow-Inner-Mac": stage1.mac,
          "X-Pow-Inner-Expire": String(stage1.exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");

    const innerWithAtomic = {
      ...baseInner,
      s: {
        ...baseInner.s,
        atomic: {
          ...baseInner.s.atomic,
          captchaToken: JSON.stringify({
            turnstile: turnToken,
            recaptcha_v3: "atomic-recaptcha-token-1234567890",
          }),
          ticketB64: args.ticketB64,
          turnstilePreflight: {
            checked: true,
            ok: true,
            reason: "",
            ticketMac: ticket.mac,
            tokenTag: await captchaTagFromToken(`${turnToken}-mismatch`),
          },
        },
      },
    };
    const stage2 = buildInnerHeaders(innerWithAtomic, "config-secret");
    let turnstileCalls = 0;
    let recaptchaCalls = 0;
    let originCalls = 0;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        turnstileCalls += 1;
      } else if (String(url) === "https://www.google.com/recaptcha/api/siteverify") {
        recaptchaCalls += 1;
      } else {
        originCalls += 1;
      }
      return new Response("ok", { status: 200 });
    };

    const res = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage2.payload,
          "X-Pow-Inner-Mac": stage2.mac,
          "X-Pow-Inner-Expire": String(stage2.exp),
        },
      })
    );
    assert.equal(res.status, 403);
    assert.equal(turnstileCalls, 0);
    assert.equal(recaptchaCalls, 0);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("atomic dual-provider path keeps each snippet <= 2 subrequests", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const powPath = await buildPowModule();
    const configPath = await buildConfigModule("config-secret", {
      configOverrides: {
        turncheck: true,
        recaptchaEnabled: true,
        RECAPTCHA_PAIRS: [{ sitekey: "rk-1", secret: "rs-1" }],
        RECAPTCHA_MIN_SCORE: 0.5,
        ATOMIC_CONSUME: true,
        TURNSTILE_SITEKEY: "sitekey",
        TURNSTILE_SECRET: "turn-secret",
      },
    });
    const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
    const configMod = await import(`${pathToFileURL(configPath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;
    const configHandler = configMod.default.fetch;
    const testing = powMod.__captchaTesting;

    let scope = "";
    const runInScope = async (nextScope, fn) => {
      const prevScope = scope;
      scope = nextScope;
      try {
        return await fn();
      } finally {
        scope = prevScope;
      }
    };

    const counters = { config: 0, pow: 0 };
    let expectedRecaptchaAction = "";
    let currentTicketMac = "";
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = String(request.url || "");
      const inConfig = scope === "config";
      const inPow = scope === "pow";

      if (inConfig && (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count"))) {
        counters.config += 1;
        return runInScope("pow", async () => powHandler(request));
      }

      if (inConfig) counters.config += 1;
      if (inPow) counters.pow += 1;

      if (url === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        return new Response(JSON.stringify({ success: true, cdata: currentTicketMac }), { status: 200 });
      }
      if (url === "https://www.google.com/recaptcha/api/siteverify") {
        return new Response(
          JSON.stringify({
            success: true,
            hostname: "example.com",
            remoteip: "1.2.3.4",
            score: 0.9,
            action: expectedRecaptchaAction,
          }),
          { status: 200 }
        );
      }
      return new Response("ok", { status: 200 });
    };

    const challengeRes = await runInScope("config", async () =>
      configHandler(
        new Request("https://example.com/protected", {
          headers: {
            Accept: "text/html",
            "CF-Connecting-IP": "1.2.3.4",
          },
        })
      )
    );
    assert.equal(challengeRes.status, 200);
    const args = extractChallengeArgs(await challengeRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");
    currentTicketMac = ticket.mac;
    const pair = await testing.pickRecaptchaPair(ticket.mac, [{ sitekey: "rk-1", secret: "rs-1" }]);
    expectedRecaptchaAction = await testing.makeRecaptchaAction(
      decodeB64UrlUtf8(args.bindingB64),
      pair.kid
    );

    counters.config = 0;
    counters.pow = 0;
    const envelope = JSON.stringify({
      turnstile: "atomic-turn-token-1234567890",
      recaptcha_v3: "atomic-recaptcha-token-1234567890",
    });
    const businessRes = await runInScope("config", async () =>
      configHandler(
        new Request(
          `https://example.com/protected?__ts=${encodeURIComponent(envelope)}&__tt=${encodeURIComponent(args.ticketB64)}`,
          {
            headers: {
              Accept: "application/json",
              "CF-Connecting-IP": "1.2.3.4",
            },
          }
        )
      )
    );

    assert.equal(businessRes.status, 200);
    assert.ok(counters.pow <= 2, `pow snippet should stay within 2 subrequests, got ${counters.pow}`);
    assert.ok(
      counters.config <= 2,
      `config snippet should stay within 2 subrequests, got ${counters.config}`
    );
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("atomic recaptcha mode disables proof-cookie bypass", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const powPath = await buildPowModule();
    const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;
    const testing = powMod.__captchaTesting;

    const recaptchaPairs = [{ sitekey: "rk-1", secret: "rs-1" }];
    const baseConfig = {
      powcheck: false,
      turncheck: false,
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: recaptchaPairs,
      RECAPTCHA_MIN_SCORE: 0.5,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 8192,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 8192,
      POW_HASHCASH_BITS: 0,
      POW_SEGMENT_LEN: 32,
      POW_SAMPLE_K: 1,
      POW_SPINE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_FORCE_EDGE_1: true,
      POW_FORCE_EDGE_LAST: true,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_TURN_QUERY: "__ts",
      ATOMIC_TICKET_QUERY: "__tt",
      ATOMIC_CONSUME_QUERY: "__ct",
      ATOMIC_TURN_HEADER: "x-turnstile",
      ATOMIC_TICKET_HEADER: "x-ticket",
      ATOMIC_CONSUME_HEADER: "x-consume",
      ATOMIC_COOKIE_NAME: "__Secure-pow_a",
      STRIP_ATOMIC_QUERY: true,
      STRIP_ATOMIC_HEADERS: true,
      INNER_AUTH_QUERY_NAME: "",
      INNER_AUTH_QUERY_VALUE: "",
      INNER_AUTH_HEADER_NAME: "",
      INNER_AUTH_HEADER_VALUE: "",
      stripInnerAuthQuery: false,
      stripInnerAuthHeader: false,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const configNoAtomic = { ...baseConfig, ATOMIC_CONSUME: false };
    const inner1Obj = {
      v: 1,
      id: 32,
      c: configNoAtomic,
      d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    };
    const inner1 = buildInnerHeaders(inner1Obj, "config-secret");
    const pageRes = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": inner1.payload,
          "X-Pow-Inner-Mac": inner1.mac,
          "X-Pow-Inner-Expire": String(inner1.exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");
    const pair = await testing.pickRecaptchaPair(ticket.mac, recaptchaPairs);
    const expectedAction = await testing.makeRecaptchaAction(decodeB64UrlUtf8(args.bindingB64), pair.kid);

    globalThis.fetch = async (url) => {
      if (String(url) === "https://www.google.com/recaptcha/api/siteverify") {
        return new Response(
          JSON.stringify({
            success: true,
            hostname: "example.com",
            remoteip: "1.2.3.4",
            score: 0.9,
            action: expectedAction,
          }),
          { status: 200 }
        );
      }
      return new Response("ok", { status: 200 });
    };
    const capRes = await powHandler(
      new Request("https://example.com/__pow/cap", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": inner1.payload,
          "X-Pow-Inner-Mac": inner1.mac,
          "X-Pow-Inner-Expire": String(inner1.exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          pathHash: args.pathHash,
          captchaToken: "proof-recaptcha-token-1234567890",
        }),
      })
    );
    assert.equal(capRes.status, 200);
    const proofCookie = (capRes.headers.get("Set-Cookie") || "").split(";")[0];
    assert.ok(proofCookie, "proof cookie issued");

    const configAtomic = { ...baseConfig, ATOMIC_CONSUME: true };
    const inner2Obj = { ...inner1Obj, c: configAtomic };
    const inner2 = buildInnerHeaders(inner2Obj, "config-secret");
    let originCalls = 0;
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response("ok", { status: 200 });
    };
    const res = await powHandler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "application/json",
          Cookie: proofCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": inner2.payload,
          "X-Pow-Inner-Mac": inner2.mac,
          "X-Pow-Inner-Expire": String(inner2.exp),
        },
      })
    );
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { code: "captcha_required" });
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("glue runtime uses captchaTag naming", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const glueSource = await readFile(join(repoRoot, "glue.js"), "utf8");
  assert.match(glueSource, /captchaTagFromToken/u);
  assert.doesNotMatch(glueSource, /\btbFromToken\b/u);
});
