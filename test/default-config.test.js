import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { __testNormalizeConfig } from "../pow-config.js";

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

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const FULL_CONFIG = {
  powcheck: false,
  turncheck: false,
  bindPathMode: "none",
  bindPathQueryName: "path",
  bindPathHeaderName: "",
  stripBindPathHeader: false,
  POW_VERSION: 3,
  POW_API_PREFIX: "/__pow",
  POW_DIFFICULTY_BASE: 8192,
  POW_DIFFICULTY_COEFF: 1.0,
  POW_MIN_STEPS: 512,
  POW_MAX_STEPS: 8192,
  POW_HASHCASH_BITS: 3,
  POW_PAGE_BYTES: 16384,
  POW_MIX_ROUNDS: 2,
  POW_SEGMENT_LEN: 2,
  POW_SAMPLE_K: 15,
  POW_CHAL_ROUNDS: 12,
  POW_OPEN_BATCH: 15,
  POW_COMMIT_TTL_SEC: 120,
  POW_MAX_GEN_TIME_SEC: 300,
  POW_TICKET_TTL_SEC: 600,
  PROOF_TTL_SEC: 600,
  PROOF_RENEW_ENABLE: false,
  PROOF_RENEW_MAX: 2,
  PROOF_RENEW_WINDOW_SEC: 90,
  PROOF_RENEW_MIN_SEC: 30,
  ATOMIC_CONSUME: false,
  AGGREGATOR_POW_ATOMIC_CONSUME: false,
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
  POW_BIND_TLS: true,
  IPV4_PREFIX: 32,
  IPV6_PREFIX: 64,
  POW_COMMIT_COOKIE: "__Host-pow_commit",
  POW_ESM_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@412f7fcc71c319b62a614e4252280f2bb3d7302b/esm/esm.js",
  POW_GLUE_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@412f7fcc71c319b62a614e4252280f2bb3d7302b/glue.js",
};

const FULL_STRATEGY = {
  nav: {},
  bypass: { bypass: false },
  bind: { ok: true, code: "", canonicalPath: "/path" },
  atomic: {
    captchaToken: "",
    ticketB64: "",
    consumeToken: "",
    fromCookie: false,
    cookieName: "__Secure-pow_a",
  },
};

test("normalizeConfig includes siteverify aggregator keys", () => {
  const cfg = __testNormalizeConfig({});
  assert.equal("SITEVERIFY_URL" in cfg, false);
  assert.equal(Array.isArray(cfg.SITEVERIFY_URLS), true);
  assert.equal(typeof cfg.SITEVERIFY_AUTH_KID, "string");
  assert.equal(typeof cfg.SITEVERIFY_AUTH_SECRET, "string");
});

test("normalizeConfig keeps valid siteverify aggregator URL shards", () => {
  const cfg = __testNormalizeConfig({
    SITEVERIFY_URLS: [
      "https://sv-1.example/siteverify",
      "  https://sv-2.example/siteverify  ",
      "",
      null,
      123,
    ],
  });

  assert.equal("SITEVERIFY_URL" in cfg, false);
  assert.deepEqual(cfg.SITEVERIFY_URLS, [
    "https://sv-1.example/siteverify",
    "https://sv-2.example/siteverify",
  ]);
});

test("normalizeConfig exposes turnstile-only captcha surface", () => {
  const cfg = __testNormalizeConfig({});
  assert.equal("recaptchaEnabled" in cfg, false);
  assert.equal("RECAPTCHA_PAIRS" in cfg, false);
  assert.equal("RECAPTCHA_ACTION" in cfg, false);
  assert.equal("RECAPTCHA_MIN_SCORE" in cfg, false);
  assert.equal(cfg.AGGREGATOR_POW_ATOMIC_CONSUME, false);
});

const buildInnerHeaders = (payloadObj, secret, expOverride) => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const exp = Number.isFinite(expOverride)
    ? expOverride
    : Math.floor(Date.now() / 1000) + 3;
  const macInput = `${payload}.${exp}`;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(macInput).digest());
  return { payload, mac, exp };
};

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const readOptionalFile = async (filePath) => {
  try {
    return await readFile(filePath, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") return null;
    throw error;
  }
};

const buildTestModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [
    core1Raw,
    core2Raw,
    transitSource,
    innerAuthSource,
    internalHeadersSource,
    apiEngineSource,
    businessGateSource,
    siteverifyClientSource,
    templateSource,
    mhgGraphSource,
    mhgHashSource,
    mhgMixSource,
    mhgMerkleSource,
    mhgVerifySource,
    mhgConstantsSource,
  ] = await Promise.all([
    readFile(join(repoRoot, "pow-core-1.js"), "utf8"),
    readFile(join(repoRoot, "pow-core-2.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "transit-auth.js"), "utf8"),
    readOptionalFile(join(repoRoot, "lib", "pow", "inner-auth.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "internal-headers.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "api-engine.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "business-gate.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "siteverify-client.js")),
    readFile(join(repoRoot, "template.html"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "graph.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "hash.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "mix-aes.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "merkle.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "verify.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "constants.js"), "utf8"),
  ]);

  const core1Source = replaceConfigSecret(core1Raw, secret);
  const core2Source = replaceConfigSecret(core2Raw, secret);
  const businessGateInjected =
    businessGateSource === null
      ? null
      : businessGateSource.replace(/__HTML_TEMPLATE__/gu, JSON.stringify(templateSource));

  const tmpDir = await mkdtemp(join(tmpdir(), "pow-split-test-"));
  await mkdir(join(tmpDir, "lib", "pow"), { recursive: true });
  await mkdir(join(tmpDir, "lib", "mhg"), { recursive: true });
  const writes = [
    writeFile(join(tmpDir, "pow-core-1.js"), core1Source),
    writeFile(join(tmpDir, "pow-core-2.js"), core2Source),
    writeFile(join(tmpDir, "lib", "pow", "transit-auth.js"), transitSource),
    writeFile(join(tmpDir, "lib", "mhg", "graph.js"), mhgGraphSource),
    writeFile(join(tmpDir, "lib", "mhg", "hash.js"), mhgHashSource),
    writeFile(join(tmpDir, "lib", "mhg", "mix-aes.js"), mhgMixSource),
    writeFile(join(tmpDir, "lib", "mhg", "merkle.js"), mhgMerkleSource),
    writeFile(join(tmpDir, "lib", "mhg", "verify.js"), mhgVerifySource),
    writeFile(join(tmpDir, "lib", "mhg", "constants.js"), mhgConstantsSource),
  ];
  if (innerAuthSource !== null) writes.push(writeFile(join(tmpDir, "lib", "pow", "inner-auth.js"), innerAuthSource));
  if (internalHeadersSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "internal-headers.js"), internalHeadersSource));
  }
  if (apiEngineSource !== null) writes.push(writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineSource));
  if (businessGateInjected !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "business-gate.js"), businessGateInjected));
  }
  if (siteverifyClientSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "siteverify-client.js"), siteverifyClientSource));
  }

  const secretLiteral = JSON.stringify(secret);
  const bridgeSource = `
import core1 from "./pow-core-1.js";
import core2 from "./pow-core-2.js";
import { issueTransit } from "./lib/pow/transit-auth.js";

const CONFIG_SECRET = ${secretLiteral};
const API_PREFIX = "/__pow";

const stripPowHeaders = (request) => {
  const headers = new Headers(request.headers);
  for (const key of Array.from(headers.keys())) {
    const lower = key.toLowerCase();
    if (lower.startsWith("x-pow-inner") || lower.startsWith("x-pow-transit")) {
      headers.delete(key);
    }
  }
  return new Request(request, { headers });
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith(API_PREFIX + "/")) {
      const transit = await issueTransit({
        secret: CONFIG_SECRET,
        method: request.method,
        pathname: url.pathname,
        kind: "api",
        apiPrefix: API_PREFIX,
      });
      if (!transit) return new Response(null, { status: 500 });
      const headers = new Headers(request.headers);
      for (const [key, value] of Object.entries(transit.headers)) headers.set(key, value);
      return core2.fetch(new Request(request, { headers }), env, ctx);
    }

    const upstreamFetch = globalThis.fetch;
    try {
      globalThis.fetch = async (input, init) => {
        const req = input instanceof Request ? input : new Request(input, init);
        if (req.headers.has("X-Pow-Transit")) return core2.fetch(req, env, ctx);
        if (typeof upstreamFetch === "function") return upstreamFetch(stripPowHeaders(req), init);
        return new Response(null, { status: 500 });
      };
      return await core1.fetch(request, env, ctx);
    } finally {
      globalThis.fetch = upstreamFetch;
    }
  },
};
`;
  writes.push(writeFile(join(tmpDir, "pow-test.js"), bridgeSource));
  await Promise.all(writes);

  return join(tmpDir, "pow-test.js");
};

test("split core bridge fails closed without inner header", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("ok", { status: 200 });

    const res = await handler(new Request("https://example.com/protected"));
    assert.equal(res.status, 500);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge rejects placeholder CONFIG_SECRET", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule("replace-me");
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
        s: FULL_STRATEGY,
      },
      "replace-me"
    );
    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 500);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("valid inner header passes through", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
        s: FULL_STRATEGY,
      },
      "config-secret"
    );
    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 200);
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge rejects expired inner header", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const now = Math.floor(Date.now() / 1000);
    const expiredExp = now - 10;
    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
        s: FULL_STRATEGY,
      },
      "config-secret",
      expiredExp
    );
    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 500);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge rejects future inner header", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const now = Math.floor(Date.now() / 1000);
    const futureExp = now + 10;
    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
        s: FULL_STRATEGY,
      },
      "config-secret",
      futureExp
    );
    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 500);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge fails closed when inner strategy snapshot is missing", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
      },
      "config-secret"
    );

    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 500);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge fails closed when inner strategy is malformed", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          ...FULL_STRATEGY,
          bind: { ok: "true", code: "", canonicalPath: "/path" },
        },
      },
      "config-secret"
    );

    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 500);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge fail-closes bind missing/invalid from inner.s with 400", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    for (const code of ["missing", "invalid"]) {
      const { payload, mac, exp } = buildInnerHeaders(
        {
          v: 1,
          id: 0,
          c: { ...FULL_CONFIG, powcheck: true, POW_BIND_TLS: false, POW_TOKEN: "test" },
          d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
          s: {
            ...FULL_STRATEGY,
            bind: { ok: false, code, canonicalPath: "/path" },
          },
        },
        "config-secret"
      );

      const res = await handler(
        new Request("https://no-match.test/path", {
          headers: {
            "X-Pow-Inner": payload,
            "X-Pow-Inner-Mac": mac,
            "X-Pow-Inner-Expire": exp.toString(10),
          },
        })
      );
      assert.equal(res.status, 400);
    }

    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge bypasses directly when inner.s.bypass.bypass is true", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, powcheck: true, POW_BIND_TLS: false, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          ...FULL_STRATEGY,
          bypass: { bypass: true },
          bind: { ok: false, code: "missing", canonicalPath: "/path" },
        },
      },
      "config-secret"
    );

    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 200);
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("requiredMask only uses pow+turn bits", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const apiEngineSource = await readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8");
  assert.match(apiEngineSource, /const requiredMask = \(needPow \? 1 : 0\) \| \(needTurn \? 2 : 0\);/u);
  assert.doesNotMatch(apiEngineSource, /needRecaptcha/u);
  assert.doesNotMatch(apiEngineSource, /const providersRaw = typeof config\.providers === "string"/u);
});

test("cap proof issuance uses computed requiredMask", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const apiEngineSource = await readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8");
  assert.match(apiEngineSource, /const handleCap = async \(/u);
  assert.match(apiEngineSource, /const requiredMask = \(needPow \? 1 : 0\) \| \(needTurn \? 2 : 0\);/u);
  assert.match(apiEngineSource, /if \(needPow \|\| !needTurn \|\| config\.ATOMIC_CONSUME === true\) return S\(404\);/u);
  assert.match(apiEngineSource, /await issueProofCookie\([\s\S]*requiredMask/u);
  assert.doesNotMatch(
    apiEngineSource,
    /const handleCap = async \([\s\S]*?await issueProofCookie\([\s\S]*?\n\s*2\s*\n\s*\);/u
  );
});

test("mask enforcement keeps bitwise AND semantics", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const businessGateSource = await readFile(join(repoRoot, "lib", "pow", "business-gate.js"), "utf8");
  assert.match(businessGateSource, /if \(\(parsed\.m & requiredMask\) !== requiredMask\) return null;/u);
  assert.match(businessGateSource, /if \(\(proof\.m & requiredMask\) !== requiredMask\) return null;/u);
});

test("README documents split-chain deployment and snippet contracts", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const readme = await readFile(join(repoRoot, "README.md"), "utf8");

  assert.match(readme, /`pow-core-1\.js`/u);
  assert.match(readme, /`pow-core-2\.js`/u);
  assert.match(readme, /pow_config_snippet\.js/u);
  assert.match(readme, /pow_core1_snippet\.js/u);
  assert.match(readme, /pow_core2_snippet\.js/u);
  assert.match(readme, /pow-config\s*->\s*pow-core-1\s*->\s*pow-core-2/u);
  assert.match(readme, /fail-closed/u);
  assert.match(readme, /no compat/u);
  assert.match(readme, /32\s*KiB.*hard/u);
  assert.match(readme, /23\s*KiB.*best-effort/u);
  assert.match(
    readme,
    /Subrequest matrix \(API \+ business paths\):[\s\S]*\| Flow \| `pow-config` subrequests \| `pow-core-1` subrequests \| `pow-core-2` subrequests \| Total \|/u
  );
  assert.doesNotMatch(readme, /### Flow Analysis Table/u);
  assert.doesNotMatch(readme, /\bpow\.js\b/u);
});
