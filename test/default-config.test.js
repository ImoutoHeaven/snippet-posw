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

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const FULL_CONFIG = {
  powcheck: false,
  turncheck: false,
  recaptchaEnabled: false,
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
  POW_SEGMENT_LEN: "48-64",
  POW_SAMPLE_K: 15,
  POW_SPINE_K: 2,
  POW_CHAL_ROUNDS: 12,
  POW_OPEN_BATCH: 15,
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
  POW_BIND_TLS: true,
  IPV4_PREFIX: 32,
  IPV6_PREFIX: 64,
  POW_COMMIT_COOKIE: "__Host-pow_commit",
  POW_ESM_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@412f7fcc71c319b62a614e4252280f2bb3d7302b/esm/esm.js",
  POW_GLUE_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@412f7fcc71c319b62a614e4252280f2bb3d7302b/glue.js",
  RECAPTCHA_PAIRS: [],
  RECAPTCHA_ACTION: "submit",
  RECAPTCHA_MIN_SCORE: 0.5,
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

const buildTestModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  const template = await readFile(join(repoRoot, "template.html"), "utf8");
  const compiledConfig = JSON.stringify([
    {
      host: { s: "^example\\.com$", f: "" },
      path: null,
      config: { POW_TOKEN: "test", powcheck: true, POW_BIND_TLS: false },
    },
  ]);
  const injected = powSource
    .replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template))
    .replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-test-"));
  const tmpPath = join(tmpDir, "pow-test.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

test("pow.js fails closed without inner header", async () => {
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

test("pow.js rejects placeholder CONFIG_SECRET", async () => {
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

test("pow.js rejects expired inner header", async () => {
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

test("pow.js rejects future inner header", async () => {
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

test("pow.js fails closed when inner strategy snapshot is missing", async () => {
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

test("pow.js fails closed when inner strategy is malformed", async () => {
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

test("pow.js fail-closes bind missing/invalid from inner.s with 400", async () => {
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

test("pow.js bypasses directly when inner.s.bypass.bypass is true", async () => {
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

test("requiredMask includes recaptcha bit in main gate", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  assert.match(
    powSource,
    /const requiredMask = \(needPow \? 1 : 0\) \| \(needTurn \? 2 : 0\) \| \(needRecaptcha \? 4 : 0\);/u
  );
});

test("cap proof issuance uses computed requiredMask", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  assert.match(
    powSource,
    /const handleCap = async \([\s\S]*?const requiredMask = \(needPow \? 1 : 0\) \| \(needTurn \? 2 : 0\) \| \(needRecaptcha \? 4 : 0\);[\s\S]*?await issueProofCookie\([\s\S]*?requiredMask\s*\);/u
  );
  assert.doesNotMatch(
    powSource,
    /const handleCap = async \([\s\S]*?await issueProofCookie\([\s\S]*?\n\s*2\s*\n\s*\);/u
  );
});

test("mask enforcement keeps bitwise AND semantics", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  assert.match(powSource, /if \(\(parsed\.m & requiredMask\) !== requiredMask\) return null;/u);
  assert.match(powSource, /if \(\(proof\.m & requiredMask\) !== requiredMask\) return null;/u);
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
  assert.match(
    readme,
    /### Flow Analysis Table[\s\S]*\| # \|[\s\S]*`pow-core-1` subrequests[\s\S]*`pow-core-2` subrequests/u
  );
  assert.doesNotMatch(readme, /\bpow\.js\b/u);
});
