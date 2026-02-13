import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
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

const buildApiEngineTestModule = async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [apiEngineSource, siteverifyClientSource, mhgVerifySource, mhgConstantsSource, mhgGraphSource, mhgHashSource, mhgMixSource, mhgMerkleSource] =
    await Promise.all([
      readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8"),
      readFile(join(repoRoot, "lib", "pow", "siteverify-client.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "verify.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "constants.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "graph.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "hash.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "mix-aes.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "merkle.js"), "utf8"),
    ]);

  const tmpDir = await mkdtemp(join(tmpdir(), "pow-api-engine-test-"));
  await mkdir(join(tmpDir, "lib", "pow"), { recursive: true });
  await mkdir(join(tmpDir, "lib", "mhg"), { recursive: true });

  const apiEngineInjected = `${apiEngineSource}\nexport const __captchaTesting = { verifyRequiredCaptchaForTicket, captchaTagV1 };\n`;

  await Promise.all([
    writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineInjected),
    writeFile(join(tmpDir, "lib", "pow", "siteverify-client.js"), siteverifyClientSource),
    writeFile(join(tmpDir, "lib", "mhg", "verify.js"), mhgVerifySource),
    writeFile(join(tmpDir, "lib", "mhg", "constants.js"), mhgConstantsSource),
    writeFile(join(tmpDir, "lib", "mhg", "graph.js"), mhgGraphSource),
    writeFile(join(tmpDir, "lib", "mhg", "hash.js"), mhgHashSource),
    writeFile(join(tmpDir, "lib", "mhg", "mix-aes.js"), mhgMixSource),
    writeFile(join(tmpDir, "lib", "mhg", "merkle.js"), mhgMerkleSource),
  ]);

  return join(tmpDir, "lib", "pow", "api-engine.js");
};

const loadCaptchaTesting = async () => {
  const modulePath = await buildApiEngineTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  return mod.__captchaTesting;
};

const getApiEngineSource = async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  return readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8");
};

test("cap endpoint is turnstile-only and non-atomic", async () => {
  const source = await getApiEngineSource();
  assert.match(source, /if \(needPow \|\| !needTurn \|\| config\.ATOMIC_CONSUME === true\) return S\(404\);/u);
});

test("canonical captcha parser only accepts turnstile token", async () => {
  const source = await getApiEngineSource();
  assert.match(source, /const resolveCaptchaRequirements = \(config\) => \{\s*const needTurn = config\.turncheck === true;\s*return \{ needTurn \};\s*\};/u);
  assert.match(source, /const parseCanonicalCaptchaTokens = \(captchaToken, needTurn\) =>/u);
  assert.match(source, /if \(!needTurn\) \{\s*return \{ ok: true, malformed: false, tokens: \{ turnstile: "" \} \};/u);
  assert.doesNotMatch(source, /recaptcha_v3/u);
  assert.doesNotMatch(source, /needRecaptcha/u);
  assert.doesNotMatch(source, /const providersRaw = typeof config\.providers === "string"/u);
});

test("turnstile-required flow rejects malformed envelope before aggregator call", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  let called = false;

  try {
    const testing = await loadCaptchaTesting();
    globalThis.fetch = async () => {
      called = true;
      return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), { status: 200 });
    };

    const request = new Request("https://example.com/protected", {
      headers: { "CF-Connecting-IP": "1.2.3.4" },
    });

    const result = await testing.verifyRequiredCaptchaForTicket(
      request,
      {
        turncheck: true,
        TURNSTILE_SECRET: "turn-secret",
        SITEVERIFY_URLS: ["https://sv.example/siteverify"],
        SITEVERIFY_AUTH_KID: "v1",
        SITEVERIFY_AUTH_SECRET: "shared-secret",
      },
      { mac: "ticket-mac-1" },
      JSON.stringify({ wrong: "key" }),
    );

    assert.equal(result.ok, false);
    assert.equal(result.malformed, true);
    assert.equal(called, false);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("valid turnstile envelope reaches aggregator with turnstile payload", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  let calledUrl = "";
  let body = "";

  try {
    const testing = await loadCaptchaTesting();
    globalThis.fetch = async (url, init) => {
      calledUrl = String(url);
      body = init && typeof init.body === "string" ? init.body : "";
      return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), { status: 200 });
    };

    const request = new Request("https://example.com/protected", {
      headers: { "CF-Connecting-IP": "1.2.3.4" },
    });

    const turnstileToken = "turnstile-token-1234567890";
    const result = await testing.verifyRequiredCaptchaForTicket(
      request,
      {
        turncheck: true,
        TURNSTILE_SECRET: "turn-secret",
        SITEVERIFY_URLS: ["https://sv.example/siteverify"],
        SITEVERIFY_AUTH_KID: "v1",
        SITEVERIFY_AUTH_SECRET: "shared-secret",
      },
      { mac: "ticket-mac-1" },
      JSON.stringify({ turnstile: turnstileToken }),
    );

    assert.equal(result.ok, true);
    assert.equal(calledUrl, "https://sv.example/siteverify");
    const payload = JSON.parse(body);
    assert.equal(payload.token.turnstile, turnstileToken);
    assert.equal(payload.providers.turnstile.secret, "turn-secret");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("captchaTagV1 is deterministic for turnstile-only input", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const testing = await loadCaptchaTesting();
    const token = "turnstile-token-1234567890";
    const first = await testing.captchaTagV1(token);
    const second = await testing.captchaTagV1(token);
    const different = await testing.captchaTagV1("turnstile-token-0000000000");

    assert.equal(first, second);
    assert.notEqual(first, different);
    assert.match(first, /^[A-Za-z0-9_-]{16}$/u);
  } finally {
    restoreGlobals();
  }
});
