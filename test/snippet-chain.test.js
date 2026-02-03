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
    assert.equal(innerRequest.headers.get("CF-Connecting-IP"), clientIp);
    assert.ok(originRequest, "origin fetch called");
    assert.equal(originRequest.headers.get("X-Pow-Inner"), null);
    assert.equal(originRequest.headers.get("X-Pow-Inner-Mac"), null);
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
