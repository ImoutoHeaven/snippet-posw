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

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const buildPowModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  const template = await readFile(join(repoRoot, "template.html"), "utf8");
  const injected = powSource.replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template));
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-test-"));
  const tmpPath = join(tmpDir, "pow-test.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

const buildConfigModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powConfigSource = await readFile(join(repoRoot, "pow-config.js"), "utf8");
  const compiledConfig = JSON.stringify([
    {
      host: { s: "^example\\.com$", f: "" },
      path: null,
      config: {
        POW_TOKEN: "test-secret",
        powcheck: true,
        POW_BIND_TLS: false,
        POW_BIND_COUNTRY: false,
        POW_BIND_ASN: false,
        POW_DIFFICULTY_BASE: 64,
        POW_MIN_STEPS: 16,
        POW_MAX_STEPS: 64,
        POW_CHAL_ROUNDS: 2,
        POW_SAMPLE_K: 1,
        POW_OPEN_BATCH: 4,
        POW_HASHCASH_BITS: 0,
        POW_SEGMENT_LEN: 4,
      },
    },
  ]);
  const injected = powConfigSource.replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-config-test-"));
  const tmpPath = join(tmpDir, "pow-config-test.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
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

test("challenge rejects binding mismatch after commit", async () => {
  const restoreGlobals = ensureGlobals();
  const powModulePath = await buildPowModule();
  const configModulePath = await buildConfigModule();
  const powMod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configModulePath).href}?v=${Date.now()}`);
  const powHandler = powMod.default.fetch;
  const configHandler = configMod.default.fetch;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      const hasInner = Array.from(request.headers.keys()).some((key) =>
        key.toLowerCase().startsWith("x-pow-inner")
      );
      if (hasInner) {
        return powHandler(request);
      }
      return new Response("ok", { status: 200 });
    };

    const ipPrimary = "1.2.3.4";
    const pageRes = await configHandler(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": ipPrimary,
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const cspHeader = pageRes.headers.get("Content-Security-Policy");
    assert.ok(
      cspHeader && cspHeader.includes("frame-ancestors 'none'"),
      "challenge page sets frame-ancestors to none"
    );
    assert.equal(pageRes.headers.get("X-Frame-Options"), "DENY");
    const html = await pageRes.text();
    const args = extractChallengeArgs(html);
    assert.ok(args, "challenge html includes args");

    const rootB64 = base64Url(crypto.randomBytes(32));
    const nonce = base64Url(crypto.randomBytes(12));
    const commitRes = await configHandler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": ipPrimary,
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64,
          pathHash: args.pathHash,
          nonce,
        }),
      })
    );
    assert.equal(commitRes.status, 200);
    const setCookie = commitRes.headers.get("Set-Cookie");
    assert.ok(setCookie, "commit sets cookie");
    assert.ok(setCookie.includes("SameSite=Lax"), "commit cookie uses SameSite=Lax");
    const commitCookie = setCookie.split(";")[0];

    const challengeResPrimary = await configHandler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": ipPrimary,
          Cookie: commitCookie,
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(challengeResPrimary.status, 200);
    const challengePayload = await challengeResPrimary.json();
    assert.equal(challengePayload.done, false);
    assert.equal(challengePayload.cursor, 0);
    assert.ok(Array.isArray(challengePayload.indices));
    assert.ok(challengePayload.indices.length > 0);
    assert.ok(challengePayload.indices.every((value) => Number.isInteger(value)));
    assert.ok(Array.isArray(challengePayload.segs));
    assert.equal(challengePayload.segs.length, challengePayload.indices.length);
    assert.ok(challengePayload.segs.every((value) => Number.isInteger(value)));
    assert.ok(typeof challengePayload.token === "string");
    assert.ok(challengePayload.token.length > 0);
    assert.ok(typeof challengePayload.sid === "string");
    assert.ok(challengePayload.sid.length > 0);
    assert.ok(Array.isArray(challengePayload.spinePos));

    const ipSecondary = "5.6.7.8";
    const challengeRes = await configHandler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": ipSecondary,
          Cookie: commitCookie,
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(challengeRes.status, 403);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
