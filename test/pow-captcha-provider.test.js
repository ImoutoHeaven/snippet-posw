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

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const buildCore1Module = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [
    core1SourceRaw,
    core2SourceRaw,
    transitSource,
    innerAuthSource,
    internalHeadersSource,
    apiEngineSource,
    businessGateSource,
    templateSource,
    mhgGraphSource,
    mhgMixSource,
    mhgMerkleSource,
  ] = await Promise.all([
    readFile(join(repoRoot, "pow-core-1.js"), "utf8"),
    readFile(join(repoRoot, "pow-core-2.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "transit-auth.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "inner-auth.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "internal-headers.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "business-gate.js"), "utf8"),
    readFile(join(repoRoot, "template.html"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "graph.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "mix-aes.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "merkle.js"), "utf8"),
  ]);

  const core1Source = replaceConfigSecret(core1SourceRaw, secret);
  const core2Source = replaceConfigSecret(core2SourceRaw, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-provider-test-"));
  await mkdir(join(tmpDir, "lib", "pow"), { recursive: true });
  await mkdir(join(tmpDir, "lib", "mhg"), { recursive: true });
  const businessGateInjected = businessGateSource
    .replace(
    /__HTML_TEMPLATE__/gu,
    JSON.stringify(templateSource)
    )
    .concat(
      "\nexport const __captchaTesting = { pickRecaptchaPair, captchaTagV1, verifyCaptchaForTicket };\n"
    );
  const writes = [
    writeFile(join(tmpDir, "pow-core-1.js"), core1Source),
    writeFile(join(tmpDir, "pow-core-2.js"), core2Source),
    writeFile(join(tmpDir, "lib", "pow", "transit-auth.js"), transitSource),
    writeFile(join(tmpDir, "lib", "pow", "inner-auth.js"), innerAuthSource),
    writeFile(join(tmpDir, "lib", "pow", "internal-headers.js"), internalHeadersSource),
    writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineSource),
    writeFile(join(tmpDir, "lib", "pow", "business-gate.js"), businessGateInjected),
    writeFile(join(tmpDir, "lib", "mhg", "graph.js"), mhgGraphSource),
    writeFile(join(tmpDir, "lib", "mhg", "mix-aes.js"), mhgMixSource),
    writeFile(join(tmpDir, "lib", "mhg", "merkle.js"), mhgMerkleSource),
  ];

  const harnessSource = `
import core1 from "./pow-core-1.js";
import core2 from "./pow-core-2.js";
import * as businessGate from "./lib/pow/business-gate.js";

const toRequest = (input, init) =>
  input instanceof Request ? input : new Request(input, init);

const isTransitRequest = (request) =>
  request.headers.has("X-Pow-Transit");

export default {
  async fetch(request) {
    const upstreamFetch = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const nextRequest = toRequest(input, init);
      if (isTransitRequest(nextRequest)) {
        return core2.fetch(nextRequest);
      }
      return upstreamFetch(input, init);
    };
    try {
      return await core1.fetch(request);
    } finally {
      globalThis.fetch = upstreamFetch;
    }
  },
};

export const __captchaTesting = {
  pickRecaptchaPair: businessGate.__captchaTesting.pickRecaptchaPair,
  captchaTagV1: businessGate.__captchaTesting.captchaTagV1,
  verifyCaptchaForTicket: businessGate.__captchaTesting.verifyCaptchaForTicket,
};
`;
  const tmpPath = join(tmpDir, "pow-provider-test.js");
  writes.push(writeFile(tmpPath, harnessSource));

  await Promise.all(writes);
  return tmpPath;
};

const loadTestingApi = async () => {
  const modulePath = await buildCore1Module();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  assert.equal(typeof mod.default?.fetch, "function");
  return mod.__captchaTesting;
};

test("deterministically selects recaptcha pair from ticket.mac", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const testing = await loadTestingApi();
    const pairs = [
      { sitekey: "rk-1", secret: "rs-1" },
      { sitekey: "rk-2", secret: "rs-2" },
      { sitekey: "rk-3", secret: "rs-3" },
    ];

    const first = await testing.pickRecaptchaPair("ticket-mac-1", pairs);
    const second = await testing.pickRecaptchaPair("ticket-mac-1", pairs);
    assert.equal(first.kid, second.kid);
    assert.deepEqual(first.pair, second.pair);
    assert.ok(first.kid >= 0 && first.kid < pairs.length);
  } finally {
    restoreGlobals();
  }
});

test("captcha testing API does not expose recaptcha action derivation helper", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const testing = await loadTestingApi();
    assert.equal("makeRecaptchaAction" in testing, false);
  } finally {
    restoreGlobals();
  }
});

test("captchaTag(v1) binds turnstile and recaptcha tokens", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const testing = await loadTestingApi();
    const turn = "turn-token-1234567890";
    const recaptcha = "recaptcha-token-1234567890";
    const dual = await testing.captchaTagV1(turn, recaptcha);
    const onlyTurn = await testing.captchaTagV1(turn, "");
    const onlyRecaptcha = await testing.captchaTagV1("", recaptcha);

    const expected = Buffer.from(
      await crypto.webcrypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(`ctag|v1|t=${turn}|r=${recaptcha}`)
      )
    )
      .subarray(0, 12)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/u, "");

    assert.equal(dual, expected);
    assert.match(dual, /^[A-Za-z0-9_-]{16}$/u);
    assert.notEqual(dual, onlyTurn);
    assert.notEqual(dual, onlyRecaptcha);
  } finally {
    restoreGlobals();
  }
});

test("recaptcha verify requires hostname score action remoteip", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const testing = await loadTestingApi();
    const request = new Request("https://example.com/protected", {
      headers: { "CF-Connecting-IP": "1.2.3.4" },
    });

    const runCase = async (payload) => {
      let calledUrl = "";
      globalThis.fetch = async (url) => {
        calledUrl = String(url);
        return new Response(JSON.stringify(payload), { status: 200 });
      };
      const ok = await testing.verifyCaptchaForTicket(request, {
        provider: "recaptcha_v3",
        secret: "recaptcha-secret",
        token: "recaptcha-token",
        ticketMac: "unused-for-recaptcha",
        action: "submit",
        minScore: 0.7,
      });
      return { ok, calledUrl };
    };

    const expectedAction = "submit";

    const pass = await runCase({
      success: true,
      hostname: "example.com",
      remoteip: "1.2.3.4",
      score: 0.9,
      action: expectedAction,
    });
    assert.equal(pass.ok, true);
    assert.equal(pass.calledUrl, "https://www.google.com/recaptcha/api/siteverify");

    const noHostname = await runCase({
      success: true,
      remoteip: "1.2.3.4",
      score: 0.9,
      action: expectedAction,
    });
    assert.equal(noHostname.ok, false);

    const badScore = await runCase({
      success: true,
      hostname: "example.com",
      remoteip: "1.2.3.4",
      score: 0.5,
      action: expectedAction,
    });
    assert.equal(badScore.ok, false);

    const noRemoteIp = await runCase({
      success: true,
      hostname: "example.com",
      score: 0.9,
      action: expectedAction,
    });
    assert.equal(noRemoteIp.ok, true);

    const badAction = await runCase({
      success: true,
      hostname: "example.com",
      remoteip: "1.2.3.4",
      score: 0.9,
      action: "wrong-action",
    });
    assert.equal(badAction.ok, false);

    const badRemoteIp = await runCase({
      success: true,
      hostname: "example.com",
      remoteip: "9.9.9.9",
      score: 0.9,
      action: expectedAction,
    });
    assert.equal(badRemoteIp.ok, false);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("turnstile verify still requires cdata binding", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const testing = await loadTestingApi();
    const request = new Request("https://example.com/protected", {
      headers: { "CF-Connecting-IP": "1.2.3.4" },
    });

    let calledUrl = "";
    globalThis.fetch = async (url) => {
      calledUrl = String(url);
      return new Response(JSON.stringify({ success: true, cdata: "mismatch" }), { status: 200 });
    };
    const mismatch = await testing.verifyCaptchaForTicket(request, {
      provider: "turnstile",
      secret: "turnstile-secret",
      token: "turnstile-token-value",
      ticketMac: "expected-mac",
    });
    assert.equal(mismatch, false);
    assert.equal(calledUrl, "https://challenges.cloudflare.com/turnstile/v0/siteverify");

    globalThis.fetch = async () =>
      new Response(JSON.stringify({ success: true, cdata: "expected-mac" }), { status: 200 });
    const match = await testing.verifyCaptchaForTicket(request, {
      provider: "turnstile",
      secret: "turnstile-secret",
      token: "turnstile-token-value",
      ticketMac: "expected-mac",
    });
    assert.equal(match, true);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
