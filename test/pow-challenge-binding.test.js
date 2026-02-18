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

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const buildSplitHarnessModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [
    core1SourceRaw,
    core2SourceRaw,
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

  const core1Source = replaceConfigSecret(core1SourceRaw, secret);
  const core2Source = replaceConfigSecret(core2SourceRaw, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-test-"));
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
  if (innerAuthSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "inner-auth.js"), innerAuthSource));
  }
  if (internalHeadersSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "internal-headers.js"), internalHeadersSource));
  }
  if (apiEngineSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineSource));
  }
  if (businessGateSource !== null) {
    const businessGateInjected = businessGateSource.replace(
      /__HTML_TEMPLATE__/gu,
      JSON.stringify(templateSource),
    );
    writes.push(writeFile(join(tmpDir, "lib", "pow", "business-gate.js"), businessGateInjected));
  }
  if (siteverifyClientSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "siteverify-client.js"), siteverifyClientSource));
  }

const harnessSource = `
import core1 from "./pow-core-1.js";
import core2 from "./pow-core-2.js";

const toRequest = (input, init) =>
  input instanceof Request ? input : new Request(input, init);

const isTransitRequest = (request) =>
  request.headers.has("X-Pow-Transit");

const splitTrace = {
  core1Calls: 0,
  core2Calls: 0,
  originCalls: 0,
};

export default {
  async fetch(request) {
    const upstreamFetch = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const nextRequest = toRequest(input, init);
      if (isTransitRequest(nextRequest)) {
        splitTrace.core2Calls += 1;
        return core2.fetch(nextRequest);
      }
      splitTrace.originCalls += 1;
      return upstreamFetch(input, init);
    };
    try {
      splitTrace.core1Calls += 1;
      return await core1.fetch(request);
    } finally {
      globalThis.fetch = upstreamFetch;
    }
  },
};

export const __splitTrace = splitTrace;
`;
  const splitHarnessPath = join(tmpDir, "split-core-harness.js");
  writes.push(writeFile(splitHarnessPath, harnessSource));

  await Promise.all(writes);
  return splitHarnessPath;
};

const buildConfigModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [powConfigSource, runtimeSource, pathGlobSource, lruCacheSource] = await Promise.all([
    readFile(join(repoRoot, "pow-config.js"), "utf8"),
    readFile(join(repoRoot, "lib", "rule-engine", "runtime.js"), "utf8"),
    readFile(join(repoRoot, "lib", "rule-engine", "path-glob.js"), "utf8"),
    readFile(join(repoRoot, "lib", "rule-engine", "lru-cache.js"), "utf8"),
  ]);
  const compiledConfig = JSON.stringify([
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
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
        POW_PAGE_BYTES: 16384,
        POW_MIX_ROUNDS: 2,
        POW_SEGMENT_LEN: 4,
      },
    },
  ]);
  const injected = powConfigSource.replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-config-test-"));
  await mkdir(join(tmpDir, "lib", "rule-engine"), { recursive: true });
  await writeFile(join(tmpDir, "lib", "rule-engine", "runtime.js"), runtimeSource);
  await writeFile(join(tmpDir, "lib", "rule-engine", "path-glob.js"), pathGlobSource);
  await writeFile(join(tmpDir, "lib", "rule-engine", "lru-cache.js"), lruCacheSource);
  const tmpPath = join(tmpDir, "pow-config-test.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

const readOptionalFile = async (filePath) => {
  try {
    return await readFile(filePath, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
};

const buildCore2Module = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [
    core2SourceRaw,
    transitSource,
    innerAuthSource,
    internalHeadersSource,
    apiEngineSource,
    siteverifyClientSource,
    mhgGraphSource,
    mhgHashSource,
    mhgMixSource,
    mhgMerkleSource,
    mhgVerifySource,
    mhgConstantsSource,
  ] =
    await Promise.all([
      readFile(join(repoRoot, "pow-core-2.js"), "utf8"),
      readFile(join(repoRoot, "lib", "pow", "transit-auth.js"), "utf8"),
      readFile(join(repoRoot, "lib", "pow", "inner-auth.js"), "utf8"),
      readFile(join(repoRoot, "lib", "pow", "internal-headers.js"), "utf8"),
      readOptionalFile(join(repoRoot, "lib", "pow", "api-engine.js")),
      readOptionalFile(join(repoRoot, "lib", "pow", "siteverify-client.js")),
      readFile(join(repoRoot, "lib", "mhg", "graph.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "hash.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "mix-aes.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "merkle.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "verify.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "constants.js"), "utf8"),
    ]);

  const core2Source = replaceConfigSecret(core2SourceRaw, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-core2-binding-test-"));
  await mkdir(join(tmpDir, "lib", "pow"), { recursive: true });
  await mkdir(join(tmpDir, "lib", "mhg"), { recursive: true });
  const writes = [
    writeFile(join(tmpDir, "pow-core-2.js"), core2Source),
    writeFile(join(tmpDir, "lib", "pow", "transit-auth.js"), transitSource),
    writeFile(join(tmpDir, "lib", "pow", "inner-auth.js"), innerAuthSource),
    writeFile(join(tmpDir, "lib", "pow", "internal-headers.js"), internalHeadersSource),
    writeFile(join(tmpDir, "lib", "mhg", "graph.js"), mhgGraphSource),
    writeFile(join(tmpDir, "lib", "mhg", "hash.js"), mhgHashSource),
    writeFile(join(tmpDir, "lib", "mhg", "mix-aes.js"), mhgMixSource),
    writeFile(join(tmpDir, "lib", "mhg", "merkle.js"), mhgMerkleSource),
    writeFile(join(tmpDir, "lib", "mhg", "verify.js"), mhgVerifySource),
    writeFile(join(tmpDir, "lib", "mhg", "constants.js"), mhgConstantsSource),
  ];
  if (apiEngineSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineSource));
  }
  if (siteverifyClientSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "siteverify-client.js"), siteverifyClientSource));
  }
  await Promise.all(writes);

  const core2Mod = await import(`${pathToFileURL(join(tmpDir, "pow-core-2.js")).href}?v=${Date.now()}`);
  return core2Mod.default.fetch;
};

const normalizeApiPrefix = (value) => {
  if (typeof value !== "string") return "/__pow";
  const trimmed = value.trim();
  if (!trimmed) return "/__pow";
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  const normalized = withSlash.replace(/\/+$/u, "");
  return normalized || "/__pow";
};

const makeTransitHeaders = ({ secret, exp, kind, method, pathname, apiPrefix }) => {
  const normalizedMethod = typeof method === "string" && method ? method.toUpperCase() : "GET";
  const normalizedPath =
    typeof pathname === "string" && pathname
      ? pathname.startsWith("/")
        ? pathname
        : `/${pathname}`
      : "/";
  const normalizedApiPrefix = normalizeApiPrefix(apiPrefix);
  const macInput = `v1|${exp}|${kind}|${normalizedMethod}|${normalizedPath}|${normalizedApiPrefix}`;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(macInput).digest());
  return {
    "X-Pow-Transit": kind,
    "X-Pow-Transit-Mac": mac,
    "X-Pow-Transit-Expire": String(exp),
    "X-Pow-Transit-Api-Prefix": normalizedApiPrefix,
  };
};

const sha256Base64Url = (value) =>
  base64Url(crypto.createHash("sha256").update(String(value || "")).digest());

const makePowBindingString = (
  ticket,
  hostname,
  pathHash,
  ipScope,
  country,
  asn,
  tlsFingerprint,
  pageBytes,
  mixRounds,
) => {
  const host = typeof hostname === "string" ? hostname.toLowerCase() : "";
  return `${ticket.v}|${ticket.e}|${ticket.L}|${ticket.r}|${ticket.cfgId}|${host}|${pathHash}|${ipScope}|${country}|${asn}|${tlsFingerprint}|${pageBytes}|${mixRounds}|${ticket.issuedAt}`;
};

const resolveBindingValues = (payloadObj, pathHash) => ({
  pathHash: payloadObj.c.POW_BIND_PATH === false ? "any" : pathHash,
  ipScope: payloadObj.c.POW_BIND_IPRANGE === false ? "any" : payloadObj.d.ipScope,
  country: payloadObj.c.POW_BIND_COUNTRY === true ? payloadObj.d.country : "any",
  asn: payloadObj.c.POW_BIND_ASN === true ? payloadObj.d.asn : "any",
  tlsFingerprint: payloadObj.c.POW_BIND_TLS === true ? payloadObj.d.tlsFingerprint : "any",
});

const makeTicketFromPayload = ({ payloadObj, pathHash, host = "example.com" }) => {
  const ticket = {
    v: payloadObj.c.POW_VERSION,
    e: Math.floor(Date.now() / 1000) + 300,
    L: 20,
    r: base64Url(crypto.randomBytes(16)),
    cfgId: payloadObj.id,
    issuedAt: Math.floor(Date.now() / 1000),
    mac: "",
  };
  const binding = resolveBindingValues(payloadObj, pathHash);
  const pageBytes = Math.max(1, Math.floor(Number(payloadObj.c.POW_PAGE_BYTES) || 0));
  const mixRounds = Math.max(1, Math.floor(Number(payloadObj.c.POW_MIX_ROUNDS) || 0));
  const bindingString = makePowBindingString(
    ticket,
    host,
    binding.pathHash,
    binding.ipScope,
    binding.country,
    binding.asn,
    binding.tlsFingerprint,
    pageBytes,
    mixRounds,
  );
  ticket.mac = base64Url(crypto.createHmac("sha256", payloadObj.c.POW_TOKEN).update(bindingString).digest());
  const ticketB64 = base64Url(
    Buffer.from(
      `${ticket.v}.${ticket.e}.${ticket.L}.${ticket.r}.${ticket.cfgId}.${ticket.issuedAt}.${ticket.mac}`,
      "utf8",
    ),
  );
  return { ticket, ticketB64 };
};

const makeInnerHeaders = (payloadObj, secret = "config-secret", expireOffsetSec = 2) => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const exp = Math.floor(Date.now() / 1000) + expireOffsetSec;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(`${payload}.${exp}`).digest());
  return { payload, mac, exp };
};

const makeSplitApiHeaders = ({ payloadObj, configSecret, method, pathname, apiPrefix }) => {
  const { payload, mac, exp } = makeInnerHeaders(payloadObj, configSecret);
  const transitExp = Math.floor(Date.now() / 1000) + 3;
  const transit = makeTransitHeaders({
    secret: configSecret,
    exp: transitExp,
    kind: "api",
    method,
    pathname,
    apiPrefix,
  });
  const headers = new Headers();
  headers.set("X-Pow-Inner", payload);
  headers.set("X-Pow-Inner-Mac", mac);
  headers.set("X-Pow-Inner-Expire", String(exp));
  for (const [key, value] of Object.entries(transit)) {
    headers.set(key, value);
  }
  return headers;
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

test("challenge rejects binding mismatch after commit via split core harness", async () => {
  const restoreGlobals = ensureGlobals();
  const core1ModulePath = await buildSplitHarnessModule();
  const configModulePath = await buildConfigModule();
  const core1Mod = await import(`${pathToFileURL(core1ModulePath).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configModulePath).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;
  const configHandler = configMod.default.fetch;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      const hasInner = Array.from(request.headers.keys()).some((key) =>
        key.toLowerCase().startsWith("x-pow-inner")
      );
      if (hasInner) {
        return core1Handler(request);
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
    const ticketRaw = Buffer.from(
      String(args.ticketB64).replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    ).toString("utf8");
    const ticketParts = ticketRaw.split(".");
    assert.equal(ticketParts.length, 7);
    const issuedAt = Number.parseInt(ticketParts[5], 10);
    assert.ok(Number.isFinite(issuedAt) && issuedAt > 0);
    const bindingRaw = Buffer.from(
      String(args.bindingB64).replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    ).toString("utf8");
    assert.match(bindingRaw, new RegExp(`\\|${issuedAt}$`, "u"));

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
    assert.equal(Object.hasOwn(challengePayload, "spinePos"), false);

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
    assert.ok(core1Mod.__splitTrace, "split trace is exposed");
    assert.ok(core1Mod.__splitTrace.core1Calls >= 4);
    assert.ok(core1Mod.__splitTrace.core2Calls >= 3);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split runtime uses captchaTag naming", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [businessGateSource, apiEngineSource] = await Promise.all([
    readFile(join(repoRoot, "lib", "pow", "business-gate.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8"),
  ]);
  for (const source of [businessGateSource, apiEngineSource]) {
    assert.match(source, /CAPTCHA_TAG_LEN/u);
    assert.match(source, /captchaTagV1/u);
    assert.doesNotMatch(source, /\bTB_LEN\b/u);
    assert.doesNotMatch(source, /\btbFromToken\b/u);
  }
});

test("core-2 open final step uses provider-aware captcha verification", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const apiEngineSource = await readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8");
  const openBlockMatch = apiEngineSource.match(
    /const handlePowOpen = async[\s\S]+?export const handlePowApi = async/u,
  );
  assert.ok(openBlockMatch, "handlePowOpen block exists");
  const openBlock = openBlockMatch[0];
  assert.match(openBlock, /verifyRequiredCaptchaForTicket\(/u);
  assert.doesNotMatch(openBlock, /verifyTurnstileForTicket\(/u);
});

test("split core-2 challenge rejects commit cookie tamper after commit", async () => {
  const restoreGlobals = ensureGlobals();
  const core2Fetch = await buildCore2Module();
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("ok", { status: 200 });

    const config = {
      POW_TOKEN: "test-secret",
      powcheck: true,
      turncheck: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 64,
      POW_MIN_STEPS: 16,
      POW_MAX_STEPS: 64,
      POW_CHAL_ROUNDS: 2,
      POW_SAMPLE_K: 1,
      POW_OPEN_BATCH: 4,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 16384,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 4,
      POW_COMMIT_TTL_SEC: 120,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      PROOF_TTL_SEC: 300,
      ATOMIC_CONSUME: false,
      POW_TICKET_TTL_SEC: 180,
    };
    const derived = {
      ipScope: "1.2.3.4/32",
      country: "any",
      asn: "any",
      tlsFingerprint: "any",
    };
    const pathHash = sha256Base64Url("/protected");

    const payloadObj = {
      v: 1,
      id: 7,
      c: config,
      d: derived,
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "",
          turnstilePreflight: null,
        },
      },
    };
    const { ticketB64 } = makeTicketFromPayload({ payloadObj, pathHash });

    const commitHeaders = makeSplitApiHeaders({
      payloadObj,
      configSecret: "config-secret",
      method: "POST",
      pathname: "/__pow/commit",
      apiPrefix: config.POW_API_PREFIX,
    });
    commitHeaders.set("Content-Type", "application/json");
    commitHeaders.set("CF-Connecting-IP", "1.2.3.4");
    const rootB64 = base64Url(crypto.randomBytes(32));
    const nonce = base64Url(crypto.randomBytes(16));
    const commitRes = await core2Fetch(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: commitHeaders,
        body: JSON.stringify({
          ticketB64,
          rootB64,
          pathHash,
          nonce,
        }),
      }),
    );
    assert.equal(commitRes.status, 200);
    const setCookie = commitRes.headers.get("Set-Cookie");
    assert.ok(setCookie, "commit sets cookie");
    const commitCookie = setCookie.split(";")[0];

    const challengeHeadersPrimary = makeSplitApiHeaders({
      payloadObj,
      configSecret: "config-secret",
      method: "POST",
      pathname: "/__pow/challenge",
      apiPrefix: config.POW_API_PREFIX,
    });
    challengeHeadersPrimary.set("Content-Type", "application/json");
    challengeHeadersPrimary.set("CF-Connecting-IP", "1.2.3.4");
    challengeHeadersPrimary.set("Cookie", commitCookie);
    const challengeResPrimary = await core2Fetch(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: challengeHeadersPrimary,
        body: JSON.stringify({}),
      }),
    );
    assert.equal(challengeResPrimary.status, 200);

    const commitValue = decodeURIComponent(commitCookie.split("=")[1] || "");
    const commitParts = commitValue.split(".");
    assert.equal(commitParts.length, 8);
    const tamperedNonce = base64Url(crypto.randomBytes(16));
    commitParts[5] = tamperedNonce;
    const tamperedCookie = `${commitCookie.split("=")[0]}=${encodeURIComponent(commitParts.join("."))}`;

    const challengeHeadersSecondary = makeSplitApiHeaders({
      payloadObj,
      configSecret: "config-secret",
      method: "POST",
      pathname: "/__pow/challenge",
      apiPrefix: config.POW_API_PREFIX,
    });
    challengeHeadersSecondary.set("Content-Type", "application/json");
    challengeHeadersSecondary.set("CF-Connecting-IP", "1.2.3.4");
    challengeHeadersSecondary.set("Cookie", tamperedCookie);
    const challengeResSecondary = await core2Fetch(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: challengeHeadersSecondary,
        body: JSON.stringify({}),
      }),
    );
    assert.equal(challengeResSecondary.status, 403);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
