import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const CONFIG_SECRET = "config-secret";
const POW_SECRET = "pow-secret";
const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const RECAPTCHA_SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const fromBase64Url = (value) => {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, "base64");
};

const hmacSha256 = (secret, data) =>
  crypto.createHmac("sha256", secret).update(data).digest();

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

  if (didSetCrypto) globalThis.crypto = crypto.webcrypto;
  if (didSetBtoa) globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
  if (didSetAtob) globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");

  return () => {
    if (didSetCrypto) {
      if (typeof priorCrypto === "undefined") delete globalThis.crypto;
      else globalThis.crypto = priorCrypto;
    }
    if (didSetBtoa) {
      if (typeof priorBtoa === "undefined") delete globalThis.btoa;
      else globalThis.btoa = priorBtoa;
    }
    if (didSetAtob) {
      if (typeof priorAtob === "undefined") delete globalThis.atob;
      else globalThis.atob = priorAtob;
    }
  };
};

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const buildCore1Module = async (secret = CONFIG_SECRET) => {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
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
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-mhg-atomic-split-"));
  await mkdir(join(tmpDir, "lib", "pow"), { recursive: true });
  await mkdir(join(tmpDir, "lib", "mhg"), { recursive: true });
  const businessGateInjected = businessGateSource.replace(
    /__HTML_TEMPLATE__/gu,
    JSON.stringify(templateSource)
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

const toRequest = (input, init) =>
  input instanceof Request ? input : new Request(input, init);

const isTransitRequest = (request) =>
  request.headers.has("X-Pow-Transit");

export default {
  async fetch(request, env, ctx) {
    const upstreamFetch = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const nextRequest = toRequest(input, init);
      if (isTransitRequest(nextRequest)) {
        return core2.fetch(nextRequest, env, ctx);
      }
      return upstreamFetch(input, init);
    };
    try {
      return await core1.fetch(request, env, ctx);
    } finally {
      globalThis.fetch = upstreamFetch;
    }
  },
};
`;
  const tmpPath = join(tmpDir, "core1-harness.js");
  writes.push(writeFile(tmpPath, harnessSource));

  await Promise.all(writes);
  return tmpPath;
};

const buildConfigModule = async (secret = CONFIG_SECRET, configOverrides = {}) => {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  const powConfigSource = await readFile(join(repoRoot, "pow-config.js"), "utf8");
  const compiledConfig = JSON.stringify([
    {
      host: { s: "^example\\.com$", f: "" },
      path: null,
      config: {
        POW_TOKEN: POW_SECRET,
        powcheck: true,
        turncheck: true,
        recaptchaEnabled: true,
        RECAPTCHA_PAIRS: [{ sitekey: "rk-1", secret: "rs-1" }],
        RECAPTCHA_ACTION: "submit",
        RECAPTCHA_MIN_SCORE: 0.5,
        TURNSTILE_SITEKEY: "turn-site",
        TURNSTILE_SECRET: "turn-secret",
        POW_BIND_TLS: false,
        POW_BIND_COUNTRY: false,
        POW_BIND_ASN: false,
        POW_VERSION: 3,
        POW_API_PREFIX: "/__pow",
        POW_DIFFICULTY_BASE: 16,
        POW_DIFFICULTY_COEFF: 1,
        POW_MIN_STEPS: 4,
        POW_MAX_STEPS: 8,
        POW_CHAL_ROUNDS: 2,
        POW_SAMPLE_K: 2,
        POW_OPEN_BATCH: 2,
        POW_HASHCASH_BITS: 0,
        POW_SEGMENT_LEN: 2,
        POW_COMMIT_TTL_SEC: 120,
        POW_TICKET_TTL_SEC: 180,
        PROOF_TTL_SEC: 300,
        ATOMIC_CONSUME: true,
        ATOMIC_TURN_QUERY: "__ts",
        ATOMIC_TICKET_QUERY: "__tt",
        ATOMIC_CONSUME_QUERY: "__ct",
        ATOMIC_TURN_HEADER: "x-turnstile",
        ATOMIC_TICKET_HEADER: "x-ticket",
        ATOMIC_CONSUME_HEADER: "x-consume",
        ATOMIC_COOKIE_NAME: "__Secure-pow_a",
        POW_ESM_URL: "https://cdn.example/esm.js",
        POW_GLUE_URL: "https://cdn.example/glue.js",
        ...configOverrides,
      },
    },
  ]);
  const injected = powConfigSource.replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-config-mhg-atomic-split-"));
  const tmpPath = join(tmpDir, "pow-config.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

const parseTicket = (ticketB64) => {
  const raw = fromBase64Url(ticketB64).toString("utf8");
  const parts = raw.split(".");
  return {
    v: Number.parseInt(parts[0], 10),
    e: Number.parseInt(parts[1], 10),
    L: Number.parseInt(parts[2], 10),
    r: parts[3],
    cfgId: Number.parseInt(parts[4], 10),
    mac: parts[5],
  };
};

const parseConsume = (consumeToken) => {
  const parts = String(consumeToken || "").split(".");
  if (parts.length !== 6 || parts[0] !== "v2") return null;
  return {
    ticketB64: parts[1],
    exp: Number.parseInt(parts[2], 10),
    captchaTag: parts[3],
    mask: Number.parseInt(parts[4], 10),
    mac: parts[5],
  };
};

const makeConsumeToken = ({ ticketB64, exp, captchaTag, mask }) => {
  const mac = base64Url(hmacSha256(POW_SECRET, `U|${ticketB64}|${exp}|${captchaTag}|${mask}`));
  return `v2.${ticketB64}.${exp}.${captchaTag}.${mask}.${mac}`;
};

const deriveMhgGraphSeed = (ticketB64, nonce) =>
  crypto.createHash("sha256").update(`mhg|graph|v2|${ticketB64}|${nonce}`).digest().subarray(0, 16);

const deriveMhgNonce16 = (nonce) => {
  const raw = fromBase64Url(nonce);
  if (raw.length >= 16) return raw.subarray(0, 16);
  return crypto.createHash("sha256").update(raw).digest().subarray(0, 16);
};

const extractChallengeArgs = (html) => {
  const match = html.match(/g\("([^"]+)",\s*(\d+),\s*"([^"]+)",\s*"([^"]+)"/u);
  if (!match) return null;
  return { ticketB64: match[3], pathHash: match[4] };
};

const makeInnerPayload = (strategyAtomic) => ({
  v: 1,
  id: 0,
  c: {
    POW_TOKEN: POW_SECRET,
    powcheck: true,
    turncheck: true,
    recaptchaEnabled: true,
    RECAPTCHA_PAIRS: [{ sitekey: "rk-1", secret: "rs-1" }],
    RECAPTCHA_ACTION: "submit",
    RECAPTCHA_MIN_SCORE: 0.5,
    TURNSTILE_SITEKEY: "turn-site",
    TURNSTILE_SECRET: "turn-secret",
    POW_VERSION: 3,
    POW_API_PREFIX: "/__pow",
    POW_DIFFICULTY_BASE: 16,
    POW_DIFFICULTY_COEFF: 1,
    POW_MIN_STEPS: 4,
    POW_MAX_STEPS: 8,
    POW_CHAL_ROUNDS: 2,
    POW_SAMPLE_K: 2,
    POW_OPEN_BATCH: 2,
    POW_HASHCASH_BITS: 0,
    POW_SEGMENT_LEN: 2,
    POW_COMMIT_TTL_SEC: 120,
    POW_TICKET_TTL_SEC: 180,
    POW_COMMIT_COOKIE: "__Host-pow_commit",
    POW_BIND_PATH: true,
    POW_BIND_IPRANGE: true,
    POW_BIND_COUNTRY: false,
    POW_BIND_ASN: false,
    POW_BIND_TLS: false,
    PROOF_TTL_SEC: 300,
    ATOMIC_CONSUME: true,
    ATOMIC_TURN_QUERY: "__ts",
    ATOMIC_TICKET_QUERY: "__tt",
    ATOMIC_CONSUME_QUERY: "__ct",
    ATOMIC_TURN_HEADER: "x-turnstile",
    ATOMIC_TICKET_HEADER: "x-ticket",
    ATOMIC_CONSUME_HEADER: "x-consume",
    ATOMIC_COOKIE_NAME: "__Secure-pow_a",
    POW_ESM_URL: "https://cdn.example/esm.js",
    POW_GLUE_URL: "https://cdn.example/glue.js",
  },
  d: {
    ipScope: "1.2.3.4/32",
    country: "any",
    asn: "any",
    tlsFingerprint: "any",
  },
  s: {
    nav: {},
    bypass: { bypass: false },
    bind: { ok: true, code: "", canonicalPath: "/protected" },
    atomic: strategyAtomic,
  },
});

const makeInnerHeaders = (payloadObj, secret = CONFIG_SECRET, expireOffsetSec = 2) => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const exp = Math.floor(Date.now() / 1000) + expireOffsetSec;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(`${payload}.${exp}`).digest());
  return {
    "X-Pow-Inner": payload,
    "X-Pow-Inner-Mac": mac,
    "X-Pow-Inner-Expire": String(exp),
  };
};

const buildMhgWitnessBundle = async ({ ticketB64, nonce }) => {
  const { parentsOf } = await import("../../lib/mhg/graph.js");
  const { makeGenesisPage, mixPage } = await import("../../lib/mhg/mix-aes.js");
  const { buildMerkle, buildProof } = await import("../../lib/mhg/merkle.js");
  const ticket = parseTicket(ticketB64);
  const graphSeed = deriveMhgGraphSeed(ticketB64, nonce);
  const nonce16 = deriveMhgNonce16(nonce);
  const pageBytes = 64;
  const pages = new Array(ticket.L + 1);
  pages[0] = await makeGenesisPage({ graphSeed, nonce: nonce16, pageBytes });
  const parentByIndex = new Map();
  for (let i = 1; i <= ticket.L; i += 1) {
    const parents = await parentsOf(i, graphSeed);
    parentByIndex.set(i, parents);
    pages[i] = await mixPage({
      i,
      p0: pages[parents.p0],
      p1: pages[parents.p1],
      p2: pages[parents.p2],
      graphSeed,
      nonce: nonce16,
      pageBytes,
    });
  }

  const tree = await buildMerkle(pages);
  const witnessByIndex = new Map();
  for (let i = 1; i <= ticket.L; i += 1) {
    const parents = parentByIndex.get(i);
    witnessByIndex.set(i, {
      i,
      p0: base64Url(pages[parents.p0]),
      p1: base64Url(pages[parents.p1]),
      p2: base64Url(pages[parents.p2]),
      page: base64Url(pages[i]),
      proof: {
        page: buildProof(tree, i).map((sib) => base64Url(sib)),
        p0: buildProof(tree, parents.p0).map((sib) => base64Url(sib)),
        p1: buildProof(tree, parents.p1).map((sib) => base64Url(sib)),
        p2: buildProof(tree, parents.p2).map((sib) => base64Url(sib)),
      },
    });
  }
  return { rootB64: base64Url(tree.root), witnessByIndex };
};

const bootstrapConsume = async (core1Handler) => {
  const captchaEnvelope = JSON.stringify({
    turnstile: "atomic-turn-token-1234567890",
    recaptcha_v3: "atomic-recaptcha-token-1234567890",
  });
  const emptyAtomic = {
    captchaToken: "",
    ticketB64: "",
    consumeToken: "",
    fromCookie: false,
    cookieName: "__Secure-pow_a",
    turnstilePreflight: null,
  };
  const payload = makeInnerPayload(emptyAtomic);

  const pageRes = await core1Handler(
    new Request("https://example.com/protected", {
      method: "GET",
      headers: {
        ...makeInnerHeaders(payload),
        Accept: "text/html",
        "CF-Connecting-IP": "1.2.3.4",
      },
    }),
    {},
    {}
  );
  assert.equal(pageRes.status, 200);
  const args = extractChallengeArgs(await pageRes.text());
  assert.ok(args);

  const nonce = base64Url(crypto.randomBytes(16));
  const witness = await buildMhgWitnessBundle({ ticketB64: args.ticketB64, nonce });
  const commitRes = await core1Handler(
    new Request("https://example.com/__pow/commit", {
      method: "POST",
      headers: {
        ...makeInnerHeaders(payload),
        "Content-Type": "application/json",
        "CF-Connecting-IP": "1.2.3.4",
      },
      body: JSON.stringify({
        ticketB64: args.ticketB64,
        rootB64: witness.rootB64,
        pathHash: args.pathHash,
        nonce,
        captchaToken: captchaEnvelope,
      }),
    }),
    {},
    {}
  );
  assert.equal(commitRes.status, 200);
  const commitCookie = (commitRes.headers.get("set-cookie") || "").split(";")[0];
  assert.ok(commitCookie);

  const challengeRes = await core1Handler(
    new Request("https://example.com/__pow/challenge", {
      method: "POST",
      headers: {
        ...makeInnerHeaders(payload),
        "Content-Type": "application/json",
        Cookie: commitCookie,
      },
      body: JSON.stringify({}),
    }),
    {},
    {}
  );
  assert.equal(challengeRes.status, 200);
  let state = await challengeRes.json();

  while (state.done === false) {
    const opens = state.indices.map((idx) => witness.witnessByIndex.get(idx));
    const openRes = await core1Handler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(payload),
          "Content-Type": "application/json",
          Cookie: commitCookie,
        },
        body: JSON.stringify({
          cursor: state.cursor,
          token: state.token,
          captchaToken: captchaEnvelope,
          opens,
        }),
      }),
      {},
      {}
    );
    assert.equal(openRes.status, 200);
    state = await openRes.json();
  }

  assert.equal(typeof state.consume, "string");
  return { consumeToken: state.consume, captchaEnvelope, ticket: parseTicket(args.ticketB64) };
};

const makeAtomicBusinessRequest = ({ consumeToken, captchaEnvelope }) =>
  new Request(
    `https://example.com/protected?__ts=${encodeURIComponent(captchaEnvelope)}&__ct=${encodeURIComponent(consumeToken)}`,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
        "CF-Connecting-IP": "1.2.3.4",
      },
    }
  );

test("dual-provider atomic preflight keeps split and subrequest budget (providers mode)", async () => {
  const restoreGlobals = ensureGlobals();
  const core1Path = await buildCore1Module();
  const configPath = await buildConfigModule(CONFIG_SECRET, {
    turncheck: false,
    recaptchaEnabled: false,
    providers: "turnstile,recaptcha",
  });
  const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
  assert.equal(typeof core1Mod.default?.fetch, "function");
  const configMod = await import(`${pathToFileURL(configPath).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;
  const configHandler = configMod.default.fetch;
  const originalFetch = globalThis.fetch;

  try {
    const seed = await bootstrapConsume(core1Handler);
    const counters = {
      turnstileVerifyInPowConfig: 0,
      turnstileVerifyInCore1: 0,
      recaptchaVerifyInCore1: 0,
      powConfigSubrequests: 0,
      core1Subrequests: 0,
    };

    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const reqUrl = String(req.url);
      if (reqUrl === TURNSTILE_SITEVERIFY_URL) {
        counters.turnstileVerifyInPowConfig += 1;
        counters.powConfigSubrequests += 1;
        return new Response(JSON.stringify({ success: true, cdata: seed.ticket.mac }), { status: 200 });
      }
      if (reqUrl === RECAPTCHA_SITEVERIFY_URL) {
        counters.recaptchaVerifyInCore1 += 1;
        counters.core1Subrequests += 1;
        return new Response(
          JSON.stringify({
            success: true,
            hostname: "example.com",
            remoteip: "1.2.3.4",
            action: "submit",
            score: 0.9,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (req.headers.has("X-Pow-Inner") || req.headers.has("X-Pow-Inner-Count")) {
        counters.powConfigSubrequests += 1;
        return core1Handler(req, {}, {});
      }
      counters.core1Subrequests += 1;
      return new Response("ok", { status: 200 });
    };

    const result = await configHandler(makeAtomicBusinessRequest(seed), {}, {});
    assert.equal(result.status, 200);
    assert.equal(counters.turnstileVerifyInPowConfig, 1);
    assert.equal(counters.turnstileVerifyInCore1, 0);
    assert.equal(counters.recaptchaVerifyInCore1, 1);
    assert.ok(counters.powConfigSubrequests <= 2);
    assert.ok(counters.core1Subrequests <= 2);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("expired consume returns stale on atomic business path", async () => {
  const restoreGlobals = ensureGlobals();
  const core1Path = await buildCore1Module();
  const configPath = await buildConfigModule();
  const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configPath).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;
  const configHandler = configMod.default.fetch;
  const originalFetch = globalThis.fetch;

  try {
    const seed = await bootstrapConsume(core1Handler);
    const parsed = parseConsume(seed.consumeToken);
    assert.ok(parsed);
    const expiredConsume = makeConsumeToken({
      ticketB64: parsed.ticketB64,
      exp: Math.floor(Date.now() / 1000) - 10,
      captchaTag: parsed.captchaTag,
      mask: parsed.mask,
    });

    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      if (String(req.url) === TURNSTILE_SITEVERIFY_URL) {
        return new Response(JSON.stringify({ success: true, cdata: seed.ticket.mac }), { status: 200 });
      }
      if (String(req.url) === RECAPTCHA_SITEVERIFY_URL) {
        return new Response(
          JSON.stringify({
            success: true,
            hostname: "example.com",
            remoteip: "1.2.3.4",
            action: "submit",
            score: 0.9,
          }),
          { status: 200 }
        );
      }
      if (req.headers.has("X-Pow-Inner") || req.headers.has("X-Pow-Inner-Count")) {
        return core1Handler(req, {}, {});
      }
      return new Response("ok", { status: 200 });
    };

    const result = await configHandler(
      makeAtomicBusinessRequest({ consumeToken: expiredConsume, captchaEnvelope: seed.captchaEnvelope }),
      {},
      {}
    );
    assert.equal(result.status, 403);
    assert.equal(result.headers.get("x-pow-h"), "stale");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("atomic rejects missing preflight evidence", async () => {
  const restoreGlobals = ensureGlobals();
  const core1Path = await buildCore1Module();
  const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;
  const originalFetch = globalThis.fetch;

  try {
    const seed = await bootstrapConsume(core1Handler);
    globalThis.fetch = async () => new Response("ok", { status: 200 });
    const payload = makeInnerPayload({
      captchaToken: seed.captchaEnvelope,
      ticketB64: "",
      consumeToken: seed.consumeToken,
      fromCookie: false,
      cookieName: "",
      turnstilePreflight: null,
    });

    const result = await core1Handler(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: {
          ...makeInnerHeaders(payload),
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
        },
      }),
      {},
      {}
    );

    assert.equal(result.status, 403);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("atomic rejects preflight tokenTag mismatch", async () => {
  const restoreGlobals = ensureGlobals();
  const core1Path = await buildCore1Module();
  const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;
  const originalFetch = globalThis.fetch;

  try {
    const seed = await bootstrapConsume(core1Handler);
    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      if (String(req.url) === RECAPTCHA_SITEVERIFY_URL) {
        return new Response(
          JSON.stringify({
            success: true,
            hostname: "example.com",
            remoteip: "1.2.3.4",
            action: "submit",
            score: 0.9,
          }),
          { status: 200 }
        );
      }
      return new Response("ok", { status: 200 });
    };

    const payload = makeInnerPayload({
      captchaToken: seed.captchaEnvelope,
      ticketB64: "",
      consumeToken: seed.consumeToken,
      fromCookie: false,
      cookieName: "",
      turnstilePreflight: {
        checked: true,
        ok: true,
        reason: "",
        ticketMac: seed.ticket.mac,
        tokenTag: "AAAAAAAAAAAAAAAA",
      },
    });

    const result = await core1Handler(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: {
          ...makeInnerHeaders(payload),
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
        },
      }),
      {},
      {}
    );

    assert.equal(result.status, 403);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
