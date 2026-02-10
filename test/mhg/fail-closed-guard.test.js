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

const buildPowModule = async (secret = CONFIG_SECRET) => {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  const template = await readFile(join(repoRoot, "template.html"), "utf8");
  const injected = powSource.replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template));
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-fail-closed-"));
  const tmpPath = join(tmpDir, "pow.js");
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

const buildCoreModules = async (secret = CONFIG_SECRET) => {
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
    readOptionalFile(join(repoRoot, "lib", "pow", "inner-auth.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "internal-headers.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "api-engine.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "business-gate.js")),
    readFile(join(repoRoot, "template.html"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "graph.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "mix-aes.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "merkle.js"), "utf8"),
  ]);

  const core1Source = replaceConfigSecret(core1SourceRaw, secret);
  const core2Source = replaceConfigSecret(core2SourceRaw, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-split-fail-closed-"));
  await mkdir(join(tmpDir, "lib", "pow"), { recursive: true });
  await mkdir(join(tmpDir, "lib", "mhg"), { recursive: true });
  const writes = [
    writeFile(join(tmpDir, "pow-core-1.js"), core1Source),
    writeFile(join(tmpDir, "pow-core-2.js"), core2Source),
    writeFile(join(tmpDir, "lib", "pow", "transit-auth.js"), transitSource),
    writeFile(join(tmpDir, "lib", "mhg", "graph.js"), mhgGraphSource),
    writeFile(join(tmpDir, "lib", "mhg", "mix-aes.js"), mhgMixSource),
    writeFile(join(tmpDir, "lib", "mhg", "merkle.js"), mhgMerkleSource),
  ];
  if (innerAuthSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "inner-auth.js"), innerAuthSource));
  }
  if (internalHeadersSource !== null) {
    writes.push(
      writeFile(join(tmpDir, "lib", "pow", "internal-headers.js"), internalHeadersSource)
    );
  }
  if (apiEngineSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineSource));
  }
  if (businessGateSource !== null) {
    const businessGateInjected = businessGateSource.replace(
      /__HTML_TEMPLATE__/gu,
      JSON.stringify(templateSource)
    );
    writes.push(writeFile(join(tmpDir, "lib", "pow", "business-gate.js"), businessGateInjected));
  }
  await Promise.all(writes);

  const nonce = `${Date.now()}-${Math.random()}`;
  const [core1Module, core2Module] = await Promise.all([
    import(`${pathToFileURL(join(tmpDir, "pow-core-1.js")).href}?v=${nonce}`),
    import(`${pathToFileURL(join(tmpDir, "pow-core-2.js")).href}?v=${nonce}`),
  ]);
  return { core1Fetch: core1Module.default.fetch, core2Fetch: core2Module.default.fetch };
};

const makeSplitInnerHeaders = (payloadObj, secret = CONFIG_SECRET, expireOffsetSec = 2) => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const exp = Math.floor(Date.now() / 1000) + expireOffsetSec;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(`${payload}.${exp}`).digest());
  return {
    "X-Pow-Inner": payload,
    "X-Pow-Inner-Mac": mac,
    "X-Pow-Inner-Expire": String(exp),
  };
};

const parseTicket = (ticketB64) => {
  const raw = fromBase64Url(ticketB64).toString("utf8");
  const parts = raw.split(".");
  return {
    L: Number.parseInt(parts[2], 10),
    cfgId: Number.parseInt(parts[4], 10),
    mac: parts[5],
  };
};

const makeInnerPayload = ({ atomic = false } = {}) => ({
  v: 1,
  id: 77,
  c: {
    POW_TOKEN: POW_SECRET,
    powcheck: true,
    turncheck: true,
    recaptchaEnabled: false,
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
    ATOMIC_CONSUME: atomic,
    ATOMIC_TURN_QUERY: "__ts",
    ATOMIC_TICKET_QUERY: "__tt",
    ATOMIC_CONSUME_QUERY: "__ct",
    ATOMIC_TURN_HEADER: "x-turnstile",
    ATOMIC_TICKET_HEADER: "x-ticket",
    ATOMIC_CONSUME_HEADER: "x-consume",
    ATOMIC_COOKIE_NAME: "__Secure-pow_a",
    TURNSTILE_SITEKEY: "turn-site",
    TURNSTILE_SECRET: "turn-secret",
    POW_ESM_URL: "https://cdn.example/esm.js",
    POW_GLUE_URL: "https://cdn.example/glue.js",
  },
  d: { ipScope: "1.2.3.4/32", country: "", asn: "", tlsFingerprint: "" },
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

const extractChallengeArgs = (html) => {
  const match = html.match(/g\("([^"]+)",\s*(\d+),\s*"([^"]+)",\s*"([^"]+)"/u);
  if (!match) return null;
  return { ticketB64: match[3], pathHash: match[4] };
};

const deriveMhgGraphSeed = (ticketB64, nonce) =>
  crypto.createHash("sha256").update(`mhg|graph|v2|${ticketB64}|${nonce}`).digest().subarray(0, 16);

const deriveMhgNonce16 = (nonce) => {
  const raw = fromBase64Url(nonce);
  if (raw.length >= 16) return raw.subarray(0, 16);
  return crypto.createHash("sha256").update(raw).digest().subarray(0, 16);
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

const runInnerFailClosedCases = async (handler) => {
  const payload = makeInnerPayload();
  const good = makeInnerHeaders(payload);
  const missingInner = await handler(new Request("https://example.com/protected", { headers: {} }), {}, {});
  const badMac = await handler(
    new Request("https://example.com/protected", {
      headers: { ...good, "X-Pow-Inner-Mac": "bad" },
    }),
    {},
    {}
  );
  const expired = await handler(
    new Request("https://example.com/protected", {
      headers: makeInnerHeaders(payload, CONFIG_SECRET, -10),
    }),
    {},
    {}
  );
  return { missingInner: missingInner.status, badMac: badMac.status, expired: expired.status };
};

const runForbiddenVerifyPointCases = async (handler) => {
  const payload = makeInnerPayload({ atomic: true });
  const headers = makeInnerHeaders(payload);
  const tokenEnvelope = JSON.stringify({ turnstile: "turnstile-token-value-1234567890" });
  let siteverifyCalls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input) => {
      const req = input instanceof Request ? input : new Request(input);
      if (String(req.url) === TURNSTILE_SITEVERIFY_URL) {
        siteverifyCalls += 1;
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      return new Response("ok", { status: 200 });
    };

    const pageRes = await handler(
      new Request("https://example.com/protected", {
        headers: { ...headers, Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" },
      }),
      {},
      {}
    );
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);
    const nonce = base64Url(crypto.randomBytes(16));
    const witness = await buildMhgWitnessBundle({ ticketB64: args.ticketB64, nonce });

    const commitRes = await handler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64: witness.rootB64,
          pathHash: args.pathHash,
          nonce,
          captchaToken: tokenEnvelope,
        }),
      }),
      {},
      {}
    );
    const commitSiteverifyCalls = siteverifyCalls;
    assert.equal(commitRes.status, 200);
    const commitCookie = (commitRes.headers.get("set-cookie") || "").split(";")[0];

    const challengeRes = await handler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json", Cookie: commitCookie },
        body: JSON.stringify({}),
      }),
      {},
      {}
    );
    const challengeSiteverifyCalls = siteverifyCalls - commitSiteverifyCalls;
    assert.equal(challengeRes.status, 200);
    let state = await challengeRes.json();
    let nonFinalOpenSiteverifyCalls = 0;
    let atomicFinalOpenSiteverifyCalls = 0;
    while (state.done === false) {
      const opens = state.indices.map((idx) => witness.witnessByIndex.get(idx));
      const before = siteverifyCalls;
      const openRes = await handler(
        new Request("https://example.com/__pow/open", {
          method: "POST",
          headers: { ...headers, "Content-Type": "application/json", Cookie: commitCookie },
          body: JSON.stringify({
            cursor: state.cursor,
            token: state.token,
            captchaToken: tokenEnvelope,
            opens,
          }),
        }),
        {},
        {}
      );
      assert.equal(openRes.status, 200);
      const body = await openRes.json();
      const delta = siteverifyCalls - before;
      if (body.done === false) {
        nonFinalOpenSiteverifyCalls += delta;
      } else {
        atomicFinalOpenSiteverifyCalls += delta;
      }
      state = body;
    }

    return {
      commitSiteverifyCalls,
      challengeSiteverifyCalls,
      nonFinalOpenSiteverifyCalls,
      atomicFinalOpenSiteverifyCalls,
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
};

const runAtomicProofBypassCase = async (handler) => {
  const payload = makeInnerPayload({ atomic: true });
  const res = await handler(
    new Request("https://example.com/protected", {
      headers: {
        ...makeInnerHeaders(payload),
        Accept: "application/json",
        Cookie: "__Host-proof=v1.fake.fake.fake.fake.fake.fake",
      },
    }),
    {},
    {}
  );
  return { allowed: res.status === 200 };
};

test("pow.js fails closed when inner header is missing/invalid/expired", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  try {
    const out = await runInnerFailClosedCases(mod.default.fetch);
    assert.equal(out.missingInner, 500);
    assert.equal(out.badMac, 500);
    assert.equal(out.expired, 500);
  } finally {
    restoreGlobals();
  }
});

test("forbidden nodes never trigger provider siteverify", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  try {
    const out = await runForbiddenVerifyPointCases(mod.default.fetch);
    assert.equal(out.commitSiteverifyCalls, 0);
    assert.equal(out.challengeSiteverifyCalls, 0);
    assert.equal(out.nonFinalOpenSiteverifyCalls, 0);
    assert.equal(out.atomicFinalOpenSiteverifyCalls, 0);
  } finally {
    restoreGlobals();
  }
});

test("atomic captcha path cannot be bypassed by proof cookie", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  try {
    const out = await runAtomicProofBypassCase(mod.default.fetch);
    assert.equal(out.allowed, false);
  } finally {
    restoreGlobals();
  }
});

test("split core1 denies unauthorized non-navigation fail-closed", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const { core1Fetch, core2Fetch } = await buildCoreModules();
    const payload = makeInnerPayload();

    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Transit")) {
        return core2Fetch(request);
      }
      return new Response("origin should not be reached", { status: 599 });
    };

    const res = await core1Fetch(
      new Request("https://example.com/protected", {
        headers: {
          ...makeSplitInnerHeaders(payload),
          Accept: "application/json",
        },
      }),
      {},
      {}
    );

    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { code: "pow_required" });
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
