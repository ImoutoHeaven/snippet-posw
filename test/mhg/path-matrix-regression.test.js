import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const CONFIG_SECRET = "config-secret";
const POW_SECRET = "pow-secret";
const SITEVERIFY_URL = "https://sv.example/siteverify";

const TURN_TOKEN = "turnstile-token-value-1234567890";

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
  const [
    core1Raw,
    core2Raw,
    transitSource,
    innerAuthSource,
    internalHeadersSource,
    apiEngineSource,
    siteverifyClientSource,
    businessGateSource,
    templateSource,
    mhgGraphSource,
    mhgHashSource,
    mhgConstantsSource,
    mhgMixSource,
    mhgMerkleSource,
    mhgVerifySource,
  ] = await Promise.all([
    readFile(join(repoRoot, "pow-core-1.js"), "utf8"),
    readFile(join(repoRoot, "pow-core-2.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "transit-auth.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "inner-auth.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "internal-headers.js"), "utf8"),
    readOptionalFile(join(repoRoot, "lib", "pow", "api-engine.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "siteverify-client.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "business-gate.js")),
    readFile(join(repoRoot, "template.html"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "graph.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "hash.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "constants.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "mix-aes.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "merkle.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "verify.js"), "utf8"),
  ]);

  const core1Source = replaceConfigSecret(core1Raw, secret);
  const core2Source = replaceConfigSecret(core2Raw, secret);
  const businessGateInjected =
    businessGateSource === null
      ? null
      : businessGateSource.replace(/__HTML_TEMPLATE__/gu, JSON.stringify(templateSource));

  const tmpDir = await mkdtemp(join(tmpdir(), "pow-matrix-"));
  await mkdir(join(tmpDir, "lib", "pow"), { recursive: true });
  await mkdir(join(tmpDir, "lib", "mhg"), { recursive: true });
  const writes = [
    writeFile(join(tmpDir, "pow-core-1.js"), core1Source),
    writeFile(join(tmpDir, "pow-core-2.js"), core2Source),
    writeFile(join(tmpDir, "lib", "pow", "transit-auth.js"), transitSource),
    writeFile(join(tmpDir, "lib", "pow", "inner-auth.js"), innerAuthSource),
    writeFile(join(tmpDir, "lib", "pow", "internal-headers.js"), internalHeadersSource),
    writeFile(join(tmpDir, "lib", "mhg", "graph.js"), mhgGraphSource),
    writeFile(join(tmpDir, "lib", "mhg", "hash.js"), mhgHashSource),
    writeFile(join(tmpDir, "lib", "mhg", "constants.js"), mhgConstantsSource),
    writeFile(join(tmpDir, "lib", "mhg", "mix-aes.js"), mhgMixSource),
    writeFile(join(tmpDir, "lib", "mhg", "merkle.js"), mhgMerkleSource),
    writeFile(join(tmpDir, "lib", "mhg", "verify.js"), mhgVerifySource),
  ];
  if (apiEngineSource !== null) writes.push(writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineSource));
  if (siteverifyClientSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "siteverify-client.js"), siteverifyClientSource));
  }
  if (businessGateInjected !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "business-gate.js"), businessGateInjected));
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
      return core1.fetch(request, env, ctx);
    } finally {
      globalThis.fetch = upstreamFetch;
    }
  },
};
`;
  const tmpPath = join(tmpDir, "pow-test.js");
  writes.push(writeFile(tmpPath, bridgeSource));
  await Promise.all(writes);
  return tmpPath;
};

const buildConfigModule = async (secret = CONFIG_SECRET, overrides = {}) => {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  const source = await readFile(join(repoRoot, "pow-config.js"), "utf8");
  const compiledConfig = JSON.stringify([
    {
      host: { s: "^example\\.com$", f: "" },
      path: null,
      config: {
        POW_TOKEN: POW_SECRET,
        powcheck: true,
        turncheck: true,
        SITEVERIFY_URLS: [SITEVERIFY_URL],
        SITEVERIFY_AUTH_KID: "v1",
        SITEVERIFY_AUTH_SECRET: "siteverify-secret",
        TURNSTILE_SITEKEY: "turn-site",
        TURNSTILE_SECRET: "turn-secret",
        POW_BIND_PATH: true,
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
        POW_COMMIT_COOKIE: "__Host-pow_commit",
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
        ...overrides,
      },
    },
  ]);
  const injected = source.replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-config-matrix-"));
  const tmpPath = join(tmpDir, "pow-config.js");
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

const parseTicket = (ticketB64) => {
  const raw = fromBase64Url(ticketB64).toString("utf8");
  const parts = raw.split(".");
  if (parts.length !== 7) return null;
  const issuedAt = Number.parseInt(parts[5], 10);
  if (!Number.isFinite(issuedAt) || issuedAt <= 0) return null;
  return {
    e: Number.parseInt(parts[1], 10),
    L: Number.parseInt(parts[2], 10),
    cfgId: Number.parseInt(parts[4], 10),
    issuedAt,
    mac: parts[6],
  };
};

const mutateTicketExpiry = (ticketB64, exp) => {
  const parts = fromBase64Url(ticketB64).toString("utf8").split(".");
  parts[1] = String(exp);
  return base64Url(Buffer.from(parts.join("."), "utf8"));
};

const mutateCommitExpiry = (commitCookie, exp) => {
  const value = commitCookie.split("=")[1] || "";
  const parts = decodeURIComponent(value).split(".");
  parts[6] = String(exp);
  return `${commitCookie.split("=")[0]}=${encodeURIComponent(parts.join("."))}`;
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

const makeConsumeToken = ({ ticketB64, exp, captchaTag, mask, secret = POW_SECRET }) => {
  const mac = base64Url(
    crypto.createHmac("sha256", secret).update(`U|${ticketB64}|${exp}|${captchaTag}|${mask}`).digest()
  );
  return `v2.${ticketB64}.${exp}.${captchaTag}.${mask}.${mac}`;
};

const makeSignedTicketB64 = ({ payload, host, pathHash, issuedAt, exp, steps, nonce, secret = POW_SECRET }) => {
  const ticket = {
    v: payload.c.POW_VERSION,
    e: exp,
    L: steps,
    r: nonce,
    cfgId: payload.id,
    issuedAt,
    mac: "",
  };
  const pageBytes = Math.max(1, Math.floor(Number(payload.c.POW_PAGE_BYTES) || 0));
  const mixRounds = Math.max(1, Math.floor(Number(payload.c.POW_MIX_ROUNDS) || 0));
  const binding = `${ticket.v}|${ticket.e}|${ticket.L}|${ticket.r}|${ticket.cfgId}|${host}|${pathHash}|${payload.d.ipScope}|any|any|any|${pageBytes}|${mixRounds}|${ticket.issuedAt}`;
  assert.ok(binding.endsWith(`|${ticket.issuedAt}`));
  ticket.mac = base64Url(crypto.createHmac("sha256", secret).update(binding).digest());
  const raw = `${ticket.v}.${ticket.e}.${ticket.L}.${ticket.r}.${ticket.cfgId}.${ticket.issuedAt}.${ticket.mac}`;
  return base64Url(Buffer.from(raw, "utf8"));
};

const makeSignedCommitCookie = ({
  ticketB64,
  rootB64,
  pathHash,
  captchaTag,
  nonce,
  exp,
  secret = POW_SECRET,
}) => {
  const mac = base64Url(
    crypto
      .createHmac("sha256", secret)
      .update(`C2|${ticketB64}|${rootB64}|${pathHash}|${captchaTag}|${nonce}|${exp}`)
      .digest()
  );
  const value = `v5.${ticketB64}.${rootB64}.${pathHash}.${captchaTag}.${nonce}.${exp}.${mac}`;
  return `__Host-pow_commit=${encodeURIComponent(value)}`;
};

const extractChallengeArgs = (html) => {
  const match = html.match(/g\("([^"]+)",\s*(\d+),\s*"([^"]+)",\s*"([^"]+)"/u);
  if (!match) return null;
  return { ticketB64: match[3], pathHash: match[4] };
};

const resolveCaptchaRequirements = (spec) => {
  let needTurn = spec.turncheck === true;
  if (!needTurn) {
    const providers = String(spec.providers || "")
      .split(/[\s,]+/u)
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);
    needTurn = providers.includes("turnstile");
  }
  return { needTurn };
};

const makeInnerPayload = ({
  powcheck,
  atomic,
  turncheck,
  providers = "",
  atomicState = null,
  aggregatorPowAtomicConsume = false,
}) => ({
  v: 1,
  id: 99,
  c: {
    POW_TOKEN: POW_SECRET,
    powcheck,
    turncheck,
    SITEVERIFY_URLS: [SITEVERIFY_URL],
    SITEVERIFY_AUTH_KID: "v1",
    SITEVERIFY_AUTH_SECRET: "siteverify-secret",
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
    POW_PAGE_BYTES: 16384,
    POW_MIX_ROUNDS: 2,
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
    AGGREGATOR_POW_ATOMIC_CONSUME: aggregatorPowAtomicConsume,
    POW_ESM_URL: "https://cdn.example/esm.js",
    POW_GLUE_URL: "https://cdn.example/glue.js",
  },
  d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
  s: {
    nav: {},
    bypass: { bypass: false },
    bind: { ok: true, code: "", canonicalPath: "/protected" },
    atomic:
      atomicState ||
      {
        captchaToken: "",
        ticketB64: "",
        consumeToken: "",
        fromCookie: false,
        cookieName: "",
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

const deriveMhgGraphSeed = (ticketB64, nonce) =>
  crypto.createHash("sha256").update(`mhg|graph|v2|${ticketB64}|${nonce}`).digest().subarray(0, 16);

const deriveMhgNonce16 = (nonce) => {
  const raw = fromBase64Url(nonce);
  if (raw.length >= 16) return raw.subarray(0, 16);
  return crypto.createHash("sha256").update(raw).digest().subarray(0, 16);
};

const buildEqSet = (index, segmentLen) => {
  const start = Math.max(1, index - segmentLen + 1);
  const out = [];
  for (let i = start; i <= index; i += 1) out.push(i);
  return out;
};

const buildOpenEntryFromBundle = ({ bundle, idx, seg }) => {
  const segmentLen = Math.max(1, Math.floor(Number(seg) || 1));
  const eqSet = buildEqSet(idx, segmentLen);
  const need = new Set();
  for (const j of eqSet) {
    const parents = bundle.parentByIndex.get(j);
    need.add(j);
    need.add(parents.p0);
    need.add(parents.p1);
    need.add(parents.p2);
  }
  const nodes = {};
  for (const needIdx of Array.from(need).sort((a, b) => a - b)) {
    nodes[String(needIdx)] = {
      pageB64: base64Url(bundle.pages[needIdx]),
      proof: bundle.buildProof(bundle.tree, needIdx).map((sib) => base64Url(sib)),
    };
  }
  return { i: idx, seg: segmentLen, nodes };
};

const buildMhgWitnessBundle = async ({ ticketB64, nonce, pageBytes = 16384, mixRounds = 2 }) => {
  const { parentsOf } = await import("../../lib/mhg/graph.js");
  const { makeGenesisPage, mixPage } = await import("../../lib/mhg/mix-aes.js");
  const { buildMerkle, buildProof } = await import("../../lib/mhg/merkle.js");
  const ticket = parseTicket(ticketB64);
  const graphSeed = deriveMhgGraphSeed(ticketB64, nonce);
  const nonce16 = deriveMhgNonce16(nonce);
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
      mixRounds,
    });
  }
  const tree = await buildMerkle(pages);
  return { rootB64: base64Url(tree.root), parentByIndex, pages, tree, buildProof };
};

const PATH_CHECKLIST = [
  { pathId: 0, pow: false, turncheck: false, atomic: false, cap: null, key: "no_protection" },
  { pathId: 1, pow: false, turncheck: true, atomic: false, cap: 200, key: "cap_turnstile" },
  { pathId: 2, pow: false, turncheck: false, atomic: true, cap: null, key: "degraded_no_protection" },
  { pathId: 3, pow: false, turncheck: true, atomic: true, cap: 404, key: "atomic_business_turnstile" },
  { pathId: 4, pow: true, turncheck: false, atomic: false, cap: 404, key: "pow_only" },
  { pathId: 5, pow: true, turncheck: true, atomic: false, cap: 404, key: "pow_final_turnstile" },
  {
    pathId: 6,
    pow: true,
    turncheck: false,
    atomic: true,
    cap: 404,
    key: "pow_atomic_business",
    aggregatorPowAtomicConsume: true,
  },
  {
    pathId: 7,
    pow: true,
    turncheck: true,
    atomic: true,
    cap: 404,
    key: "pow_atomic_business_turnstile",
    aggregatorPowAtomicConsume: true,
  },
];

const pushFailure = (failures, pathId, reason, expected, actual) => {
  failures.push({ pathId: `#${pathId}`, reason, expected, actual });
};

const assertDeltaBudget = (failures, pathId, reason, delta) => {
  if (delta.total > 2) {
    pushFailure(failures, pathId, reason, "<=2", delta.total);
  }
};

const assertVerifyPlacement = (failures, pathId, key, observed) => {
  const expected = {
    no_protection: { capVerify: 0, finalVerify: 0, businessVerify: 0 },
    cap_turnstile: { capVerify: 1, finalVerify: 0, businessVerify: 0 },
    degraded_no_protection: { capVerify: 0, finalVerify: 0, businessVerify: 0 },
    atomic_business_turnstile: { capVerify: 0, finalVerify: 0, businessVerify: 1 },
    pow_only: { capVerify: 0, finalVerify: 0, businessVerify: 0 },
    pow_final_turnstile: { capVerify: 0, finalVerify: 1, businessVerify: 0 },
    pow_atomic_business: { capVerify: 0, finalVerify: 0, businessVerify: 1 },
    pow_atomic_business_turnstile: { capVerify: 0, finalVerify: 0, businessVerify: 1 },
  }[key];

  for (const field of Object.keys(expected)) {
    if (observed[field] !== expected[field]) {
      pushFailure(failures, pathId, `verify_${field}`, expected[field], observed[field]);
    }
  }
};

const runOnePath = async (mod, spec, failures) => {
  const tokenEnvelope = JSON.stringify({ turnstile: TURN_TOKEN });
  const { needTurn } = resolveCaptchaRequirements(spec);
  const counters = { aggregator: 0, origin: 0 };
  let activeTicketMac = "";

  const snapshot = () => ({ ...counters });
  const delta = (before, after) => ({
    aggregator: after.aggregator - before.aggregator,
    origin: after.origin - before.origin,
    total: after.aggregator - before.aggregator + (after.origin - before.origin),
  });

  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const reqUrl = String(req.url);
      if (reqUrl === SITEVERIFY_URL) {
        counters.aggregator += 1;
        return new Response(
          JSON.stringify({
            ok: true,
            reason: "ok",
            checks: {},
            providers: {
              turnstile: {
                ok: true,
                httpStatus: 200,
                normalized: { success: true, cdata: activeTicketMac },
                rawResponse: { success: true, cdata: activeTicketMac },
              },
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      counters.origin += 1;
      return new Response("ok", { status: 200 });
    };

    const payload = makeInnerPayload({
      powcheck: spec.pow,
      atomic: spec.atomic,
      turncheck: spec.turncheck,
      providers: spec.providers || "",
      aggregatorPowAtomicConsume: spec.aggregatorPowAtomicConsume === true,
    });
    const freshHeaders = () => makeInnerHeaders(payload);
    const pageRes = await mod.default.fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: { ...freshHeaders(), Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" },
      }),
      {},
      {}
    );
    const args = extractChallengeArgs(await pageRes.text());
    if (!args) {
      if (!spec.pow && !needTurn && spec.cap === null) {
        return;
      }
      pushFailure(failures, spec.pathId, "challenge_args", "present", "missing");
      return;
    }
    const parsedTicket = parseTicket(args.ticketB64);
    assert.ok(parsedTicket);
    assert.ok(Number.isSafeInteger(parsedTicket.issuedAt));
    assert.ok(parsedTicket.issuedAt > 0);
    activeTicketMac = parsedTicket.mac;

    let capDelta = { aggregator: 0, origin: 0, total: 0 };
    if (spec.cap !== null) {
      const capBefore = snapshot();
      const capRes = await mod.default.fetch(
        new Request("https://example.com/__pow/cap", {
          method: "POST",
          headers: {
            ...freshHeaders(),
            "CF-Connecting-IP": "1.2.3.4",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            ticketB64: args.ticketB64,
            pathHash: args.pathHash,
            captchaToken: tokenEnvelope,
          }),
        }),
        {},
        {}
      );
      const capAfter = snapshot();
      capDelta = delta(capBefore, capAfter);
      if (capRes.status !== spec.cap) {
        pushFailure(failures, spec.pathId, "cap_status", spec.cap, capRes.status);
      }
      assertDeltaBudget(failures, spec.pathId, "cap_budget", capDelta);
    }

    const observed = {
      capVerify: capDelta.aggregator,
      finalVerify: 0,
      businessVerify: 0,
      forbiddenVerify: 0,
    };

    if (spec.pow) {
      const nonce = base64Url(crypto.randomBytes(16));
      const witness = await buildMhgWitnessBundle({
        ticketB64: args.ticketB64,
        nonce,
        pageBytes: payload.c.POW_PAGE_BYTES,
        mixRounds: payload.c.POW_MIX_ROUNDS,
      });

      const commitBefore = snapshot();
      const commitRes = await mod.default.fetch(
        new Request("https://example.com/__pow/commit", {
          method: "POST",
          headers: {
            ...freshHeaders(),
            "Content-Type": "application/json",
            "CF-Connecting-IP": "1.2.3.4",
          },
          body: JSON.stringify({
            ticketB64: args.ticketB64,
            rootB64: witness.rootB64,
            pathHash: args.pathHash,
            nonce,
            captchaToken: needTurn ? tokenEnvelope : undefined,
          }),
        }),
        {},
        {}
      );
      const commitAfter = snapshot();
      const commitDelta = delta(commitBefore, commitAfter);
      assertDeltaBudget(failures, spec.pathId, "commit_budget", commitDelta);
      observed.forbiddenVerify += commitDelta.aggregator;
      if (commitRes.status !== 200) {
        pushFailure(failures, spec.pathId, "commit_status", 200, commitRes.status);
        return;
      }
      const commitCookie = (commitRes.headers.get("set-cookie") || "").split(";")[0];

      const challengeBefore = snapshot();
      const challengeRes = await mod.default.fetch(
        new Request("https://example.com/__pow/challenge", {
          method: "POST",
          headers: { ...freshHeaders(), "Content-Type": "application/json", Cookie: commitCookie },
          body: JSON.stringify({}),
        }),
        {},
        {}
      );
      const challengeAfter = snapshot();
      const challengeDelta = delta(challengeBefore, challengeAfter);
      assertDeltaBudget(failures, spec.pathId, "challenge_budget", challengeDelta);
      observed.forbiddenVerify += challengeDelta.aggregator;
      if (challengeRes.status !== 200) {
        pushFailure(failures, spec.pathId, "challenge_status", 200, challengeRes.status);
        return;
      }
      let state = await challengeRes.json();
      let finalBody = null;

      while (state.done === false) {
        const opens = state.indices.map((idx, pos) =>
          buildOpenEntryFromBundle({ bundle: witness, idx, seg: state.segs[pos] ?? 1 })
        );
        const openBefore = snapshot();
        const openRes = await mod.default.fetch(
          new Request("https://example.com/__pow/open", {
            method: "POST",
            headers: { ...freshHeaders(), "Content-Type": "application/json", Cookie: commitCookie },
            body: JSON.stringify({
              sid: state.sid,
              cursor: state.cursor,
              token: state.token,
              captchaToken: needTurn ? tokenEnvelope : undefined,
              opens,
            }),
          }),
          {},
          {}
        );
        const openAfter = snapshot();
        const openDelta = delta(openBefore, openAfter);
        assertDeltaBudget(failures, spec.pathId, state.cursor === 0 ? "open_budget" : "open_next_budget", openDelta);
        if (openRes.status !== 200) {
          pushFailure(failures, spec.pathId, "open_status", 200, openRes.status);
          return;
        }
        const body = await openRes.json();
        if (body.done === false) {
          observed.forbiddenVerify += openDelta.aggregator;
        } else {
          observed.finalVerify += openDelta.aggregator;
          finalBody = body;
        }
        state = body;
      }

      if (spec.atomic) {
        const consumeToken =
          finalBody && typeof finalBody.consume === "string"
            ? finalBody.consume
            : null;
        if (!consumeToken) {
          pushFailure(failures, spec.pathId, "consume_token", "present", finalBody?.consume ?? null);
        } else {
          const businessPayload = makeInnerPayload({
            powcheck: spec.pow,
            atomic: spec.atomic,
            turncheck: spec.turncheck,
            providers: spec.providers || "",
            aggregatorPowAtomicConsume: spec.aggregatorPowAtomicConsume === true,
            atomicState: {
              captchaToken: needTurn ? tokenEnvelope : "",
              ticketB64: "",
              consumeToken,
              fromCookie: false,
              cookieName: "",
            },
          });
          const businessBefore = snapshot();
          const businessRes = await mod.default.fetch(
            new Request("https://example.com/protected", {
              method: "GET",
              headers: {
                ...makeInnerHeaders(businessPayload),
                Accept: "application/json",
                "CF-Connecting-IP": "1.2.3.4",
              },
            }),
            {},
            {}
          );
          const businessAfter = snapshot();
          const businessDelta = delta(businessBefore, businessAfter);
          assertDeltaBudget(failures, spec.pathId, "business_budget", businessDelta);
          observed.businessVerify += businessDelta.aggregator;
          if (businessRes.status !== 200) {
            pushFailure(failures, spec.pathId, "business_status", 200, businessRes.status);
          }
        }
      }
    } else if (spec.atomic && needTurn) {
      const businessPayload = makeInnerPayload({
        powcheck: spec.pow,
        atomic: spec.atomic,
        turncheck: spec.turncheck,
        providers: spec.providers || "",
        aggregatorPowAtomicConsume: spec.aggregatorPowAtomicConsume === true,
        atomicState: {
          captchaToken: tokenEnvelope,
          ticketB64: args.ticketB64,
          consumeToken: "",
          fromCookie: false,
          cookieName: "",
        },
      });
      const businessBefore = snapshot();
      const businessRes = await mod.default.fetch(
        new Request("https://example.com/protected", {
          method: "GET",
          headers: {
            ...makeInnerHeaders(businessPayload),
            Accept: "application/json",
            "CF-Connecting-IP": "1.2.3.4",
          },
        }),
        {},
        {}
      );
      const businessAfter = snapshot();
      const businessDelta = delta(businessBefore, businessAfter);
      assertDeltaBudget(failures, spec.pathId, "business_budget", businessDelta);
      observed.businessVerify += businessDelta.aggregator;
      if (businessRes.status !== 200) {
        pushFailure(failures, spec.pathId, "business_status", 200, businessRes.status);
      }
    }

    if (observed.forbiddenVerify !== 0) {
      pushFailure(
        failures,
        spec.pathId,
        "forbidden_verify_points",
        { verify: 0 },
        { verify: observed.forbiddenVerify }
      );
    }
    assertVerifyPlacement(failures, spec.pathId, spec.key, observed);
  } finally {
    globalThis.fetch = originalFetch;
  }
};

const runSplitLinkedCase = async ({ pathId }) => {
  const restoreGlobals = ensureGlobals();
  const powModulePath = await buildPowModule();
  const cfgModulePath = await buildConfigModule(CONFIG_SECRET, {
    turncheck: true,
    ATOMIC_CONSUME: true,
    AGGREGATOR_POW_ATOMIC_CONSUME: true,
  });
  const powMod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}-${pathId}-pow`);
  const cfgMod = await import(`${pathToFileURL(cfgModulePath).href}?v=${Date.now()}-${pathId}-cfg`);
  const powHandler = powMod.default.fetch;
  const cfgHandler = cfgMod.default.fetch;

  const captchaEnvelope = JSON.stringify({
    turnstile: "atomic-turn-token-1234567890",
  });
  const emptyAtomic = {
    captchaToken: "",
    ticketB64: "",
    consumeToken: "",
    fromCookie: false,
    cookieName: "__Secure-pow_a",
  };
  const seedPayload = makeInnerPayload({
    powcheck: true,
    atomic: true,
    turncheck: true,
    providers: "",
    atomicState: emptyAtomic,
  });
  seedPayload.id = 0;

  const originalFetch = globalThis.fetch;
  try {
    let inPowHandler = false;
    const pageRes = await powHandler(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: {
          ...makeInnerHeaders(seedPayload),
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
    const witness = await buildMhgWitnessBundle({
      ticketB64: args.ticketB64,
      nonce,
      pageBytes: seedPayload.c.POW_PAGE_BYTES,
      mixRounds: seedPayload.c.POW_MIX_ROUNDS,
    });
    const commitRes = await powHandler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(seedPayload),
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

    const challengeRes = await powHandler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(seedPayload),
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
      const opens = state.indices.map((idx, pos) =>
        buildOpenEntryFromBundle({ bundle: witness, idx, seg: state.segs[pos] ?? 1 })
      );
      const openRes = await powHandler(
        new Request("https://example.com/__pow/open", {
          method: "POST",
          headers: {
            ...makeInnerHeaders(seedPayload),
            "Content-Type": "application/json",
            Cookie: commitCookie,
          },
          body: JSON.stringify({
            sid: state.sid,
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
    const seedTicketMac = parseTicket(args.ticketB64).mac;

    const counters = {
      aggregatorInPowConfig: 0,
      aggregatorInPowJs: 0,
      powConfigSubrequests: 0,
      powJsSubrequests: 0,
    };
    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const reqUrl = String(req.url);
      if (reqUrl === SITEVERIFY_URL) {
        if (inPowHandler) {
          counters.aggregatorInPowJs += 1;
          counters.powJsSubrequests += 1;
        } else {
          counters.aggregatorInPowConfig += 1;
          counters.powConfigSubrequests += 1;
        }
        return new Response(
          JSON.stringify({
            ok: true,
            reason: "ok",
            checks: {},
            providers: {
              turnstile: {
                ok: true,
                httpStatus: 200,
                normalized: { success: true, cdata: seedTicketMac },
                rawResponse: { success: true, cdata: seedTicketMac },
              },
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      const hasInnerHeaders = req.headers.has("X-Pow-Inner") || req.headers.has("X-Pow-Inner-Count");
      if (hasInnerHeaders && !inPowHandler) {
        counters.powConfigSubrequests += 1;
        inPowHandler = true;
        try {
          return await powHandler(req, {}, {});
        } finally {
          inPowHandler = false;
        }
      }
      if (hasInnerHeaders) {
        counters.powJsSubrequests += 1;
        return new Response("ok", { status: 200 });
      }
      counters.powJsSubrequests += 1;
      return new Response("ok", { status: 200 });
    };

    const businessReq = new Request(
      `https://example.com/protected?__ts=${encodeURIComponent(captchaEnvelope)}&__ct=${encodeURIComponent(state.consume)}`,
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
        },
      }
    );
    const businessRes = await cfgHandler(businessReq, {}, {});
    return {
      ...counters,
      status: businessRes.status,
      hint: businessRes.headers.get("x-pow-h"),
    };
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
};

const runMatrix8 = async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const failures = [];
  try {
    for (const spec of PATH_CHECKLIST) {
      await runOnePath(mod, spec, failures);
      if (spec.pathId === 7) {
        const split = await runSplitLinkedCase({ pathId: spec.pathId });
        if (split.status !== 200) {
          pushFailure(failures, spec.pathId, "split_business_status", 200, {
            status: split.status,
            hint: split.hint,
          });
        }
        if (split.aggregatorInPowConfig !== 0) {
          pushFailure(
            failures,
            spec.pathId,
            "split_aggregator_in_pow_config",
            0,
            split.aggregatorInPowConfig
          );
        }
        if (split.aggregatorInPowJs !== 1) {
          pushFailure(failures, spec.pathId, "split_aggregator_in_pow_js", 1, split.aggregatorInPowJs);
        }
        if (split.powConfigSubrequests > 2) {
          pushFailure(failures, spec.pathId, "split_pow_config_budget", "<=2", split.powConfigSubrequests);
        }
        if (split.powJsSubrequests > 3) {
          pushFailure(failures, spec.pathId, "split_pow_js_budget", "<=3", split.powJsSubrequests);
        }
      }
    }
  } finally {
    restoreGlobals();
  }
  return { failures };
};

const runStaleSemantics = async () => {
  const restoreGlobals = ensureGlobals();
  const powModulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}`);

  const payload = makeInnerPayload({ powcheck: true, atomic: false, turncheck: false });
  const freshHeaders = () => makeInnerHeaders(payload);

  const pageRes = await mod.default.fetch(
    new Request("https://example.com/protected", {
      method: "GET",
      headers: { ...freshHeaders(), Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" },
    }),
    {},
    {}
  );
  const args = extractChallengeArgs(await pageRes.text());
  assert.ok(args);

  const staleTicket = mutateTicketExpiry(args.ticketB64, Math.floor(Date.now() / 1000) - 20);
  const ticketStaleRes = await mod.default.fetch(
    new Request("https://example.com/__pow/commit", {
      method: "POST",
      headers: { ...freshHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        ticketB64: staleTicket,
        rootB64: base64Url(crypto.randomBytes(32)),
        pathHash: args.pathHash,
        nonce: base64Url(crypto.randomBytes(16)),
      }),
    }),
    {},
    {}
  );

  const nonce = base64Url(crypto.randomBytes(16));
  const witness = await buildMhgWitnessBundle({
    ticketB64: args.ticketB64,
    nonce,
    pageBytes: payload.c.POW_PAGE_BYTES,
    mixRounds: payload.c.POW_MIX_ROUNDS,
  });
  const commitRes = await mod.default.fetch(
    new Request("https://example.com/__pow/commit", {
      method: "POST",
      headers: { ...freshHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        ticketB64: args.ticketB64,
        rootB64: witness.rootB64,
        pathHash: args.pathHash,
        nonce,
      }),
    }),
    {},
    {}
  );
  const staleCommitCookie = mutateCommitExpiry(
    (commitRes.headers.get("set-cookie") || "").split(";")[0],
    Math.floor(Date.now() / 1000) - 10
  );
  const commitStaleRes = await mod.default.fetch(
    new Request("https://example.com/__pow/challenge", {
      method: "POST",
      headers: { ...freshHeaders(), "Content-Type": "application/json", Cookie: staleCommitCookie },
      body: JSON.stringify({}),
    }),
    {},
    {}
  );

  const configModulePath = await buildConfigModule();
  const configMod = await import(`${pathToFileURL(configModulePath).href}?v=${Date.now()}`);
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      if (req.headers.has("X-Pow-Inner") || req.headers.has("X-Pow-Inner-Count")) {
        return mod.default.fetch(req, {}, {});
      }
      return new Response("ok", { status: 200 });
    };
    const expiredConsume = makeConsumeToken({
      ticketB64: base64Url(Buffer.from("1.1700000000.16.r.1.m", "utf8")),
      exp: Math.floor(Date.now() / 1000) - 1,
      captchaTag: "AAAAAAAAAAAAAAAA",
      mask: 7,
    });
    const consumeStaleRes = await configMod.default.fetch(
      new Request(
        `https://example.com/protected?__ts=${encodeURIComponent(
          JSON.stringify({ turnstile: TURN_TOKEN })
        )}&__ct=${encodeURIComponent(expiredConsume)}`,
        { method: "GET", headers: { "CF-Connecting-IP": "1.2.3.4" } }
      ),
      {},
      {}
    );
    return {
      ticketStale: { status: ticketStaleRes.status, hint: ticketStaleRes.headers.get("x-pow-h") },
      commitStale: { status: commitStaleRes.status, hint: commitStaleRes.headers.get("x-pow-h") },
      consumeStale: { status: consumeStaleRes.status, hint: consumeStaleRes.headers.get("x-pow-h") },
    };
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
};

test("pow-only atomic mode requires consume token when aggregator consume is enabled", async () => {
  const restoreGlobals = ensureGlobals();
  const powModulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}-pow-only-atomic-consume`);

  const basePayload = makeInnerPayload({
    powcheck: true,
    atomic: true,
    turncheck: false,
  });
  basePayload.c.AGGREGATOR_POW_ATOMIC_CONSUME = true;
  const freshHeaders = (payload) => makeInnerHeaders(payload);

  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  let aggregatorCalls = 0;
  try {
    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      if (String(req.url) === SITEVERIFY_URL) {
        aggregatorCalls += 1;
        return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      originCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const pageRes = await mod.default.fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: { ...freshHeaders(basePayload), Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" },
      }),
      {},
      {}
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);

    const consumeToken = makeConsumeToken({
      ticketB64: args.ticketB64,
      exp: Math.floor(Date.now() / 1000) + 120,
      captchaTag: "any",
      mask: 1,
    });

    const missingConsumePayload = makeInnerPayload({
      powcheck: true,
      atomic: true,
      turncheck: false,
      atomicState: {
        captchaToken: "",
        ticketB64: "",
        consumeToken: "",
        fromCookie: false,
        cookieName: "",
      },
    });
    missingConsumePayload.c.AGGREGATOR_POW_ATOMIC_CONSUME = true;

    const missingConsumeRes = await mod.default.fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: {
          ...freshHeaders(missingConsumePayload),
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
        },
      }),
      {},
      {}
    );
    assert.equal(missingConsumeRes.status, 403);
    assert.equal(originCalls, 0);

    const consumePayload = makeInnerPayload({
      powcheck: true,
      atomic: true,
      turncheck: false,
      atomicState: {
        captchaToken: "",
        ticketB64: "",
        consumeToken,
        fromCookie: false,
        cookieName: "",
      },
    });
    consumePayload.c.AGGREGATOR_POW_ATOMIC_CONSUME = true;

    const consumeRes = await mod.default.fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: {
          ...freshHeaders(consumePayload),
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
        },
      }),
      {},
      {}
    );
    assert.equal(consumeRes.status, 200);
    assert.equal(originCalls, 1);
    assert.equal(aggregatorCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("non-atomic pow path with AGG true and turncheck false calls aggregator once", async () => {
  const restoreGlobals = ensureGlobals();
  const powModulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}-non-atomic-agg-true`);

  const payload = makeInnerPayload({ powcheck: true, atomic: false, turncheck: false });
  payload.c.AGGREGATOR_POW_ATOMIC_CONSUME = true;
  const freshHeaders = () => makeInnerHeaders(payload);

  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  let aggregatorCalls = 0;
  try {
    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      if (String(req.url) === SITEVERIFY_URL) {
        aggregatorCalls += 1;
        return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      originCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const pageRes = await mod.default.fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: { ...freshHeaders(), Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" },
      }),
      {},
      {}
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);

    const nonce = base64Url(crypto.randomBytes(16));
    const witness = await buildMhgWitnessBundle({
      ticketB64: args.ticketB64,
      nonce,
      pageBytes: payload.c.POW_PAGE_BYTES,
      mixRounds: payload.c.POW_MIX_ROUNDS,
    });

    const commitRes = await mod.default.fetch(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: { ...freshHeaders(), "Content-Type": "application/json", "CF-Connecting-IP": "1.2.3.4" },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64: witness.rootB64,
          pathHash: args.pathHash,
          nonce,
        }),
      }),
      {},
      {}
    );
    assert.equal(commitRes.status, 200);
    const commitCookie = (commitRes.headers.get("set-cookie") || "").split(";")[0];

    const challengeRes = await mod.default.fetch(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: { ...freshHeaders(), "Content-Type": "application/json", Cookie: commitCookie },
        body: JSON.stringify({}),
      }),
      {},
      {}
    );
    assert.equal(challengeRes.status, 200);
    let state = await challengeRes.json();

    while (state.done === false) {
      const opens = state.indices.map((idx, pos) =>
        buildOpenEntryFromBundle({ bundle: witness, idx, seg: state.segs[pos] ?? 1 })
      );
      const openRes = await mod.default.fetch(
        new Request("https://example.com/__pow/open", {
          method: "POST",
          headers: { ...freshHeaders(), "Content-Type": "application/json", Cookie: commitCookie },
          body: JSON.stringify({ sid: state.sid, cursor: state.cursor, token: state.token, opens }),
        }),
        {},
        {}
      );
      assert.equal(openRes.status, 200);
      state = await openRes.json();
    }

    assert.equal(originCalls, 0);
    assert.equal(aggregatorCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("non-atomic pow path with AGG false and turncheck false keeps aggregator at zero", async () => {
  const restoreGlobals = ensureGlobals();
  const powModulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}-non-atomic-agg-false`);

  const payload = makeInnerPayload({ powcheck: true, atomic: false, turncheck: false });
  payload.c.AGGREGATOR_POW_ATOMIC_CONSUME = false;
  const freshHeaders = () => makeInnerHeaders(payload);

  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  let aggregatorCalls = 0;
  try {
    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      if (String(req.url) === SITEVERIFY_URL) {
        aggregatorCalls += 1;
        return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      originCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const pageRes = await mod.default.fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: { ...freshHeaders(), Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" },
      }),
      {},
      {}
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);

    const nonce = base64Url(crypto.randomBytes(16));
    const witness = await buildMhgWitnessBundle({
      ticketB64: args.ticketB64,
      nonce,
      pageBytes: payload.c.POW_PAGE_BYTES,
      mixRounds: payload.c.POW_MIX_ROUNDS,
    });

    const commitRes = await mod.default.fetch(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: { ...freshHeaders(), "Content-Type": "application/json", "CF-Connecting-IP": "1.2.3.4" },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64: witness.rootB64,
          pathHash: args.pathHash,
          nonce,
        }),
      }),
      {},
      {}
    );
    assert.equal(commitRes.status, 200);
    const commitCookie = (commitRes.headers.get("set-cookie") || "").split(";")[0];

    const challengeRes = await mod.default.fetch(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: { ...freshHeaders(), "Content-Type": "application/json", Cookie: commitCookie },
        body: JSON.stringify({}),
      }),
      {},
      {}
    );
    assert.equal(challengeRes.status, 200);
    let state = await challengeRes.json();

    while (state.done === false) {
      const opens = state.indices.map((idx, pos) =>
        buildOpenEntryFromBundle({ bundle: witness, idx, seg: state.segs[pos] ?? 1 })
      );
      const openRes = await mod.default.fetch(
        new Request("https://example.com/__pow/open", {
          method: "POST",
          headers: { ...freshHeaders(), "Content-Type": "application/json", Cookie: commitCookie },
          body: JSON.stringify({ sid: state.sid, cursor: state.cursor, token: state.token, opens }),
        }),
        {},
        {}
      );
      assert.equal(openRes.status, 200);
      state = await openRes.json();
    }

    assert.equal(aggregatorCalls, 0);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-only atomic mode falls back to pow_required when aggregator consume is disabled", async () => {
  const restoreGlobals = ensureGlobals();
  const powModulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}-pow-only-atomic-no-agg`);

  const payload = makeInnerPayload({
    powcheck: true,
    atomic: true,
    turncheck: false,
  });
  payload.c.AGGREGATOR_POW_ATOMIC_CONSUME = false;
  const headers = makeInnerHeaders(payload);

  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  let aggregatorCalls = 0;
  try {
    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      if (String(req.url) === SITEVERIFY_URL) {
        aggregatorCalls += 1;
        return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      originCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const res = await mod.default.fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: { ...headers, Accept: "application/json", "CF-Connecting-IP": "1.2.3.4" },
      }),
      {},
      {}
    );

    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { code: "pow_required" });
    assert.equal(aggregatorCalls, 0);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("all 8 path combinations preserve api/subrequest semantics", async () => {
  const report = await runMatrix8();
  assert.equal(report.failures.length, 0, JSON.stringify(report.failures, null, 2));
});

test("stale semantics cover ticket commit and consume expiry", async () => {
  const out = await runStaleSemantics();
  assert.equal(out.ticketStale.status, 403);
  assert.equal(out.ticketStale.hint, "stale");
  assert.equal(out.commitStale.status, 403);
  assert.equal(out.commitStale.hint, "stale");
  assert.equal(out.consumeStale.status, 403);
  assert.equal(out.consumeStale.hint, "stale");
});

test("commit rejects stale issuedAt ticket even when mac and exp are valid", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const powModulePath = await buildPowModule();
    const mod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}-issued-at-stale`);
    const payload = makeInnerPayload({ powcheck: true, atomic: false, turncheck: false });
    const freshHeaders = () => makeInnerHeaders(payload);
    const pageRes = await mod.default.fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: { ...freshHeaders(), Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" },
      }),
      {},
      {}
    );
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);

    const nowSeconds = Math.floor(Date.now() / 1000);
    const staleTicketB64 = makeSignedTicketB64({
      payload,
      host: "example.com",
      pathHash: args.pathHash,
      issuedAt: nowSeconds - 301,
      exp: nowSeconds + 120,
      steps: 6,
      nonce: base64Url(crypto.randomBytes(12)),
    });

    const commitRes = await mod.default.fetch(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: { ...freshHeaders(), "Content-Type": "application/json", "CF-Connecting-IP": "1.2.3.4" },
        body: JSON.stringify({
          ticketB64: staleTicketB64,
          rootB64: base64Url(crypto.randomBytes(32)),
          pathHash: args.pathHash,
          nonce: base64Url(crypto.randomBytes(16)),
        }),
      }),
      {},
      {}
    );

    assert.equal(commitRes.status, 403);
    assert.equal(commitRes.headers.get("x-pow-h"), "stale");
  } finally {
    restoreGlobals();
  }
});

test("commit treats POW_MAX_GEN_TIME_SEC=0 as clamp-to-1 instead of fallback", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const powModulePath = await buildPowModule();
    const mod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}-issued-at-zero-clamp`);
    const payload = makeInnerPayload({ powcheck: true, atomic: false, turncheck: false });
    payload.c.POW_MAX_GEN_TIME_SEC = 0;
    const freshHeaders = () => makeInnerHeaders(payload);
    const pageRes = await mod.default.fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: { ...freshHeaders(), Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" },
      }),
      {},
      {}
    );
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);

    const nowSeconds = Math.floor(Date.now() / 1000);
    const staleTicketB64 = makeSignedTicketB64({
      payload,
      host: "example.com",
      pathHash: args.pathHash,
      issuedAt: nowSeconds - 2,
      exp: nowSeconds + 120,
      steps: 6,
      nonce: base64Url(crypto.randomBytes(12)),
    });

    const commitRes = await mod.default.fetch(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: { ...freshHeaders(), "Content-Type": "application/json", "CF-Connecting-IP": "1.2.3.4" },
        body: JSON.stringify({
          ticketB64: staleTicketB64,
          rootB64: base64Url(crypto.randomBytes(32)),
          pathHash: args.pathHash,
          nonce: base64Url(crypto.randomBytes(16)),
        }),
      }),
      {},
      {}
    );

    assert.equal(commitRes.status, 403);
    assert.equal(commitRes.headers.get("x-pow-h"), "stale");
  } finally {
    restoreGlobals();
  }
});

test("challenge rejects absolute issuedAt lifecycle overflow even when ticket and commit are fresh", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const powModulePath = await buildPowModule();
    const mod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}-challenge-absolute-stale`);
    const payload = makeInnerPayload({ powcheck: true, atomic: false, turncheck: false });
    const freshHeaders = () => makeInnerHeaders(payload);
    const pageRes = await mod.default.fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: { ...freshHeaders(), Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" },
      }),
      {},
      {}
    );
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);

    const nowSeconds = Math.floor(Date.now() / 1000);
    const staleTicketB64 = makeSignedTicketB64({
      payload,
      host: "example.com",
      pathHash: args.pathHash,
      issuedAt: nowSeconds - 421,
      exp: nowSeconds + 120,
      steps: 6,
      nonce: base64Url(crypto.randomBytes(12)),
    });
    const commitCookie = makeSignedCommitCookie({
      ticketB64: staleTicketB64,
      rootB64: base64Url(crypto.randomBytes(32)),
      pathHash: args.pathHash,
      captchaTag: "any",
      nonce: base64Url(crypto.randomBytes(16)),
      exp: nowSeconds + 60,
    });

    const challengeRes = await mod.default.fetch(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: { ...freshHeaders(), "Content-Type": "application/json", Cookie: commitCookie },
        body: JSON.stringify({}),
      }),
      {},
      {}
    );

    assert.equal(challengeRes.status, 403);
    assert.equal(challengeRes.headers.get("x-pow-h"), "stale");
  } finally {
    restoreGlobals();
  }
});

test("open rejects absolute issuedAt lifecycle overflow even when ticket and commit are fresh", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const powModulePath = await buildPowModule();
    const mod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}-open-absolute-stale`);
    const payload = makeInnerPayload({ powcheck: true, atomic: false, turncheck: false });
    const freshHeaders = () => makeInnerHeaders(payload);
    const pageRes = await mod.default.fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: { ...freshHeaders(), Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" },
      }),
      {},
      {}
    );
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);

    const nowSeconds = Math.floor(Date.now() / 1000);
    const staleTicketB64 = makeSignedTicketB64({
      payload,
      host: "example.com",
      pathHash: args.pathHash,
      issuedAt: nowSeconds - 421,
      exp: nowSeconds + 120,
      steps: 6,
      nonce: base64Url(crypto.randomBytes(12)),
    });
    const commitCookie = makeSignedCommitCookie({
      ticketB64: staleTicketB64,
      rootB64: base64Url(crypto.randomBytes(32)),
      pathHash: args.pathHash,
      captchaTag: "any",
      nonce: base64Url(crypto.randomBytes(16)),
      exp: nowSeconds + 60,
    });

    const openRes = await mod.default.fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: { ...freshHeaders(), "Content-Type": "application/json", Cookie: commitCookie },
        body: JSON.stringify({}),
      }),
      {},
      {}
    );

    assert.equal(openRes.status, 403);
    assert.equal(openRes.headers.get("x-pow-h"), "stale");
  } finally {
    restoreGlobals();
  }
});

test("challenge allows request exactly at absolute issuedAt lifecycle deadline", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const powModulePath = await buildPowModule();
    const mod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}-challenge-absolute-deadline`);
    const payload = makeInnerPayload({ powcheck: true, atomic: false, turncheck: false });
    payload.c.POW_MAX_GEN_TIME_SEC = 5;
    payload.c.POW_COMMIT_TTL_SEC = 7;
    const freshHeaders = () => makeInnerHeaders(payload);
    const pageRes = await mod.default.fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: { ...freshHeaders(), Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" },
      }),
      {},
      {}
    );
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);

    const nowSeconds = Math.floor(Date.now() / 1000);
    const issuedAt = nowSeconds - 12;
    const ticketB64 = makeSignedTicketB64({
      payload,
      host: "example.com",
      pathHash: args.pathHash,
      issuedAt,
      exp: nowSeconds + 60,
      steps: 6,
      nonce: base64Url(crypto.randomBytes(12)),
    });
    const commitCookie = makeSignedCommitCookie({
      ticketB64,
      rootB64: base64Url(crypto.randomBytes(32)),
      pathHash: args.pathHash,
      captchaTag: "any",
      nonce: base64Url(crypto.randomBytes(16)),
      exp: nowSeconds + 30,
    });

    const challengeRes = await mod.default.fetch(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: { ...freshHeaders(), "Content-Type": "application/json", Cookie: commitCookie },
        body: JSON.stringify({}),
      }),
      {},
      {}
    );

    assert.equal(challengeRes.status, 200);
  } finally {
    restoreGlobals();
  }
});
