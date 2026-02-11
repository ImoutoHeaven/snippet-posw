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

const TURN_TOKEN = "turnstile-token-value-1234567890";
const RECAPTCHA_TOKEN = "recaptcha-token-value-1234567890";

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
        recaptchaEnabled: true,
        RECAPTCHA_PAIRS: [{ sitekey: "rk-1", secret: "rs-1" }],
        RECAPTCHA_ACTION: "submit",
        RECAPTCHA_MIN_SCORE: 0.5,
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
  return {
    e: Number.parseInt(parts[1], 10),
    L: Number.parseInt(parts[2], 10),
    cfgId: Number.parseInt(parts[4], 10),
    mac: parts[5],
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

const extractChallengeArgs = (html) => {
  const match = html.match(/g\("([^"]+)",\s*(\d+),\s*"([^"]+)",\s*"([^"]+)"/u);
  if (!match) return null;
  return { ticketB64: match[3], pathHash: match[4] };
};

const captchaTagV1 = async (turnToken, recaptchaToken) =>
  base64Url(
    crypto
      .createHash("sha256")
      .update(`ctag|v1|t=${String(turnToken || "")}|r=${String(recaptchaToken || "")}`)
      .digest()
      .subarray(0, 12)
  );

const resolveCaptchaRequirements = (spec) => {
  let needTurn = spec.turncheck === true;
  let needRecaptcha = spec.recaptchaEnabled === true;
  if (!needTurn && !needRecaptcha) {
    const providers = String(spec.providers || "")
      .split(/[\s,]+/u)
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);
    needTurn = providers.includes("turnstile");
    needRecaptcha = providers.includes("recaptcha") || providers.includes("recaptcha_v3");
  }
  return { needTurn, needRecaptcha };
};

const makeInnerPayload = ({ powcheck, atomic, turncheck, recaptchaEnabled, providers = "", atomicState = null }) => ({
  v: 1,
  id: 99,
  c: {
    POW_TOKEN: POW_SECRET,
    powcheck,
    turncheck,
    recaptchaEnabled,
    providers,
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
  { pathId: 0, pow: false, turncheck: false, recaptchaEnabled: false, atomic: false, cap: null, key: "no_protection" },
  { pathId: 1, pow: false, turncheck: false, recaptchaEnabled: false, providers: "recaptcha", atomic: false, cap: 200, key: "cap_recaptcha" },
  { pathId: 2, pow: false, turncheck: false, recaptchaEnabled: false, providers: "turnstile", atomic: false, cap: 200, key: "cap_turnstile" },
  { pathId: 3, pow: false, turncheck: false, recaptchaEnabled: false, providers: "turnstile,recaptcha", atomic: false, cap: 200, key: "cap_dual" },
  { pathId: 4, pow: false, turncheck: false, recaptchaEnabled: false, atomic: false, cap: null, key: "degraded_no_protection" },
  { pathId: 5, pow: false, turncheck: false, recaptchaEnabled: false, providers: "recaptcha", atomic: true, cap: 404, key: "atomic_business_recaptcha" },
  { pathId: 6, pow: false, turncheck: false, recaptchaEnabled: false, providers: "turnstile", atomic: true, cap: 404, key: "atomic_business_turnstile" },
  { pathId: 7, pow: false, turncheck: false, recaptchaEnabled: false, providers: "turnstile,recaptcha", atomic: true, cap: 404, key: "atomic_business_dual_split" },
  { pathId: 8, pow: true, turncheck: false, recaptchaEnabled: false, atomic: false, cap: 404, key: "pow_only" },
  { pathId: 9, pow: true, turncheck: false, recaptchaEnabled: true, atomic: false, cap: 404, key: "pow_final_recaptcha" },
  { pathId: 10, pow: true, turncheck: true, recaptchaEnabled: false, atomic: false, cap: 404, key: "pow_final_turnstile" },
  { pathId: 11, pow: true, turncheck: false, recaptchaEnabled: false, providers: "turnstile,recaptcha", atomic: false, cap: 404, key: "pow_final_dual" },
  { pathId: 12, pow: true, turncheck: false, recaptchaEnabled: false, atomic: false, cap: 404, key: "pow_only_degraded" },
  { pathId: 13, pow: true, turncheck: false, recaptchaEnabled: true, atomic: true, cap: 404, key: "pow_atomic_business_recaptcha" },
  { pathId: 14, pow: true, turncheck: true, recaptchaEnabled: false, atomic: true, cap: 404, key: "pow_atomic_business_turnstile" },
  { pathId: 15, pow: true, turncheck: false, recaptchaEnabled: false, providers: "turnstile,recaptcha", atomic: true, cap: 404, key: "pow_atomic_business_dual_split" },
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
    no_protection: { capTurn: 0, capRecaptcha: 0, finalTurn: 0, finalRecaptcha: 0, businessTurn: 0, businessRecaptcha: 0 },
    cap_recaptcha: { capTurn: 0, capRecaptcha: 1, finalTurn: 0, finalRecaptcha: 0, businessTurn: 0, businessRecaptcha: 0 },
    cap_turnstile: { capTurn: 1, capRecaptcha: 0, finalTurn: 0, finalRecaptcha: 0, businessTurn: 0, businessRecaptcha: 0 },
    cap_dual: { capTurn: 1, capRecaptcha: 1, finalTurn: 0, finalRecaptcha: 0, businessTurn: 0, businessRecaptcha: 0 },
    degraded_no_protection: { capTurn: 0, capRecaptcha: 0, finalTurn: 0, finalRecaptcha: 0, businessTurn: 0, businessRecaptcha: 0 },
    atomic_business_recaptcha: { capTurn: 0, capRecaptcha: 0, finalTurn: 0, finalRecaptcha: 0, businessTurn: 0, businessRecaptcha: 1 },
    atomic_business_turnstile: { capTurn: 0, capRecaptcha: 0, finalTurn: 0, finalRecaptcha: 0, businessTurn: 1, businessRecaptcha: 0 },
    atomic_business_dual_split: { capTurn: 0, capRecaptcha: 0, finalTurn: 0, finalRecaptcha: 0, businessTurn: 0, businessRecaptcha: 1 },
    pow_only: { capTurn: 0, capRecaptcha: 0, finalTurn: 0, finalRecaptcha: 0, businessTurn: 0, businessRecaptcha: 0 },
    pow_final_recaptcha: { capTurn: 0, capRecaptcha: 0, finalTurn: 0, finalRecaptcha: 1, businessTurn: 0, businessRecaptcha: 0 },
    pow_final_turnstile: { capTurn: 0, capRecaptcha: 0, finalTurn: 1, finalRecaptcha: 0, businessTurn: 0, businessRecaptcha: 0 },
    pow_final_dual: { capTurn: 0, capRecaptcha: 0, finalTurn: 1, finalRecaptcha: 1, businessTurn: 0, businessRecaptcha: 0 },
    pow_only_degraded: { capTurn: 0, capRecaptcha: 0, finalTurn: 0, finalRecaptcha: 0, businessTurn: 0, businessRecaptcha: 0 },
    pow_atomic_business_recaptcha: { capTurn: 0, capRecaptcha: 0, finalTurn: 0, finalRecaptcha: 0, businessTurn: 0, businessRecaptcha: 1 },
    pow_atomic_business_turnstile: { capTurn: 0, capRecaptcha: 0, finalTurn: 0, finalRecaptcha: 0, businessTurn: 1, businessRecaptcha: 0 },
    pow_atomic_business_dual_split: { capTurn: 0, capRecaptcha: 0, finalTurn: 0, finalRecaptcha: 0, businessTurn: 0, businessRecaptcha: 1 },
  }[key];

  for (const field of Object.keys(expected)) {
    if (observed[field] !== expected[field]) {
      pushFailure(failures, pathId, `verify_${field}`, expected[field], observed[field]);
    }
  }
};

const runOnePath = async (mod, spec, failures) => {
  const tokenEnvelope = JSON.stringify({ turnstile: TURN_TOKEN, recaptcha_v3: RECAPTCHA_TOKEN });
  const { needTurn, needRecaptcha } = resolveCaptchaRequirements(spec);
  const counters = { turn: 0, recaptcha: 0, origin: 0 };
  let activeTicketMac = "";

  const snapshot = () => ({ ...counters });
  const delta = (before, after) => ({
    turn: after.turn - before.turn,
    recaptcha: after.recaptcha - before.recaptcha,
    origin: after.origin - before.origin,
    total:
      after.turn - before.turn + (after.recaptcha - before.recaptcha) + (after.origin - before.origin),
  });

  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const reqUrl = String(req.url);
      if (reqUrl === TURNSTILE_SITEVERIFY_URL) {
        counters.turn += 1;
        return new Response(JSON.stringify({ success: true, cdata: activeTicketMac }), { status: 200 });
      }
      if (reqUrl === RECAPTCHA_SITEVERIFY_URL) {
        counters.recaptcha += 1;
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
      counters.origin += 1;
      return new Response("ok", { status: 200 });
    };

    const payload = makeInnerPayload({
      powcheck: spec.pow,
      atomic: spec.atomic,
      turncheck: spec.turncheck,
      recaptchaEnabled: spec.recaptchaEnabled,
      providers: spec.providers || "",
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
      if (!spec.pow && !needTurn && !needRecaptcha && spec.cap === null) {
        return;
      }
      pushFailure(failures, spec.pathId, "challenge_args", "present", "missing");
      return;
    }
    activeTicketMac = parseTicket(args.ticketB64).mac;

    let capDelta = { turn: 0, recaptcha: 0, origin: 0, total: 0 };
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
      capTurn: capDelta.turn,
      capRecaptcha: capDelta.recaptcha,
      finalTurn: 0,
      finalRecaptcha: 0,
      businessTurn: 0,
      businessRecaptcha: 0,
      forbiddenTurn: 0,
      forbiddenRecaptcha: 0,
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
            captchaToken: needTurn || needRecaptcha ? tokenEnvelope : undefined,
          }),
        }),
        {},
        {}
      );
      const commitAfter = snapshot();
      const commitDelta = delta(commitBefore, commitAfter);
      assertDeltaBudget(failures, spec.pathId, "commit_budget", commitDelta);
      observed.forbiddenTurn += commitDelta.turn;
      observed.forbiddenRecaptcha += commitDelta.recaptcha;
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
      observed.forbiddenTurn += challengeDelta.turn;
      observed.forbiddenRecaptcha += challengeDelta.recaptcha;
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
              captchaToken: needTurn || needRecaptcha ? tokenEnvelope : undefined,
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
          observed.forbiddenTurn += openDelta.turn;
          observed.forbiddenRecaptcha += openDelta.recaptcha;
        } else {
          observed.finalTurn += openDelta.turn;
          observed.finalRecaptcha += openDelta.recaptcha;
          finalBody = body;
        }
        state = body;
      }

      if (spec.atomic) {
        if (!finalBody || typeof finalBody.consume !== "string") {
          pushFailure(failures, spec.pathId, "consume_token", "present", finalBody?.consume ?? null);
        } else {
          const turnstilePreflight =
            needTurn && needRecaptcha
              ? {
                  checked: true,
                  ok: true,
                  reason: "",
                  ticketMac: activeTicketMac,
                  tokenTag: await captchaTagV1(TURN_TOKEN, RECAPTCHA_TOKEN),
                }
              : null;
          const businessPayload = makeInnerPayload({
            powcheck: spec.pow,
            atomic: spec.atomic,
            turncheck: spec.turncheck,
            recaptchaEnabled: spec.recaptchaEnabled,
            providers: spec.providers || "",
            atomicState: {
              captchaToken: tokenEnvelope,
              ticketB64: "",
              consumeToken: finalBody.consume,
              fromCookie: false,
              cookieName: "",
              turnstilePreflight,
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
          observed.businessTurn += businessDelta.turn;
          observed.businessRecaptcha += businessDelta.recaptcha;
          if (businessRes.status !== 200) {
            pushFailure(failures, spec.pathId, "business_status", 200, businessRes.status);
          }
        }
      }
    } else if (spec.atomic && (needTurn || needRecaptcha)) {
      const turnstilePreflight =
        needTurn && needRecaptcha
          ? {
              checked: true,
              ok: true,
              reason: "",
              ticketMac: activeTicketMac,
              tokenTag: await captchaTagV1(TURN_TOKEN, RECAPTCHA_TOKEN),
            }
          : null;
      const businessPayload = makeInnerPayload({
        powcheck: spec.pow,
        atomic: spec.atomic,
        turncheck: spec.turncheck,
        recaptchaEnabled: spec.recaptchaEnabled,
        providers: spec.providers || "",
        atomicState: {
          captchaToken: tokenEnvelope,
          ticketB64: args.ticketB64,
          consumeToken: "",
          fromCookie: false,
          cookieName: "",
          turnstilePreflight,
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
      observed.businessTurn += businessDelta.turn;
      observed.businessRecaptcha += businessDelta.recaptcha;
      if (businessRes.status !== 200) {
        pushFailure(failures, spec.pathId, "business_status", 200, businessRes.status);
      }
    }

    if (observed.forbiddenTurn !== 0 || observed.forbiddenRecaptcha !== 0) {
      pushFailure(
        failures,
        spec.pathId,
        "forbidden_verify_points",
        { turn: 0, recaptcha: 0 },
        { turn: observed.forbiddenTurn, recaptcha: observed.forbiddenRecaptcha }
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
    turncheck: false,
    recaptchaEnabled: false,
    providers: "turnstile,recaptcha",
    ATOMIC_CONSUME: true,
  });
  const powMod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}-${pathId}-pow`);
  const cfgMod = await import(`${pathToFileURL(cfgModulePath).href}?v=${Date.now()}-${pathId}-cfg`);
  const powHandler = powMod.default.fetch;
  const cfgHandler = cfgMod.default.fetch;

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
  const seedPayload = makeInnerPayload({
    powcheck: true,
    atomic: true,
    turncheck: true,
    recaptchaEnabled: true,
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
      turnInPowConfig: 0,
      turnInPowJs: 0,
      recaptchaInPowConfig: 0,
      recaptchaInPowJs: 0,
      powConfigSubrequests: 0,
      powJsSubrequests: 0,
    };
    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const reqUrl = String(req.url);
      if (reqUrl === TURNSTILE_SITEVERIFY_URL) {
        if (inPowHandler) {
          counters.turnInPowJs += 1;
          counters.powJsSubrequests += 1;
        } else {
          counters.turnInPowConfig += 1;
          counters.powConfigSubrequests += 1;
        }
        return new Response(JSON.stringify({ success: true, cdata: seedTicketMac }), { status: 200 });
      }
      if (reqUrl === RECAPTCHA_SITEVERIFY_URL) {
        if (inPowHandler) {
          counters.recaptchaInPowJs += 1;
          counters.powJsSubrequests += 1;
        } else {
          counters.recaptchaInPowConfig += 1;
          counters.powConfigSubrequests += 1;
        }
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

const runMatrix16 = async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const failures = [];
  try {
    for (const spec of PATH_CHECKLIST) {
      await runOnePath(mod, spec, failures);
      if (spec.pathId === 7 || spec.pathId === 15) {
        const split = await runSplitLinkedCase({ pathId: spec.pathId });
        if (split.status !== 200) {
          pushFailure(failures, spec.pathId, "split_business_status", 200, {
            status: split.status,
            hint: split.hint,
          });
        }
        if (split.turnInPowConfig !== 1) {
          pushFailure(failures, spec.pathId, "split_turnstile_in_pow_config", 1, split.turnInPowConfig);
        }
        if (split.turnInPowJs !== 0) {
          pushFailure(failures, spec.pathId, "split_turnstile_in_pow_js", 0, split.turnInPowJs);
        }
        if (split.recaptchaInPowJs !== 1) {
          pushFailure(failures, spec.pathId, "split_recaptcha_in_pow_js", 1, split.recaptchaInPowJs);
        }
        if (split.recaptchaInPowConfig !== 0) {
          pushFailure(failures, spec.pathId, "split_recaptcha_in_pow_config", 0, split.recaptchaInPowConfig);
        }
        if (split.powConfigSubrequests > 2) {
          pushFailure(failures, spec.pathId, "split_pow_config_budget", "<=2", split.powConfigSubrequests);
        }
        if (split.powJsSubrequests > 2) {
          pushFailure(failures, spec.pathId, "split_pow_js_budget", "<=2", split.powJsSubrequests);
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

  const payload = makeInnerPayload({ powcheck: true, atomic: false, turncheck: false, recaptchaEnabled: false });
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
          JSON.stringify({ turnstile: TURN_TOKEN, recaptcha_v3: RECAPTCHA_TOKEN })
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

test("all 16 path combinations preserve api/subrequest semantics", async () => {
  const report = await runMatrix16();
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
