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

const assertNoLegacyCaptchaKeys = (config) => {
  assert.equal("recaptchaEnabled" in config, false);
  assert.equal("RECAPTCHA_PAIRS" in config, false);
  assert.equal("RECAPTCHA_ACTION" in config, false);
  assert.equal("RECAPTCHA_MIN_SCORE" in config, false);
};

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const buildInnerHeaders = (payloadObj, secret, expOverride) => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const exp = Number.isFinite(expOverride)
    ? expOverride
    : Math.floor(Date.now() / 1000) + 3;
  const macInput = `${payload}.${exp}`;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(macInput).digest());
  return { payload, mac, exp };
};

const decodeTicket = (ticketB64) => {
  const raw = Buffer.from(String(ticketB64 || "").replace(/-/g, "+").replace(/_/g, "/"), "base64")
    .toString("utf8");
  const parts = raw.split(".");
  if (parts.length !== 7) return null;
  const issuedAt = Number.parseInt(parts[5], 10);
  if (!Number.isFinite(issuedAt) || issuedAt <= 0) return null;
  return {
    v: Number.parseInt(parts[0], 10),
    e: Number.parseInt(parts[1], 10),
    L: Number.parseInt(parts[2], 10),
    r: parts[3] || "",
    cfgId: Number.parseInt(parts[4], 10),
    issuedAt,
    mac: parts[6] || "",
  };
};

test("ticket helper enforces 7-part schema with issuedAt", () => {
  const sixPart = base64Url(Buffer.from("3.1700000000.16.rand.7.sig", "utf8"));
  assert.equal(decodeTicket(sixPart), null);

  const issuedAt = Math.floor(Date.now() / 1000);
  const sevenPart = base64Url(
    Buffer.from(`3.1700000000.16.rand.7.${issuedAt}.sig`, "utf8")
  );
  const parsed = decodeTicket(sevenPart);
  assert.ok(parsed, "7-part ticket parses");
  assert.equal(parsed.issuedAt, issuedAt);
  assert.equal(parsed.mac, "sig");
});

test("runtime contracts are turnstile-only", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const runtimeSources = await Promise.all([
    readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "business-gate.js"), "utf8"),
    readFile(join(repoRoot, "glue.js"), "utf8"),
  ]);
  for (const source of runtimeSources) {
    assert.doesNotMatch(source, /recaptcha|RECAPTCHA_|recaptcha_v3/u);
  }
});

const extractChallengeArgs = (html) => {
  const match = html.match(
    /g\("([^"]+)",\s*(\d+),\s*"([^"]+)",\s*"([^"]+)",\s*\d+,\s*\d+,\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]*)"(?:,\s*\d+,\s*\d+)?\)/u
  );
  if (!match) return null;
  return {
    bindingB64: match[1],
    steps: Number.parseInt(match[2], 10),
    ticketB64: match[3],
    pathHash: match[4],
    captchaCfgB64: match[8],
  };
};

const decodeB64UrlUtf8 = (value) => {
  let b64 = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return Buffer.from(b64, "base64").toString("utf8");
};

const fromBase64Url = (value) => {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, "base64");
};

const deriveMhgGraphSeed = (ticketB64, nonce) =>
  crypto.createHash("sha256").update(`mhg|graph|v2|${ticketB64}|${nonce}`).digest().subarray(0, 16);

const deriveMhgNonce16 = (nonce) => {
  const raw = fromBase64Url(nonce);
  if (raw.length >= 16) return raw.subarray(0, 16);
  return crypto.createHash("sha256").update(raw).digest().subarray(0, 16);
};

const buildMhgWitnessBundle = async ({ ticketB64, nonce }) => {
  const ticket = decodeTicket(ticketB64);
  if (!ticket) throw new Error("invalid ticket");
  const { parentsOf } = await import("../lib/mhg/graph.js");
  const { makeGenesisPage, mixPage } = await import("../lib/mhg/mix-aes.js");
  const { buildMerkle, buildProof } = await import("../lib/mhg/merkle.js");

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
    witnessByIndex.set(i, {
      pageB64: base64Url(pages[i]),
      proof: buildProof(tree, i).map((sib) => base64Url(sib)),
    });
  }
  witnessByIndex.set(0, {
    pageB64: base64Url(pages[0]),
    proof: buildProof(tree, 0).map((sib) => base64Url(sib)),
  });

  return { rootB64: base64Url(tree.root), witnessByIndex, parentByIndex };
};

const buildEqSet = (index, seg) => {
  const out = [];
  const start = Math.max(1, index - seg + 1);
  for (let i = start; i <= index; i += 1) out.push(i);
  return out;
};

const buildNeedSet = (eqSet, parentByIndex) => {
  const out = new Set();
  for (const i of eqSet) {
    const edge = parentByIndex.get(i);
    if (!edge) throw new Error(`missing parents for index ${i}`);
    out.add(i);
    out.add(edge.p0);
    out.add(edge.p1);
    out.add(edge.p2);
  }
  return out;
};

const buildMhgOpensForChallenge = ({ indices, segs, witnessByIndex, parentByIndex }) => {
  if (!Array.isArray(indices) || !Array.isArray(segs) || indices.length !== segs.length) {
    throw new Error("challenge shape mismatch");
  }
  return indices.map((index, pos) => {
    const seg = Number.parseInt(segs[pos], 10);
    if (!Number.isInteger(seg) || seg <= 0) throw new Error(`invalid seg at ${pos}`);
    const eqSet = buildEqSet(index, seg);
    const need = buildNeedSet(eqSet, parentByIndex);
    const nodes = {};
    for (const needIdx of need) {
      const witness = witnessByIndex.get(needIdx);
      if (!witness) throw new Error(`missing witness for index ${needIdx}`);
      nodes[String(needIdx)] = { pageB64: witness.pageB64, proof: witness.proof };
    }
    return { i: index, seg, nodes };
  });
};

const sha256Bytes = async (value) => {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const digest = await crypto.webcrypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
};

const concatBytes = (...chunks) => {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

const encodeUint32BE = (value) => {
  const out = new Uint8Array(4);
  const v = Number(value) >>> 0;
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  return out;
};

const captchaTagFromToken = async (turnToken) => {
  const material = `ctag|v1|t=${String(turnToken || "")}`;
  const digest = await sha256Bytes(material);
  return base64Url(digest.slice(0, 12));
};

const makeConsumeToken = ({ powSecret, ticketB64, exp, captchaTag, mask }) => {
  const payload = `U|${ticketB64}|${exp}|${captchaTag}|${mask}`;
  const mac = base64Url(crypto.createHmac("sha256", powSecret).update(payload).digest());
  return `v2.${ticketB64}.${exp}.${captchaTag}.${mask}.${mac}`;
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

const buildCoreModules = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [
    core1SourceRaw,
    core2SourceRaw,
    transitSource,
    innerAuthSource,
    internalHeadersSource,
    apiEngineSource,
    siteverifyClientSource,
    businessGateSource,
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
    readOptionalFile(join(repoRoot, "lib", "pow", "siteverify-client.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "business-gate.js")),
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

  const tmpDir = await mkdtemp(join(tmpdir(), "pow-core-chain-"));
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
    writes.push(
      writeFile(join(tmpDir, "lib", "pow", "internal-headers.js"), internalHeadersSource)
    );
  }
  if (apiEngineSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineSource));
  }
  if (siteverifyClientSource !== null) {
    writes.push(
      writeFile(join(tmpDir, "lib", "pow", "siteverify-client.js"), siteverifyClientSource)
    );
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
  return {
    core1Fetch: core1Module.default.fetch,
    core2Fetch: core2Module.default.fetch,
    tmpDir,
  };
};

const normalizeApiPrefix = (value) => {
  if (typeof value !== "string") return "/__pow";
  const trimmed = value.trim();
  if (!trimmed) return "/__pow";
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  const normalized = withSlash.replace(/\/+$/u, "");
  return normalized || "/__pow";
};

const makeTransitMac = ({ secret, exp, kind, method, pathname, apiPrefix }) => {
  const normalizedMethod = typeof method === "string" && method ? method.toUpperCase() : "GET";
  const normalizedPath =
    typeof pathname === "string" && pathname
      ? pathname.startsWith("/")
        ? pathname
        : `/${pathname}`
      : "/";
  const normalizedApiPrefix = normalizeApiPrefix(apiPrefix);
  const macInput = `v1|${exp}|${kind}|${normalizedMethod}|${normalizedPath}|${normalizedApiPrefix}`;
  return base64Url(crypto.createHmac("sha256", secret).update(macInput).digest());
};

const buildSplitApiHeaders = ({
  payloadObj,
  secret,
  method,
  pathname,
  kind = "api",
  apiPrefix,
}) => {
  const { payload, mac, exp } = buildInnerHeaders(payloadObj, secret);
  const transitExpire = Math.floor(Date.now() / 1000) + 3;
  const resolvedApiPrefix = normalizeApiPrefix(apiPrefix || payloadObj?.c?.POW_API_PREFIX);
  const transitMac = makeTransitMac({
    secret,
    exp: transitExpire,
    kind,
    method,
    pathname,
    apiPrefix: resolvedApiPrefix,
  });
  return {
    "X-Pow-Inner": payload,
    "X-Pow-Inner-Mac": mac,
    "X-Pow-Inner-Expire": String(exp),
    "X-Pow-Transit": kind,
    "X-Pow-Transit-Mac": transitMac,
    "X-Pow-Transit-Expire": String(transitExpire),
    "X-Pow-Transit-Api-Prefix": resolvedApiPrefix,
  };
};

const buildCore1Module = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [
    core1SourceRaw,
    core2SourceRaw,
    transitSource,
    innerAuthSource,
    internalHeadersSource,
    apiEngineSource,
    siteverifyClientSource,
    businessGateSource,
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
    readOptionalFile(join(repoRoot, "lib", "pow", "siteverify-client.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "business-gate.js")),
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

  const tmpDir = await mkdtemp(join(tmpdir(), "pow-chain-"));
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
  if (siteverifyClientSource !== null) {
    writes.push(
      writeFile(join(tmpDir, "lib", "pow", "siteverify-client.js"), siteverifyClientSource)
    );
  }
  if (businessGateSource !== null) {
    const businessGateInjected = businessGateSource.replace(
      /__HTML_TEMPLATE__/gu,
      JSON.stringify(templateSource)
    );
    writes.push(writeFile(join(tmpDir, "lib", "pow", "business-gate.js"), businessGateInjected));
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
  writes.push(writeFile(join(tmpDir, "pow-harness.js"), harnessSource));

  await Promise.all(writes);
  return join(tmpDir, "pow-harness.js");
};

const buildConfigModule = async (secret = "config-secret", options = {}) => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [powConfigSource, runtimeSource, pathGlobSource, lruCacheSource] = await Promise.all([
    readFile(join(repoRoot, "pow-config.js"), "utf8"),
    readFile(join(repoRoot, "lib", "rule-engine", "runtime.js"), "utf8"),
    readFile(join(repoRoot, "lib", "rule-engine", "path-glob.js"), "utf8"),
    readFile(join(repoRoot, "lib", "rule-engine", "lru-cache.js"), "utf8"),
  ]);
  const gluePadding = options.longGlue ? "x".repeat(12000) : "";
  const configOverrides = options.configOverrides || {};
  const compiledConfig = JSON.stringify([
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
      path: null,
      config: {
        POW_TOKEN: "pow-secret",
        powcheck: false,
        turncheck: false,
        POW_BIND_TLS: false,
        POW_BIND_COUNTRY: false,
        POW_BIND_ASN: false,
        POW_GLUE_URL: `https://example.com/glue${gluePadding}`,
        ...configOverrides,
      },
    },
  ]);
  const injected = powConfigSource.replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-config-chain-"));
  await mkdir(join(tmpDir, "lib", "rule-engine"), { recursive: true });
  await writeFile(join(tmpDir, "lib", "rule-engine", "runtime.js"), runtimeSource);
  await writeFile(join(tmpDir, "lib", "rule-engine", "path-glob.js"), pathGlobSource);
  await writeFile(join(tmpDir, "lib", "rule-engine", "lru-cache.js"), lruCacheSource);
  const tmpPath = join(tmpDir, "pow-config.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

test("pow-config -> split core chain strips inner headers before origin fetch", async () => {
  const restoreGlobals = ensureGlobals();
  const core1Path = await buildCore1Module();
  const configPath = await buildConfigModule();
  const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configPath).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;
  const configHandler = configMod.default.fetch;

  let innerRequest = null;
  let originRequest = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) {
        innerRequest = request;
        return core1Handler(request);
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
    assert.ok(innerRequest, "pow-config forwards to split core chain");
    const innerPayload = innerRequest.headers.get("X-Pow-Inner");
    const innerCount = innerRequest.headers.get("X-Pow-Inner-Count");
    assert.ok(innerPayload || innerCount, "inner header set");
    assert.ok(innerRequest.headers.get("X-Pow-Inner-Mac"), "inner mac set");
    assert.ok(innerRequest.headers.get("X-Pow-Inner-Expire"), "inner expire set");
    assert.equal(innerRequest.headers.get("CF-Connecting-IP"), clientIp);
    assert.ok(originRequest, "origin fetch called");
    assert.equal(originRequest.headers.get("X-Pow-Inner"), null);
    assert.equal(originRequest.headers.get("X-Pow-Inner-Mac"), null);
    assert.equal(originRequest.headers.get("X-Pow-Inner-Expire"), null);
    assert.equal(originRequest.headers.get("CF-Connecting-IP"), clientIp);
    assert.ok(core1Mod.__splitTrace, "split trace is exposed");
    assert.equal(core1Mod.__splitTrace.core1Calls, 1);
    assert.equal(core1Mod.__splitTrace.core2Calls, 1);
    assert.equal(core1Mod.__splitTrace.originCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config -> split core chain strips chunked inner headers", async () => {
  const restoreGlobals = ensureGlobals();
  const core1Path = await buildCore1Module();
  const configPath = await buildConfigModule("config-secret", { longGlue: true });
  const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configPath).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;
  const configHandler = configMod.default.fetch;

  let innerRequest = null;
  let originRequest = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) {
        innerRequest = request;
        return core1Handler(request);
      }
      originRequest = request;
      return new Response("ok", { status: 200 });
    };

    const res = await configHandler(new Request("https://example.com/protected"));
    assert.equal(res.status, 200);
    assert.ok(innerRequest, "pow-config forwards to split core chain");
    assert.ok(innerRequest.headers.get("X-Pow-Inner-Count"), "chunked headers set");
    assert.ok(innerRequest.headers.get("X-Pow-Inner-Expire"), "inner expire set");
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

test("pow-config strips atomic query/header before split core handoff", async () => {
  const restoreGlobals = ensureGlobals();
  const core1Path = await buildCore1Module();
  const configPath = await buildConfigModule();
  const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configPath).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;
  const configHandler = configMod.default.fetch;

  let innerRequest = null;
  let originRequest = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) {
        innerRequest = request;
        return core1Handler(request);
      }
      originRequest = request;
      return new Response("ok", { status: 200 });
    };

    const res = await configHandler(
      new Request("https://example.com/protected?__ts=q-turn&__tt=q-ticket&__ct=1&keep=1", {
        headers: {
          "x-turnstile": "h-turn",
          "x-ticket": "h-ticket",
          "x-consume": "1",
        },
      })
    );
    assert.equal(res.status, 200);
    assert.ok(innerRequest, "pow-config forwards to split core chain");
    assert.equal(innerRequest.headers.get("x-turnstile"), null);
    assert.equal(innerRequest.headers.get("x-ticket"), null);
    assert.equal(innerRequest.headers.get("x-consume"), null);
    const innerUrl = new URL(innerRequest.url);
    assert.equal(innerUrl.searchParams.get("__ts"), null);
    assert.equal(innerUrl.searchParams.get("__tt"), null);
    assert.equal(innerUrl.searchParams.get("__ct"), null);
    assert.equal(innerUrl.searchParams.get("keep"), "1");
    assert.ok(originRequest, "origin fetch called");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core chain consumes atomic only from inner.s (no request fallback)", async () => {
  const restoreGlobals = ensureGlobals();
  const core1Path = await buildCore1Module();
  const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;

  const config = {
    powcheck: false,
    turncheck: true,
    bindPathMode: "none",
    bindPathQueryName: "path",
    bindPathHeaderName: "",
    stripBindPathHeader: false,
    POW_VERSION: 3,
    POW_API_PREFIX: "/__pow",
    POW_DIFFICULTY_BASE: 8192,
    POW_DIFFICULTY_COEFF: 1,
    POW_MIN_STEPS: 1,
    POW_MAX_STEPS: 8192,
    POW_HASHCASH_BITS: 0,
    POW_SEGMENT_LEN: 32,
    POW_SAMPLE_K: 1,
    POW_CHAL_ROUNDS: 1,
    POW_OPEN_BATCH: 1,
    POW_COMMIT_TTL_SEC: 120,
    POW_TICKET_TTL_SEC: 600,
    PROOF_TTL_SEC: 600,
    PROOF_RENEW_ENABLE: false,
    PROOF_RENEW_MAX: 2,
    PROOF_RENEW_WINDOW_SEC: 90,
    PROOF_RENEW_MIN_SEC: 30,
    ATOMIC_CONSUME: true,
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
    POW_BIND_TLS: false,
    POW_TOKEN: "pow-secret",
    TURNSTILE_SITEKEY: "sitekey",
    TURNSTILE_SECRET: "turn-secret",
    POW_COMMIT_COOKIE: "__Host-pow_commit",
    POW_ESM_URL: "https://example.com/esm",
    POW_GLUE_URL: "https://example.com/glue",
  };

  const { payload, mac, exp } = buildInnerHeaders(
    {
      v: 1,
      id: 7,
      c: config,
      d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    },
    "config-secret"
  );

  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const res = await core1Handler(
      new Request("https://example.com/protected?__ts=q-turn&__tt=q-ticket&__ct=1", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "x-turnstile": "header-turn-token",
          "x-ticket": "header-ticket",
          "x-consume": "1",
          Cookie: "__Secure-pow_a=1%7Ct%7Ccookie-turn%7Ccookie-ticket",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );

    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { code: "captcha_required" });
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow api uses /cap and rejects /turn", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: false,
      turncheck: true,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 8192,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 8192,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 32,
      POW_SAMPLE_K: 1,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 9,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    const capRes = await core1Handler(
      new Request("https://example.com/__pow/cap", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({}),
      })
    );
    assert.notEqual(capRes.status, 404);

    const turnRes = await core1Handler(
      new Request("https://example.com/__pow/turn", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(turnRes.status, 404);
  } finally {
    restoreGlobals();
  }
});

test("/cap works for no-pow turnstile flow and issues proof", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: false,
      turncheck: true,
      AGGREGATOR_POW_ATOMIC_CONSUME: true,
      SITEVERIFY_URLS: ["https://sv.example/siteverify"],
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "siteverify-secret",
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 8192,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 8192,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 32,
      POW_SAMPLE_K: 1,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };
    assertNoLegacyCaptchaKeys(config);

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 11,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    let calledUrl = "";
    let capturedSiteverifyBody = null;
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      calledUrl = String(request.url);
      if (calledUrl === "https://sv.example/siteverify") {
        capturedSiteverifyBody = JSON.parse(await request.text());
        return new Response(
          JSON.stringify({
            ok: true,
            reason: "ok",
            checks: {},
            providers: {
              turnstile: {
                ok: true,
                httpStatus: 200,
                normalized: {
                  success: true,
                  cdata: ticket.mac,
                },
                rawResponse: {
                  success: true,
                  cdata: ticket.mac,
                },
              },
            },
          }),
          { status: 200 }
        );
      }
      return new Response("ok", { status: 200 });
    };

    const pageRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");

    const capRes = await core1Handler(
      new Request("https://example.com/__pow/cap", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          pathHash: args.pathHash,
          captchaToken: JSON.stringify({ turnstile: "turnstile-token-value-1234567890" }),
        }),
      })
    );

    assert.equal(capRes.status, 200);
    assert.equal(calledUrl, "https://sv.example/siteverify");
    assert.equal(capturedSiteverifyBody.powConsume.expireAt, ticket.e);
    assert.equal(typeof capturedSiteverifyBody.powConsume.consumeKey, "string");
    const proofCookie = capRes.headers.get("Set-Cookie") || "";
    assert.match(proofCookie, /__Host-proof=/u);
    assert.match(proofCookie, /\.2\./u);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("/cap returns stale hint when siteverify rejects", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: false,
      turncheck: true,
      SITEVERIFY_URLS: ["https://sv.example/siteverify"],
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "siteverify-secret",
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 8192,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 8192,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 32,
      POW_SAMPLE_K: 1,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 113,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    const pageRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");

    let calledUrl = "";
    globalThis.fetch = async (url) => {
      calledUrl = String(url);
      if (calledUrl === "https://sv.example/siteverify") {
        return new Response(
          JSON.stringify({
            ok: false,
            reason: "provider_failed",
            checks: {},
            providers: {
              turnstile: {
                ok: false,
                httpStatus: 200,
                normalized: {
                  success: false,
                  cdata: "",
                },
                rawResponse: {
                  success: false,
                },
              },
            },
          }),
          { status: 200 }
        );
      }
      return new Response("ok", { status: 200 });
    };

    const capRes = await core1Handler(
      new Request("https://example.com/__pow/cap", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          pathHash: args.pathHash,
          captchaToken: JSON.stringify({ turnstile: "turnstile-token-value-1234567890" }),
        }),
      })
    );

    assert.equal(capRes.status, 403);
    assert.equal(calledUrl, "https://sv.example/siteverify");
    assert.equal(capRes.headers.get("x-pow-h"), "stale");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("/cap returns 400 for malformed captcha envelope", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: false,
      turncheck: true,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 8192,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 8192,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 32,
      POW_SAMPLE_K: 1,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 112,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    const pageRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");

    let upstreamCalls = 0;
    globalThis.fetch = async () => {
      upstreamCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const capRes = await core1Handler(
      new Request("https://example.com/__pow/cap", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          pathHash: args.pathHash,
          captchaToken: JSON.stringify({}),
        }),
      })
    );

    assert.equal(capRes.status, 400);
    assert.equal(upstreamCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("/commit, /challenge, and non-final /open do not call siteverify", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: true,
      turncheck: true,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 2,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 2,
      POW_MAX_STEPS: 2,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 130,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    const pageRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");

    const turnToken = "turnstile-disallowed-endpoint-token-1234567890";
    const captchaToken = JSON.stringify({ turnstile: turnToken });
    const nonce = base64Url(crypto.randomBytes(12));
    const bindingString = decodeB64UrlUtf8(args.bindingB64);
    const captchaTag = await captchaTagFromToken(turnToken);
    const powBinding = `${bindingString}|${captchaTag}`;
    const { rootB64, witnessByIndex, parentByIndex } = await buildMhgWitnessBundle({
      ticketB64: args.ticketB64,
      nonce,
    });

    let siteverifyCalls = 0;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        siteverifyCalls += 1;
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      return new Response("ok", { status: 200 });
    };

    const commitRes = await core1Handler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64,
          pathHash: args.pathHash,
          nonce,
          captchaToken,
        }),
      })
    );
    assert.equal(commitRes.status, 200);
    assert.equal(siteverifyCalls, 0);
    const commitCookie = (commitRes.headers.get("Set-Cookie") || "").split(";")[0];
    assert.ok(commitCookie, "commit cookie issued");

    const challengeRes = await core1Handler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(challengeRes.status, 200);
    assert.equal(siteverifyCalls, 0);
    const challenge = await challengeRes.json();
    assert.equal(challenge.done, false);
    assert.equal(challenge.cursor, 0);
    const opens = buildMhgOpensForChallenge({
      indices: challenge.indices,
      segs: challenge.segs,
      witnessByIndex,
      parentByIndex,
    });

    const nonFinalOpenRes = await core1Handler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          sid: challenge.sid,
          cursor: challenge.cursor,
          token: challenge.token,
          captchaToken,
          opens,
        }),
      })
    );
    assert.equal(nonFinalOpenRes.status, 200);
    assert.equal(siteverifyCalls, 0);
    const nonFinalOpen = await nonFinalOpenRes.json();
    assert.equal(nonFinalOpen.done, false);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("/commit returns stale hint when ticket cfgId mismatches inner context", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: true,
      turncheck: false,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 140,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    globalThis.fetch = async () => new Response("ok", { status: 200 });
    const pageRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");

    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");
    const tamperedTicketB64 = base64Url(
      Buffer.from(
        `${ticket.v}.${ticket.e}.${ticket.L}.${ticket.r}.${ticket.cfgId + 1}.${ticket.issuedAt}.${ticket.mac}`,
        "utf8"
      )
    );

    const commitRes = await core1Handler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: tamperedTicketB64,
          rootB64: base64Url(crypto.randomBytes(32)),
          pathHash: args.pathHash,
          nonce: base64Url(crypto.randomBytes(16)),
          captchaToken: "",
        }),
      })
    );

    assert.equal(commitRes.status, 403);
    assert.equal(commitRes.headers.get("x-pow-h"), "stale");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("atomic /open final does not call siteverify", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: true,
      turncheck: true,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: true,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 131,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    const pageRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");

    const turnToken = "atomic-open-final-token-1234567890";
    const captchaToken = JSON.stringify({ turnstile: turnToken });
    const nonce = base64Url(crypto.randomBytes(12));
    const { rootB64, witnessByIndex, parentByIndex } = await buildMhgWitnessBundle({
      ticketB64: args.ticketB64,
      nonce,
    });

    let siteverifyCalls = 0;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        siteverifyCalls += 1;
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      return new Response("ok", { status: 200 });
    };

    const commitRes = await core1Handler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64,
          pathHash: args.pathHash,
          nonce,
          captchaToken,
        }),
      })
    );
    assert.equal(commitRes.status, 200);
    const commitCookie = (commitRes.headers.get("Set-Cookie") || "").split(";")[0];
    assert.ok(commitCookie, "commit cookie issued");

    const challengeRes = await core1Handler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(challengeRes.status, 200);
    const challenge = await challengeRes.json();
    const opens = buildMhgOpensForChallenge({
      indices: challenge.indices,
      segs: challenge.segs,
      witnessByIndex,
      parentByIndex,
    });

    const openRes = await core1Handler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          sid: challenge.sid,
          cursor: challenge.cursor,
          token: challenge.token,
          captchaToken,
          opens,
        }),
      })
    );
    assert.equal(openRes.status, 200);
    assert.equal(siteverifyCalls, 0);
    const open = await openRes.json();
    assert.equal(open.done, true);
    assert.equal(typeof open.consume, "string");
    assert.match(open.consume, /^v2\./u);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("combined pow+captcha /open returns cheat hint for tampered payload and captcha mismatch", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: true,
      turncheck: true,
      SITEVERIFY_URLS: ["https://sv.example/siteverify"],
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "siteverify-secret",
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 13,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    const goodToken = "turnstile-open-token-value-1234567890";
    const badToken = "turnstile-open-token-value-bad-1234567890";
    const goodEnvelope = JSON.stringify({ turnstile: goodToken });
    const badEnvelope = JSON.stringify({ turnstile: badToken });

    const pageRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");

    const bindingString = decodeB64UrlUtf8(args.bindingB64);
    const nonce = base64Url(crypto.randomBytes(12));
    const commitCaptchaTag = await captchaTagFromToken(goodToken);
    const powBinding = `${bindingString}|${commitCaptchaTag}`;
    const { rootB64, witnessByIndex, parentByIndex } = await buildMhgWitnessBundle({
      ticketB64: args.ticketB64,
      nonce,
    });

    globalThis.fetch = async (url) => {
      if (String(url) === "https://sv.example/siteverify") {
        return new Response(
          JSON.stringify({
            ok: true,
            reason: "ok",
            checks: {},
            providers: {
              turnstile: {
                ok: true,
                httpStatus: 200,
                normalized: {
                  success: true,
                  cdata: ticket.mac,
                },
                rawResponse: {
                  success: true,
                  cdata: ticket.mac,
                },
              },
            },
          }),
          { status: 200 }
        );
      }
      return new Response("ok", { status: 200 });
    };

    const commitRes = await core1Handler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64,
          pathHash: args.pathHash,
          nonce,
          captchaToken: goodEnvelope,
        }),
      })
    );
    assert.equal(commitRes.status, 200);
    const commitCookie = (commitRes.headers.get("Set-Cookie") || "").split(";")[0];
    assert.ok(commitCookie, "commit cookie issued");

    const challengeRes = await core1Handler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(challengeRes.status, 200);
    const challenge = await challengeRes.json();
    assert.deepEqual(challenge.indices, [1]);
    assert.deepEqual(challenge.segs, [1]);
    const opens = buildMhgOpensForChallenge({
      indices: challenge.indices,
      segs: challenge.segs,
      witnessByIndex,
      parentByIndex,
    });

    const openBody = {
      sid: challenge.sid,
      cursor: challenge.cursor,
      token: challenge.token,
      opens,
    };

    const tamperedOpen = await core1Handler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ...openBody,
          captchaToken: goodEnvelope,
          opens: [
            {
              ...openBody.opens[0],
              nodes: {
                ...openBody.opens[0].nodes,
                [String(openBody.opens[0].i)]: {
                  ...openBody.opens[0].nodes[String(openBody.opens[0].i)],
                  pageB64: base64Url(crypto.randomBytes(64)),
                },
              },
            },
          ],
        }),
      })
    );
    assert.equal(tamperedOpen.status, 403);
    assert.equal(tamperedOpen.headers.get("x-pow-h"), "cheat");

    globalThis.fetch = async (url) => {
      if (String(url) === "https://sv.example/siteverify") {
        return new Response(
          JSON.stringify({
            ok: false,
            reason: "provider_failed",
            checks: {},
            providers: {
              turnstile: {
                ok: false,
                httpStatus: 200,
                normalized: {
                  success: false,
                  cdata: "",
                },
                rawResponse: {
                  success: false,
                },
              },
            },
          }),
          { status: 200 }
        );
      }
      return new Response("ok", { status: 200 });
    };
    const staleOpen = await core1Handler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({ ...openBody, captchaToken: goodEnvelope }),
      })
    );
    assert.equal(staleOpen.status, 403);
    assert.equal(staleOpen.headers.get("x-pow-h"), "stale");

    globalThis.fetch = async (url) => {
      if (String(url) === "https://sv.example/siteverify") {
        return new Response(
          JSON.stringify({
            ok: true,
            reason: "ok",
            checks: {},
            providers: {
              turnstile: {
                ok: true,
                httpStatus: 200,
                normalized: {
                  success: true,
                  cdata: ticket.mac,
                },
                rawResponse: {
                  success: true,
                  cdata: ticket.mac,
                },
              },
            },
          }),
          { status: 200 }
        );
      }
      return new Response("ok", { status: 200 });
    };

    const rejectOpen = await core1Handler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({ ...openBody, captchaToken: badEnvelope }),
      })
    );
    assert.equal(rejectOpen.status, 403);
    assert.equal(rejectOpen.headers.get("x-pow-h"), "cheat");

    const passOpen = await core1Handler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({ ...openBody, captchaToken: goodEnvelope }),
      })
    );
    assert.equal(passOpen.status, 200);
    assert.deepEqual(await passOpen.json(), { done: true });
    const proofCookie = passOpen.headers.get("Set-Cookie") || "";
    assert.match(proofCookie, /__Host-proof=/u);
    assert.match(proofCookie, /\.3\./u);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow+captcha /open fails closed when aggregator returns non-200 or non-json", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: true,
      turncheck: true,
      SITEVERIFY_URLS: ["https://sv.example/siteverify"],
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "siteverify-secret",
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 1301,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    const turnToken = "turnstile-open-token-value-1234567890";
    const captchaEnvelope = JSON.stringify({ turnstile: turnToken });
    const pageRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");

    const nonce = base64Url(crypto.randomBytes(12));
    const { rootB64, witnessByIndex, parentByIndex } = await buildMhgWitnessBundle({
      ticketB64: args.ticketB64,
      nonce,
    });

    let mode = "ok";
    globalThis.fetch = async (url) => {
      if (String(url) === "https://sv.example/siteverify") {
        if (mode === "non200") {
          return new Response(
            JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }),
            { status: 502 }
          );
        }
        if (mode === "nonjson") {
          return new Response("not-json", { status: 200, headers: { "content-type": "text/plain" } });
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
                normalized: { success: true, cdata: ticket.mac },
                rawResponse: { success: true, cdata: ticket.mac },
              },
            },
          }),
          { status: 200 }
        );
      }
      return new Response("ok", { status: 200 });
    };

    const commitRes = await core1Handler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64,
          pathHash: args.pathHash,
          nonce,
          captchaToken: captchaEnvelope,
        }),
      })
    );
    assert.equal(commitRes.status, 200);
    const commitCookie = (commitRes.headers.get("Set-Cookie") || "").split(";")[0];
    assert.ok(commitCookie, "commit cookie issued");

    const challengeRes = await core1Handler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(challengeRes.status, 200);
    const challenge = await challengeRes.json();
    const opens = buildMhgOpensForChallenge({
      indices: challenge.indices,
      segs: challenge.segs,
      witnessByIndex,
      parentByIndex,
    });

    const openBody = {
      sid: challenge.sid,
      cursor: challenge.cursor,
      token: challenge.token,
      captchaToken: captchaEnvelope,
      opens,
    };

    mode = "non200";
    const non200Open = await core1Handler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify(openBody),
      })
    );
    assert.equal(non200Open.status, 403);
    assert.equal(non200Open.headers.get("x-pow-h"), "stale");

    mode = "nonjson";
    const nonJsonOpen = await core1Handler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify(openBody),
      })
    );
    assert.equal(nonJsonOpen.status, 403);
    assert.equal(nonJsonOpen.headers.get("x-pow-h"), "stale");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("non-atomic /open returns 400 for malformed captcha envelope", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: true,
      turncheck: true,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 132,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    const pageRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");

    const goodTurnToken = "turnstile-open-token-value-1234567890";
    const goodEnvelope = JSON.stringify({ turnstile: goodTurnToken });
    const nonce = base64Url(crypto.randomBytes(12));
    const bindingString = decodeB64UrlUtf8(args.bindingB64);
    const commitCaptchaTag = await captchaTagFromToken(goodTurnToken);
    const powBinding = `${bindingString}|${commitCaptchaTag}`;
    const seedPrefix = new TextEncoder().encode("posw|seed|");
    const stepPrefix = new TextEncoder().encode("posw|step|");
    const leafPrefix = new TextEncoder().encode("leaf|");
    const nodePrefix = new TextEncoder().encode("node|");
    const pipe = new TextEncoder().encode("|");

    const seedHash = await sha256Bytes(
      concatBytes(seedPrefix, new TextEncoder().encode(powBinding), pipe, new TextEncoder().encode(nonce))
    );
    const hCurr = await sha256Bytes(concatBytes(stepPrefix, encodeUint32BE(1), seedHash));
    const leaf0 = await sha256Bytes(concatBytes(leafPrefix, encodeUint32BE(0), seedHash));
    const leaf1 = await sha256Bytes(concatBytes(leafPrefix, encodeUint32BE(1), hCurr));
    const root = await sha256Bytes(concatBytes(nodePrefix, leaf0, leaf1));
    const rootB64 = base64Url(root);

    let siteverifyCalls = 0;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        siteverifyCalls += 1;
        return new Response(JSON.stringify({ success: true, cdata: ticket.mac }), {
          status: 200,
        });
      }
      return new Response("ok", { status: 200 });
    };

    const commitRes = await core1Handler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64,
          pathHash: args.pathHash,
          nonce,
          captchaToken: goodEnvelope,
        }),
      })
    );
    assert.equal(commitRes.status, 200);
    const commitCookie = (commitRes.headers.get("Set-Cookie") || "").split(";")[0];
    assert.ok(commitCookie, "commit cookie issued");

    const challengeRes = await core1Handler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(challengeRes.status, 200);
    const challenge = await challengeRes.json();

    const malformedOpen = await core1Handler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: commitCookie,
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
        body: JSON.stringify({
          sid: challenge.sid,
          cursor: challenge.cursor,
          token: challenge.token,
          spinePos: challenge.spinePos,
          captchaToken: JSON.stringify({}),
          opens: [
            {
              i: 1,
              hPrev: base64Url(seedHash),
              hCurr: base64Url(hCurr),
              proofPrev: { sibs: [base64Url(leaf1)] },
              proofCurr: { sibs: [base64Url(leaf0)] },
            },
          ],
        }),
      })
    );
    assert.equal(malformedOpen.status, 400);
    assert.equal(siteverifyCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-only + atomic + aggregator consume requires consume token on business path", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: true,
      turncheck: false,
      AGGREGATOR_POW_ATOMIC_CONSUME: true,
      SITEVERIFY_URLS: ["https://sv.example/siteverify"],
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "siteverify-secret",
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: true,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const baseInner = {
      v: 1,
      id: 39,
      c: config,
      d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    };

    const stage1 = buildInnerHeaders(baseInner, "config-secret");
    const pageRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage1.payload,
          "X-Pow-Inner-Mac": stage1.mac,
          "X-Pow-Inner-Expire": String(stage1.exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");

    let originCalls = 0;
    let aggregatorCalls = 0;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://sv.example/siteverify") {
        aggregatorCalls += 1;
        return new Response(
          JSON.stringify({
            ok: true,
            reason: "ok",
            checks: {},
            providers: {},
          }),
          { status: 200 }
        );
      }
      originCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const missingConsumeRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage1.payload,
          "X-Pow-Inner-Mac": stage1.mac,
          "X-Pow-Inner-Expire": String(stage1.exp),
        },
      })
    );
    assert.equal(missingConsumeRes.status, 403);
    assert.equal(originCalls, 0);
    assert.equal(aggregatorCalls, 0);

    const consumeToken = makeConsumeToken({
      powSecret: "pow-secret",
      ticketB64: args.ticketB64,
      exp: Math.floor(Date.now() / 1000) + 120,
      captchaTag: "any",
      mask: 1,
    });
    const innerWithConsume = {
      ...baseInner,
      s: {
        ...baseInner.s,
        atomic: {
          ...baseInner.s.atomic,
          consumeToken,
        },
      },
    };
    const stage2 = buildInnerHeaders(innerWithConsume, "config-secret");
    const consumeRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage2.payload,
          "X-Pow-Inner-Mac": stage2.mac,
          "X-Pow-Inner-Expire": String(stage2.exp),
        },
      })
    );
    assert.equal(consumeRes.status, 200);
    assert.equal(originCalls, 1);
    assert.equal(aggregatorCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-only + atomic falls back to pow_required when aggregator consume is disabled", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: true,
      turncheck: false,
      AGGREGATOR_POW_ATOMIC_CONSUME: false,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: true,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const inner = buildInnerHeaders(
      {
        v: 1,
        id: 40,
        c: config,
        d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          nav: {},
          bypass: { bypass: false },
          bind: { ok: true, code: "", canonicalPath: "/protected" },
          atomic: {
            captchaToken: "",
            ticketB64: "",
            consumeToken: "",
            fromCookie: false,
            cookieName: "__Secure-pow_a",
          },
        },
      },
      "config-secret"
    );

    let originCalls = 0;
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const res = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": inner.payload,
          "X-Pow-Inner-Mac": inner.mac,
          "X-Pow-Inner-Expire": String(inner.exp),
        },
      })
    );
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { code: "pow_required" });
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("turnstile atomic behavior is unchanged by aggregator pow-only extension", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const core1Path = await buildCore1Module();
    const core1Mod = await import(`${pathToFileURL(core1Path).href}?v=${Date.now()}`);
    const core1Handler = core1Mod.default.fetch;

    const config = {
      powcheck: false,
      turncheck: true,
      AGGREGATOR_POW_ATOMIC_CONSUME: true,
      SITEVERIFY_URLS: ["https://sv.example/siteverify"],
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "siteverify-secret",
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      PROOF_RENEW_ENABLE: false,
      PROOF_RENEW_MAX: 2,
      PROOF_RENEW_WINDOW_SEC: 90,
      PROOF_RENEW_MIN_SEC: 30,
      ATOMIC_CONSUME: true,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };

    const baseInner = {
      v: 1,
      id: 41,
      c: config,
      d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    };

    const stage1 = buildInnerHeaders(baseInner, "config-secret");
    const pageRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage1.payload,
          "X-Pow-Inner-Mac": stage1.mac,
          "X-Pow-Inner-Expire": String(stage1.exp),
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");

    let aggregatorCalls = 0;
    let originCalls = 0;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://sv.example/siteverify") {
        aggregatorCalls += 1;
        return new Response(
          JSON.stringify({
            ok: true,
            reason: "ok",
            checks: {},
            providers: {
              turnstile: {
                ok: true,
                httpStatus: 200,
                normalized: { success: true },
                rawResponse: { success: true },
              },
            },
          }),
          { status: 200 }
        );
      }
      originCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const missingCaptchaRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage1.payload,
          "X-Pow-Inner-Mac": stage1.mac,
          "X-Pow-Inner-Expire": String(stage1.exp),
        },
      })
    );
    assert.equal(missingCaptchaRes.status, 403);
    assert.equal(aggregatorCalls, 0);
    assert.equal(originCalls, 0);

    const withCaptcha = {
      ...baseInner,
      s: {
        ...baseInner.s,
        atomic: {
          ...baseInner.s.atomic,
          captchaToken: JSON.stringify({ turnstile: "turnstile-token-value-1234567890" }),
          ticketB64: args.ticketB64,
        },
      },
    };
    const stage2 = buildInnerHeaders(withCaptcha, "config-secret");
    const okRes = await core1Handler(
      new Request("https://example.com/protected", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "X-Pow-Inner": stage2.payload,
          "X-Pow-Inner-Mac": stage2.mac,
          "X-Pow-Inner-Expire": String(stage2.exp),
        },
      })
    );
    assert.equal(okRes.status, 200);
    assert.equal(aggregatorCalls, 1);
    assert.equal(originCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core1 enforces business gate for non-navigation unauthorized request", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const { core1Fetch, core2Fetch } = await buildCoreModules("config-secret");
    const innerConfig = {
      powcheck: true,
      turncheck: false,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };
    const innerPayloadObj = {
      v: 1,
      id: 222,
      c: innerConfig,
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
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    };

    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Transit")) {
        return core2Fetch(request);
      }
      return new Response("origin should not be reached", { status: 599 });
    };

    const splitHeaders = buildSplitApiHeaders({
      payloadObj: innerPayloadObj,
      secret: "config-secret",
      method: "GET",
      pathname: "/protected",
      kind: "biz",
      apiPrefix: "/__pow",
    });
    const res = await core1Fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: splitHeaders,
      })
    );

    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { code: "pow_required" });
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core1 enforces navigation unauthorized challenge html", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const { core1Fetch, core2Fetch } = await buildCoreModules("config-secret");
    const innerConfig = {
      powcheck: true,
      turncheck: false,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };
    const innerPayloadObj = {
      v: 1,
      id: 223,
      c: innerConfig,
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
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    };

    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Transit")) {
        return core2Fetch(request);
      }
      return new Response("origin should not be reached", { status: 599 });
    };

    const splitHeaders = buildSplitApiHeaders({
      payloadObj: innerPayloadObj,
      secret: "config-secret",
      method: "GET",
      pathname: "/protected",
      kind: "biz",
      apiPrefix: "/__pow",
    });
    splitHeaders.Accept = "text/html";
    const res = await core1Fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: splitHeaders,
      })
    );

    assert.equal(res.status, 200);
    assert.equal(res.headers.get("Content-Type"), "text/html");
    const html = await res.text();
    assert.match(html, /<body/u);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core1 forwards valid proof path to origin", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const { core1Fetch, core2Fetch } = await buildCoreModules("config-secret");
    const innerConfig = {
      powcheck: false,
      turncheck: true,
      SITEVERIFY_URLS: ["https://sv.example/siteverify"],
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "siteverify-secret",
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };
    const innerPayloadObj = {
      v: 1,
      id: 225,
      c: innerConfig,
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
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    };

    const originRequests = [];
    let turnstileCdata = "";
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.headers.has("X-Pow-Transit")) {
        return core2Fetch(request);
      }
      if (request.url === "https://sv.example/siteverify") {
        return new Response(
          JSON.stringify({
            ok: true,
            reason: "ok",
            checks: {},
            providers: {
              turnstile: {
                ok: true,
                httpStatus: 200,
                normalized: {
                  success: true,
                  cdata: turnstileCdata,
                },
                rawResponse: {
                  success: true,
                  cdata: turnstileCdata,
                },
              },
            },
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }
        );
      }
      originRequests.push(request);
      return new Response("origin-ok", { status: 200 });
    };

    const pageHeaders = buildSplitApiHeaders({
      payloadObj: innerPayloadObj,
      secret: "config-secret",
      method: "GET",
      pathname: "/protected",
      kind: "biz",
      apiPrefix: "/__pow",
    });
    pageHeaders.Accept = "text/html";
    const pageRes = await core1Fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: pageHeaders,
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");
    const ticket = decodeTicket(args.ticketB64);
    assert.ok(ticket, "ticket decodes");
    turnstileCdata = ticket.mac;

    const capHeaders = buildSplitApiHeaders({
      payloadObj: innerPayloadObj,
      secret: "config-secret",
      method: "POST",
      pathname: "/__pow/cap",
      kind: "api",
      apiPrefix: "/__pow",
    });
    capHeaders["Content-Type"] = "application/json";
    const capRes = await core1Fetch(
      new Request("https://example.com/__pow/cap", {
        method: "POST",
        headers: capHeaders,
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          pathHash: args.pathHash,
          captchaToken: JSON.stringify({ turnstile: "split-proof-turn-token-1234567890" }),
        }),
      })
    );
    assert.equal(capRes.status, 200);
    const proofCookie = (capRes.headers.get("Set-Cookie") || "").split(";")[0];
    assert.ok(proofCookie, "proof cookie issued");

    originRequests.length = 0;
    const protectedHeaders = buildSplitApiHeaders({
      payloadObj: innerPayloadObj,
      secret: "config-secret",
      method: "GET",
      pathname: "/protected",
      kind: "biz",
      apiPrefix: "/__pow",
    });
    protectedHeaders.Accept = "application/json";
    protectedHeaders.Cookie = proofCookie;
    const protectedRes = await core1Fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: protectedHeaders,
      })
    );

    assert.equal(protectedRes.status, 200);
    assert.equal(await protectedRes.text(), "origin-ok");
    assert.equal(originRequests.length, 1);
    assert.equal(new URL(originRequests[0].url).pathname, "/protected");
    for (const key of originRequests[0].headers.keys()) {
      const normalized = key.toLowerCase();
      assert.equal(normalized.startsWith("x-pow-inner"), false, `origin strips ${key}`);
      assert.equal(normalized.startsWith("x-pow-transit"), false, `origin strips ${key}`);
    }
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core1 preserves stale/cheat hints on api deny", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const { core1Fetch, core2Fetch } = await buildCoreModules("config-secret");
    const innerConfig = {
      powcheck: true,
      turncheck: true,
      bindPathMode: "none",
      bindPathQueryName: "path",
      bindPathHeaderName: "",
      stripBindPathHeader: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 1,
      POW_DIFFICULTY_COEFF: 1,
      POW_MIN_STEPS: 1,
      POW_MAX_STEPS: 1,
      POW_HASHCASH_BITS: 0,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 1,
      POW_SAMPLE_K: 0,
      POW_CHAL_ROUNDS: 1,
      POW_OPEN_BATCH: 1,
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
      POW_BIND_TLS: false,
      POW_TOKEN: "pow-secret",
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_ESM_URL: "https://example.com/esm",
      POW_GLUE_URL: "https://example.com/glue",
    };
    const innerPayloadObj = {
      v: 1,
      id: 224,
      c: innerConfig,
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
        atomic: {
          captchaToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    };

    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Transit")) {
        return core2Fetch(request);
      }
      if (String(request.url) === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        return new Response(JSON.stringify({ success: false }), { status: 200 });
      }
      return new Response("origin should not be reached", { status: 599 });
    };

    const pageHeaders = buildSplitApiHeaders({
      payloadObj: innerPayloadObj,
      secret: "config-secret",
      method: "GET",
      pathname: "/protected",
      kind: "biz",
      apiPrefix: "/__pow",
    });
    pageHeaders.Accept = "text/html";
    const pageRes = await core1Fetch(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: pageHeaders,
      })
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge args present");

    const commitHeaders = buildSplitApiHeaders({
      payloadObj: innerPayloadObj,
      secret: "config-secret",
      method: "POST",
      pathname: "/__pow/commit",
      kind: "api",
      apiPrefix: "/__pow",
    });
    commitHeaders["Content-Type"] = "application/json";
    const commitRes = await core2Fetch(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: commitHeaders,
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64: base64Url(crypto.randomBytes(32)),
          pathHash: args.pathHash,
          nonce: base64Url(crypto.randomBytes(16)),
          captchaToken: JSON.stringify({ turnstile: "split-turn-token-1234567890" }),
        }),
      })
    );
    assert.equal(commitRes.status, 200);
    const commitCookie = (commitRes.headers.get("Set-Cookie") || "").split(";")[0];
    assert.ok(commitCookie, "commit cookie issued");

    const challengeHeaders = buildSplitApiHeaders({
      payloadObj: innerPayloadObj,
      secret: "config-secret",
      method: "POST",
      pathname: "/__pow/challenge",
      kind: "api",
      apiPrefix: "/__pow",
    });
    challengeHeaders["Content-Type"] = "application/json";
    challengeHeaders.Cookie = commitCookie;
    const challengeRes = await core2Fetch(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: challengeHeaders,
        body: JSON.stringify({}),
      })
    );
    assert.equal(challengeRes.status, 200);
    const challengeBody = await challengeRes.json();

    const badOpenHeaders = buildSplitApiHeaders({
      payloadObj: innerPayloadObj,
      secret: "config-secret",
      method: "POST",
      pathname: "/__pow/open",
      kind: "api",
      apiPrefix: "/__pow",
    });
    badOpenHeaders["Content-Type"] = "application/json";
    badOpenHeaders.Cookie = commitCookie;
    const badOpenRes = await core1Fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: badOpenHeaders,
        body: JSON.stringify({
          sid: challengeBody.sid,
          cursor: challengeBody.cursor,
          token: challengeBody.token,
          captchaToken: JSON.stringify({ turnstile: "split-turn-token-1234567890" }),
          opens: [
            {
              i: challengeBody.indices[0],
              seg: challengeBody.segs[0],
              nodes: {
                [String(challengeBody.indices[0])]: {
                  pageB64: base64Url(crypto.randomBytes(64)),
                  proof: [],
                },
              },
            },
          ],
        }),
      })
    );
    assert.equal(badOpenRes.status, 403);
    assert.equal(badOpenRes.headers.get("x-pow-h"), "cheat");

    const staleCommitCookie = (() => {
      const [cookieName, cookieValueRaw = ""] = commitCookie.split("=");
      const decodedValue = decodeURIComponent(cookieValueRaw);
      const parts = decodedValue.split(".");
      assert.equal(parts.length, 8);
      parts[6] = String(Math.floor(Date.now() / 1000) - 10);
      return `${cookieName}=${encodeURIComponent(parts.join("."))}`;
    })();

    const staleOpenHeaders = buildSplitApiHeaders({
      payloadObj: innerPayloadObj,
      secret: "config-secret",
      method: "POST",
      pathname: "/__pow/open",
      kind: "api",
      apiPrefix: "/__pow",
    });
    staleOpenHeaders["Content-Type"] = "application/json";
    staleOpenHeaders.Cookie = staleCommitCookie;
    const staleOpenRes = await core1Fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: staleOpenHeaders,
        body: JSON.stringify({
          sid: challengeBody.sid,
          cursor: challengeBody.cursor,
          token: challengeBody.token,
          captchaToken: JSON.stringify({ turnstile: "split-turn-token-1234567890" }),
          opens: [
            {
              i: challengeBody.indices[0],
              seg: challengeBody.segs[0],
              nodes: {
                [String(challengeBody.indices[0])]: {
                  pageB64: base64Url(crypto.randomBytes(64)),
                  proof: [],
                },
              },
            },
          ],
        }),
      })
    );
    assert.equal(staleOpenRes.status, 403);
    assert.equal(staleOpenRes.headers.get("x-pow-h"), "stale");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("glue runtime uses captchaTag naming", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const glueSource = await readFile(join(repoRoot, "glue.js"), "utf8");
  assert.match(glueSource, /captchaTagV1/u);
  assert.doesNotMatch(glueSource, /\btbFromToken\b/u);
});
