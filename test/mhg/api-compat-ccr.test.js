import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";

const CONFIG_SECRET = "config-secret";

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const hmacSha256 = (secret, data) =>
  crypto.createHmac("sha256", secret).update(data).digest();

const fromBase64Url = (value) => {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, "base64");
};

const tamperBase64UrlBytes = (value) => {
  const bytes = Buffer.from(fromBase64Url(value));
  bytes[0] ^= 0x01;
  return base64Url(bytes);
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

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const workerAdapterUrl = pathToFileURL(
  join(repoRoot, "test", "mhg", "helpers", "mhg-worker-node-adapter.mjs")
);

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

const buildPowModule = async (secret = CONFIG_SECRET) => {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  const template = await readFile(join(repoRoot, "template.html"), "utf8");
  const injected = powSource.replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template));
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-mhg-ccr-test-"));
  const tmpPath = join(tmpDir, "pow-test.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

const extractChallengeArgs = (html) => {
  const match = html.match(/g\("([^"]+)",\s*(\d+),\s*"([^"]+)",\s*"([^"]+)"/u);
  if (!match) return null;
  return {
    ticketB64: match[3],
    pathHash: match[4],
  };
};

const makeInnerPayload = () => ({
  v: 1,
  id: 7,
  c: {
    POW_TOKEN: "pow-secret",
    powcheck: true,
    turncheck: false,
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
    ATOMIC_CONSUME: false,
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
    country: "",
    asn: "",
    tlsFingerprint: "",
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

const mutateTicketExpiry = (ticketB64, exp) => {
  const raw = fromBase64Url(ticketB64).toString("utf8");
  const parts = raw.split(".");
  parts[1] = String(exp);
  return base64Url(Buffer.from(parts.join("."), "utf8"));
};

const mutateCommitExpiry = (commitCookie, exp) => {
  const value = commitCookie.split("=")[1] || "";
  const parts = decodeURIComponent(value).split(".");
  parts[6] = String(exp);
  return `${commitCookie.split("=")[0]}=${encodeURIComponent(parts.join("."))}`;
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

const buildCore2Module = async (secret = CONFIG_SECRET) => {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  const [
    core2SourceRaw,
    transitSource,
    innerAuthSource,
    internalHeadersSource,
    apiEngineSource,
    mhgGraphSource,
    mhgMixSource,
    mhgMerkleSource,
  ] =
    await Promise.all([
      readFile(join(repoRoot, "pow-core-2.js"), "utf8"),
      readFile(join(repoRoot, "lib", "pow", "transit-auth.js"), "utf8"),
      readFile(join(repoRoot, "lib", "pow", "inner-auth.js"), "utf8"),
      readFile(join(repoRoot, "lib", "pow", "internal-headers.js"), "utf8"),
      readOptionalFile(join(repoRoot, "lib", "pow", "api-engine.js")),
      readFile(join(repoRoot, "lib", "mhg", "graph.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "mix-aes.js"), "utf8"),
      readFile(join(repoRoot, "lib", "mhg", "merkle.js"), "utf8"),
    ]);

  const core2Source = replaceConfigSecret(core2SourceRaw, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-mhg-core2-ccr-test-"));
  await mkdir(join(tmpDir, "lib", "pow"), { recursive: true });
  await mkdir(join(tmpDir, "lib", "mhg"), { recursive: true });
  const writes = [
    writeFile(join(tmpDir, "pow-core-2.js"), core2Source),
    writeFile(join(tmpDir, "lib", "pow", "transit-auth.js"), transitSource),
    writeFile(join(tmpDir, "lib", "pow", "inner-auth.js"), innerAuthSource),
    writeFile(join(tmpDir, "lib", "pow", "internal-headers.js"), internalHeadersSource),
    writeFile(join(tmpDir, "lib", "mhg", "graph.js"), mhgGraphSource),
    writeFile(join(tmpDir, "lib", "mhg", "mix-aes.js"), mhgMixSource),
    writeFile(join(tmpDir, "lib", "mhg", "merkle.js"), mhgMerkleSource),
  ];
  if (apiEngineSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineSource));
  }
  await Promise.all(writes);

  const mod = await import(`${pathToFileURL(join(tmpDir, "pow-core-2.js")).href}?v=${Date.now()}`);
  return mod.default.fetch;
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
  const input = `v1|${exp}|${kind}|${normalizedMethod}|${normalizedPath}|${normalizedApiPrefix}`;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(input).digest());
  return {
    "X-Pow-Transit": kind,
    "X-Pow-Transit-Mac": mac,
    "X-Pow-Transit-Expire": String(exp),
    "X-Pow-Transit-Api-Prefix": normalizedApiPrefix,
  };
};

const withSplitApiHeaders = ({ payload, method, pathname }) => ({
  ...makeInnerHeaders(payload),
  ...makeTransitHeaders({
    secret: CONFIG_SECRET,
    exp: Math.floor(Date.now() / 1000) + 3,
    kind: "api",
    method,
    pathname,
    apiPrefix: payload.c?.POW_API_PREFIX || "/__pow",
  }),
});

const makeTicketB64 = ({ powSecret, payload, pathHash, host = "example.com" }) => {
  const ticket = {
    v: payload.c.POW_VERSION,
    e: Math.floor(Date.now() / 1000) + 300,
    L: 8,
    r: base64Url(crypto.randomBytes(16)),
    cfgId: payload.id,
    mac: "",
  };
  const bindPath = payload.c.POW_BIND_PATH !== false ? pathHash : "any";
  const bindIp = payload.c.POW_BIND_IPRANGE !== false ? payload.d.ipScope : "any";
  const bindCountry = payload.c.POW_BIND_COUNTRY === true ? payload.d.country : "any";
  const bindAsn = payload.c.POW_BIND_ASN === true ? payload.d.asn : "any";
  const bindTls = payload.c.POW_BIND_TLS === true ? payload.d.tlsFingerprint : "any";
  const binding = `${ticket.v}|${ticket.e}|${ticket.L}|${ticket.r}|${ticket.cfgId}|${host.toLowerCase()}|${bindPath}|${bindIp}|${bindCountry}|${bindAsn}|${bindTls}`;
  ticket.mac = base64Url(crypto.createHmac("sha256", powSecret).update(binding).digest());
  return base64Url(
    Buffer.from(
      `${ticket.v}.${ticket.e}.${ticket.L}.${ticket.r}.${ticket.cfgId}.${ticket.mac}`,
      "utf8",
    ),
  );
};

const sha256Base64Url = (value) =>
  base64Url(crypto.createHash("sha256").update(String(value || "")).digest());

const createWorkerRpc = () => {
  const worker = new Worker(workerAdapterUrl, { type: "module" });
  let rid = 0;
  const pending = new Map();

  worker.on("message", (data) => {
    const entry = pending.get(data.rid);
    if (!entry) return;
    pending.delete(data.rid);
    if (data.type === "ERROR") {
      entry.reject(new Error(data.message || "worker error"));
      return;
    }
    entry.resolve(data);
  });

  worker.on("error", (err) => {
    for (const entry of pending.values()) entry.reject(err);
    pending.clear();
  });

  worker.on("exit", () => {
    for (const entry of pending.values()) entry.reject(new Error("worker exited"));
    pending.clear();
  });

  return {
    call(type, payload = {}) {
      const id = ++rid;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        worker.postMessage({ ...payload, type, rid: id });
      });
    },
    dispose() {
      worker.terminate();
    },
  };
};

const createMhgSolver = async ({ ticketB64, steps, hashcashBits, segmentLen }) => {
  const rpc = createWorkerRpc();
  await rpc.call("INIT", {
    ticketB64,
    steps,
    hashcashBits,
    segmentLen,
    bindingString: "unused",
  });
  return rpc;
};

const runOpenToFinal = async (handler, payload, commitCookie, challengeBody, solveOpens) => {
  let state = challengeBody;
  while (state.done === false) {
    const opens = await solveOpens(state.indices);
    const res = await handler(
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
          opens,
        }),
      }),
      {},
      {}
    );
    assert.equal(res.status, 200);
    state = await res.json();
  }
  return state;
};

const runCcrBootstrap = async (handler) => {
  const payload = makeInnerPayload();
  const challengePage = await handler(
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
  assert.equal(challengePage.status, 200);
  const html = await challengePage.text();
  const args = extractChallengeArgs(html);
  assert.ok(args);
  const ticket = parseTicket(args.ticketB64);
  const solver = await createMhgSolver({
    ticketB64: args.ticketB64,
    steps: ticket.L,
    hashcashBits: payload.c.POW_HASHCASH_BITS,
    segmentLen: payload.c.POW_SEGMENT_LEN,
  });
  const commitResult = await solver.call("COMMIT");
  const commitRes2 = await handler(
    new Request("https://example.com/__pow/commit", {
      method: "POST",
      headers: {
        ...makeInnerHeaders(payload),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ticketB64: args.ticketB64,
        rootB64: commitResult.rootB64,
        pathHash: args.pathHash,
        nonce: commitResult.nonce,
      }),
    }),
    {},
    {}
  );
  assert.equal(commitRes2.status, 200);
  const commitCookie2 = (commitRes2.headers.get("set-cookie") || "").split(";")[0];
  assert.ok(commitCookie2);

  const challengeRes = await handler(
    new Request("https://example.com/__pow/challenge", {
      method: "POST",
      headers: {
        ...makeInnerHeaders(payload),
        "Content-Type": "application/json",
        Cookie: commitCookie2,
      },
      body: JSON.stringify({}),
    }),
    {},
    {}
  );
  assert.equal(challengeRes.status, 200);
  const challengeBody = await challengeRes.json();
  const solveOpens = async (indices) => {
    const out = await solver.call("OPEN", { indices });
    return out.opens;
  };
  return {
    payload,
    args,
    commitCookie: commitCookie2,
    challengeBody,
    solveOpens,
    disposeSolver: () => solver.dispose(),
  };
};

const runCcrBootstrapSplit = async (handler) => {
  const payload = makeInnerPayload();
  const pathHash = sha256Base64Url("/protected");
  const ticketB64 = makeTicketB64({
    powSecret: payload.c.POW_TOKEN,
    payload,
    pathHash,
  });
  const ticket = parseTicket(ticketB64);
  const solver = await createMhgSolver({
    ticketB64,
    steps: ticket.L,
    hashcashBits: payload.c.POW_HASHCASH_BITS,
    segmentLen: payload.c.POW_SEGMENT_LEN,
  });
  const commitResult = await solver.call("COMMIT");

  const commitRes = await handler(
    new Request("https://example.com/__pow/commit", {
      method: "POST",
      headers: {
        ...withSplitApiHeaders({ payload, method: "POST", pathname: "/__pow/commit" }),
        "Content-Type": "application/json",
      },
        body: JSON.stringify({
        ticketB64,
        rootB64: commitResult.rootB64,
        pathHash,
        nonce: commitResult.nonce,
      }),
    }),
    {},
    {},
  );
  assert.equal(commitRes.status, 200);
  const commitCookie = (commitRes.headers.get("set-cookie") || "").split(";")[0];
  assert.ok(commitCookie);

  const challengeRes = await handler(
    new Request("https://example.com/__pow/challenge", {
      method: "POST",
      headers: {
        ...withSplitApiHeaders({ payload, method: "POST", pathname: "/__pow/challenge" }),
        "Content-Type": "application/json",
        Cookie: commitCookie,
      },
      body: JSON.stringify({}),
    }),
    {},
    {},
  );
  assert.equal(challengeRes.status, 200);
  const challengeBody = await challengeRes.json();
  const solveOpens = async (indices) => {
    const out = await solver.call("OPEN", { indices });
    return out.opens;
  };

  return {
    payload,
    commitCookie,
    challengeBody,
    solveOpens,
    disposeSolver: () => solver.dispose(),
  };
};

test("challenge/open return required fields and status", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  let bootstrap;
  try {
    bootstrap = await runCcrBootstrap(mod.default.fetch);
    const { payload, commitCookie, challengeBody, solveOpens } = bootstrap;
    const opens = await solveOpens(challengeBody.indices);
    assert.equal(challengeBody.done, false);
    assert.ok(Array.isArray(challengeBody.indices));
    assert.ok(Array.isArray(challengeBody.segs));
    assert.equal(challengeBody.indices.length, challengeBody.segs.length);
    assert.equal(typeof challengeBody.token, "string");
    assert.ok(Number.isInteger(challengeBody.cursor));

    const openRes = await mod.default.fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(payload),
          "Content-Type": "application/json",
          Cookie: commitCookie,
        },
        body: JSON.stringify({
          cursor: challengeBody.cursor,
          token: challengeBody.token,
          opens,
        }),
      }),
      {},
      {}
    );
    assert.equal(openRes.status, 200);
    const openBody = await openRes.json();
    assert.equal(typeof openBody.done, "boolean");
    if (openBody.done === false) {
      assert.ok(Number.isInteger(openBody.cursor));
      assert.ok(openBody.cursor > challengeBody.cursor);
      assert.ok(Array.isArray(openBody.indices));
      assert.ok(Array.isArray(openBody.segs));
      assert.equal(typeof openBody.token, "string");
    }
  } finally {
    if (bootstrap) bootstrap.disposeSolver();
    restoreGlobals();
  }
});

test("open reaches done=true terminal state", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  let bootstrap;
  try {
    bootstrap = await runCcrBootstrap(mod.default.fetch);
    const { payload, commitCookie, challengeBody, solveOpens } = bootstrap;
    const finalBody = await runOpenToFinal(
      mod.default.fetch,
      payload,
      commitCookie,
      challengeBody,
      solveOpens
    );
    assert.equal(finalBody.done, true);
  } finally {
    if (bootstrap) bootstrap.disposeSolver();
    restoreGlobals();
  }
});

test("invalid open token -> 403 + cheat", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  let bootstrap;
  try {
    bootstrap = await runCcrBootstrap(mod.default.fetch);
    const { payload, commitCookie, challengeBody, solveOpens } = bootstrap;
    const opens = await solveOpens(challengeBody.indices);
    const badToken = challengeBody.token.slice(0, -1) + (challengeBody.token.endsWith("A") ? "B" : "A");
    const res = await mod.default.fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(payload),
          "Content-Type": "application/json",
          Cookie: commitCookie,
        },
        body: JSON.stringify({
          cursor: challengeBody.cursor,
          token: badToken,
          opens,
        }),
      }),
      {},
      {}
    );
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-pow-h"), "cheat");
  } finally {
    if (bootstrap) bootstrap.disposeSolver();
    restoreGlobals();
  }
});

test("invalid mhg witness -> 403 + cheat", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  let bootstrap;
  try {
    bootstrap = await runCcrBootstrap(mod.default.fetch);
    const { payload, commitCookie, challengeBody, solveOpens } = bootstrap;
    const opens = await solveOpens(challengeBody.indices);
    const tampered = structuredClone(opens);
    tampered[0].page = tamperBase64UrlBytes(tampered[0].page);
    const res = await mod.default.fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(payload),
          "Content-Type": "application/json",
          Cookie: commitCookie,
        },
        body: JSON.stringify({
          cursor: challengeBody.cursor,
          token: challengeBody.token,
          opens: tampered,
        }),
      }),
      {},
      {}
    );
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-pow-h"), "cheat");
  } finally {
    if (bootstrap) bootstrap.disposeSolver();
    restoreGlobals();
  }
});

test("expired ticket -> 403 + stale", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  try {
    const payload = makeInnerPayload();
    const pageRes = await mod.default.fetch(
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
    const expiredTicket = mutateTicketExpiry(args.ticketB64, Math.floor(Date.now() / 1000) - 30);
    const commitRes = await mod.default.fetch(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(payload),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ticketB64: expiredTicket,
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

test("expired commit -> 403 + stale", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  let bootstrap;
  try {
    bootstrap = await runCcrBootstrap(mod.default.fetch);
    const { payload, commitCookie } = bootstrap;
    const staleCommitCookie = mutateCommitExpiry(commitCookie, Math.floor(Date.now() / 1000) - 10);
    const res = await mod.default.fetch(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(payload),
          "Content-Type": "application/json",
          Cookie: staleCommitCookie,
        },
        body: JSON.stringify({}),
      }),
      {},
      {}
    );
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-pow-h"), "stale");
  } finally {
    if (bootstrap) bootstrap.disposeSolver();
    restoreGlobals();
  }
});

test("malformed open payload -> 400", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  let bootstrap;
  try {
    bootstrap = await runCcrBootstrap(mod.default.fetch);
    const { payload, commitCookie, challengeBody } = bootstrap;
    const res = await mod.default.fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(payload),
          "Content-Type": "application/json",
          Cookie: commitCookie,
        },
        body: JSON.stringify({
          cursor: challengeBody.cursor,
          token: challengeBody.token,
        }),
      }),
      {},
      {}
    );
    assert.equal(res.status, 400);
  } finally {
    if (bootstrap) bootstrap.disposeSolver();
    restoreGlobals();
  }
});

test("split core-2 ccr challenge/open return required fields and terminal state", async () => {
  const restoreGlobals = ensureGlobals();
  const core2Fetch = await buildCore2Module();
  let bootstrap;
  try {
    bootstrap = await runCcrBootstrapSplit(core2Fetch);
    const { payload, commitCookie, challengeBody, solveOpens } = bootstrap;

    assert.equal(challengeBody.done, false);
    assert.ok(Array.isArray(challengeBody.indices));
    assert.ok(Array.isArray(challengeBody.segs));
    assert.equal(challengeBody.indices.length, challengeBody.segs.length);
    assert.equal(typeof challengeBody.token, "string");
    assert.ok(Number.isInteger(challengeBody.cursor));

    let state = challengeBody;
    while (state.done === false) {
      const opens = await solveOpens(state.indices);
      const openRes = await core2Fetch(
        new Request("https://example.com/__pow/open", {
          method: "POST",
          headers: {
            ...withSplitApiHeaders({ payload, method: "POST", pathname: "/__pow/open" }),
            "Content-Type": "application/json",
            Cookie: commitCookie,
          },
          body: JSON.stringify({
            cursor: state.cursor,
            token: state.token,
            opens,
          }),
        }),
        {},
        {},
      );
      assert.equal(openRes.status, 200);
      state = await openRes.json();
    }

    assert.equal(state.done, true);
  } finally {
    if (bootstrap) bootstrap.disposeSolver();
    restoreGlobals();
  }
});
