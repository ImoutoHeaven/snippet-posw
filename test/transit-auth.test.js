import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import defaultCore1 from "../pow-core-1.js";
import defaultCore2 from "../pow-core-2.js";

const PLACEHOLDER_SECRET = "replace-me";
const TEST_SECRET = "config-secret";

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

const normalizeApiPrefix = (value) => {
  if (typeof value !== "string") return "/__pow";
  const trimmed = value.trim();
  if (!trimmed) return "/__pow";
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  const normalized = withSlash.replace(/\/+$/u, "");
  return normalized || "/__pow";
};

const makeTransitMac = ({ secret, exp, kind, method, pathname, apiPrefix = "/__pow" }) => {
  const input = `v1|${exp}|${kind}|${method}|${pathname}|${normalizeApiPrefix(apiPrefix)}`;
  return base64Url(crypto.createHmac("sha256", secret).update(input).digest());
};

const makeTransitHeaders = ({ secret, exp, kind, method, pathname, apiPrefix = "/__pow" }) => {
  const normalizedApiPrefix = normalizeApiPrefix(apiPrefix);
  const headers = new Headers();
  headers.set("X-Pow-Transit", kind);
  headers.set("X-Pow-Transit-Expire", String(exp));
  headers.set("X-Pow-Transit-Api-Prefix", normalizedApiPrefix);
  headers.set(
    "X-Pow-Transit-Mac",
    makeTransitMac({
      secret,
      exp,
      kind,
      method,
      pathname,
      apiPrefix: normalizedApiPrefix,
    })
  );
  return headers;
};

const makeInnerHeaders = ({
  secret,
  exp = Math.floor(Date.now() / 1000) + 3,
  apiPrefix = "/__pow",
  bindPath = "/protected",
}) => {
  const payloadObj = {
    v: 1,
    id: 0,
    c: { POW_API_PREFIX: apiPrefix },
    d: {
      ipScope: "1.2.3.4/32",
      country: "any",
      asn: "any",
      tlsFingerprint: "any",
    },
    s: {
      nav: {},
      bypass: { bypass: false },
      bind: { ok: true, code: "", canonicalPath: bindPath },
      atomic: {
        captchaToken: "",
        ticketB64: "",
        consumeToken: "",
        fromCookie: false,
        cookieName: "__Secure-pow_a",
      },
    },
  };
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const mac = base64Url(crypto.createHmac("sha256", secret).update(`${payload}.${exp}`).digest());
  const headers = new Headers();
  headers.set("X-Pow-Inner", payload);
  headers.set("X-Pow-Inner-Mac", mac);
  headers.set("X-Pow-Inner-Expire", String(exp));
  return headers;
};

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

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

const buildCoreModules = async (secret) => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [
    core1SourceRaw,
    core2SourceRaw,
    transitSource,
    innerAuthSource,
    internalHeadersSource,
    apiEngineSource,
    businessGateSource,
    mhgGraphSource,
    mhgMixSource,
    mhgMerkleSource,
  ] =
    await Promise.all([
      readFile(join(repoRoot, "pow-core-1.js"), "utf8"),
      readFile(join(repoRoot, "pow-core-2.js"), "utf8"),
      readFile(join(repoRoot, "lib", "pow", "transit-auth.js"), "utf8"),
      readFile(join(repoRoot, "lib", "pow", "inner-auth.js"), "utf8"),
      readFile(join(repoRoot, "lib", "pow", "internal-headers.js"), "utf8"),
      readOptionalFile(join(repoRoot, "lib", "pow", "api-engine.js")),
      readOptionalFile(join(repoRoot, "lib", "pow", "business-gate.js")),
      readOptionalFile(join(repoRoot, "lib", "mhg", "graph.js")),
      readOptionalFile(join(repoRoot, "lib", "mhg", "mix-aes.js")),
      readOptionalFile(join(repoRoot, "lib", "mhg", "merkle.js")),
    ]);

  const core1Source = replaceConfigSecret(core1SourceRaw, secret);
  const core2Source = replaceConfigSecret(core2SourceRaw, secret);

  const tmpDir = await mkdtemp(join(tmpdir(), "pow-transit-core-"));
  await mkdir(join(tmpDir, "lib", "pow"), { recursive: true });
  await mkdir(join(tmpDir, "lib", "mhg"), { recursive: true });
  await Promise.all([
    writeFile(join(tmpDir, "pow-core-1.js"), core1Source),
    writeFile(join(tmpDir, "pow-core-2.js"), core2Source),
    writeFile(join(tmpDir, "lib", "pow", "transit-auth.js"), transitSource),
    writeFile(join(tmpDir, "lib", "pow", "inner-auth.js"), innerAuthSource),
    writeFile(join(tmpDir, "lib", "pow", "internal-headers.js"), internalHeadersSource),
    ...(apiEngineSource === null
      ? []
      : [writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineSource)]),
    ...(businessGateSource === null
      ? []
      : [writeFile(join(tmpDir, "lib", "pow", "business-gate.js"), businessGateSource)]),
    ...(mhgGraphSource === null
      ? []
      : [writeFile(join(tmpDir, "lib", "mhg", "graph.js"), mhgGraphSource)]),
    ...(mhgMixSource === null
      ? []
      : [writeFile(join(tmpDir, "lib", "mhg", "mix-aes.js"), mhgMixSource)]),
    ...(mhgMerkleSource === null
      ? []
      : [writeFile(join(tmpDir, "lib", "mhg", "merkle.js"), mhgMerkleSource)]),
  ]);

  const nonce = `${Date.now()}-${Math.random()}`;
  const [core1Module, core2Module] = await Promise.all([
    import(`${pathToFileURL(join(tmpDir, "pow-core-1.js")).href}?v=${nonce}`),
    import(`${pathToFileURL(join(tmpDir, "pow-core-2.js")).href}?v=${nonce}`),
  ]);
  return {
    core1: core1Module.default,
    core2: core2Module.default,
  };
};

test("core1 fail-closed when transit secret is placeholder", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const res = await defaultCore1.fetch(new Request("https://example.com/protected"));
    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 fail-closed when transit secret is placeholder", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const method = "GET";
    const pathname = "/protected";
    const exp = Math.floor(Date.now() / 1000) + 3;
    const headers = makeTransitHeaders({
      secret: PLACEHOLDER_SECRET,
      exp,
      kind: "biz",
      method,
      pathname,
      apiPrefix: "/protected-api",
    });
    const res = await defaultCore2.fetch(
      new Request(`https://example.com${pathname}`, { method, headers })
    );

    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 fail-closed on missing transit headers", async () => {
  const restoreGlobals = ensureGlobals();
  const { core2 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const res = await core2.fetch(new Request("https://example.com/protected"));
    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 fail-closed on expired transit token", async () => {
  const restoreGlobals = ensureGlobals();
  const { core2 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const method = "GET";
    const pathname = "/protected";
    const exp = Math.floor(Date.now() / 1000) - 1;
    const headers = makeTransitHeaders({
      secret: TEST_SECRET,
      exp,
      kind: "biz",
      method,
      pathname,
      apiPrefix: "/protected-api",
    });
    const res = await core2.fetch(
      new Request(`https://example.com${pathname}`, { method, headers })
    );

    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 fail-closed on too-far future transit expiry", async () => {
  const restoreGlobals = ensureGlobals();
  const { core2 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const method = "GET";
    const pathname = "/protected";
    const exp = Math.floor(Date.now() / 1000) + 30;
    const headers = makeTransitHeaders({
      secret: TEST_SECRET,
      exp,
      kind: "biz",
      method,
      pathname,
      apiPrefix: "/protected-api",
    });
    const res = await core2.fetch(
      new Request(`https://example.com${pathname}`, { method, headers })
    );

    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 fail-closed on kind mismatch", async () => {
  const restoreGlobals = ensureGlobals();
  const { core2 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const apiPath = "/__pow/open";
    const apiHeaders = makeTransitHeaders({
      secret: TEST_SECRET,
      exp: Math.floor(Date.now() / 1000) + 3,
      kind: "biz",
      method: "POST",
      pathname: apiPath,
      apiPrefix: "/__pow",
    });
    const apiRes = await core2.fetch(
      new Request(`https://example.com${apiPath}`, { method: "POST", headers: apiHeaders })
    );
    assert.equal(apiRes.status, 500);

    const bizPath = "/protected";
    const bizHeaders = makeTransitHeaders({
      secret: TEST_SECRET,
      exp: Math.floor(Date.now() / 1000) + 3,
      kind: "api",
      method: "GET",
      pathname: bizPath,
      apiPrefix: "/protected-api",
    });
    const bizRes = await core2.fetch(
      new Request(`https://example.com${bizPath}`, { method: "GET", headers: bizHeaders })
    );
    assert.equal(bizRes.status, 500);

    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 fail-closed on transit MAC tamper", async () => {
  const restoreGlobals = ensureGlobals();
  const { core2 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const method = "GET";
    const pathname = "/protected";
    const exp = Math.floor(Date.now() / 1000) + 3;
    const headers = makeTransitHeaders({
      secret: TEST_SECRET,
      exp,
      kind: "biz",
      method,
      pathname,
      apiPrefix: "/protected-api",
    });
    const mac = headers.get("X-Pow-Transit-Mac") || "";
    const tampered = `${mac.slice(0, -1)}${mac.endsWith("A") ? "B" : "A"}`;
    headers.set("X-Pow-Transit-Mac", tampered);

    const res = await core2.fetch(
      new Request(`https://example.com${pathname}`, { method, headers })
    );
    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 accepts valid short-lived transit and strips x-pow-transit* namespace", async () => {
  const restoreGlobals = ensureGlobals();
  const { core2 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let forwardedRequest = null;
  try {
    globalThis.fetch = async (request) => {
      forwardedRequest = request;
      return new Response(null, { status: 200 });
    };

    const method = "GET";
    const pathname = "/protected";
    const exp = Math.floor(Date.now() / 1000) + 3;
    const headers = makeTransitHeaders({
      secret: TEST_SECRET,
      exp,
      kind: "biz",
      method,
      pathname,
      apiPrefix: "/protected-api",
    });
    headers.set("X-Pow-Transit-Extra", "spoof");

    const res = await core2.fetch(
      new Request(`https://example.com${pathname}`, { method, headers })
    );

    assert.equal(res.status, 200);
    assert.ok(forwardedRequest, "origin fetch called");
    for (const key of forwardedRequest.headers.keys()) {
      assert.ok(
        !key.toLowerCase().startsWith("x-pow-transit"),
        `forwarded transit namespace header: ${key}`
      );
    }
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core1 strips prefix-only spoof headers before issuing biz transit", async () => {
  const restoreGlobals = ensureGlobals();
  const { core1 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let forwardedRequest = null;
  try {
    globalThis.fetch = async (request) => {
      forwardedRequest = request;
      return new Response(null, { status: 200 });
    };

    const method = "GET";
    const pathname = "/protected";
    const innerHeaders = makeInnerHeaders({ secret: TEST_SECRET });
    innerHeaders.set("X-Pow-Transit-Extra", "spoofed");
    const res = await core1.fetch(
      new Request(`https://example.com${pathname}`, {
        method,
        headers: innerHeaders,
      })
    );

    assert.equal(res.status, 200);
    assert.ok(forwardedRequest, "forwarded request exists");
    const kind = forwardedRequest.headers.get("X-Pow-Transit");
    const mac = forwardedRequest.headers.get("X-Pow-Transit-Mac") || "";
    const expRaw = forwardedRequest.headers.get("X-Pow-Transit-Expire") || "";
    const exp = Number.parseInt(expRaw, 10);

    assert.equal(kind, "biz");
    assert.ok(Number.isSafeInteger(exp));
    assert.ok(exp > Math.floor(Date.now() / 1000));
    const expectedMac = makeTransitMac({
      secret: TEST_SECRET,
      exp,
      kind,
      method,
      pathname,
      apiPrefix: "/__pow",
    });
    assert.equal(mac, expectedMac);

    const transitKeys = Array.from(forwardedRequest.headers.keys())
      .map((key) => key.toLowerCase())
      .filter((key) => key.startsWith("x-pow-transit"))
      .sort();
    assert.deepEqual(transitKeys, [
      "x-pow-transit",
      "x-pow-transit-api-prefix",
      "x-pow-transit-expire",
      "x-pow-transit-mac",
    ]);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core1 issues api transit on /__pow/* path", async () => {
  const restoreGlobals = ensureGlobals();
  const { core1 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let forwardedRequest = null;
  try {
    globalThis.fetch = async (request) => {
      forwardedRequest = request;
      return new Response(null, { status: 200 });
    };

    const method = "POST";
    const pathname = "/__pow/open";
    const innerHeaders = makeInnerHeaders({ secret: TEST_SECRET });
    const res = await core1.fetch(
      new Request(`https://example.com${pathname}`, { method, headers: innerHeaders })
    );

    assert.equal(res.status, 200);
    assert.ok(forwardedRequest, "forwarded request exists");
    const kind = forwardedRequest.headers.get("X-Pow-Transit");
    const mac = forwardedRequest.headers.get("X-Pow-Transit-Mac") || "";
    const expRaw = forwardedRequest.headers.get("X-Pow-Transit-Expire") || "";
    const exp = Number.parseInt(expRaw, 10);

    assert.equal(kind, "api");
    assert.ok(Number.isSafeInteger(exp));
    const expectedMac = makeTransitMac({
      secret: TEST_SECRET,
      exp,
      kind,
      method,
      pathname,
      apiPrefix: "/__pow",
    });
    assert.equal(mac, expectedMac);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core1 treats encoded api path as api transit", async () => {
  const restoreGlobals = ensureGlobals();
  const { core1 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let forwardedRequest = null;
  try {
    globalThis.fetch = async (request) => {
      forwardedRequest = request;
      return new Response(null, { status: 200 });
    };

    const method = "POST";
    const requestPathname = "/__pow%2Fopen";
    const transitPathname = "/__pow/open";
    const innerHeaders = makeInnerHeaders({ secret: TEST_SECRET });
    const res = await core1.fetch(
      new Request(`https://example.com${requestPathname}`, { method, headers: innerHeaders })
    );

    assert.equal(res.status, 200);
    assert.ok(forwardedRequest, "forwarded request exists");
    const kind = forwardedRequest.headers.get("X-Pow-Transit");
    const mac = forwardedRequest.headers.get("X-Pow-Transit-Mac") || "";
    const expRaw = forwardedRequest.headers.get("X-Pow-Transit-Expire") || "";
    const exp = Number.parseInt(expRaw, 10);

    assert.equal(kind, "api");
    assert.ok(Number.isSafeInteger(exp));
    const expectedMac = makeTransitMac({
      secret: TEST_SECRET,
      exp,
      kind,
      method,
      pathname: transitPathname,
      apiPrefix: "/__pow",
    });
    assert.equal(mac, expectedMac);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core1 classifies kind using signed inner POW_API_PREFIX", async () => {
  const restoreGlobals = ensureGlobals();
  const { core1 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let forwardedRequest = null;
  try {
    globalThis.fetch = async (request) => {
      forwardedRequest = request;
      return new Response(null, { status: 200 });
    };

    const method = "POST";
    const pathname = "/altpow/open";
    const innerHeaders = makeInnerHeaders({
      secret: TEST_SECRET,
      apiPrefix: "/altpow",
      bindPath: pathname,
    });
    const res = await core1.fetch(
      new Request(`https://example.com${pathname}`, { method, headers: innerHeaders })
    );

    assert.equal(res.status, 200);
    assert.ok(forwardedRequest, "forwarded request exists");
    const kind = forwardedRequest.headers.get("X-Pow-Transit");
    const mac = forwardedRequest.headers.get("X-Pow-Transit-Mac") || "";
    const expRaw = forwardedRequest.headers.get("X-Pow-Transit-Expire") || "";
    const exp = Number.parseInt(expRaw, 10);

    assert.equal(kind, "api");
    assert.ok(Number.isSafeInteger(exp));
    const expectedMac = makeTransitMac({
      secret: TEST_SECRET,
      exp,
      kind,
      method,
      pathname,
      apiPrefix: "/altpow",
    });
    assert.equal(mac, expectedMac);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 fail-closes api transit without signed inner headers", async () => {
  const restoreGlobals = ensureGlobals();
  const { core2 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const method = "POST";
    const pathname = "/altpow/open";
    const exp = Math.floor(Date.now() / 1000) + 3;
    const headers = makeTransitHeaders({
      secret: TEST_SECRET,
      exp,
      kind: "api",
      method,
      pathname,
      apiPrefix: "/altpow",
    });

    const res = await core2.fetch(
      new Request(`https://example.com${pathname}`, { method, headers })
    );
    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 routes encoded api path through api engine", async () => {
  const restoreGlobals = ensureGlobals();
  const { core2 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const method = "POST";
    const requestPathname = "/__pow%2Fcommit";
    const transitPathname = "/__pow/commit";
    const exp = Math.floor(Date.now() / 1000) + 3;
    const headers = makeTransitHeaders({
      secret: TEST_SECRET,
      exp,
      kind: "api",
      method,
      pathname: transitPathname,
      apiPrefix: "/__pow",
    });
    const innerHeaders = makeInnerHeaders({ secret: TEST_SECRET });
    for (const [key, value] of innerHeaders.entries()) {
      headers.set(key, value);
    }
    headers.set("Content-Type", "application/json");

    const res = await core2.fetch(
      new Request(`https://example.com${requestPathname}`, {
        method,
        headers,
        body: JSON.stringify({}),
      })
    );

    assert.equal(res.status, 400);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core1->core2 api path keeps signed inner and denies without commit", async () => {
  const restoreGlobals = ensureGlobals();
  const { core1, core2 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let hopRequest = null;
  let originRequest = null;
  try {
    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Transit")) {
        hopRequest = request;
        return core2.fetch(request);
      }
      originRequest = request;
      return new Response(null, { status: 200 });
    };

    const method = "POST";
    const pathname = "/altpow/open";
    const innerHeaders = makeInnerHeaders({
      secret: TEST_SECRET,
      apiPrefix: "/altpow",
      bindPath: pathname,
    });
    const res = await core1.fetch(
      new Request(`https://example.com${pathname}`, { method, headers: innerHeaders })
    );

    assert.equal(res.status, 403);
    assert.ok(hopRequest, "core1 forwards to core2");
    assert.ok(hopRequest.headers.get("X-Pow-Inner"), "hop keeps signed inner payload");
    assert.ok(hopRequest.headers.get("X-Pow-Inner-Mac"), "hop keeps signed inner mac");
    assert.ok(hopRequest.headers.get("X-Pow-Inner-Expire"), "hop keeps signed inner expire");
    assert.equal(originRequest, null);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 rejects transit when api prefix header is tampered", async () => {
  const restoreGlobals = ensureGlobals();
  const { core2 } = await buildCoreModules(TEST_SECRET);
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const method = "POST";
    const pathname = "/altpow/open";
    const exp = Math.floor(Date.now() / 1000) + 3;
    const headers = makeTransitHeaders({
      secret: TEST_SECRET,
      exp,
      kind: "api",
      method,
      pathname,
      apiPrefix: "/altpow",
    });
    headers.set("X-Pow-Transit-Api-Prefix", "/tampered");

    const res = await core2.fetch(
      new Request(`https://example.com${pathname}`, { method, headers })
    );

    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
