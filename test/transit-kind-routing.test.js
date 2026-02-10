import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

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

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const makeTransitMac = ({ secret, exp, kind, method, pathname, apiPrefix }) => {
  const normalizedMethod = typeof method === "string" && method ? method.toUpperCase() : "GET";
  const normalizedPath =
    typeof pathname === "string" && pathname
      ? pathname.startsWith("/")
        ? pathname
        : `/${pathname}`
      : "/";
  const normalizedApiPrefix = normalizeApiPrefix(apiPrefix);
  const macInput =
    `v1|${exp}|${kind}|${normalizedMethod}|${normalizedPath}|${normalizedApiPrefix}`;
  return base64Url(crypto.createHmac("sha256", secret).update(macInput).digest());
};

const makeTransitHeaders = ({ secret, method, pathname, kind, apiPrefix, exp }) => {
  const headers = new Headers();
  const transitExp = Number.isFinite(exp) ? exp : Math.floor(Date.now() / 1000) + 3;
  const normalizedApiPrefix = normalizeApiPrefix(apiPrefix);
  headers.set("X-Pow-Transit", kind);
  headers.set("X-Pow-Transit-Expire", String(transitExp));
  headers.set("X-Pow-Transit-Api-Prefix", normalizedApiPrefix);
  headers.set(
    "X-Pow-Transit-Mac",
    makeTransitMac({
      secret,
      exp: transitExp,
      kind,
      method,
      pathname,
      apiPrefix: normalizedApiPrefix,
    })
  );
  return headers;
};

const makeInnerHeaders = ({ secret, apiPrefix }) => {
  const exp = Math.floor(Date.now() / 1000) + 3;
  const payloadObj = {
    v: 1,
    id: 1,
    c: {
      POW_API_PREFIX: normalizeApiPrefix(apiPrefix),
      POW_TOKEN: "pow-secret",
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
  };
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const mac = base64Url(crypto.createHmac("sha256", secret).update(`${payload}.${exp}`).digest());
  const headers = new Headers();
  headers.set("X-Pow-Inner", payload);
  headers.set("X-Pow-Inner-Mac", mac);
  headers.set("X-Pow-Inner-Expire", String(exp));
  return headers;
};

const buildCore2Module = async (secret = TEST_SECRET) => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [
    core2SourceRaw,
    transitSource,
    innerAuthSource,
    internalHeadersSource,
    apiEngineSource,
    mhgGraphSource,
    mhgMixSource,
    mhgMerkleSource,
  ] = await Promise.all([
    readFile(join(repoRoot, "pow-core-2.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "transit-auth.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "inner-auth.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "internal-headers.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "graph.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "mix-aes.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "merkle.js"), "utf8"),
  ]);

  const core2Source = replaceConfigSecret(core2SourceRaw, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-core2-kind-"));
  await mkdir(join(tmpDir, "lib", "pow"), { recursive: true });
  await mkdir(join(tmpDir, "lib", "mhg"), { recursive: true });
  await Promise.all([
    writeFile(join(tmpDir, "pow-core-2.js"), core2Source),
    writeFile(join(tmpDir, "lib", "pow", "transit-auth.js"), transitSource),
    writeFile(join(tmpDir, "lib", "pow", "inner-auth.js"), innerAuthSource),
    writeFile(join(tmpDir, "lib", "pow", "internal-headers.js"), internalHeadersSource),
    writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineSource),
    writeFile(join(tmpDir, "lib", "mhg", "graph.js"), mhgGraphSource),
    writeFile(join(tmpDir, "lib", "mhg", "mix-aes.js"), mhgMixSource),
    writeFile(join(tmpDir, "lib", "mhg", "merkle.js"), mhgMerkleSource),
  ]);

  const moduleUrl = `${pathToFileURL(join(tmpDir, "pow-core-2.js")).href}?v=${Date.now()}`;
  const core2Module = await import(moduleUrl);
  return core2Module.default;
};

test("reject api path with biz transit kind", async () => {
  const restoreGlobals = ensureGlobals();
  const core2 = await buildCore2Module();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const method = "POST";
    const pathname = "/__pow/open";
    const headers = makeTransitHeaders({
      secret: TEST_SECRET,
      method,
      pathname,
      kind: "biz",
      apiPrefix: "/__pow",
    });
    const res = await core2.fetch(new Request(`https://example.com${pathname}`, { method, headers }));

    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("reject business path with api transit kind", async () => {
  const restoreGlobals = ensureGlobals();
  const core2 = await buildCore2Module();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const method = "GET";
    const pathname = "/protected";
    const headers = makeTransitHeaders({
      secret: TEST_SECRET,
      method,
      pathname,
      kind: "api",
      apiPrefix: "/__pow",
    });
    const res = await core2.fetch(new Request(`https://example.com${pathname}`, { method, headers }));

    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("reject expired transit token", async () => {
  const restoreGlobals = ensureGlobals();
  const core2 = await buildCore2Module();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const method = "GET";
    const pathname = "/protected";
    const headers = makeTransitHeaders({
      secret: TEST_SECRET,
      method,
      pathname,
      kind: "biz",
      apiPrefix: "/__pow",
      exp: Math.floor(Date.now() / 1000) - 1,
    });
    const res = await core2.fetch(new Request(`https://example.com${pathname}`, { method, headers }));

    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("reject api path forged as biz by transit api-prefix", async () => {
  const restoreGlobals = ensureGlobals();
  const core2 = await buildCore2Module();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const method = "POST";
    const pathname = "/__pow/open";
    const headers = makeTransitHeaders({
      secret: TEST_SECRET,
      method,
      pathname,
      kind: "biz",
      apiPrefix: "/altpow",
    });
    const innerHeaders = makeInnerHeaders({ secret: TEST_SECRET, apiPrefix: "/__pow" });
    for (const [key, value] of innerHeaders.entries()) {
      headers.set(key, value);
    }

    const res = await core2.fetch(new Request(`https://example.com${pathname}`, { method, headers }));

    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("reject business path forged as api by transit api-prefix", async () => {
  const restoreGlobals = ensureGlobals();
  const core2 = await buildCore2Module();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response(null, { status: 200 });
    };

    const method = "POST";
    const pathname = "/protected/open";
    const headers = makeTransitHeaders({
      secret: TEST_SECRET,
      method,
      pathname,
      kind: "api",
      apiPrefix: "/protected",
    });
    const innerHeaders = makeInnerHeaders({ secret: TEST_SECRET, apiPrefix: "/__pow" });
    for (const [key, value] of innerHeaders.entries()) {
      headers.set(key, value);
    }

    const res = await core2.fetch(new Request(`https://example.com${pathname}`, { method, headers }));

    assert.equal(res.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
