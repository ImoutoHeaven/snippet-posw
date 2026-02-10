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

const base64UrlDecode = (value) => {
  if (!value || typeof value !== "string") return null;
  let b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  try {
    return Buffer.from(b64, "base64").toString("utf8");
  } catch {
    return null;
  }
};

const encodeAtomicCookie = (value) => encodeURIComponent(value);

const hmacSha256Base64Url = (secret, data) =>
  base64Url(crypto.createHmac("sha256", secret).update(data).digest());

const captchaTagV1 = (turnToken = "", recaptchaToken = "") => {
  const material = `ctag|v1|t=${String(turnToken || "")}|r=${String(recaptchaToken || "")}`;
  return base64Url(crypto.createHash("sha256").update(material).digest().subarray(0, 12));
};

const makePowBindingString = (ticket, hostname, pathHash, ipScope, country, asn, tlsFingerprint) =>
  [
    String(ticket.v),
    String(ticket.e),
    String(ticket.L),
    String(ticket.r),
    String(ticket.cfgId),
    String(hostname || "").toLowerCase(),
    pathHash,
    ipScope,
    country,
    asn,
    tlsFingerprint,
  ].join("|");

const assertExpireWindow = (expireHeader) => {
  const expire = Number.parseInt(expireHeader, 10);
  assert.ok(Number.isSafeInteger(expire), "expire is integer seconds");
  const now = Math.floor(Date.now() / 1000);
  assert.ok(
    expire >= now && expire <= now + 3,
    "expire within expected window"
  );
};

const assertPayloadSections = (parsed) => {
  assert.ok(parsed && parsed.s && typeof parsed.s === "object", "payload includes s section");
  assert.ok(parsed.s.nav && typeof parsed.s.nav === "object");
  assert.ok(parsed.s.bypass && typeof parsed.s.bypass === "object");
  assert.ok(parsed.s.bind && typeof parsed.s.bind === "object");
  assert.ok(parsed.s.atomic && typeof parsed.s.atomic === "object");
};

const readInnerPayload = (headers) => {
  const countHeader = headers.get("X-Pow-Inner-Count");
  if (countHeader) {
    const count = Number.parseInt(countHeader, 10);
    if (!Number.isFinite(count) || count <= 0) {
      return { payload: "", count: 0, chunked: true };
    }
    let payload = "";
    for (let i = 0; i < count; i += 1) {
      payload += headers.get(`X-Pow-Inner-${i}`) || "";
    }
    return { payload, count, chunked: true };
  }
  return { payload: headers.get("X-Pow-Inner") || "", count: 0, chunked: false };
};

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const buildTestModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  const template = await readFile(join(repoRoot, "template.html"), "utf8");
  const compiledConfig = JSON.stringify([]);
  const injected = powSource
    .replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template))
    .replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-test-"));
  const tmpPath = join(tmpDir, "pow-test.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

const buildConfigModule = async (secret = "config-secret", options = {}) => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powConfigSource = await readFile(join(repoRoot, "pow-config.js"), "utf8");
  const gluePadding = options.longGlue ? "x".repeat(6000) : "";
  const configOverrides = options.configOverrides || {};
  const compiledConfig = JSON.stringify([
    {
      host: { s: "^example\\.com$", f: "" },
      path: { s: "^/protected$", f: "" },
      config: {
        POW_TOKEN: "pow-secret",
        powcheck: true,
        POW_BIND_TLS: false,
        POW_ESM_URL: "https://example.com/esm",
        POW_GLUE_URL: `https://example.com/glue${gluePadding}`,
        ...configOverrides,
      },
    },
  ]);
  const injected = powConfigSource.replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-config-test-"));
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

const buildCoreModules = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [
    core1SourceRaw,
    core2SourceRaw,
    transitSource,
    innerAuthSource,
    internalHeadersSource,
    apiEngineSource,
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
    readFile(join(repoRoot, "lib", "mhg", "graph.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "mix-aes.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "merkle.js"), "utf8"),
  ]);

  const core1Source = replaceConfigSecret(core1SourceRaw, secret);
  const core2Source = replaceConfigSecret(core2SourceRaw, secret);

  const tmpDir = await mkdtemp(join(tmpdir(), "pow-core-inner-test-"));
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
  await Promise.all(writes);

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

const normalizeApiPrefix = (value) => {
  if (typeof value !== "string") return "/__pow";
  const trimmed = value.trim();
  if (!trimmed) return "/__pow";
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  const normalized = withSlash.replace(/\/+$/u, "");
  return normalized || "/__pow";
};

const makeTransitHeaders = ({
  secret,
  exp,
  kind,
  method,
  pathname,
  apiPrefix = "/__pow",
}) => {
  const normalizedMethod = typeof method === "string" && method ? method.toUpperCase() : "GET";
  const normalizedPath =
    typeof pathname === "string" && pathname ? (pathname.startsWith("/") ? pathname : `/${pathname}`) : "/";
  const normalizedApiPrefix = normalizeApiPrefix(apiPrefix);
  const input = `v1|${exp}|${kind}|${normalizedMethod}|${normalizedPath}|${normalizedApiPrefix}`;
  const mac = hmacSha256Base64Url(secret, input);
  const headers = new Headers();
  headers.set("X-Pow-Transit", kind);
  headers.set("X-Pow-Transit-Mac", mac);
  headers.set("X-Pow-Transit-Expire", String(exp));
  headers.set("X-Pow-Transit-Api-Prefix", normalizedApiPrefix);
  return headers;
};

const buildInnerPayloadForCore = ({ apiPrefix = "/__pow", extraConfig = {} } = {}) => ({
  v: 1,
  id: 0,
  c: { POW_API_PREFIX: apiPrefix, ...extraConfig },
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
});

const makeInnerHeaders = ({
  secret,
  chunked = false,
  exp = Math.floor(Date.now() / 1000) + 3,
  apiPrefix = "/__pow",
  payloadObj,
}) => {
  const encodedPayload = payloadObj || buildInnerPayloadForCore({ apiPrefix });
  const payload = base64Url(Buffer.from(JSON.stringify(encodedPayload), "utf8"));
  const mac = hmacSha256Base64Url(secret, `${payload}.${exp}`);
  const headers = new Headers();
  if (chunked) {
    const midpoint = Math.floor(payload.length / 2);
    const part0 = payload.slice(0, midpoint);
    const part1 = payload.slice(midpoint);
    headers.set("X-Pow-Inner-Count", "2");
    headers.set("X-Pow-Inner-0", part0);
    headers.set("X-Pow-Inner-1", part1);
  } else {
    headers.set("X-Pow-Inner", payload);
  }
  headers.set("X-Pow-Inner-Mac", mac);
  headers.set("X-Pow-Inner-Expire", String(exp));
  return headers;
};

test("core-1 rejects missing or invalid inner payload", async () => {
  const restoreGlobals = ensureGlobals();
  const { core1 } = await buildCoreModules("config-secret");
  const originalFetch = globalThis.fetch;
  let forwardedCalls = 0;
  try {
    globalThis.fetch = async () => {
      forwardedCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const missing = await core1.fetch(new Request("https://example.com/protected"));
    assert.equal(missing.status, 500);
    assert.equal(forwardedCalls, 0);

    const invalidHeaders = makeInnerHeaders({ secret: "config-secret" });
    invalidHeaders.set("X-Pow-Inner-Mac", "tampered");
    const invalid = await core1.fetch(
      new Request("https://example.com/protected", { headers: invalidHeaders })
    );
    assert.equal(invalid.status, 500);
    assert.equal(forwardedCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core-1 rejects oversized direct inner payload header", async () => {
  const restoreGlobals = ensureGlobals();
  const { core1 } = await buildCoreModules("config-secret");
  const originalFetch = globalThis.fetch;
  let forwardedCalls = 0;
  try {
    globalThis.fetch = async () => {
      forwardedCalls += 1;
      return new Response("ok", { status: 200 });
    };

    const hugePayload = buildInnerPayloadForCore({
      extraConfig: {
        oversized: "x".repeat(130000),
      },
    });
    const headers = makeInnerHeaders({
      secret: "config-secret",
      payloadObj: hugePayload,
    });
    const { payload } = readInnerPayload(headers);
    assert.ok(payload.length > 128 * 1024, "direct inner payload exceeds parser max");

    const res = await core1.fetch(new Request("https://example.com/protected", { headers }));
    assert.equal(res.status, 500);
    assert.equal(forwardedCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core-2 strips x-pow-inner* and x-pow-transit* before origin fetch", async () => {
  const restoreGlobals = ensureGlobals();
  const { core2 } = await buildCoreModules("config-secret");
  const originalFetch = globalThis.fetch;
  let forwarded = null;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const method = "GET";
    const pathname = "/protected";
    const exp = Math.floor(Date.now() / 1000) + 3;
    const headers = makeTransitHeaders({
      secret: "config-secret",
      exp,
      kind: "biz",
      method,
      pathname,
      apiPrefix: "/protected-api",
    });
    const innerHeaders = makeInnerHeaders({ secret: "config-secret", chunked: true });
    for (const [key, value] of innerHeaders.entries()) {
      headers.set(key, value);
    }
    headers.set("X-Pow-Transit-Extra", "spoofed");

    const res = await core2.fetch(
      new Request(`https://example.com${pathname}`, { method, headers })
    );
    assert.equal(res.status, 200);
    assert.ok(forwarded, "origin request forwarded");
    for (const key of forwarded.headers.keys()) {
      const normalized = key.toLowerCase();
      assert.equal(normalized.startsWith("x-pow-inner"), false, `${key} is stripped`);
      assert.equal(normalized.startsWith("x-pow-transit"), false, `${key} is stripped`);
    }
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("inner header signature helper matches node crypto", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const modulePath = await buildTestModule();
    const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
    const hmac = mod.hmacSha256Base64UrlNoPad;

    assert.equal(typeof hmac, "function");

    const payload = base64Url(Buffer.from("{\"v\":1}", "utf8"));
    const expire = "1700000000";
    const signatureInput = `${payload}.${expire}`;
    const secret = "config-secret";
    const expected = base64Url(
      crypto.createHmac("sha256", secret).update(signatureInput).digest()
    );
    const actual = await hmac(secret, signatureInput);

    assert.equal(actual, expected);
  } finally {
    restoreGlobals();
  }
});

test("pow-config injects signed header", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
        "X-Pow-Inner": "spoofed",
        "X-Pow-Inner-Mac": "spoofed",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");
    const { payload } = readInnerPayload(forwarded.headers);
    const mac = forwarded.headers.get("X-Pow-Inner-Mac") || "";
    const expireHeader = forwarded.headers.get("X-Pow-Inner-Expire") || "";
    assert.ok(payload.length > 0, "payload header set");
    assert.ok(mac.length > 0, "mac header set");
    assert.ok(expireHeader.length > 0, "expire header set");
    assert.notEqual(payload, "spoofed");
    assert.notEqual(mac, "spoofed");

    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.v, 1);
    assert.equal(parsed.id, 0);
    assertPayloadSections(parsed);

    assertExpireWindow(expireHeader);

    const expectedMac = base64Url(
      crypto
        .createHmac("sha256", "config-secret")
        .update(`${payload}.${expireHeader}`)
        .digest()
    );
    assert.equal(mac, expectedMac);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config injects chunked inner headers when payload is large", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret", { longGlue: true });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");

    const countHeader = forwarded.headers.get("X-Pow-Inner-Count");
    const mac = forwarded.headers.get("X-Pow-Inner-Mac") || "";
    const expireHeader = forwarded.headers.get("X-Pow-Inner-Expire") || "";
    assert.ok(countHeader, "chunk count header set");
    assert.equal(forwarded.headers.get("X-Pow-Inner"), null);
    assert.ok(expireHeader.length > 0, "expire header set");

    const count = Number.parseInt(countHeader, 10);
    assert.ok(Number.isFinite(count) && count > 1, "chunk count is numeric");

    let payload = "";
    for (let i = 0; i < count; i += 1) {
      const part = forwarded.headers.get(`X-Pow-Inner-${i}`) || "";
      assert.ok(part.length > 0, `chunk ${i} set`);
      payload += part;
    }
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.v, 1);
    assert.equal(parsed.id, 0);
    assert.ok(parsed.c && typeof parsed.c.POW_GLUE_URL === "string");
    assertPayloadSections(parsed);

    assertExpireWindow(expireHeader);

    const expectedMac = base64Url(
      crypto
        .createHmac("sha256", "config-secret")
        .update(`${payload}.${expireHeader}`)
        .digest()
    );
    assert.equal(mac, expectedMac);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config rejects placeholder CONFIG_SECRET", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("replace-me");
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 500);
    assert.equal(forwarded, null);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config clamps invalid cfgId from pow api", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  const ticket = ["v1", "r", "p", "t", "999", "mac"].join(".");
  const ticketB64 = base64Url(Buffer.from(ticket, "utf8"));
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/__pow/commit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ticketB64 }),
    });
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.id, -1);
    assert.equal(parsed.c.powcheck, false);
    assert.equal(parsed.c.POW_TOKEN, undefined);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config preserves numeric POW_SEGMENT_LEN", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret", {
    configOverrides: { POW_SEGMENT_LEN: 32 },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.c.POW_SEGMENT_LEN, 32);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config allows POW_SPINE_K to disable spine", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret", {
    configOverrides: { POW_SPINE_K: 0 },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.c.POW_SPINE_K, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config preserves turnstile keys for turncheck", async () => {
  const restoreGlobals = ensureGlobals();
  const secret = "config-secret";
  const modulePath = await buildConfigModule(secret, {
    configOverrides: {
      turncheck: true,
      TURNSTILE_SITEKEY: "turn-site-key",
      TURNSTILE_SECRET: "turn-secret",
    },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(typeof parsed.c.TURNSTILE_SITEKEY, "string");
    assert.equal(typeof parsed.c.TURNSTILE_SECRET, "string");
    assert.ok(parsed.c.TURNSTILE_SITEKEY.length > 0);
    assert.ok(parsed.c.TURNSTILE_SECRET.length > 0);

    const powModulePath = await buildTestModule(secret);
    const powMod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;
    const powRes = await powHandler(
      new Request("https://example.com/anything", {
        method: "OPTIONS",
        headers: forwarded.headers,
      })
    );
    assert.equal(powRes.status, 204);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config normalizes non-string turnstile keys", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret", {
    configOverrides: {
      turncheck: false,
      TURNSTILE_SITEKEY: 123,
      TURNSTILE_SECRET: { secret: true },
    },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.c.TURNSTILE_SITEKEY, "");
    assert.equal(parsed.c.TURNSTILE_SECRET, "");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config preserves recaptcha keys for recaptchaEnabled", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret", {
    configOverrides: {
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: [{ sitekey: "rk1", secret: "rs1" }],
      RECAPTCHA_MIN_SCORE: 0.7,
    },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.c.recaptchaEnabled, true);
    assert.deepEqual(parsed.c.RECAPTCHA_PAIRS, [{ sitekey: "rk1", secret: "rs1" }]);
    assert.equal(parsed.c.RECAPTCHA_ACTION, "submit");
    assert.equal(parsed.c.RECAPTCHA_MIN_SCORE, 0.7);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config preserves recaptcha action override", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret", {
    configOverrides: {
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: [{ sitekey: "rk1", secret: "rs1" }],
      RECAPTCHA_ACTION: "login_submit",
    },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.c.RECAPTCHA_ACTION, "login_submit");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config normalizes invalid recaptcha pair payload", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret", {
    configOverrides: {
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: [{ sitekey: "rk1" }, { secret: "rs2" }, { sitekey: "", secret: "rs3" }],
      RECAPTCHA_MIN_SCORE: "invalid",
    },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.deepEqual(parsed.c.RECAPTCHA_PAIRS, []);
    assert.equal(parsed.c.RECAPTCHA_MIN_SCORE, 0.5);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config normalizes numeric string POW_SEGMENT_LEN for pow.js", async () => {
  const restoreGlobals = ensureGlobals();
  const secret = "config-secret";
  const modulePath = await buildConfigModule(secret, {
    configOverrides: { POW_SEGMENT_LEN: "32" },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.c.POW_SEGMENT_LEN, 32);

    const powModulePath = await buildTestModule(secret);
    const powMod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;
    const powRes = await powHandler(
      new Request("https://example.com/anything", {
        method: "OPTIONS",
        headers: forwarded.headers,
      })
    );
    assert.equal(powRes.status, 204);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config normalizes range string POW_SEGMENT_LEN for pow.js", async () => {
  const restoreGlobals = ensureGlobals();
  const secret = "config-secret";
  const modulePath = await buildConfigModule(secret, {
    configOverrides: { POW_SEGMENT_LEN: "12-34" },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.c.POW_SEGMENT_LEN, "12-34");

    const powModulePath = await buildTestModule(secret);
    const powMod = await import(`${pathToFileURL(powModulePath).href}?v=${Date.now()}`);
    const powHandler = powMod.default.fetch;
    const powRes = await powHandler(
      new Request("https://example.com/anything", {
        method: "OPTIONS",
        headers: forwarded.headers,
      })
    );
    assert.equal(powRes.status, 204);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config rejects oversized atomic snapshot with 431 and empty body", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret");
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request(`https://example.com/protected?__ts=${"a".repeat(9000)}`, {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 431);
    assert.equal(forwarded, null);
    assert.equal(await res.text(), "");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config rejects invalid atomic format with 400 and empty body", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret");
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request("https://example.com/protected?__tt=bad*ticket", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const res = await handler(req);
    assert.equal(res.status, 400);
    assert.equal(forwarded, null);
    assert.equal(await res.text(), "");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config accepts large combined captchaToken envelope under limits", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret");
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const envelope = JSON.stringify({
      turnstile: "t".repeat(4000),
      recaptcha_v3: "r".repeat(4000),
    });
    assert.ok(envelope.length < 8192, "envelope stays under captcha token max");
    const ticket = "a".repeat(2048);
    const consume = "c".repeat(256);
    const req = new Request(
      `https://example.com/protected?__ts=${encodeURIComponent(envelope)}&__tt=${ticket}&__ct=${consume}`,
      {
        headers: {
          "CF-Connecting-IP": "1.2.3.4",
        },
      }
    );
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "request is forwarded for large valid envelope");
    assert.equal(await res.text(), "ok");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config enforces captchaToken length boundary at max and max+1", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret");
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  const originalFetch = globalThis.fetch;
  try {
    let forwarded = null;
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const atMaxReq = new Request(`https://example.com/protected?__ts=${"t".repeat(8192)}`, {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const atMaxRes = await handler(atMaxReq);
    assert.equal(atMaxRes.status, 200);
    assert.ok(forwarded, "request is forwarded at boundary max");
    assert.equal(await atMaxRes.text(), "ok");

    forwarded = null;
    const overReq = new Request(`https://example.com/protected?__ts=${"t".repeat(8193)}`, {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const overRes = await handler(overReq);
    assert.equal(overRes.status, 431);
    assert.equal(forwarded, null);
    assert.equal(await overRes.text(), "");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config enforces ticketB64 length boundary at max and max+1", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret");
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  const originalFetch = globalThis.fetch;
  try {
    let forwarded = null;
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const atMaxReq = new Request(`https://example.com/protected?__tt=${"a".repeat(2048)}`, {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const atMaxRes = await handler(atMaxReq);
    assert.equal(atMaxRes.status, 200);
    assert.ok(forwarded, "request is forwarded at boundary max");
    assert.equal(await atMaxRes.text(), "ok");

    forwarded = null;
    const overReq = new Request(`https://example.com/protected?__tt=${"a".repeat(2049)}`, {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
      },
    });
    const overRes = await handler(overReq);
    assert.equal(overRes.status, 431);
    assert.equal(forwarded, null);
    assert.equal(await overRes.text(), "");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config marks oversized bindPath input as invalid", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret", {
    configOverrides: {
      bindPathMode: "query",
      bindPathQueryName: "path",
    },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const tooLongPath = `/${"a".repeat(2048)}`;
    const req = new Request(
      `https://example.com/protected?path=${encodeURIComponent(tooLongPath)}`,
      {
        headers: {
          "CF-Connecting-IP": "1.2.3.4",
        },
      }
    );
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "request is still forwarded with bind invalid strategy");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.s.bind.ok, false);
    assert.equal(parsed.s.bind.code, "invalid");
    assert.equal(parsed.s.bind.canonicalPath, "/protected");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config frontloads atomic strategy with cookie priority and strips request", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret", {
    configOverrides: {
      bindPathMode: "query",
      bindPathQueryName: "path",
      STRIP_ATOMIC_QUERY: true,
      STRIP_ATOMIC_HEADERS: true,
    },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const req = new Request(
      "https://example.com/protected?__ts=q-turn&__tt=q-ticket&__ct=1&path=%2Fbound&keep=1",
      {
        headers: {
          "CF-Connecting-IP": "1.2.3.4",
          "x-turnstile": "h-turn",
          "x-ticket": "h-ticket",
          "x-consume": "1",
          Cookie: `a=1; __Secure-pow_a=${encodeAtomicCookie("1|t|c-turn|c-ticket")}`,
        },
      }
    );
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "fetch called with modified request");

    assert.equal(forwarded.headers.get("x-turnstile"), null);
    assert.equal(forwarded.headers.get("x-ticket"), null);
    assert.equal(forwarded.headers.get("x-consume"), null);
    const forwardedUrl = new URL(forwarded.url);
    assert.equal(forwardedUrl.searchParams.get("__ts"), null);
    assert.equal(forwardedUrl.searchParams.get("__tt"), null);
    assert.equal(forwardedUrl.searchParams.get("__ct"), null);
    assert.equal(forwardedUrl.searchParams.get("keep"), "1");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.s.atomic.captchaToken, "c-turn");
    assert.equal(parsed.s.atomic.turnToken, undefined);
    assert.equal(parsed.s.atomic.ticketB64, "c-ticket");
    assert.equal(parsed.s.atomic.consumeToken, "");
    assert.equal(parsed.s.atomic.fromCookie, true);
    assert.ok(parsed.s.bypass && typeof parsed.s.bypass === "object");
    assert.ok(parsed.s.bind && typeof parsed.s.bind === "object");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config skips turnstile preflight when consume integrity precheck fails", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret", {
    configOverrides: {
      powcheck: true,
      turncheck: true,
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: [{ sitekey: "rk1", secret: "rs1" }],
      RECAPTCHA_MIN_SCORE: 0.5,
      ATOMIC_CONSUME: true,
      TURNSTILE_SITEKEY: "turn-site-key",
      TURNSTILE_SECRET: "turn-secret",
    },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  let turnstileCalls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (String(request.url) === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        turnstileCalls += 1;
        return new Response(JSON.stringify({ success: true, cdata: "mac" }), { status: 200 });
      }
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const ticketB64 = base64Url(Buffer.from("1.1700000000.32.r.1.mac", "utf8"));
    const envelope = JSON.stringify({
      turnstile: "atomic-turn-token-1234567890",
      recaptcha_v3: "atomic-recaptcha-token-1234567890",
    });
    const req = new Request(
      `https://example.com/protected?__ts=${encodeURIComponent(envelope)}&__tt=${ticketB64}&__ct=not-a-valid-v2-consume`,
      {
        headers: {
          "CF-Connecting-IP": "1.2.3.4",
        },
      }
    );
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "request still forwards");
    assert.equal(turnstileCalls, 0, "consume precheck failure should skip turnstile preflight");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.s.atomic.turnstilePreflight?.checked, true);
    assert.equal(parsed.s.atomic.turnstilePreflight?.ok, false);
    assert.equal(parsed.s.atomic.turnstilePreflight?.reason, "consume_invalid");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config records turnstile preflight evidence for atomic dual-provider ticket flow", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret", {
    configOverrides: {
      powcheck: false,
      turncheck: true,
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: [{ sitekey: "rk1", secret: "rs1" }],
      RECAPTCHA_MIN_SCORE: 0.5,
      ATOMIC_CONSUME: true,
      TURNSTILE_SITEKEY: "turn-site-key",
      TURNSTILE_SECRET: "turn-secret",
    },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  let turnstileCalls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (String(request.url) === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        turnstileCalls += 1;
        return new Response(JSON.stringify({ success: true, cdata: ticket.mac }), { status: 200 });
      }
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const now = Math.floor(Date.now() / 1000);
    const ticket = {
      v: 1,
      e: now + 600,
      L: 32,
      r: base64Url(Buffer.from("ticket-random", "utf8")),
      cfgId: 0,
      mac: "",
    };
    const pathHash = base64Url(crypto.createHash("sha256").update("/protected").digest());
    const binding = makePowBindingString(
      ticket,
      "example.com",
      pathHash,
      "1.2.3.4/32",
      "any",
      "any",
      "any"
    );
    ticket.mac = hmacSha256Base64Url("pow-secret", binding);
    const ticketB64 = base64Url(
      Buffer.from(`${ticket.v}.${ticket.e}.${ticket.L}.${ticket.r}.${ticket.cfgId}.${ticket.mac}`, "utf8")
    );

    const turnToken = "atomic-turn-token-1234567890";
    const envelope = JSON.stringify({
      turnstile: turnToken,
      recaptcha_v3: "atomic-recaptcha-token-1234567890",
    });

    const req = new Request(
      `https://example.com/protected?__ts=${encodeURIComponent(envelope)}&__tt=${ticketB64}`,
      {
        headers: {
          "CF-Connecting-IP": "1.2.3.4",
        },
      }
    );
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "request forwards after successful preflight");
    assert.equal(turnstileCalls, 1, "preflight should call turnstile siteverify once");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.s.atomic.turnstilePreflight?.checked, true);
    assert.equal(parsed.s.atomic.turnstilePreflight?.ok, true);
    assert.equal(parsed.s.atomic.turnstilePreflight?.reason, "");
    assert.equal(parsed.s.atomic.turnstilePreflight?.ticketMac, ticket.mac);
    assert.equal(
      parsed.s.atomic.turnstilePreflight?.tokenTag,
      captchaTagV1(turnToken, "atomic-recaptcha-token-1234567890")
    );
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config skips turnstile preflight when bind strategy is invalid", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule("config-secret", {
    configOverrides: {
      powcheck: false,
      turncheck: true,
      recaptchaEnabled: true,
      RECAPTCHA_PAIRS: [{ sitekey: "rk1", secret: "rs1" }],
      RECAPTCHA_MIN_SCORE: 0.5,
      ATOMIC_CONSUME: true,
      TURNSTILE_SITEKEY: "turn-site-key",
      TURNSTILE_SECRET: "turn-secret",
      bindPathMode: "query",
      bindPathQueryName: "path",
    },
  });
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  let turnstileCalls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (String(request.url) === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
        turnstileCalls += 1;
        return new Response(JSON.stringify({ success: true, cdata: "unused" }), { status: 200 });
      }
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const envelope = JSON.stringify({
      turnstile: "atomic-turn-token-1234567890",
      recaptcha_v3: "atomic-recaptcha-token-1234567890",
    });
    const req = new Request(
      `https://example.com/protected?__ts=${encodeURIComponent(envelope)}&__tt=${"a".repeat(128)}`,
      {
        headers: {
          "CF-Connecting-IP": "1.2.3.4",
        },
      }
    );
    const res = await handler(req);
    assert.equal(res.status, 200);
    assert.ok(forwarded, "request still forwards with invalid bind strategy");
    assert.equal(turnstileCalls, 0, "bind invalid should skip preflight call");

    const { payload } = readInnerPayload(forwarded.headers);
    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.s.bind.ok, false);
    assert.equal(parsed.s.atomic.turnstilePreflight?.checked, false);
    assert.equal(parsed.s.atomic.turnstilePreflight?.ok, false);
    assert.equal(parsed.s.atomic.turnstilePreflight?.reason, "not_applicable");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
