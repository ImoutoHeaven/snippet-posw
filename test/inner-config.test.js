import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
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

test("inner header signature helper matches node crypto", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const modulePath = await buildTestModule();
    const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
    const hmac = mod.hmacSha256Base64UrlNoPad;

    assert.equal(typeof hmac, "function");

    const payload = base64Url(Buffer.from("{\"v\":1}", "utf8"));
    const secret = "config-secret";
    const expected = base64Url(
      crypto.createHmac("sha256", secret).update(payload).digest()
    );
    const actual = await hmac(secret, payload);

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
    assert.ok(payload.length > 0, "payload header set");
    assert.ok(mac.length > 0, "mac header set");
    assert.notEqual(payload, "spoofed");
    assert.notEqual(mac, "spoofed");

    const decoded = base64UrlDecode(payload);
    assert.ok(decoded, "payload decodes");
    const parsed = JSON.parse(decoded);
    assert.equal(parsed.v, 1);
    assert.equal(parsed.id, 0);

    const expectedMac = base64Url(
      crypto.createHmac("sha256", "config-secret").update(payload).digest()
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
    assert.ok(countHeader, "chunk count header set");
    assert.equal(forwarded.headers.get("X-Pow-Inner"), null);

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

    const expectedMac = base64Url(
      crypto.createHmac("sha256", "config-secret").update(payload).digest()
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
