import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));

const base64Url = (value) =>
  Buffer.from(String(value), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const makeModuleUrl = (workerUrl) =>
  `data:text/javascript,${encodeURIComponent(`export const workerUrl = "${workerUrl}";`)}`;

const encodeCaptchaCfg = (cfg) =>
  base64Url(typeof cfg === "string" ? cfg : JSON.stringify(cfg || {}));

const setupDom = ({ onScriptAppend } = {}) => {
  const makeEl = (tag = "div") => ({
    tagName: tag,
    style: { setProperty() {} },
    classList: { add() {}, remove() {}, contains() { return false; } },
    appendChild(child) {
      if (typeof onScriptAppend === "function" && tag === "head") {
        onScriptAppend(child);
      }
    },
    addEventListener() {},
    remove() {},
    innerHTML: "",
    textContent: "",
  });
  const store = new Map();
  const getEl = (id) => {
    if (!store.has(id)) store.set(id, makeEl());
    return store.get(id);
  };

  const head = makeEl("head");
  head.appendChild = (child) => {
    if (typeof onScriptAppend === "function") onScriptAppend(child);
  };

  globalThis.document = {
    title: "",
    head,
    documentElement: makeEl("html"),
    body: makeEl("body"),
    createElement: (tag) => makeEl(tag),
    getElementById: (id) => getEl(id),
    querySelectorAll: () => [],
    addEventListener() {},
  };
  globalThis.window = {
    location: { href: "https://example.com/", replace() {}, reload() {} },
    parent: null,
    opener: null,
    innerWidth: 1200,
    innerHeight: 800,
  };
  const sessionStore = new Map();
  globalThis.window.sessionStorage = {
    getItem(key) {
      return sessionStore.has(key) ? sessionStore.get(key) : null;
    },
    setItem(key, value) {
      sessionStore.set(String(key), String(value));
    },
    removeItem(key) {
      sessionStore.delete(String(key));
    },
    clear() {
      sessionStore.clear();
    },
  };
  globalThis.window.parent = globalThis.window;
  Object.defineProperty(globalThis, "navigator", {
    value: { languages: ["en-US"], language: "en-US" },
    configurable: true,
  });
  globalThis.requestAnimationFrame = () => 0;
  globalThis.setTimeout = (fn) => {
    if (typeof fn === "function") fn();
    return 0;
  };
  globalThis.clearTimeout = () => {};
  globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
  globalThis.btoa = (str) => Buffer.from(str, "binary").toString("base64");
  if (!globalThis.crypto) {
    Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
  }
  if (!globalThis.URL.createObjectURL) {
    globalThis.URL.createObjectURL = () => "blob:mock";
  }
  if (!globalThis.URL.revokeObjectURL) {
    globalThis.URL.revokeObjectURL = () => {};
  }
};

const importGlue = async (domOptions) => {
  setupDom(domOptions);
  const glueUrl = `${pathToFileURL(join(repoRoot, "glue.js")).href}?v=${Date.now()}-${Math.random()}`;
  return await import(glueUrl);
};

const makeRunPowArgs = (overrides = {}) => {
  const workerUrl = overrides.workerUrl || "https://example.com/worker.js";
  const moduleUrl = overrides.moduleUrl || makeModuleUrl(workerUrl);
  const params = {
    bindingB64: base64Url("binding"),
    steps: 1,
    ticketB64: base64Url("a.b.c.d.e.f"),
    pathHash: "pathhash",
    hashcashBits: 1,
    segmentLen: 1,
    reloadUrlB64: base64Url("https://example.com/"),
    apiPrefixB64: base64Url("/__pow"),
    esmUrlB64: base64Url(moduleUrl),
    captchaCfgB64: encodeCaptchaCfg({}),
    atomicCfg: "0",
  };
  Object.assign(params, overrides);
  if (!params.esmUrlB64) params.esmUrlB64 = base64Url(moduleUrl);
  return [
    params.bindingB64,
    params.steps,
    params.ticketB64,
    params.pathHash,
    params.hashcashBits,
    params.segmentLen,
    params.reloadUrlB64,
    params.apiPrefixB64,
    params.esmUrlB64,
    params.captchaCfgB64,
    params.atomicCfg,
  ];
};

test("glue hardening", { concurrency: 1 }, async (t) => {
  await t.test("worker init failure terminates worker", async () => {
    const createdWorkers = [];
    const glue = await importGlue();
    globalThis.fetch = async () => ({
      text: async () => "self.onmessage = () => {};",
    });
    globalThis.Worker = class FakeWorker {
      constructor() {
        this.listeners = new Map();
        this.terminated = false;
        createdWorkers.push(this);
      }
      addEventListener(type, cb) {
        const list = this.listeners.get(type) || [];
        list.push(cb);
        this.listeners.set(type, list);
      }
      postMessage(msg) {
        if (msg && msg.type === "INIT") {
          const event = { data: { type: "ERROR", rid: msg.rid, message: "init failed" } };
          const list = this.listeners.get("message") || [];
          for (const cb of list) cb(event);
        }
      }
      terminate() {
        this.terminated = true;
      }
    };
    const args = makeRunPowArgs();
    await glue.default(...args);
    assert.equal(createdWorkers.length, 1);
    assert.equal(createdWorkers[0].terminated, true);
  });

  await t.test("turnstile load failure allows retry", async () => {
    let scriptCount = 0;
    const glue = await importGlue({
      onScriptAppend: (el) => {
        if (el && el.tagName === "script") {
          scriptCount += 1;
          if (typeof el.onerror === "function") {
            queueMicrotask(() => el.onerror());
          }
        }
      },
    });
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({ turnstile: { sitekey: "sitekey" } }),
      atomicCfg: "1",
    });
    await glue.default(...args);
    await glue.default(...args);
    assert.equal(scriptCount, 2);
  });

  await t.test("recaptcha execute failure allows retry", async () => {
    const executed = [];
    let scriptCount = 0;
    let scriptSrc = "";
    const glue = await importGlue({
      onScriptAppend: (el) => {
        if (el && el.tagName === "script") {
          scriptCount += 1;
          scriptSrc = String(el.src || "");
          queueMicrotask(() => {
            globalThis.window.grecaptcha = {
              ready(cb) {
                cb();
              },
              execute: async (_sitekey, { action }) => {
                executed.push(action);
                if (executed.length === 1) throw new Error("boom");
                return "recaptcha-token-2";
              },
            };
            if (typeof el.onload === "function") el.onload();
          });
        }
      },
    });
    const calls = [];
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), body: init && init.body ? JSON.parse(init.body) : null });
      return { ok: true, status: 200, json: async () => ({}) };
    };
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({
        recaptcha_v3: { sitekey: "rk-1", action: "p_deadbeef00" },
      }),
    });
    await glue.default(...args);
    assert.equal(scriptCount, 1);
    assert.equal(scriptSrc, "https://recaptcha.net/recaptcha/api.js?render=rk-1");
    assert.equal(executed.length, 2);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "/__pow/cap");
    assert.deepEqual(JSON.parse(calls[0].body.captchaToken), { recaptcha_v3: "recaptcha-token-2" });
  });

  await t.test("recaptcha waits for execute to appear after ready", async () => {
    const calls = [];
    const glue = await importGlue({
      onScriptAppend: (el) => {
        if (el && el.tagName === "script") {
          queueMicrotask(() => {
            globalThis.window.grecaptcha = {
              ready(cb) {
                queueMicrotask(() => {
                  globalThis.window.grecaptcha.execute = async () => "recaptcha-token-late";
                  cb();
                });
              },
            };
            if (typeof el.onload === "function") el.onload();
          });
        }
      },
    });
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), body: init && init.body ? JSON.parse(init.body) : null });
      return { ok: true, status: 200, json: async () => ({}) };
    };
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({
        recaptcha_v3: { sitekey: "rk-late", action: "p_late" },
      }),
    });
    await glue.default(...args);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "/__pow/cap");
    assert.deepEqual(JSON.parse(calls[0].body.captchaToken), {
      recaptcha_v3: "recaptcha-token-late",
    });
  });

  await t.test("runCaptcha runs turn+recaptcha concurrently and keeps envelope shape", async () => {
    const fetchCalls = [];
    let solveTurnstile;
    let recaptchaStarted = false;
    const glue = await importGlue();
    globalThis.window.turnstile = {
      render: (_el, opts) => {
        solveTurnstile = opts.callback;
        return 1;
      },
      reset() {},
      remove() {},
    };
    globalThis.window.grecaptcha = {
      ready(cb) {
        cb();
      },
      execute: async (_sitekey, { action }) => {
        recaptchaStarted = true;
        assert.equal(action, "p_abc123");
        return "recaptcha-token";
      },
    };
    globalThis.fetch = async (url, init) => {
      fetchCalls.push({ url: String(url), body: init && init.body ? JSON.parse(init.body) : null });
      return { ok: true, status: 200, json: async () => ({}) };
    };
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({
        turnstile: { sitekey: "ts-1" },
        recaptcha_v3: { sitekey: "rk-1", action: "p_abc123" },
      }),
    });
    const runPromise = glue.default(...args);
    await new Promise((resolve) => queueMicrotask(resolve));
    assert.equal(recaptchaStarted, true);
    assert.equal(fetchCalls.length, 0);
    assert.equal(typeof solveTurnstile, "function");
    solveTurnstile("turn-token");
    await runPromise;
    assert.equal(fetchCalls.length, 1);
    assert.equal(fetchCalls[0].url, "/__pow/cap");
    assert.deepEqual(JSON.parse(fetchCalls[0].body.captchaToken), {
      turnstile: "turn-token",
      recaptcha_v3: "recaptcha-token",
    });
  });

  await t.test("403 stale hint triggers reload path", async () => {
    let reloadCount = 0;
    let attempts = 0;
    const headers = new Map([["x-pow-h", "stale"]]);
    const glue = await importGlue();
    globalThis.window.location.reload = () => {
      reloadCount += 1;
    };
    globalThis.window.turnstile = {
      render: (_el, opts) => {
        queueMicrotask(() => opts.callback("turn-token"));
        return 1;
      },
      reset() {},
      remove() {},
    };
    globalThis.fetch = async () => {
      attempts += 1;
      return {
        ok: false,
        status: 403,
        headers: { get: (name) => headers.get(String(name).toLowerCase()) || null },
        json: async () => ({}),
      };
    };
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({ turnstile: { sitekey: "ts-1" } }),
    });
    await glue.default(...args);
    assert.equal(reloadCount, 1);
    assert.equal(attempts, 1);
  });

  await t.test("stale reload debounce caps retries and then fails", async () => {
    let reloadCount = 0;
    let attempts = 0;
    const headers = new Map([["x-pow-h", "stale"]]);
    const glue = await importGlue();
    globalThis.window.location.reload = () => {
      reloadCount += 1;
    };
    globalThis.window.turnstile = {
      render: (_el, opts) => {
        queueMicrotask(() => opts.callback("turn-token"));
        return 1;
      },
      reset() {},
      remove() {},
    };
    globalThis.fetch = async () => {
      attempts += 1;
      return {
        ok: false,
        status: 403,
        headers: { get: (name) => headers.get(String(name).toLowerCase()) || null },
        json: async () => ({}),
      };
    };
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({ turnstile: { sitekey: "ts-1" } }),
    });

    await glue.default(...args);
    await glue.default(...args);
    await glue.default(...args);

    assert.equal(attempts, 3);
    assert.equal(reloadCount, 2);
    assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
  });

  await t.test("stale 403 fails gracefully when sessionStorage is unavailable", async () => {
    let reloadCount = 0;
    const headers = new Map([["x-pow-h", "stale"]]);
    const glue = await importGlue();
    globalThis.window.location.reload = () => {
      reloadCount += 1;
    };
    globalThis.window.sessionStorage = undefined;
    globalThis.window.turnstile = {
      render: (_el, opts) => {
        queueMicrotask(() => opts.callback("turn-token"));
        return 1;
      },
      reset() {},
      remove() {},
    };
    globalThis.fetch = async () => ({
      ok: false,
      status: 403,
      headers: { get: (name) => headers.get(String(name).toLowerCase()) || null },
      json: async () => ({}),
    });
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({ turnstile: { sitekey: "ts-1" } }),
    });

    await glue.default(...args);

    assert.equal(reloadCount, 0);
    assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
  });

  await t.test("stale 403 fails gracefully when sessionStorage.setItem throws", async () => {
    let reloadCount = 0;
    const headers = new Map([["x-pow-h", "stale"]]);
    const glue = await importGlue();
    globalThis.window.location.reload = () => {
      reloadCount += 1;
    };
    globalThis.window.sessionStorage = {
      getItem() {
        return null;
      },
      setItem() {
        throw new Error("quota");
      },
      removeItem() {},
      clear() {},
    };
    globalThis.window.turnstile = {
      render: (_el, opts) => {
        queueMicrotask(() => opts.callback("turn-token"));
        return 1;
      },
      reset() {},
      remove() {},
    };
    globalThis.fetch = async () => ({
      ok: false,
      status: 403,
      headers: { get: (name) => headers.get(String(name).toLowerCase()) || null },
      json: async () => ({}),
    });
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({ turnstile: { sitekey: "ts-1" } }),
    });

    await glue.default(...args);

    assert.equal(reloadCount, 0);
    assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
  });

  await t.test("stale reload handles malformed sessionStorage payload without crash", async () => {
    let reloadCount = 0;
    const headers = new Map([["x-pow-h", "stale"]]);
    const glue = await importGlue();
    globalThis.window.location.reload = () => {
      reloadCount += 1;
    };
    globalThis.window.sessionStorage.setItem("__pow_stale_reload_v1", "{bad-json");
    globalThis.window.turnstile = {
      render: (_el, opts) => {
        queueMicrotask(() => opts.callback("turn-token"));
        return 1;
      },
      reset() {},
      remove() {},
    };
    globalThis.fetch = async () => ({
      ok: false,
      status: 403,
      headers: { get: (name) => headers.get(String(name).toLowerCase()) || null },
      json: async () => ({}),
    });
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({ turnstile: { sitekey: "ts-1" } }),
    });

    await glue.default(...args);
    await glue.default(...args);
    await glue.default(...args);

    assert.equal(reloadCount, 2);
    assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
  });

  await t.test("403 cheat hint hard-fails without reload", async () => {
    let reloadCount = 0;
    let attempts = 0;
    const headers = new Map([["x-pow-h", "cheat"]]);
    const glue = await importGlue();
    globalThis.window.location.reload = () => {
      reloadCount += 1;
    };
    globalThis.window.turnstile = {
      render: (_el, opts) => {
        queueMicrotask(() => opts.callback("turn-token"));
        return 1;
      },
      reset() {},
      remove() {},
    };
    globalThis.fetch = async () => {
      attempts += 1;
      return {
        ok: false,
        status: 403,
        headers: { get: (name) => headers.get(String(name).toLowerCase()) || null },
        json: async () => ({}),
      };
    };
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({ turnstile: { sitekey: "ts-1" } }),
    });
    await glue.default(...args);
    assert.equal(reloadCount, 0);
    assert.equal(attempts, 1);
    assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
  });

  await t.test("500 response does not retry", async () => {
    let attempts = 0;
    const glue = await importGlue();
    globalThis.window.turnstile = {
      render: (_el, opts) => {
        queueMicrotask(() => opts.callback("turn-token"));
        return 1;
      },
      reset() {},
      remove() {},
    };
    globalThis.fetch = async () => {
      attempts += 1;
      return {
        ok: false,
        status: 500,
        headers: { get: () => null },
        json: async () => ({}),
      };
    };
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({ turnstile: { sitekey: "ts-1" } }),
    });
    await glue.default(...args);
    assert.equal(attempts, 1);
    assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
  });

  await t.test("turnstile submit 403 does not loop submit callback", async () => {
    const calls = [];
    const headers = new Map([["x-pow-h", "cheat"]]);
    const glue = await importGlue();
    globalThis.window.turnstile = {
      render: (_el, opts) => {
        queueMicrotask(() => opts.callback("turn-token"));
        return 1;
      },
      reset() {},
      remove() {},
    };
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), body: init && init.body ? JSON.parse(init.body) : null });
      return {
        ok: false,
        status: 403,
        headers: { get: (name) => headers.get(String(name).toLowerCase()) || null },
        json: async () => ({}),
      };
    };
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({ turnstile: { sitekey: "ts-1" } }),
    });
    await glue.default(...args);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "/__pow/cap");
    assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
  });

  await t.test("recaptcha submit 403 does not loop submit callback", async () => {
    const calls = [];
    const headers = new Map([["x-pow-h", "cheat"]]);
    const glue = await importGlue();
    globalThis.window.grecaptcha = {
      ready(cb) {
        cb();
      },
      execute: async () => "recaptcha-token",
    };
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), body: init && init.body ? JSON.parse(init.body) : null });
      return {
        ok: false,
        status: 403,
        headers: { get: (name) => headers.get(String(name).toLowerCase()) || null },
        json: async () => ({}),
      };
    };
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({
        recaptcha_v3: { sitekey: "rk-1", action: "p_deadbeef00" },
      }),
    });
    await glue.default(...args);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "/__pow/cap");
    assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
  });

  await t.test("network transport failure retries and succeeds", async () => {
    let attempts = 0;
    const glue = await importGlue();
    globalThis.window.turnstile = {
      render: (_el, opts) => {
        queueMicrotask(() => opts.callback("turn-token"));
        return 1;
      },
      reset() {},
      remove() {},
    };
    globalThis.fetch = async () => {
      attempts += 1;
      if (attempts < 3) {
        throw new Error("connection reset");
      }
      return { ok: true, status: 200, json: async () => ({}) };
    };
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({ turnstile: { sitekey: "ts-1" } }),
    });
    await glue.default(...args);
    assert.equal(attempts, 3);
  });

  await t.test("error messages are escaped in logs", async () => {
    const glue = await importGlue();
    globalThis.fetch = async () => {
      throw new Error('<img src="x" onerror="alert(1)">');
    };
    const args = makeRunPowArgs();
    await glue.default(...args);
    const logEl = globalThis.document.getElementById("log");
    assert.ok(logEl.innerHTML.includes("&lt;img"));
    assert.equal(logEl.innerHTML.includes("<img"), false);
  });

  await t.test("atomic postMessage only targets same-origin parent/opener", async () => {
    const calls = [];
    const glue = await importGlue();
    globalThis.window.location.href = "https://example.com/challenge";
    globalThis.window.opener = {
      closed: false,
      location: { href: "https://evil.test/" },
      postMessage: (msg, origin) => calls.push({ msg, origin, target: "opener" }),
    };
    globalThis.window.parent = {
      closed: false,
      location: { href: "https://example.com/outer" },
      postMessage: (msg, origin) => calls.push({ msg, origin, target: "parent" }),
    };
    globalThis.window.turnstile = {
      render: (el, opts) => {
        queueMicrotask(() => opts.callback("turn-token"));
        return 1;
      },
      reset() {},
      remove() {},
    };
    const args = makeRunPowArgs({
      steps: 0,
      captchaCfgB64: encodeCaptchaCfg({ turnstile: { sitekey: "sitekey" } }),
      atomicCfg: "1",
    });
    await glue.default(...args);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].target, "parent");
    assert.equal(calls[0].origin, "https://example.com");
  });
});
