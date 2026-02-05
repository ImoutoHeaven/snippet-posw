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
    turnSiteKeyB64: base64Url(""),
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
    params.turnSiteKeyB64,
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
      turnSiteKeyB64: base64Url("sitekey"),
      atomicCfg: "1",
    });
    await glue.default(...args);
    await glue.default(...args);
    assert.equal(scriptCount, 2);
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
      turnSiteKeyB64: base64Url("sitekey"),
      atomicCfg: "1",
    });
    await glue.default(...args);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].target, "parent");
    assert.equal(calls[0].origin, "https://example.com");
  });
});
