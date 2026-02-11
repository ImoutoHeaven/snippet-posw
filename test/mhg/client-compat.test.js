import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

const b64u = (value) =>
  Buffer.from(String(value), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const makeModuleUrl = (workerUrl) =>
  `data:text/javascript,${encodeURIComponent(`export const workerUrl = "${workerUrl}";`)}`;

const setupDom = () => {
  const makeEl = (tag = "div") => ({
    tagName: tag,
    style: { setProperty() {} },
    classList: { add() {}, remove() {}, contains() { return false; } },
    appendChild() {},
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

  globalThis.document = {
    title: "",
    head: makeEl("head"),
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
  globalThis.window.sessionStorage = {
    getItem() {
      return null;
    },
    setItem() {},
    removeItem() {},
    clear() {},
  };

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
  globalThis.setInterval = (fn) => {
    if (typeof fn === "function") fn();
    return 0;
  };
  globalThis.clearInterval = () => {};
  globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
  globalThis.btoa = (str) => Buffer.from(str, "binary").toString("base64");
  if (!globalThis.crypto) {
    Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
  }
  if (!globalThis.URL.createObjectURL) globalThis.URL.createObjectURL = () => "blob:mock";
  if (!globalThis.URL.revokeObjectURL) globalThis.URL.revokeObjectURL = () => {};
};

const importGlue = async () => {
  setupDom();
  const glueUrl = `${pathToFileURL(join(repoRoot, "glue.js")).href}?v=${Date.now()}-${Math.random()}`;
  return await import(glueUrl);
};

test("client still performs commit->challenge->open loop", async () => {
  const sequence = [];
  const openBodies = [];
  const initPayloads = [];
  const glue = await importGlue();

  globalThis.Worker = class FakeWorker {
    constructor() {
      this.listeners = new Map();
    }
    addEventListener(type, cb) {
      const list = this.listeners.get(type) || [];
      list.push(cb);
      this.listeners.set(type, list);
    }
    postMessage(msg) {
      const emit = (data) => {
        const list = this.listeners.get("message") || [];
        for (const cb of list) cb({ data });
      };
      if (msg.type === "INIT") {
        initPayloads.push(msg);
        emit({ type: "INIT_OK", rid: msg.rid });
      }
      if (msg.type === "COMMIT") emit({ type: "COMMIT_OK", rid: msg.rid, rootB64: "AA", nonce: "nonce" });
      if (msg.type === "OPEN") {
        if (!Array.isArray(msg.segs) || msg.segs.length !== (msg.indices || []).length) {
          emit({ type: "ERROR", rid: msg.rid, message: "missing segs" });
          return;
        }
        const opens = (msg.indices || []).map((i, k) => ({
          i,
          seg: msg.segs[k],
          nodes: {
            "0": { pageB64: "AA", proof: [] },
            [String(i)]: { pageB64: "AA", proof: [] },
          },
        }));
        emit({ type: "OPEN_OK", rid: msg.rid, opens });
      }
      if (msg.type === "CANCEL") emit({ type: "CANCEL_OK", rid: msg.rid });
      if (msg.type === "DISPOSE") emit({ type: "DISPOSE_OK", rid: msg.rid });
    }
    terminate() {}
  };

  const challenge1 = {
    done: false,
    sid: "s1",
    cursor: 0,
    token: "tok-a",
    indices: [1],
    segs: [2],
  };
  const challenge2 = {
    done: false,
    sid: "s1",
    cursor: 1,
    token: "tok-b",
    indices: [2],
    segs: [2],
  };

  globalThis.fetch = async (url, init) => {
    const endpoint = String(url);
    if (endpoint.endsWith("/worker.js")) {
      return { ok: true, status: 200, text: async () => "self.onmessage = () => {};" };
    }
    if (endpoint.endsWith("/commit")) {
      sequence.push("commit");
      return { ok: true, status: 200, json: async () => ({}) };
    }
    if (endpoint.endsWith("/challenge")) {
      sequence.push("challenge");
      return { ok: true, status: 200, json: async () => challenge1 };
    }
    if (endpoint.endsWith("/open")) {
      sequence.push("open");
      openBodies.push(JSON.parse(init.body));
      if (openBodies.length === 1) return { ok: true, status: 200, json: async () => challenge2 };
      return { ok: true, status: 200, json: async () => ({ done: true }) };
    }
    throw new Error(`unexpected fetch: ${endpoint}`);
  };

  const args = [
    b64u("binding"),
    2,
    b64u("1.2.3.4.5.6"),
    "pathhash",
    0,
    2,
    b64u("https://example.com/ok"),
    b64u("/__pow"),
    b64u(makeModuleUrl("https://example.com/worker.js")),
    b64u("{}"),
    "0",
  ];

  await glue.default(...args);
  assert.equal(sequence.join(","), "commit,challenge,open,open");
  assert.equal(initPayloads.length > 0, true);
  assert.equal(initPayloads[0].ticketB64, b64u("1.2.3.4.5.6"));
  assert.equal(Object.hasOwn(openBodies[0], "spinePos"), false);
  assert.equal(Object.hasOwn(openBodies[1], "spinePos"), false);
  assert.equal(openBodies[0].opens[0].seg, 2);
  assert.equal(typeof openBodies[0].opens[0].nodes, "object");
  assert.equal(Object.hasOwn(openBodies[0].opens[0], "page"), false);
});

test("client keeps screening log visible when worker only reports hashcash", async () => {
  const glue = await importGlue();

  globalThis.Worker = class FakeWorker {
    constructor() {
      this.listeners = new Map();
    }
    addEventListener(type, cb) {
      const list = this.listeners.get(type) || [];
      list.push(cb);
      this.listeners.set(type, list);
    }
    postMessage(msg) {
      const emit = (data) => {
        const list = this.listeners.get("message") || [];
        for (const cb of list) cb({ data });
      };
      if (msg.type === "INIT") emit({ type: "INIT_OK", rid: msg.rid });
      if (msg.type === "COMMIT") {
        emit({ type: "PROGRESS", phase: "hashcash", attempt: 1 });
        emit({ type: "COMMIT_OK", rid: msg.rid, rootB64: "AA", nonce: "nonce" });
      }
      if (msg.type === "CANCEL") emit({ type: "CANCEL_OK", rid: msg.rid });
      if (msg.type === "DISPOSE") emit({ type: "DISPOSE_OK", rid: msg.rid });
    }
    terminate() {}
  };

  globalThis.fetch = async (url) => {
    const endpoint = String(url);
    if (endpoint.endsWith("/worker.js")) {
      return { ok: true, status: 200, text: async () => "self.onmessage = () => {};" };
    }
    if (endpoint.endsWith("/__pow/commit")) {
      return {
        ok: false,
        status: 500,
        headers: { get: () => null },
        json: async () => ({}),
      };
    }
    throw new Error(`unexpected fetch: ${endpoint}`);
  };

  const args = [
    b64u("binding"),
    2,
    b64u("1.2.3.4.5.6"),
    "pathhash",
    3,
    2,
    b64u("https://example.com/ok"),
    b64u("/__pow"),
    b64u(makeModuleUrl("https://example.com/worker.js")),
    b64u("{}"),
    "0",
  ];

  await glue.default(...args);
  const logHtml = globalThis.document.getElementById("log").innerHTML;
  assert.equal(logHtml.includes("Screening hash"), true);
});
