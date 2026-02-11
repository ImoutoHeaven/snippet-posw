import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const encoder = new TextEncoder();

const digest = async (...chunks) => {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return new Uint8Array(await webcrypto.subtle.digest("SHA-256", out));
};

const runWorkerCommit = async ({
  ticketB64 = "dGVzdC10aWNrZXQ",
  steps = 8,
  hashcashBits = 0,
  progressEvery = 1,
  beforeImport,
} = {}) => {
  const prevSelf = globalThis.self;
  const prevPostMessage = globalThis.postMessage;
  const prevAtob = globalThis.atob;
  const prevBtoa = globalThis.btoa;
  const prevCrypto = globalThis.crypto;
  const prevFactory = globalThis.__MHG_HASH_WASM_FACTORY__;

  if (!globalThis.atob) {
    globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
  }
  if (!globalThis.btoa) {
    globalThis.btoa = (str) => Buffer.from(str, "binary").toString("base64");
  }
  if (!globalThis.crypto) {
    Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
  }

  const progress = [];
  const pending = new Map();
  let rid = 0;
  const workerSelf = { addEventListener() {} };

  globalThis.self = workerSelf;
  globalThis.postMessage = (msg) => {
    if (msg && msg.type === "PROGRESS") {
      progress.push(msg);
      return;
    }
    const entry = pending.get(msg && msg.rid);
    if (!entry) return;
    pending.delete(msg.rid);
    if (msg.type === "ERROR") {
      entry.reject(new Error(msg.message || "worker error"));
      return;
    }
    entry.resolve(msg);
  };

  if (typeof beforeImport === "function") {
    beforeImport();
  }

  const workerUrl = `${pathToFileURL(join(repoRoot, "esm/mhg-worker.js")).href}?v=${Date.now()}-${Math.random()}`;
  await import(workerUrl);
  const onmessage = workerSelf.onmessage;

  const call = (type, payload = {}) =>
    new Promise((resolve, reject) => {
      const id = ++rid;
      pending.set(id, { resolve, reject });
      onmessage({ data: { type, rid: id, ...payload } });
    });

  try {
    await call("INIT", { ticketB64, steps, hashcashBits, progressEvery });
    const commit = await call("COMMIT");
    return { progress, commit };
  } finally {
    globalThis.self = prevSelf;
    globalThis.postMessage = prevPostMessage;
    globalThis.atob = prevAtob;
    globalThis.btoa = prevBtoa;
    if (!prevCrypto) {
      delete globalThis.crypto;
    } else {
      Object.defineProperty(globalThis, "crypto", { value: prevCrypto, configurable: true });
    }
    if (typeof prevFactory === "undefined") {
      delete globalThis.__MHG_HASH_WASM_FACTORY__;
    } else {
      globalThis.__MHG_HASH_WASM_FACTORY__ = prevFactory;
    }
  }
};

test("mhg worker emits chain progress during commit", async () => {
  const { progress } = await runWorkerCommit({
    steps: 8,
    hashcashBits: 0,
    progressEvery: 1,
  });
  assert.equal(
    progress.some((msg) => msg && msg.phase === "chain"),
    true,
  );
});

test("mhg worker uses injected wasm hasher when available", async () => {
  let factoryCalls = 0;
  let digestCalls = 0;

  const makeHasher = () => {
    let chunks = [];
    return {
      init() {
        chunks = [];
      },
      update(input) {
        chunks.push(Buffer.from(input));
      },
      async digest(format = "binary") {
        digestCalls += 1;
        const bytes = await digest(...chunks.map((part) => new Uint8Array(part)));
        if (format === "binary") return bytes;
        return Buffer.from(bytes).toString("hex");
      },
    };
  };

  const { commit } = await runWorkerCommit({
    steps: 4,
    hashcashBits: 0,
    progressEvery: 1,
    beforeImport() {
      globalThis.__MHG_HASH_WASM_FACTORY__ = async () => {
        factoryCalls += 1;
        return makeHasher();
      };
    },
  });

  assert.equal(typeof commit.rootB64, "string");
  assert.equal(commit.rootB64.length > 0, true);
  assert.equal(factoryCalls > 0, true);
  assert.equal(digestCalls > 0, true);
  assert.equal(typeof commit.nonce, "string");
  assert.equal(commit.nonce.length > 0, true);
  assert.equal(encoder.encode(commit.nonce).length > 0, true);
});
