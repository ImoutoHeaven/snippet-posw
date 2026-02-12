import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

import { verifyOpenBatchVector } from "../../lib/mhg/verify.js";
import { mixPage } from "../../lib/mhg/mix-aes.js";
import { parentsOf } from "../../lib/mhg/graph.js";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const encoder = new TextEncoder();

const b64uToBytes = (value) => {
  let b64 = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return Uint8Array.from(Buffer.from(b64, "base64"));
};

const digest = async (...chunks) => {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return new Uint8Array(await webcrypto.subtle.digest("SHA-256", out));
};

const deriveGraphSeed16 = async (ticketB64, nonceString) => {
  const d = await digest(
    encoder.encode("mhg|graph|v2|"),
    encoder.encode(ticketB64),
    encoder.encode("|"),
    encoder.encode(nonceString),
  );
  return d.slice(0, 16);
};

const deriveNonce16 = async (nonceString) => {
  const raw = b64uToBytes(nonceString);
  if (raw.length >= 16) return raw.slice(0, 16);
  return (await digest(raw)).slice(0, 16);
};

const runWorkerFlow = async ({ ticketB64, steps, indices, segs }) => {
  const prevSelf = globalThis.self;
  const prevPostMessage = globalThis.postMessage;
  const prevAtob = globalThis.atob;
  const prevBtoa = globalThis.btoa;
  const prevCrypto = globalThis.crypto;

  if (!globalThis.atob) {
    globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
  }
  if (!globalThis.btoa) {
    globalThis.btoa = (str) => Buffer.from(str, "binary").toString("base64");
  }
  if (!globalThis.crypto) {
    Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
  }

  const pending = new Map();
  let rid = 0;
  const workerSelf = { addEventListener() {} };

  globalThis.self = workerSelf;
  globalThis.postMessage = (msg) => {
    if (msg && msg.type === "PROGRESS") return;
    const entry = pending.get(msg && msg.rid);
    if (!entry) return;
    pending.delete(msg.rid);
    if (msg.type === "ERROR") {
      entry.reject(new Error(msg.message || "worker error"));
      return;
    }
    entry.resolve(msg);
  };

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
    await call("INIT", { ticketB64, steps, hashcashBits: 0 });
    const commit = await call("COMMIT");
    const open = await call("OPEN", { indices, segs });
    return { commit, open };
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
  }
};

test("fixed vectors produce cross-end consistent verification", async () => {
  const ticketB64 = "dGVzdC10aWNrZXQ";
  const steps = 127;
  const indices = [1, 64, 127];
  const segs = [2, 2, 2];
  const { commit, open } = await runWorkerFlow({ ticketB64, steps, indices, segs });
  const graphSeed = await deriveGraphSeed16(ticketB64, commit.nonce);
  const nonce = await deriveNonce16(commit.nonce);
  const fixture = {
    rootB64: commit.rootB64,
    leafCount: steps + 1,
    graphSeed,
    nonce,
    pageBytes: 64,
    opens: open.opens,
  };
  const out = await verifyOpenBatchVector(fixture);
  assert.equal(out.ok, true);
});

test("1-bit tamper is rejected by server verification", async () => {
  const ticketB64 = "dGVzdC10aWNrZXQ";
  const steps = 127;
  const indices = [64];
  const segs = [2];
  const { commit, open } = await runWorkerFlow({ ticketB64, steps, indices, segs });
  const graphSeed = await deriveGraphSeed16(ticketB64, commit.nonce);
  const nonce = await deriveNonce16(commit.nonce);
  nonce[0] ^= 0x01;
  const fixture = {
    rootB64: commit.rootB64,
    leafCount: steps + 1,
    graphSeed,
    nonce,
    pageBytes: 64,
    opens: open.opens,
  };
  const out = await verifyOpenBatchVector(fixture);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "equation_failed");
});

test("server mixPage matches worker bytes for identical inputs", async () => {
  const ticketB64 = "dGVzdC10aWNrZXQ";
  const steps = 32;
  const index = 17;
  const { commit, open } = await runWorkerFlow({ ticketB64, steps, indices: [index], segs: [1] });
  const graphSeed = await deriveGraphSeed16(ticketB64, commit.nonce);
  const nonce = await deriveNonce16(commit.nonce);
  const parent = await parentsOf(index, graphSeed);
  const entry = open.opens[0];

  const readNodePage = (idx) => {
    const node = entry.nodes[String(idx)];
    assert.ok(node, `missing node ${idx} from worker witness`);
    return b64uToBytes(node.pageB64);
  };

  const serverPage = await mixPage({
    i: index,
    p0: readNodePage(parent.p0),
    p1: readNodePage(parent.p1),
    p2: readNodePage(parent.p2),
    graphSeed,
    nonce,
    pageBytes: 64,
    mixRounds: 2,
  });

  assert.deepEqual(serverPage, readNodePage(index));
});
