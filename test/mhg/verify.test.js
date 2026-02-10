import test from "node:test";
import assert from "node:assert/strict";
import { parentsOf } from "../../lib/mhg/graph.js";
import { makeGenesisPage, mixPage } from "../../lib/mhg/mix-aes.js";
import { buildMerkle, buildProof } from "../../lib/mhg/merkle.js";

const b64u = (bytes) =>
  Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const makeOpenVector = async ({ omit = [] } = {}) => {
  const graphSeed = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
  const nonce = Uint8Array.from({ length: 16 }, (_, i) => 16 - i);
  const pageBytes = 64;

  const p0 = await makeGenesisPage({ graphSeed, nonce, pageBytes });
  const p1 = await mixPage({ i: 1, p0, p1: p0, p2: p0, graphSeed, nonce, pageBytes });
  const p2 = await mixPage({ i: 2, p0: p1, p1: p0, p2: p0, graphSeed, nonce, pageBytes });
  const pages = [p0, p1, p2];
  const tree = await buildMerkle(pages);
  const need = new Set([2]);
  const e = [2];
  for (const j of e) {
    const p = await parentsOf(j, graphSeed);
    need.add(p.p0);
    need.add(p.p1);
    need.add(p.p2);
  }
  const nodes = {};
  for (const idx of need) {
    if (omit.includes(idx)) continue;
    nodes[String(idx)] = {
      pageB64: b64u(pages[idx]),
      proof: buildProof(tree, idx).map((x) => b64u(x)),
    };
  }

  return {
    root: tree.root,
    leafCount: tree.leafCount,
    graphSeed,
    nonce,
    pageBytes,
    opens: [{ i: 2, seg: 1, nodes }],
  };
};

test("segmentLen=2 verifies equation closure", async () => {
  const { verifyBatch } = await import("../../lib/mhg/verify.js");
  const out = await verifyBatch({ fixture: "valid-seg2" });
  assert.equal(out.ok, true);
});

test("segmentLen=1 still verifies predecessor relation", async () => {
  const { verifyBatch } = await import("../../lib/mhg/verify.js");
  const ok = await verifyBatch({ fixture: "valid-seg1-predecessor" });
  assert.equal(ok.ok, true);

  const bad = await verifyBatch({ fixture: "tampered-seg1-current-only" });
  assert.equal(bad.ok, false);
  assert.equal(bad.reason, "equation_failed");
});

test("segmentLen normalizes by floor+clamp", async () => {
  const { verifyBatch } = await import("../../lib/mhg/verify.js");
  const out = await verifyBatch({ fixture: "valid-seg2", segmentLen: 0.6 });
  assert.equal(out.ok, true);
});

test("open entry must include closure nodes for segment", async () => {
  const { verifyOpenBatchVector } = await import("../../lib/mhg/verify.js");
  const out = await verifyOpenBatchVector(await makeOpenVector({ omit: [1] }));
  assert.equal(out.ok, false);
  assert.equal(out.reason, "missing_witness");
});

test("seg=1 still verifies predecessor relation", async () => {
  const { verifyOpenBatchVector } = await import("../../lib/mhg/verify.js");
  const out = await verifyOpenBatchVector(await makeOpenVector());
  assert.equal(out.ok, true);
});
