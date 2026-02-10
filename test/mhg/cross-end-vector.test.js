import test from "node:test";
import assert from "node:assert/strict";

import { parentsOf } from "../../lib/mhg/graph.js";
import { createMixContext, makeGenesisPage, mixPage } from "../../lib/mhg/mix-aes.js";
import { buildMerkle, buildProof } from "../../lib/mhg/merkle.js";
import { verifyOpenBatchVector } from "../../lib/mhg/verify.js";

const b64u = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

const buildFixture = async (vec, options = {}) => {
  const graphSeed = Uint8Array.from(Buffer.from(vec.graphSeedHex, "hex"));
  const nonce = Uint8Array.from(Buffer.from(vec.nonceHex, "hex"));
  const pageBytes = Number(vec.pageBytes || 64);
  const pageCount = Number(vec.pages || 128);
  const mixRounds = Number(vec.mixRounds || 2);

  const pages = new Array(pageCount);
  const ctx = await createMixContext({ graphSeed, nonce });
  pages[0] = await makeGenesisPage({ graphSeed, nonce, pageBytes, ctx });
  for (let i = 1; i < pageCount; i += 1) {
    const p = await parentsOf(i, graphSeed);
    pages[i] = await mixPage({
      i,
      p0: pages[p.p0],
      p1: pages[p.p1],
      p2: pages[p.p2],
      graphSeed,
      nonce,
      pageBytes,
      mixRounds,
      ctx,
    });
  }

  if (typeof options.mutatePages === "function") options.mutatePages(pages);

  const tree = await buildMerkle(pages);
  const opens = await Promise.all(
    vec.indices.map(async (idx) => {
      const p = await parentsOf(idx, graphSeed);
      return {
        i: idx,
        page: b64u(pages[idx]),
        p0: b64u(pages[p.p0]),
        p1: b64u(pages[p.p1]),
        p2: b64u(pages[p.p2]),
        proof: {
          page: buildProof(tree, idx).map((x) => b64u(x)),
          p0: buildProof(tree, p.p0).map((x) => b64u(x)),
          p1: buildProof(tree, p.p1).map((x) => b64u(x)),
          p2: buildProof(tree, p.p2).map((x) => b64u(x)),
        },
      };
    }),
  );

  return {
    root: tree.root,
    rootB64: b64u(tree.root),
    leafCount: tree.leafCount,
    graphSeed,
    nonce,
    pageBytes,
    opens,
  };
};

test("fixed vectors produce cross-end consistent verification", async () => {
  const vec = {
    graphSeedHex: "00112233445566778899aabbccddeeff",
    nonceHex: "0f0e0d0c0b0a09080706050403020100",
    pageBytes: 64,
    pages: 128,
    mixRounds: 2,
    indices: [1, 64, 127],
  };
  const fixture = await buildFixture(vec);
  const out = await verifyOpenBatchVector(fixture);
  assert.equal(out.ok, true);
});

test("1-bit tamper is rejected by server verification", async () => {
  const vec = {
    graphSeedHex: "00112233445566778899aabbccddeeff",
    nonceHex: "0f0e0d0c0b0a09080706050403020100",
    pageBytes: 64,
    pages: 128,
    mixRounds: 2,
    indices: [64],
  };
  const fixture = await buildFixture(vec, {
    mutatePages: (pages) => {
      pages[63] = pages[63].slice();
      pages[63][0] ^= 0x01;
    },
  });
  const out = await verifyOpenBatchVector(fixture);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "equation_failed");
});
