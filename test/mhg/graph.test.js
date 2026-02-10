import test from "node:test";
import assert from "node:assert/strict";

const U32_MAX_PLUS_ONE = 0x1_0000_0000;

const u32be = (value) => {
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setUint32(0, value >>> 0, false);
  return out;
};

const asU32 = (bytes) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(0, false);
};

const referenceDraw32 = async ({ seed, label, i, ctr }) => {
  const { sha256 } = await import("../../lib/mhg/hash.js");
  const digest = await sha256("MHG1-PRF", seed, label, u32be(i), u32be(ctr));
  return asU32(digest.subarray(0, 4));
};

const referencePickDistinct = async ({ seed, i, label, exclude }) => {
  const limit = Math.floor(U32_MAX_PLUS_ONE / i) * i;
  let ctr = 0;
  while (true) {
    const n = await referenceDraw32({ seed, label, i, ctr });
    ctr += 1;
    if (n >= limit) continue;
    const pick = n % i;
    if (exclude.has(pick)) continue;
    return pick;
  }
};

const referenceParentsOf = async (i, seed) => {
  if (i === 1) return { p0: 0, p1: 0, p2: 0 };
  if (i === 2) return { p0: 1, p1: 0, p2: 0 };
  const p0 = i - 1;
  const p1 = await referencePickDistinct({ seed, i, label: "p1", exclude: new Set([p0]) });
  const p2 = await referencePickDistinct({ seed, i, label: "p2", exclude: new Set([p0, p1]) });
  return { p0, p1, p2 };
};

test("parents are deterministic and in-range", async () => {
  const { parentsOf } = await import("../../lib/mhg/graph.js");
  const seed = new Uint8Array(16);

  const a = await parentsOf(100, seed);
  const b = await parentsOf(100, seed);

  assert.deepEqual(a, b);
  assert.equal(a.p0, 99);
  assert.ok(a.p1 >= 0 && a.p1 < 100);
  assert.ok(a.p2 >= 0 && a.p2 < 100);
  assert.notEqual(a.p1, a.p0);
  assert.notEqual(a.p2, a.p0);
  assert.notEqual(a.p1, a.p2);
});

test("parentsOf matches MHG1-PRF reference", async () => {
  const { parentsOf } = await import("../../lib/mhg/graph.js");
  const seed = Uint8Array.from({ length: 16 }, (_, idx) => idx + 1);

  const expected = await referenceParentsOf(37, seed);
  const actual = await parentsOf(37, seed);

  assert.deepEqual(actual, expected);
});

test("parentsOf follows whitepaper boundary semantics", async () => {
  const { parentsOf } = await import("../../lib/mhg/graph.js");
  const seed = new Uint8Array(16);

  assert.deepEqual(await parentsOf(1, seed), { p0: 0, p1: 0, p2: 0 });
  assert.deepEqual(await parentsOf(2, seed), { p0: 1, p1: 0, p2: 0 });
});

test("sampling always includes edge_1 and edge_last", async () => {
  const { sampleIndices } = await import("../../lib/mhg/graph.js");

  const out = await sampleIndices({
    maxIndex: 8191,
    count: 32,
    seed: new Uint8Array(16),
  });

  assert.equal(out.includes(1), true);
  assert.equal(out.includes(8191), true);
});
