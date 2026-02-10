import { sha256, u32be } from "./hash.js";

const U32_MAX_PLUS_ONE = 0x1_0000_0000;

const asU32 = (bytes) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(0, false);
};

export const draw32 = async ({ seed, label, i, ctr }) => {
  const digest = await sha256("MHG1-PRF", seed, label, u32be(i), u32be(ctr));
  return asU32(digest.subarray(0, 4));
};

export const uniformMod = async ({ seed, label, i, mod, ctr = 0 }) => {
  if (!Number.isInteger(mod) || mod <= 0) {
    throw new RangeError("mod must be a positive integer");
  }
  const limit = Math.floor(U32_MAX_PLUS_ONE / mod) * mod;
  while (true) {
    const n = await draw32({ seed, label, i, ctr });
    ctr += 1;
    if (n < limit) {
      return { value: n % mod, ctr };
    }
  }
};

export const pickDistinct = async ({ seed, label, i, count, maxExclusive, exclude = new Set() }) => {
  const out = [];
  const seen = new Set(exclude);
  let ctr = 0;
  while (out.length < count && seen.size < maxExclusive) {
    const next = await uniformMod({ seed, label, i, mod: maxExclusive, ctr });
    ctr = next.ctr;
    const n = next.value;
    if (seen.has(n)) {
      continue;
    }
    seen.add(n);
    out.push(n);
  }
  while (out.length < count) {
    const next = await uniformMod({ seed, label, i, mod: maxExclusive, ctr });
    ctr = next.ctr;
    out.push(next.value);
  }
  return out;
};

export const parentsOf = async (i, seed) => {
  if (!Number.isInteger(i) || i <= 0) {
    throw new RangeError("index i must be a positive integer");
  }
  if (!(seed instanceof Uint8Array)) {
    throw new TypeError("seed must be Uint8Array");
  }

  if (i === 1) {
    return { p0: 0, p1: 0, p2: 0 };
  }
  if (i === 2) {
    return { p0: 1, p1: 0, p2: 0 };
  }

  const p0 = i - 1;
  const [p1] = await pickDistinct({ seed, label: "p1", i, count: 1, maxExclusive: i, exclude: new Set([p0]) });
  const [p2] = await pickDistinct({ seed, label: "p2", i, count: 1, maxExclusive: i, exclude: new Set([p0, p1]) });

  return { p0, p1, p2 };
};

export const sampleIndices = async ({ maxIndex, count, seed }) => {
  if (!(seed instanceof Uint8Array)) {
    throw new TypeError("seed must be Uint8Array");
  }
  const max = Math.floor(maxIndex);
  const requested = Math.max(0, Math.floor(count));
  if (max < 1) {
    return [];
  }

  const forced = [];
  if (max >= 1) {
    forced.push(1);
    forced.push(max);
  }

  const out = [];
  const seen = new Set();
  for (const idx of forced) {
    if (!seen.has(idx)) {
      seen.add(idx);
      out.push(idx);
    }
  }

  const target = Math.min(max, Math.max(requested, out.length));
  let ctr = 0;

  while (out.length < target) {
    const next = await uniformMod({ seed, label: "sample", i: max, mod: max, ctr });
    ctr = next.ctr;
    const idx = next.value + 1;
    if (seen.has(idx)) {
      continue;
    }
    seen.add(idx);
    out.push(idx);
  }

  return out;
};
