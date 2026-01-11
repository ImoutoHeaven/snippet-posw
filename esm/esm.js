const encoder = new TextEncoder();

const POSW_SEED_PREFIX = encoder.encode("posw|seed|");
const POSW_STEP_PREFIX = encoder.encode("posw|step|");
const MERKLE_LEAF_PREFIX = encoder.encode("leaf|");
const MERKLE_NODE_PREFIX = encoder.encode("node|");
const PIPE_BYTES = encoder.encode("|");
const HASHCASH_PREFIX = encoder.encode("hashcash|v3|");

const utf8ToBytes = (value) => encoder.encode(String(value ?? ""));

const concatBytes = (...chunks) => {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

const encodeUint32BE = (value) => {
  const out = new Uint8Array(4);
  const num = Number(value) >>> 0;
  out[0] = (num >>> 24) & 0xff;
  out[1] = (num >>> 16) & 0xff;
  out[2] = (num >>> 8) & 0xff;
  out[3] = num & 0xff;
  return out;
};

const sha256Bytes = async (data) => {
  const bytes = typeof data === "string" ? utf8ToBytes(data) : data;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
};

const base64UrlEncode = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_");

const base64UrlEncodeNoPad = (bytes) => base64UrlEncode(bytes).replace(/=+$/g, "");

const normalizeSteps = (steps) => {
  const value = Number(steps);
  if (!Number.isFinite(value) || value <= 0) return 1;
  return Math.max(1, Math.floor(value));
};

const normalizeBits = (bits) => {
  const value = Number(bits);
  if (!Number.isFinite(value) || value <= 0) return 0;
  return Math.max(0, Math.floor(value));
};

const normalizeSegmentLen = (value, maxSteps) => {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) return 1;
  const max = Number.isFinite(maxSteps) && maxSteps > 0 ? Math.floor(maxSteps) : 1;
  return Math.max(1, Math.min(max, Math.floor(num)));
};

const computeMidIndex = (idx, segmentLen) => {
  const effectiveSegmentLen = Math.min(segmentLen, idx);
  if (effectiveSegmentLen <= 1) return null;
  const offset = Math.max(1, Math.floor(effectiveSegmentLen / 2));
  return idx - offset;
};

const normalizeSpinePosSet = (spinePos, maxLen) => {
  if (!Array.isArray(spinePos)) return null;
  const set = new Set();
  for (const raw of spinePos) {
    const pos = Number.parseInt(raw, 10);
    if (!Number.isFinite(pos) || pos < 0 || pos >= maxLen) {
      throw new Error("indices invalid");
    }
    if (set.has(pos)) {
      throw new Error("indices invalid");
    }
    set.add(pos);
  }
  return set;
};

const shouldYield = (counter, every) =>
  Number.isFinite(every) && every > 0 && counter % every === 0;

const hashSeed = async (bindingString, nonce) =>
  sha256Bytes(
    concatBytes(POSW_SEED_PREFIX, utf8ToBytes(bindingString), PIPE_BYTES, utf8ToBytes(nonce))
  );

const hashStep = async (prevBytes, index) =>
  sha256Bytes(concatBytes(POSW_STEP_PREFIX, encodeUint32BE(index), prevBytes));

const hashLeaf = async (leafIndex, leafBytes) =>
  sha256Bytes(concatBytes(MERKLE_LEAF_PREFIX, encodeUint32BE(leafIndex), leafBytes));

const hashNode = async (leftBytes, rightBytes) =>
  sha256Bytes(concatBytes(MERKLE_NODE_PREFIX, leftBytes, rightBytes));

const hashcashRootLast = async (rootBytes, lastBytes) =>
  sha256Bytes(concatBytes(HASHCASH_PREFIX, rootBytes, lastBytes));

const leadingZeroBits = (bytes) => {
  let count = 0;
  for (const b of bytes || []) {
    if (b === 0) {
      count += 8;
      continue;
    }
    for (let i = 7; i >= 0; i--) {
      if (b & (1 << i)) {
        return count + (7 - i);
      }
    }
  }
  return count;
};

const randomNonce = (byteLength = 16) => {
  const len = Number.isInteger(byteLength) && byteLength > 0 ? byteLength : 16;
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return base64UrlEncodeNoPad(bytes);
};

const buildMerkleLevels = async (leafHashes, yieldEvery, signal) => {
  const levels = [leafHashes];
  let current = leafHashes;
  let counter = 0;
  while (current.length > 1) {
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      if (signal && signal.aborted) {
        throw new Error("posw aborted");
      }
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i];
      next.push(await hashNode(left, right));
      counter += 1;
      if (shouldYield(counter, yieldEvery)) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }
    levels.push(next);
    current = next;
  }
  return levels;
};

const buildProof = (levels, leafIndex) => {
  const sibs = [];
  const dirs = [];
  let idx = leafIndex;
  for (let level = 0; level < levels.length - 1; level++) {
    const nodes = levels[level];
    let sibIdx = idx ^ 1;
    if (sibIdx >= nodes.length) sibIdx = idx;
    const dir = idx % 2 === 0 ? 0 : 1;
    dirs.push(dir ? "1" : "0");
    sibs.push(base64UrlEncodeNoPad(nodes[sibIdx]));
    idx = Math.floor(idx / 2);
  }
  return { sibs, dirs: dirs.join("") };
};

export const workerUrl = new URL("./pow-worker.js", import.meta.url).toString();

export async function computePoswCommit(bindingString, steps, options = {}) {
  if (typeof bindingString !== "string" || bindingString.length === 0) {
    throw new Error("bindingString required");
  }
  const L = normalizeSteps(steps);
  const hashcashBits = normalizeBits(options.hashcashBits);
  const segmentLen = normalizeSegmentLen(options.segmentLen, L);
  const yieldEvery = Number.isFinite(options.yieldEvery)
    ? Math.max(1, Math.floor(options.yieldEvery))
    : 256;
  const signal = options.signal;
  const onStatus = options.onStatus;

  for (let attempt = 0; ; attempt++) {
    if (signal && signal.aborted) throw new Error("posw aborted");
    const nonce = randomNonce(16);
    const chain = new Array(L + 1);
    chain[0] = await hashSeed(bindingString, nonce);
    for (let i = 1; i <= L; i++) {
      if (signal && signal.aborted) throw new Error("posw aborted");
      chain[i] = await hashStep(chain[i - 1], i);
      if (shouldYield(i, yieldEvery)) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }
    const leafHashes = new Array(chain.length);
    for (let i = 0; i < chain.length; i++) {
      if (signal && signal.aborted) throw new Error("posw aborted");
      leafHashes[i] = await hashLeaf(i, chain[i]);
      if (shouldYield(i, yieldEvery)) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }

    const levels = await buildMerkleLevels(leafHashes, yieldEvery, signal);
    const root = levels[levels.length - 1][0];
    if (hashcashBits > 0) {
      const digest = await hashcashRootLast(root, chain[L]);
      if (leadingZeroBits(digest) < hashcashBits) {
        if (typeof onStatus === "function") {
          onStatus("retry", attempt + 1);
        }
        if (shouldYield(attempt, yieldEvery)) {
          await new Promise((resolve) => setTimeout(resolve, 0));
        }
        continue;
      }
    }
    const rootB64 = base64UrlEncodeNoPad(root);

    const open = async (indices, options = {}) => {
      if (!Array.isArray(indices) || indices.length === 0) {
        throw new Error("indices required");
      }
      const spineSet = options && options.spineSet instanceof Set ? options.spineSet : null;
      const segLens = Array.isArray(options.segLens) ? options.segLens : null;
      if (segLens && segLens.length !== indices.length) {
        throw new Error("indices invalid");
      }
      const spinePosSet = options && Array.isArray(options.spinePos)
        ? normalizeSpinePosSet(options.spinePos, indices.length)
        : null;
      const out = [];
      const seen = new Set();
      for (let pos = 0; pos < indices.length; pos++) {
        const raw = indices[pos];
        const idx = Number(raw);
        if (!Number.isFinite(idx) || idx < 1 || idx > L) {
          throw new Error("indices invalid");
        }
        if (seen.has(idx)) {
          throw new Error("indices invalid");
        }
        seen.add(idx);
        const segLenThis = segLens ? Number(segLens[pos]) : segmentLen;
        if (!Number.isFinite(segLenThis) || segLenThis <= 0) {
          throw new Error("indices invalid");
        }
        const effectiveSegmentLen = Math.min(segLenThis, idx);
        const prevIdx = idx - effectiveSegmentLen;
        const hPrev = chain[prevIdx];
        const hCurr = chain[idx];
        const wantsMid = spinePosSet
          ? spinePosSet.has(pos)
          : spineSet && spineSet.has(idx);
        const midIdx = wantsMid ? computeMidIndex(idx, segLenThis) : null;
        if (wantsMid && midIdx === null) {
          throw new Error("indices invalid");
        }
        const entry = {
          i: idx,
          hPrev: base64UrlEncodeNoPad(hPrev),
          hCurr: base64UrlEncodeNoPad(hCurr),
          proofPrev: buildProof(levels, prevIdx),
          proofCurr: buildProof(levels, idx),
        };
        if (wantsMid) {
          const hMid = chain[midIdx];
          entry.hMid = base64UrlEncodeNoPad(hMid);
          entry.proofMid = buildProof(levels, midIdx);
        }
        out.push(entry);
      }
      return out;
    };

    return { rootB64, nonce, open };
  }
}
