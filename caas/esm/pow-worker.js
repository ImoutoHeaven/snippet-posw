const encoder = new TextEncoder();

const POSW_SEED_PREFIX = encoder.encode("posw|seed|");
const POSW_STEP_PREFIX = encoder.encode("posw|step|");
const MERKLE_LEAF_PREFIX = encoder.encode("leaf|");
const MERKLE_NODE_PREFIX = encoder.encode("node|");
const PIPE_BYTES = encoder.encode("|");
const HASHCASH_PREFIX = encoder.encode("hashcash|v3|");

const base64UrlEncodeNoPad = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

const encodeToBuffer = (value, buffer) => {
  const text = String(value ?? "");
  if (encoder.encodeInto) {
    return encoder.encodeInto(text, buffer).written;
  }
  const bytes = encoder.encode(text);
  buffer.set(bytes);
  return bytes.length;
};

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

const sleep0 = () => new Promise((resolve) => setTimeout(resolve, 0));

const randomNonce = (byteLength = 16) => {
  const len = Number.isInteger(byteLength) && byteLength > 0 ? byteLength : 16;
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return base64UrlEncodeNoPad(bytes);
};

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

const buildProof = (levels, leafIndex) => {
  const sibs = [];
  const dirs = [];
  let idx = leafIndex;
  for (let level = 0; level < levels.length - 1; level++) {
    const nodes = levels[level];
    const nodeCount = nodes.length / 32;
    let sibIdx = idx ^ 1;
    if (sibIdx >= nodeCount) sibIdx = idx;
    dirs.push(idx % 2 === 0 ? "0" : "1");
    sibs.push(base64UrlEncodeNoPad(nodes.subarray(sibIdx * 32, sibIdx * 32 + 32)));
    idx = Math.floor(idx / 2);
  }
  return { sibs, dirs: dirs.join("") };
};

let cancelFlag = false;
let state = null;

const emitProgress = (phase, done, total, attempt) => {
  postMessage({ type: "PROGRESS", phase, done, total, attempt });
};

const checkCanceled = () => {
  if (cancelFlag) {
    throw new Error("posw aborted");
  }
};

const initState = (payload) => {
  const bindingString = typeof payload.bindingString === "string" ? payload.bindingString : "";
  if (!bindingString) {
    throw new Error("bindingString required");
  }
  const L = normalizeSteps(payload.steps);
  const hashcashBits = normalizeBits(payload.hashcashBits);
  const segmentLen = normalizeSegmentLen(payload.segmentLen, L);
  const yieldEvery = Number.isFinite(payload.yieldEvery)
    ? Math.max(1, Math.floor(payload.yieldEvery))
    : 1024;
  const progressEvery = Number.isFinite(payload.progressEvery)
    ? Math.max(1, Math.floor(payload.progressEvery))
    : yieldEvery;

  const bindingBytes = encoder.encode(bindingString);
  const leafCount = L + 1;
  const chainBuf = new Uint8Array(leafCount * 32);
  const leafBuf = new Uint8Array(leafCount * 32);

  const levels = [leafBuf];
  let count = leafCount;
  while (count > 1) {
    count = Math.ceil(count / 2);
    levels.push(new Uint8Array(count * 32));
  }

  const stepIn = new Uint8Array(POSW_STEP_PREFIX.length + 4 + 32);
  stepIn.set(POSW_STEP_PREFIX, 0);
  const stepView = new DataView(stepIn.buffer);

  const leafIn = new Uint8Array(MERKLE_LEAF_PREFIX.length + 4 + 32);
  leafIn.set(MERKLE_LEAF_PREFIX, 0);
  const leafView = new DataView(leafIn.buffer);

  const nodeIn = new Uint8Array(MERKLE_NODE_PREFIX.length + 32 + 32);
  nodeIn.set(MERKLE_NODE_PREFIX, 0);

  const hashcashIn = new Uint8Array(HASHCASH_PREFIX.length + 32 + 32);
  hashcashIn.set(HASHCASH_PREFIX, 0);

  const nonceBytes = new Uint8Array(64);
  const seedIn = new Uint8Array(
    POSW_SEED_PREFIX.length + bindingBytes.length + PIPE_BYTES.length + nonceBytes.length
  );
  seedIn.set(POSW_SEED_PREFIX, 0);
  seedIn.set(bindingBytes, POSW_SEED_PREFIX.length);
  seedIn.set(PIPE_BYTES, POSW_SEED_PREFIX.length + bindingBytes.length);
  const seedNonceOffset = POSW_SEED_PREFIX.length + bindingBytes.length + PIPE_BYTES.length;

  state = {
    bindingString,
    L,
    hashcashBits,
    segmentLen,
    yieldEvery,
    progressEvery,
    chainBuf,
    leafBuf,
    levels,
    stepIn,
    stepView,
    leafIn,
    leafView,
    nodeIn,
    hashcashIn,
    seedIn,
    seedNonceOffset,
    nonceBytes,
    rootB64: "",
    nonce: "",
    ready: false,
  };
  cancelFlag = false;
};

const computeCommit = async () => {
  if (!state) throw new Error("not initialized");

  state.ready = false;
  state.rootB64 = "";
  state.nonce = "";

  const {
    L,
    hashcashBits,
    yieldEvery,
    progressEvery,
    chainBuf,
    leafBuf,
    levels,
    stepIn,
    stepView,
    leafIn,
    leafView,
    nodeIn,
    hashcashIn,
    seedIn,
    seedNonceOffset,
    nonceBytes,
  } = state;

  const stepIndexOffset = POSW_STEP_PREFIX.length;
  const stepDataOffset = stepIndexOffset + 4;
  const leafIndexOffset = MERKLE_LEAF_PREFIX.length;
  const leafDataOffset = leafIndexOffset + 4;
  const nodeDataOffset = MERKLE_NODE_PREFIX.length;
  const hashcashDataOffset = HASHCASH_PREFIX.length;

  const leafCount = L + 1;
  let attempt = 0;

  for (;;) {
    attempt += 1;
    checkCanceled();

    const nonce = randomNonce(16);
    const nonceLen = encodeToBuffer(nonce, nonceBytes);
    seedIn.set(nonceBytes.subarray(0, nonceLen), seedNonceOffset);
    const seedView = seedIn.subarray(0, seedNonceOffset + nonceLen);
    const seedDigest = await crypto.subtle.digest("SHA-256", seedView);
    chainBuf.set(new Uint8Array(seedDigest), 0);

    for (let i = 1; i <= L; i++) {
      checkCanceled();
      stepView.setUint32(stepIndexOffset, i >>> 0, false);
      stepIn.set(chainBuf.subarray((i - 1) * 32, i * 32), stepDataOffset);
      const digest = await crypto.subtle.digest("SHA-256", stepIn);
      chainBuf.set(new Uint8Array(digest), i * 32);
      if (shouldYield(i, yieldEvery)) {
        if (shouldYield(i, progressEvery)) {
          emitProgress("chain", i, L, attempt - 1);
        }
        await sleep0();
      }
    }

    for (let i = 0; i <= L; i++) {
      checkCanceled();
      leafView.setUint32(leafIndexOffset, i >>> 0, false);
      leafIn.set(chainBuf.subarray(i * 32, i * 32 + 32), leafDataOffset);
      const digest = await crypto.subtle.digest("SHA-256", leafIn);
      leafBuf.set(new Uint8Array(digest), i * 32);
      if (shouldYield(i + 1, yieldEvery)) {
        if (shouldYield(i + 1, progressEvery)) {
          emitProgress("leaf", i + 1, leafCount, attempt - 1);
        }
        await sleep0();
      }
    }

    let levelCount = leafCount;
    for (let level = 0; level < levels.length - 1; level++) {
      const curr = levels[level];
      const next = levels[level + 1];
      const nextCount = Math.ceil(levelCount / 2);
      for (let i = 0; i < nextCount; i++) {
        checkCanceled();
        const leftOffset = i * 2 * 32;
        const rightIdx = Math.min(i * 2 + 1, levelCount - 1);
        const rightOffset = rightIdx * 32;
        nodeIn.set(curr.subarray(leftOffset, leftOffset + 32), nodeDataOffset);
        nodeIn.set(curr.subarray(rightOffset, rightOffset + 32), nodeDataOffset + 32);
        const digest = await crypto.subtle.digest("SHA-256", nodeIn);
        next.set(new Uint8Array(digest), i * 32);
      }
      levelCount = nextCount;
      emitProgress("merkle", level + 1, levels.length - 1, attempt - 1);
      await sleep0();
    }

    const rootBytes = levels[levels.length - 1].subarray(0, 32);
    if (hashcashBits > 0) {
      hashcashIn.set(rootBytes, hashcashDataOffset);
      hashcashIn.set(chainBuf.subarray(L * 32, L * 32 + 32), hashcashDataOffset + 32);
      const digest = await crypto.subtle.digest("SHA-256", hashcashIn);
      if (leadingZeroBits(new Uint8Array(digest)) < hashcashBits) {
        emitProgress("hashcash", 0, 0, attempt);
        if (shouldYield(attempt, yieldEvery)) {
          await sleep0();
        }
        continue;
      }
    }

    state.rootB64 = base64UrlEncodeNoPad(rootBytes);
    state.nonce = nonce;
    state.ready = true;
    return { rootB64: state.rootB64, nonce };
  }
};

const computeOpen = async (payload) => {
  if (!state || !state.ready) throw new Error("commit missing");
  const indices = Array.isArray(payload.indices) ? payload.indices : null;
  if (!indices || indices.length === 0) {
    throw new Error("indices required");
  }
  const segLens = Array.isArray(payload.segLens) ? payload.segLens : null;
  if (segLens && segLens.length !== indices.length) {
    throw new Error("indices invalid");
  }
  const spinePosSet = Array.isArray(payload.spinePos)
    ? normalizeSpinePosSet(payload.spinePos, indices.length)
    : null;

  const out = [];
  const seen = new Set();
  const total = indices.length;

  for (let pos = 0; pos < indices.length; pos++) {
    checkCanceled();
    const raw = indices[pos];
    const idx = Number(raw);
    if (!Number.isFinite(idx) || idx < 1 || idx > state.L) {
      throw new Error("indices invalid");
    }
    if (seen.has(idx)) {
      throw new Error("indices invalid");
    }
    seen.add(idx);

    const segLenThis = segLens ? Number(segLens[pos]) : state.segmentLen;
    if (!Number.isFinite(segLenThis) || segLenThis <= 0) {
      throw new Error("indices invalid");
    }
    const effectiveSegmentLen = Math.min(segLenThis, idx);
    const prevIdx = idx - effectiveSegmentLen;
    const hPrev = state.chainBuf.subarray(prevIdx * 32, prevIdx * 32 + 32);
    const hCurr = state.chainBuf.subarray(idx * 32, idx * 32 + 32);

    const wantsMid = spinePosSet ? spinePosSet.has(pos) : false;
    const midIdx = wantsMid ? computeMidIndex(idx, segLenThis) : null;
    if (wantsMid && midIdx === null) {
      throw new Error("indices invalid");
    }

    const entry = {
      i: idx,
      hPrev: base64UrlEncodeNoPad(hPrev),
      hCurr: base64UrlEncodeNoPad(hCurr),
      proofPrev: buildProof(state.levels, prevIdx),
      proofCurr: buildProof(state.levels, idx),
    };

    if (wantsMid) {
      const hMid = state.chainBuf.subarray(midIdx * 32, midIdx * 32 + 32);
      entry.hMid = base64UrlEncodeNoPad(hMid);
      entry.proofMid = buildProof(state.levels, midIdx);
    }

    out.push(entry);

    if (shouldYield(pos + 1, state.yieldEvery)) {
      if (shouldYield(pos + 1, state.progressEvery)) {
        emitProgress("open", pos + 1, total, 0);
      }
      await sleep0();
    }
  }
  return out;
};

self.onmessage = (event) => {
  const data = event && event.data ? event.data : {};
  const type = data.type;
  const rid = data.rid;

  if (type === "CANCEL") {
    cancelFlag = true;
    postMessage({ type: "CANCEL_OK", rid });
    return;
  }

  if (type === "DISPOSE") {
    cancelFlag = true;
    state = null;
    postMessage({ type: "DISPOSE_OK", rid });
    return;
  }

  const replyError = (err) => {
    postMessage({
      type: "ERROR",
      rid,
      message: err && err.message ? err.message : String(err),
    });
  };

  (async () => {
    try {
      if (type === "INIT") {
        initState(data);
        postMessage({ type: "INIT_OK", rid });
        return;
      }
      if (type === "COMMIT") {
        const result = await computeCommit();
        postMessage({ type: "COMMIT_OK", rid, rootB64: result.rootB64, nonce: result.nonce });
        return;
      }
      if (type === "OPEN") {
        const opens = await computeOpen(data);
        postMessage({ type: "OPEN_OK", rid, opens });
        return;
      }
      throw new Error("unknown command");
    } catch (err) {
      replyError(err);
    }
  })();
};
