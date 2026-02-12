import test from "node:test";
import assert from "node:assert/strict";

const subtle = globalThis.crypto?.subtle;
const encoder = new TextEncoder();

const concat = (...chunks) => {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

const sha256 = async (...chunks) => {
  const data = concat(...chunks);
  return new Uint8Array(await subtle.digest("SHA-256", data));
};

const u32be = (value) => {
  const out = new Uint8Array(4);
  const v = value >>> 0;
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  return out;
};

const xorBytes = (...chunks) => {
  const out = new Uint8Array(chunks[0].length);
  for (let i = 0; i < out.length; i += 1) {
    let v = 0;
    for (const chunk of chunks) v ^= chunk[i];
    out[i] = v;
  }
  return out;
};

const rotlBytes = (buf, k) => {
  const n = buf.length;
  const shift = ((k % n) + n) % n;
  if (shift === 0) return buf.slice();
  const out = new Uint8Array(n);
  out.set(buf.subarray(shift), 0);
  out.set(buf.subarray(0, shift), n - shift);
  return out;
};

const aesCbcNoPadding = async ({ key, iv, input, pageBytes }) => {
  const encrypted = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, key, input));
  return encrypted.slice(0, pageBytes);
};

const rotl32 = (v, r) => ((v << r) | (v >>> (32 - r))) >>> 0;

const referenceMixPageFullDynamic = async ({ i, p0, p1, p2, graphSeed, nonce, pageBytes, mixRounds = 2 }) => {
  const keyMaterial = await sha256(encoder.encode("MHG1-KEY"), graphSeed, nonce);
  const key = await subtle.importKey("raw", keyMaterial.slice(0, 32), { name: "AES-CBC" }, false, ["encrypt"]);
  const pa = await sha256(encoder.encode("MHG1-PA"), graphSeed, nonce, u32be(i));
  const pb = await sha256(encoder.encode("MHG1-PB"), graphSeed, nonce, u32be(i));
  let dyn1 = (((pa[0] << 24) | (pa[1] << 16) | (pa[2] << 8) | pa[3]) >>> 0) % pageBytes;
  let dyn2 = (((pa[4] << 24) | (pa[5] << 16) | (pa[6] << 8) | pa[7]) >>> 0) % pageBytes;
  let dyn3 = (((pa[8] << 24) | (pa[9] << 16) | (pa[10] << 8) | pa[11]) >>> 0) % pageBytes;
  let dyn4 = (((pa[12] << 24) | (pa[13] << 16) | (pa[14] << 8) | pa[15]) >>> 0) % pageBytes;
  let dyn5 = (((pa[16] << 24) | (pa[17] << 16) | (pa[18] << 8) | pa[19]) >>> 0) % pageBytes;
  const iv1 = pb.slice(0, 16);
  const iv2 = pb.slice(16, 32);
  let state = p0;

  for (let round = 0; round < mixRounds; round += 1) {
    const dep = ((state[0] << 24) | (state[1] << 16) | (state[2] << 8) | state[3]) >>> 0;
    dyn1 = (dyn1 + dep) % pageBytes;
    dyn2 = (dyn2 + rotl32(dep, 8)) % pageBytes;
    dyn3 = (dyn3 + rotl32(dep, 16)) % pageBytes;
    dyn4 = (dyn4 + rotl32(dep, 24)) % pageBytes;
    dyn5 = (dyn5 + ((dep ^ 0x9e3779b9) >>> 0)) % pageBytes;
    const x0 = xorBytes(state, rotlBytes(p1, dyn1), rotlBytes(p2, dyn2));
    const x1 = await aesCbcNoPadding({ key, iv: iv1, input: x0, pageBytes });
    const x2 = xorBytes(x1, rotlBytes(p1, dyn3), rotlBytes(p2, dyn4));
    const x3 = await aesCbcNoPadding({ key, iv: iv2, input: x2, pageBytes });
    state = xorBytes(x3, x0, rotlBytes(x1, dyn5));
  }

  return state;
};

test("mixPage defaults to full-dynamic two-round output", async () => {
  const { mixPage } = await import("../../lib/mhg/mix-aes.js");
  const graphSeed = Uint8Array.from({ length: 16 }, (_, i) => i);
  const nonce = Uint8Array.from({ length: 16 }, (_, i) => 15 - i);
  const pageBytes = 64;
  const p0 = Uint8Array.from({ length: pageBytes }, (_, i) => i);
  const p1 = Uint8Array.from({ length: pageBytes }, (_, i) => (i * 3) & 0xff);
  const p2 = Uint8Array.from({ length: pageBytes }, (_, i) => (255 - i) & 0xff);

  const expected = await referenceMixPageFullDynamic({ i: 7, p0, p1, p2, graphSeed, nonce, pageBytes, mixRounds: 2 });
  const actual = await mixPage({ i: 7, p0, p1, p2, graphSeed, nonce, pageBytes });

  assert.deepEqual(Buffer.from(actual), Buffer.from(expected));
});

test("mixPage supports configurable rounds and differs from one-round mode", async () => {
  const { mixPage } = await import("../../lib/mhg/mix-aes.js");
  const graphSeed = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
  const nonce = Uint8Array.from({ length: 16 }, (_, i) => 32 - i);
  const pageBytes = 64;
  const p0 = Uint8Array.from({ length: pageBytes }, (_, i) => (i + 11) & 0xff);
  const p1 = Uint8Array.from({ length: pageBytes }, (_, i) => (i * 7) & 0xff);
  const p2 = Uint8Array.from({ length: pageBytes }, (_, i) => (i * 13) & 0xff);

  const oneRound = await mixPage({ i: 9, p0, p1, p2, graphSeed, nonce, pageBytes, mixRounds: 1 });
  const twoRounds = await mixPage({ i: 9, p0, p1, p2, graphSeed, nonce, pageBytes, mixRounds: 2 });

  assert.notDeepEqual(Buffer.from(oneRound), Buffer.from(twoRounds));
});

test("mixPage matches full-dynamic offsets reference", async () => {
  const { mixPage } = await import("../../lib/mhg/mix-aes.js");
  const graphSeed = Uint8Array.from({ length: 16 }, (_, i) => i + 3);
  const nonce = Uint8Array.from({ length: 16 }, (_, i) => 23 - i);
  const pageBytes = 64;
  const p0 = Uint8Array.from({ length: pageBytes }, (_, i) => (i * 11) & 0xff);
  const p1 = Uint8Array.from({ length: pageBytes }, (_, i) => (i * 17) & 0xff);
  const p2 = Uint8Array.from({ length: pageBytes }, (_, i) => (255 - i * 9) & 0xff);

  const expected = await referenceMixPageFullDynamic({ i: 7, p0, p1, p2, graphSeed, nonce, pageBytes, mixRounds: 2 });
  const actual = await mixPage({ i: 7, p0, p1, p2, graphSeed, nonce, pageBytes, mixRounds: 2 });

  assert.deepEqual(Buffer.from(actual), Buffer.from(expected));
});

test("mixPage derives PA/PB once per page index", async () => {
  const subtleDigest = globalThis.crypto.subtle.digest;
  const origDigest = subtleDigest.bind(globalThis.crypto.subtle);
  let paCalls = 0;
  let pbCalls = 0;

  globalThis.crypto.subtle.digest = async (algo, data) => {
    const bytes = new Uint8Array(data);
    const head = new TextDecoder().decode(bytes.subarray(0, 7));
    if (head === "MHG1-PA") paCalls += 1;
    if (head === "MHG1-PB") pbCalls += 1;
    return origDigest(algo, data);
  };

  try {
    const { mixPage } = await import("../../lib/mhg/mix-aes.js");
    const graphSeed = Uint8Array.from({ length: 16 }, (_, i) => i + 5);
    const nonce = Uint8Array.from({ length: 16 }, (_, i) => 31 - i);
    const pageBytes = 64;
    const p0 = Uint8Array.from({ length: pageBytes }, (_, i) => i ^ 0x23);
    const p1 = Uint8Array.from({ length: pageBytes }, (_, i) => (i * 5) & 0xff);
    const p2 = Uint8Array.from({ length: pageBytes }, (_, i) => (255 - i * 3) & 0xff);

    await mixPage({ i: 7, p0, p1, p2, graphSeed, nonce, pageBytes, mixRounds: 4 });
  } finally {
    globalThis.crypto.subtle.digest = subtleDigest;
  }

  assert.equal(paCalls, 1);
  assert.equal(pbCalls, 1);
});

test("createMixContext imports key once and reuses it across rounds", async () => {
  const { createMixContext, mixPage } = await import("../../lib/mhg/mix-aes.js");

  const graphSeed = new Uint8Array(16);
  const nonce = new Uint8Array(16);
  const pageBytes = 64;
  const p0 = Uint8Array.from({ length: pageBytes }, (_, i) => i);
  const p1 = Uint8Array.from({ length: pageBytes }, (_, i) => i ^ 0xaa);
  const p2 = Uint8Array.from({ length: pageBytes }, (_, i) => i ^ 0x55);

  const ctx = await createMixContext({ graphSeed, nonce });
  const first = await mixPage({ i: 1, p0, p1, p2, graphSeed, nonce, pageBytes, mixRounds: 2, ctx });
  const keyRef = ctx.key;
  const second = await mixPage({ i: 1, p0, p1, p2, graphSeed, nonce, pageBytes, mixRounds: 2, ctx });

  assert.ok(ctx.key, "context should cache imported key");
  assert.strictEqual(ctx.key, keyRef);
  assert.deepEqual(Buffer.from(first), Buffer.from(second));
});

test("makeGenesisPage returns a view over padded AES output", async () => {
  const { makeGenesisPage } = await import("../../lib/mhg/mix-aes.js");
  const graphSeed = Uint8Array.from({ length: 16 }, (_, i) => i + 2);
  const nonce = Uint8Array.from({ length: 16 }, (_, i) => 20 - i);
  const pageBytes = 64;

  const out = await makeGenesisPage({ graphSeed, nonce, pageBytes });

  assert.equal(out.length, pageBytes);
  assert.equal(out.buffer.byteLength > out.length, true);
});
