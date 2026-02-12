const subtle = globalThis.crypto?.subtle;
const encoder = new TextEncoder();
const keyCache = new Map();

if (!subtle) {
  throw new Error("WebCrypto subtle API is required");
}

const concatBytes = (...chunks) => {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
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

const readU32be = (bytes, offset) =>
  (((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0);

const rotl32 = (value, bits) => ((value << bits) | (value >>> (32 - bits))) >>> 0;

const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

const assertPageBytes = (pageBytes) => {
  if (!Number.isInteger(pageBytes) || pageBytes <= 0 || pageBytes % 16 !== 0) {
    throw new RangeError("pageBytes must be a positive multiple of 16");
  }
};

const assertPage = (name, value, pageBytes) => {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be Uint8Array`);
  }
  if (value.length !== pageBytes) {
    throw new RangeError(`${name} must match pageBytes`);
  }
};

const assert16Bytes = (name, value) => {
  if (!(value instanceof Uint8Array) || value.length !== 16) {
    throw new TypeError(`${name} must be Uint8Array(16)`);
  }
};

const assertMixRounds = (mixRounds) => {
  if (!Number.isInteger(mixRounds) || mixRounds < 1 || mixRounds > 4) {
    throw new RangeError("mixRounds must be an integer between 1 and 4");
  }
};

const digest = async (...chunks) => {
  const data = concatBytes(...chunks);
  return new Uint8Array(await subtle.digest("SHA-256", data));
};

const xor3 = (a, b, c) => {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = a[i] ^ b[i] ^ c[i];
  }
  return out;
};

const rotlBytes = (buf, k) => {
  const n = buf.length;
  if (n === 0) return new Uint8Array(0);
  const shift = ((k % n) + n) % n;
  if (shift === 0) return buf.slice();
  const out = new Uint8Array(n);
  out.set(buf.subarray(shift), 0);
  out.set(buf.subarray(0, shift), n - shift);
  return out;
};

const aesCbcNoPadding = async ({ key, iv, input, pageBytes }) => {
  const encrypted = new Uint8Array(
    await subtle.encrypt({ name: "AES-CBC", iv }, key, input),
  );

  // WebCrypto AES-CBC applies PKCS#7 padding; trim the extra block.
  return encrypted.subarray(0, pageBytes);
};

const contextId = (graphSeed, nonce) => `${bytesToHex(graphSeed)}:${bytesToHex(nonce)}`;

const getImportedKey = async ({ graphSeed, nonce }) => {
  const keyId = contextId(graphSeed, nonce);
  let keyPromise = keyCache.get(keyId);
  if (!keyPromise) {
    keyPromise = (async () => {
      const keyMaterial = await digest(encoder.encode("MHG1-KEY"), graphSeed, nonce);
      return subtle.importKey("raw", keyMaterial.slice(0, 32), { name: "AES-CBC" }, false, ["encrypt"]);
    })();
    keyCache.set(keyId, keyPromise);
  }
  try {
    return await keyPromise;
  } catch (error) {
    keyCache.delete(keyId);
    throw error;
  }
};

const resolveContextKey = async ({ ctx, graphSeed, nonce }) => {
  const keyId = contextId(graphSeed, nonce);
  if (!ctx) {
    return getImportedKey({ graphSeed, nonce });
  }
  if (ctx.id && ctx.id !== keyId) {
    throw new RangeError("ctx does not match graphSeed/nonce");
  }
  ctx.id = keyId;
  if (!ctx.key) {
    ctx.key = await getImportedKey({ graphSeed, nonce });
  }
  return ctx.key;
};

export const deriveKey = async ({ graphSeed, nonce }) => {
  assert16Bytes("graphSeed", graphSeed);
  assert16Bytes("nonce", nonce);
  const key = await getImportedKey({ graphSeed, nonce });
  return { key };
};

export const createMixContext = async ({ graphSeed, nonce }) => {
  assert16Bytes("graphSeed", graphSeed);
  assert16Bytes("nonce", nonce);
  const key = await getImportedKey({ graphSeed, nonce });
  return {
    id: contextId(graphSeed, nonce),
    key,
  };
};

export const makeGenesisPage = async ({ graphSeed, nonce, pageBytes, ctx }) => {
  assertPageBytes(pageBytes);
  assert16Bytes("graphSeed", graphSeed);
  assert16Bytes("nonce", nonce);

  const key = await resolveContextKey({ ctx, graphSeed, nonce });
  const iv0 = (await digest(encoder.encode("MHG1-IV0"), graphSeed, nonce)).slice(0, 16);
  const zeros = new Uint8Array(pageBytes);
  return aesCbcNoPadding({ key, iv: iv0, input: zeros, pageBytes });
};

export const mixPage = async ({ i, p0, p1, p2, graphSeed, nonce, pageBytes, mixRounds = 2, ctx }) => {
  assertPageBytes(pageBytes);
  assert16Bytes("graphSeed", graphSeed);
  assert16Bytes("nonce", nonce);
  if (!Number.isInteger(i) || i < 0 || i > 0xffffffff) {
    throw new RangeError("i must be a non-negative uint32 integer");
  }
  assertMixRounds(mixRounds);
  assertPage("p0", p0, pageBytes);
  assertPage("p1", p1, pageBytes);
  assertPage("p2", p2, pageBytes);

  const key = await resolveContextKey({ ctx, graphSeed, nonce });
  const pageIndex = u32be(i);
  const pa = await digest(encoder.encode("MHG1-PA"), graphSeed, nonce, pageIndex);
  const pb = await digest(encoder.encode("MHG1-PB"), graphSeed, nonce, pageIndex);
  const off1 = readU32be(pa, 0) % pageBytes;
  const off2 = readU32be(pa, 4) % pageBytes;
  const off3 = readU32be(pa, 8) % pageBytes;
  const off4 = readU32be(pa, 12) % pageBytes;
  const off5 = readU32be(pa, 16) % pageBytes;
  const iv1 = pb.slice(0, 16);
  const iv2 = pb.slice(16, 32);
  let state = p0;
  let dyn1 = off1;
  let dyn2 = off2;
  let dyn3 = off3;
  let dyn4 = off4;
  let dyn5 = off5;

  for (let round = 0; round < mixRounds; round += 1) {
    const dep = readU32be(state, 0);
    dyn1 = (dyn1 + dep) % pageBytes;
    dyn2 = (dyn2 + rotl32(dep, 8)) % pageBytes;
    dyn3 = (dyn3 + rotl32(dep, 16)) % pageBytes;
    dyn4 = (dyn4 + rotl32(dep, 24)) % pageBytes;
    dyn5 = (dyn5 + ((dep ^ 0x9e3779b9) >>> 0)) % pageBytes;

    const x0 = xor3(state, rotlBytes(p1, dyn1), rotlBytes(p2, dyn2));
    const x1 = await aesCbcNoPadding({ key, iv: iv1, input: x0, pageBytes });
    const x2 = xor3(x1, rotlBytes(p1, dyn3), rotlBytes(p2, dyn4));
    const x3 = await aesCbcNoPadding({ key, iv: iv2, input: x2, pageBytes });
    state = xor3(x3, x0, rotlBytes(x1, dyn5));
  }

  return state;
};
