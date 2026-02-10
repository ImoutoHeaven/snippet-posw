const subtle = globalThis.crypto?.subtle;

if (!subtle) {
  throw new Error("WebCrypto subtle API is required");
}

export const toBytes = (value) => {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof value === "string") return new TextEncoder().encode(value);
  throw new TypeError("value must be bytes-like or string");
};

export const concatBytes = (...chunks) => {
  const normalized = chunks.map((chunk) => toBytes(chunk));
  const total = normalized.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of normalized) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

export const sha256 = async (...chunks) => {
  if (chunks.length === 0) {
    throw new TypeError("sha256 requires at least one chunk");
  }
  const input = chunks.length === 1 ? toBytes(chunks[0]) : concatBytes(...chunks);
  const digest = await subtle.digest("SHA-256", input);
  return new Uint8Array(digest);
};

export const sha256Hex = async (...chunks) => {
  const bytes = await sha256(...chunks);
  return Array.from(bytes, (v) => v.toString(16).padStart(2, "0")).join("");
};

export const u32be = (value) => {
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setUint32(0, value >>> 0, false);
  return out;
};
