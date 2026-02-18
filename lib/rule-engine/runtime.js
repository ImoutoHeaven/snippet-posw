import { compilePathGlobRegexSource } from "./path-glob.js";
import { LruCache } from "./lru-cache.js";

const GLOB_CACHE = new LruCache(512);
const NEVER_MATCH = /^\b\B$/;

const escapeRegex = (value) => value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");

const toCaseMode = (matcher, defaultCase) => {
  if (matcher && matcher.case === "sensitive") return "sensitive";
  if (matcher && matcher.case === "insensitive") return "insensitive";
  return defaultCase;
};

const toStringValue = (value) => {
  if (value === null || value === undefined) return null;
  return String(value);
};

const compareText = (actual, expected, caseMode) => {
  if (actual === null || expected === null) return false;
  if (caseMode === "sensitive") return actual === expected;
  return actual.toLowerCase() === expected.toLowerCase();
};

const textLikeGlobToRegexSource = (pattern, mode) => {
  const globMode = mode === "host" ? "host" : "text";
  const unit = globMode === "host" ? "[^.]*" : ".*";
  let out = "";
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char !== "*") {
      out += escapeRegex(char);
      continue;
    }

    let runLength = 1;
    while (i + 1 < pattern.length && pattern[i + 1] === "*") {
      runLength += 1;
      i += 1;
    }

    out += unit;
  }
  return out;
};

const compileGlobRegex = (pattern, caseMode, globMode = "text") => {
  const mode = globMode === "path" || globMode === "host" ? globMode : "text";
  const key = `${caseMode}:${mode}:${pattern}`;
  const cached = GLOB_CACHE.get(key);
  if (cached) return cached;

  let regex = NEVER_MATCH;
  try {
    const source =
      mode === "path"
        ? compilePathGlobRegexSource(pattern)
        : textLikeGlobToRegexSource(pattern, mode);
    regex = new RegExp(`^${source}$`, caseMode === "sensitive" ? "" : "i");
  } catch {
    // Fail closed when malformed path glob IR reaches runtime.
  }

  GLOB_CACHE.set(key, regex);
  return regex;
};

const anyMatch = (actual, predicate) => {
  if (Array.isArray(actual)) {
    for (const entry of actual) {
      if (predicate(toStringValue(entry))) return true;
    }
    return false;
  }
  return predicate(toStringValue(actual));
};

export function matchExistsMatcher(matcher, exists) {
  if (!matcher || matcher.kind !== "exists") return false;
  return Boolean(matcher.value) === Boolean(exists);
}

export function matchTextMatcher(matcher, actual, options = {}) {
  if (!matcher || typeof matcher !== "object") return false;
  const defaultCase = options.defaultCase === "sensitive" ? "sensitive" : "insensitive";
  const caseMode = toCaseMode(matcher, defaultCase);

  if (matcher.kind === "eq") {
    const expected = toStringValue(matcher.value);
    return anyMatch(actual, (entry) => compareText(entry, expected, caseMode));
  }

  if (matcher.kind === "in") {
    if (!Array.isArray(matcher.values)) return false;
    for (const expectedRaw of matcher.values) {
      const expected = toStringValue(expectedRaw);
      if (anyMatch(actual, (entry) => compareText(entry, expected, caseMode))) {
        return true;
      }
    }
    return false;
  }

  if (matcher.kind === "glob") {
    const pattern = toStringValue(matcher.pattern);
    if (pattern === null) return false;
    const globMode =
      options.globMode === "path" || options.globMode === "host" ? options.globMode : "text";
    const regex = compileGlobRegex(pattern, caseMode, globMode);
    return anyMatch(actual, (entry) => {
      if (entry === null) return false;
      regex.lastIndex = 0;
      return regex.test(entry);
    });
  }

  if (matcher.kind === "re") {
    const source = toStringValue(matcher.source);
    if (source === null) return false;
    const flags = typeof matcher.flags === "string" ? matcher.flags : "";
    let regex;
    try {
      regex = new RegExp(source, flags);
    } catch {
      return false;
    }
    return anyMatch(actual, (entry) => {
      if (entry === null) return false;
      regex.lastIndex = 0;
      return regex.test(entry);
    });
  }

  return false;
}

const isIpv4 = (ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
const isIpv6 = (ip) => ip.includes(":");

const parseIpv4 = (ip) => {
  if (!isIpv4(ip)) return null;
  const parts = ip.split(".").map((entry) => Number.parseInt(entry, 10));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return null;
  }
  return parts;
};

const parseIpv6Hextets = (part) => {
  if (!part) return [];
  const tokens = part.split(":");
  const out = [];
  for (const token of tokens) {
    if (!token) continue;
    if (token.includes(".")) {
      const v4 = parseIpv4(token);
      if (!v4) return null;
      out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      continue;
    }
    const value = Number.parseInt(token, 16);
    if (!Number.isFinite(value) || value < 0 || value > 0xffff) return null;
    out.push(value);
  }
  return out;
};

const parseIpv6 = (ip) => {
  if (!ip || typeof ip !== "string") return null;
  const raw = ip.split("%")[0];
  if (!raw) return null;
  if (raw === "::") return new Uint8Array(16);
  const parts = raw.split("::");
  if (parts.length > 2) return null;
  const head = parseIpv6Hextets(parts[0]);
  if (head === null) return null;
  const tail = parts.length === 2 ? parseIpv6Hextets(parts[1]) : [];
  if (tail === null) return null;
  const total = head.length + tail.length;
  if (total > 8) return null;
  const zeros = parts.length === 2 ? 8 - total : 0;
  if (parts.length === 1 && total !== 8) return null;
  const full = head.concat(Array(zeros).fill(0)).concat(tail);
  if (full.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (full[i] >>> 8) & 0xff;
    bytes[i * 2 + 1] = full[i] & 0xff;
  }
  return bytes;
};

const ipInCidr = (ip, cidr) => {
  if (typeof ip !== "string" || typeof cidr !== "string") return false;
  const slash = cidr.indexOf("/");
  if (slash === -1) return false;
  const base = cidr.slice(0, slash);
  const prefix = Number(cidr.slice(slash + 1));
  if (!Number.isFinite(prefix)) return false;
  if (isIpv4(base) && isIpv4(ip)) {
    const baseBytes = parseIpv4(base);
    const ipBytes = parseIpv4(ip);
    if (!baseBytes || !ipBytes) return false;
    const p = Math.min(32, Math.max(0, prefix));
    const toInt = (bytes) => ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
    const mask = p === 0 ? 0 : (~0 << (32 - p)) >>> 0;
    return (toInt(ipBytes) & mask) === (toInt(baseBytes) & mask);
  }
  if (isIpv6(base) && isIpv6(ip)) {
    const baseBytes = parseIpv6(base);
    const ipBytes = parseIpv6(ip);
    if (!baseBytes || !ipBytes) return false;
    const p = Math.min(128, Math.max(0, prefix));
    const fullBytes = Math.floor(p / 8);
    const rem = p % 8;
    for (let i = 0; i < fullBytes; i++) {
      if (ipBytes[i] !== baseBytes[i]) return false;
    }
    if (rem === 0) return true;
    const mask = 0xff << (8 - rem);
    return (ipBytes[fullBytes] & mask) === (baseBytes[fullBytes] & mask);
  }
  return false;
};

export function matchIpMatcher(matcher, ip) {
  if (!matcher || typeof matcher !== "object") return false;
  if (matcher.kind === "eq") {
    return typeof ip === "string" && typeof matcher.value === "string" && ip === matcher.value;
  }
  if (matcher.kind === "in") {
    if (typeof ip !== "string" || !Array.isArray(matcher.values)) return false;
    return matcher.values.some((entry) => typeof entry === "string" && entry === ip);
  }
  if (matcher.kind === "cidr") {
    if (typeof ip !== "string") return false;
    if (Array.isArray(matcher.value)) {
      return matcher.value.some((entry) => typeof entry === "string" && (entry.includes("/") ? ipInCidr(ip, entry) : ip === entry));
    }
    if (typeof matcher.value !== "string") return false;
    if (!matcher.value.includes("/")) return ip === matcher.value;
    return ipInCidr(ip, matcher.value);
  }
  return false;
}

const readValueMapField = (container, field, key) => {
  if (typeof key !== "string") {
    return { exists: false, value: undefined };
  }
  if (field === "header" && container instanceof Headers) {
    return { exists: container.has(key), value: container.get(key) };
  }
  if (field === "cookie" && container instanceof Map) {
    return { exists: container.has(key), value: container.get(key) };
  }
  if (field === "query" && container instanceof URLSearchParams) {
    const values = container.getAll(key);
    return { exists: container.has(key), value: values.length > 0 ? values : undefined };
  }
  return { exists: false, value: undefined };
};

const matchBooleanMatcher = (matcher, value) => {
  if (!matcher || typeof matcher !== "object") return false;
  const actual = value === true;
  if (matcher.kind === "eq") {
    return typeof matcher.value === "boolean" && matcher.value === actual;
  }
  if (matcher.kind === "in") {
    return Array.isArray(matcher.values) && matcher.values.some((entry) => entry === actual);
  }
  return false;
};

const evaluateAtom = (node, context) => {
  const field = node && typeof node.field === "string" ? node.field : "";
  const matcher = node && typeof node.matcher === "object" ? node.matcher : null;
  if (!field || !matcher) return false;

  if (field === "header" || field === "cookie" || field === "query") {
    const { exists, value } = readValueMapField(context && context[field], field, node.key);
    if (matcher.kind === "exists") {
      return matchExistsMatcher(matcher, exists);
    }
    return matchTextMatcher(matcher, value, { defaultCase: "insensitive" });
  }

  if (field === "ip") {
    return matchIpMatcher(matcher, context && context.ip);
  }

  if (field === "tls") {
    return matchBooleanMatcher(matcher, context && context.tls);
  }

  if (matcher.kind === "exists") {
    return matchExistsMatcher(matcher, context && context[field] !== undefined && context[field] !== null);
  }

  const defaultCase = field === "path" ? "sensitive" : "insensitive";
  const globMode = field === "path" ? "path" : undefined;
  return matchTextMatcher(matcher, context && context[field], { defaultCase, globMode });
};

export function evaluateWhen(node, context) {
  if (node === null || node === undefined) {
    return true;
  }

  if (Array.isArray(node)) {
    return node.every((entry) => evaluateWhen(entry, context));
  }

  if (!node || typeof node !== "object") {
    return false;
  }

  if (node.kind === "and") {
    if (!Array.isArray(node.children)) return false;
    return node.children.every((entry) => evaluateWhen(entry, context));
  }

  if (node.kind === "or") {
    if (!Array.isArray(node.children)) return false;
    return node.children.some((entry) => evaluateWhen(entry, context));
  }

  if (node.kind === "not") {
    return !evaluateWhen(node.child, context);
  }

  if (node.kind === "atom") {
    return evaluateAtom(node, context);
  }

  return false;
}
