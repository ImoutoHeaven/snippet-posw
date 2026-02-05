import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";

import {
  compileWhenCondition,
  collectWhenNeeds,
  validateWhenCondition,
} from "./when-compile.js";

const extractConfigLiteral = (source) => {
  const match = source.match(/^\s*const\s+CONFIG\s*=/m);
  if (!match || match.index === undefined) return null;
  const start = source.indexOf("[", match.index + match[0].length);
  if (start === -1) return null;
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  let inTemplate = false;
  let inLine = false;
  let inBlock = false;
  for (let i = start; i < source.length; i++) {
    const ch = source[i];
    const next = source[i + 1];
    if (inLine) {
      if (ch === "\n") inLine = false;
      continue;
    }
    if (inBlock) {
      if (ch === "*" && next === "/") {
        inBlock = false;
        i++;
      }
      continue;
    }
    if (inSingle) {
      if (ch === "\\") {
        i++;
        continue;
      }
      if (ch === "'") inSingle = false;
      continue;
    }
    if (inDouble) {
      if (ch === "\\") {
        i++;
        continue;
      }
      if (ch === '"') inDouble = false;
      continue;
    }
    if (inTemplate) {
      if (ch === "\\") {
        i++;
        continue;
      }
      if (ch === "`") inTemplate = false;
      continue;
    }
    if (ch === "/" && next === "/") {
      inLine = true;
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlock = true;
      i++;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      continue;
    }
    if (ch === "`") {
      inTemplate = true;
      continue;
    }
    if (ch === "[") depth++;
    if (ch === "]") {
      depth--;
      if (depth === 0) {
        return source.slice(start, i + 1);
      }
    }
  }
  return null;
};

const escapeRegex = (value) => value.replace(/[.+?^${}()|[\]\\]/g, "\\$&");

const isRegExp = (value) => Object.prototype.toString.call(value) === "[object RegExp]";

const cloneValue = (value) => {
  if (Array.isArray(value)) {
    return value.map((entry) => cloneValue(entry));
  }
  if (isRegExp(value)) {
    return new RegExp(value.source, value.flags);
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, entry] of Object.entries(value)) {
      out[key] = cloneValue(entry);
    }
    return out;
  }
  return value;
};

const compileHostPattern = (pattern) => {
  if (typeof pattern !== "string") return null;
  const host = pattern.trim().toLowerCase();
  if (!host) return null;
  const escaped = escapeRegex(host).replace(/\*/g, "[^.]*");
  try {
    return new RegExp(`^${escaped}$`);
  } catch {
    return null;
  }
};

const compilePathPattern = (pattern) => {
  if (typeof pattern !== "string") return null;
  const path = pattern.trim();
  if (!path.startsWith("/")) return null;
  let out = "";
  for (let i = 0; i < path.length; i++) {
    const ch = path[i];
    if (ch === "*") {
      if (path[i + 1] === "*") {
        const isLast = i + 2 >= path.length;
        const prevIsSlash = i > 0 && path[i - 1] === "/";
        if (isLast && prevIsSlash && out.endsWith("/") && out.length > 1) {
          out = `${out.slice(0, -1)}(?:/.*)?`;
        } else {
          out += ".*";
        }
        i++;
      } else {
        out += "[^/]*";
      }
      continue;
    }
    out += /[.+?^${}()|[\]\\]/.test(ch) ? `\\${ch}` : ch;
  }
  try {
    return new RegExp(`^${out}$`);
  } catch {
    return null;
  }
};

const analyzeHostPattern = (pattern) => {
  if (typeof pattern !== "string") {
    return {
      hostType: null,
      hostExact: null,
      hostLabels: null,
      hostLabelCount: null,
    };
  }
  const host = pattern.trim().toLowerCase();
  if (!host) {
    return {
      hostType: null,
      hostExact: null,
      hostLabels: null,
      hostLabelCount: null,
    };
  }
  if (!host.includes("*")) {
    return {
      hostType: "exact",
      hostExact: host,
      hostLabels: null,
      hostLabelCount: null,
    };
  }
  const hostLabels = host.split(".");
  const isWildcardLabels = hostLabels.every(
    (label) => !label.includes("*") || label === "*"
  );
  if (!isWildcardLabels) {
    return {
      hostType: "regex",
      hostExact: null,
      hostLabels: null,
      hostLabelCount: null,
    };
  }
  return {
    hostType: "wildcard",
    hostExact: null,
    hostLabels,
    hostLabelCount: hostLabels.length,
  };
};

const analyzePathPattern = (pattern) => {
  if (typeof pattern !== "string") {
    return { pathType: null, pathExact: null, pathPrefix: null };
  }
  const path = pattern.trim();
  if (!path.startsWith("/")) {
    return { pathType: null, pathExact: null, pathPrefix: null };
  }
  if (!path.includes("*")) {
    return { pathType: "exact", pathExact: path, pathPrefix: null };
  }
  const prefixCandidate = path.endsWith("/**") ? path.slice(0, -3) : null;
  if (
    prefixCandidate !== null &&
    prefixCandidate.length > 0 &&
    !prefixCandidate.includes("*")
  ) {
    return {
      pathType: "prefix",
      pathExact: null,
      pathPrefix: prefixCandidate || "/",
    };
  }
  return { pathType: "regex", pathExact: null, pathPrefix: null };
};

const compileConfigEntry = (entry) => {
  const config = (entry && entry.config) || {};
  const when = entry && entry.when;
  validateWhenCondition(when);
  const compiledWhen = compileWhenCondition(when);
  const whenNeeds = collectWhenNeeds(when);
  const hasHost = entry && Object.prototype.hasOwnProperty.call(entry, "host");
  const hostPattern = hasHost ? entry.host : null;
  if (!hasHost) {
    throw new Error("CONFIG entry missing host");
  }
  if (typeof hostPattern !== "string" || !hostPattern.trim()) {
    throw new Error("CONFIG entry host must be a non-empty string");
  }
  const hostRegex = compileHostPattern(hostPattern);
  if (!hostRegex) {
    throw new Error(`Invalid host pattern: ${hostPattern}`);
  }
  let pathPattern = null;
  let pathRegex = null;
  if (entry && Object.prototype.hasOwnProperty.call(entry, "path")) {
    pathPattern = entry.path;
    if (typeof pathPattern !== "string" || !pathPattern.trim()) {
      throw new Error("CONFIG entry path must be a non-empty string");
    }
    pathRegex = compilePathPattern(pathPattern);
    if (!pathRegex) {
      throw new Error(`Invalid path pattern: ${pathPattern}`);
    }
  }
  const { hostType, hostExact, hostLabels, hostLabelCount } = analyzeHostPattern(
    hostPattern
  );
  const { pathType, pathExact, pathPrefix } = analyzePathPattern(pathPattern);
  return {
    hostRegex,
    pathRegex,
    config,
    when: compiledWhen,
    whenNeeds,
    hostType,
    hostExact,
    hostLabels,
    hostLabelCount,
    pathType,
    pathExact,
    pathPrefix,
  };
};

export const buildCompiledConfig = async (sourcePath) => {
  const source = await readFile(sourcePath, "utf-8");
  const literal = extractConfigLiteral(source);
  if (!literal) {
    throw new Error(`CONFIG not found in ${sourcePath}`);
  }
  const config = runInNewContext(`(${literal})`);
  if (!Array.isArray(config)) {
    throw new Error("CONFIG must be array");
  }
  for (const entry of config) {
    if (entry && typeof entry === "object") {
      if (Object.prototype.hasOwnProperty.call(entry, "pattern")) {
        throw new Error("CONFIG entries must use host/path (pattern is not supported)");
      }
    }
  }
  const normalized = cloneValue(config);
  const compiled = normalized.map(compileConfigEntry);
  return JSON.stringify(
    compiled.map((entry) => ({
      host: entry.hostRegex ? { s: entry.hostRegex.source, f: entry.hostRegex.flags } : null,
      path: entry.pathRegex ? { s: entry.pathRegex.source, f: entry.pathRegex.flags } : null,
      when: entry.when ?? null,
      whenNeeds: entry.whenNeeds,
      hostType: entry.hostType,
      hostExact: entry.hostExact,
      hostLabels: entry.hostLabels,
      hostLabelCount: entry.hostLabelCount,
      pathType: entry.pathType,
      pathExact: entry.pathExact,
      pathPrefix: entry.pathPrefix,
      config: entry.config || {},
    }))
  );
};
