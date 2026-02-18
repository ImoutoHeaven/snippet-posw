import { isPlainObject } from "./types.js";
import { validatePathGlobPattern } from "./path-glob.js";

const VALUE_MAP_FIELDS = new Set(["header", "cookie", "query"]);

export function compileConfigEntry(entry) {
  if (!isPlainObject(entry)) {
    throw new Error("CONFIG entry must be an object");
  }
  if (!("host" in entry)) {
    throw new Error("CONFIG entry missing host");
  }

  const host = compileTextMatcher(entry.host, "CONFIG.host");
  const path =
    "path" in entry
      ? compileTextMatcher(entry.path, "CONFIG.path", { globMode: "path" })
      : null;
  const when = "when" in entry ? compileWhenCondition(entry.when, "CONFIG.when") : null;
  const whenNeeds = deriveWhenNeeds(when);

  const hostMeta = analyzeHostMatcher(host);
  const pathMeta = analyzePathMatcher(path);

  return {
    host,
    path,
    when,
    whenNeeds,
    hostType: hostMeta.hostType,
    hostExact: hostMeta.hostExact,
    hostLabels: hostMeta.hostLabels,
    hostLabelCount: hostMeta.hostLabelCount,
    pathType: pathMeta.pathType,
    pathExact: pathMeta.pathExact,
    pathPrefix: pathMeta.pathPrefix,
    config: entry.config || {},
  };
}

function compileWhenCondition(node, path) {
  const nodes = [];

  for (const [key, value] of Object.entries(node || {})) {
    if (key === "and") {
      nodes.push({
        kind: "and",
        children: value.map((entry, index) => compileWhenCondition(entry, `${path}.and[${index}]`)),
      });
      continue;
    }
    if (key === "or") {
      nodes.push({
        kind: "or",
        children: value.map((entry, index) => compileWhenCondition(entry, `${path}.or[${index}]`)),
      });
      continue;
    }
    if (key === "not") {
      nodes.push({ kind: "not", child: compileWhenCondition(value, `${path}.not`) });
      continue;
    }

    if (VALUE_MAP_FIELDS.has(key)) {
      const mappedAtoms = Object.entries(value).map(([entryKey, matcher]) => ({
        kind: "atom",
        field: key,
        key: entryKey,
        matcher: compileTextMatcher(matcher, `${path}.${key}[${JSON.stringify(entryKey)}]`),
      }));
      nodes.push(...mappedAtoms);
      continue;
    }

    nodes.push({
      kind: "atom",
      field: key,
      matcher: compileWhenAtomMatcher(key, value, `${path}.${key}`),
    });
  }

  if (nodes.length === 1) {
    return nodes[0];
  }
  return { kind: "and", children: nodes };
}

function compileWhenAtomMatcher(field, matcher, path) {
  if (field === "ip") {
    return compileIpMatcher(matcher);
  }
  if (field === "tls") {
    return compileOperatorMatcher(matcher);
  }

  return compileTextMatcher(matcher, path, {
    globMode: field === "path" ? "path" : "text",
  });
}

function compileTextMatcher(matcher, path, options = {}) {
  const compiled = compileOperatorMatcher(matcher);
  if (compiled.kind === "re") {
    ensureValidRegex(compiled.source, compiled.flags, path);
  }
  if (compiled.kind === "glob" && options.globMode === "path") {
    try {
      validatePathGlobPattern(compiled.pattern);
    } catch (error) {
      const detail = error instanceof Error && error.message ? `: ${error.message}` : "";
      throw new Error(`${path} contains invalid path glob${detail}`);
    }
  }
  return compiled;
}

function compileIpMatcher(matcher) {
  return compileOperatorMatcher(matcher);
}

function compileOperatorMatcher(matcher) {
  if ("exists" in matcher) {
    return { kind: "exists", value: matcher.exists };
  }
  if ("eq" in matcher) {
    return { kind: "eq", value: matcher.eq };
  }
  if ("in" in matcher) {
    return { kind: "in", values: [...matcher.in] };
  }
  if ("glob" in matcher) {
    return { kind: "glob", pattern: matcher.glob };
  }
  if ("re" in matcher) {
    return { kind: "re", source: matcher.re, flags: matcher.flags || "" };
  }
  if ("cidr" in matcher) {
    return { kind: "cidr", value: matcher.cidr };
  }
  throw new Error("Unsupported matcher operator");
}

function ensureValidRegex(source, flags, path) {
  try {
    // Validate regex syntax at compile-time, but keep JSON-safe source/flags in IR.
    new RegExp(source, flags);
  } catch (error) {
    const detail = error instanceof Error && error.message ? `: ${error.message}` : "";
    throw new Error(`${path} contains invalid regex${detail}`);
  }
}

function deriveWhenNeeds(whenNode) {
  if (!whenNode) {
    return {};
  }

  const needs = {};
  const visit = (node) => {
    if (!node || typeof node !== "object") return;
    if (node.kind === "atom") {
      needs[node.field] = true;
      return;
    }
    if (node.kind === "not") {
      visit(node.child);
      return;
    }
    if (Array.isArray(node.children)) {
      for (const child of node.children) {
        visit(child);
      }
    }
  };

  visit(whenNode);
  return needs;
}

function analyzeHostMatcher(hostMatcher) {
  const empty = {
    hostType: null,
    hostExact: null,
    hostLabels: null,
    hostLabelCount: null,
  };

  if (!hostMatcher || hostMatcher.kind === "re" || hostMatcher.kind === "in") {
    return {
      ...empty,
      hostType: "regex",
    };
  }

  if (hostMatcher.kind === "eq") {
    const host = String(hostMatcher.value || "").trim().toLowerCase();
    if (!host) return empty;
    return {
      ...empty,
      hostType: "exact",
      hostExact: host,
    };
  }

  if (hostMatcher.kind !== "glob") {
    return empty;
  }

  const host = String(hostMatcher.pattern || "").trim().toLowerCase();
  if (!host) return empty;

  if (!host.includes("*")) {
    return {
      ...empty,
      hostType: "exact",
      hostExact: host,
    };
  }

  const hostLabels = host.split(".");
  const wildcardByLabel = hostLabels.every(
    (label) => !label.includes("*") || label === "*",
  );
  if (!wildcardByLabel) {
    return {
      ...empty,
      hostType: "regex",
    };
  }

  return {
    ...empty,
    hostType: "wildcard",
    hostLabels,
    hostLabelCount: hostLabels.length,
  };
}

function analyzePathMatcher(pathMatcher) {
  const empty = {
    pathType: null,
    pathExact: null,
    pathPrefix: null,
  };

  if (!pathMatcher) {
    return empty;
  }

  if (pathMatcher.kind === "eq") {
    return {
      ...empty,
      pathType: "exact",
      pathExact: pathMatcher.value,
    };
  }

  if (pathMatcher.kind !== "glob") {
    return {
      ...empty,
      pathType: "regex",
    };
  }

  const path = String(pathMatcher.pattern || "").trim();
  if (!path.includes("*")) {
    return {
      ...empty,
      pathType: "exact",
      pathExact: path,
    };
  }

  const prefixCandidate = path.endsWith("/**") ? path.slice(0, -3) : null;
  if (
    prefixCandidate !== null &&
    prefixCandidate.length > 0 &&
    !prefixCandidate.includes("*")
  ) {
    return {
      ...empty,
      pathType: "prefix",
      pathPrefix: prefixCandidate,
    };
  }

  return {
    ...empty,
    pathType: "regex",
  };
}
