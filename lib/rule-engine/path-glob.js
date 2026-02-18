const escapeRegex = (value) => value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");

const compileSegment = (segment) =>
  segment
    .split("*")
    .map((part) => escapeRegex(part))
    .join("[^/]*");

export function validatePathGlobPattern(pattern) {
  const value = String(pattern ?? "");
  const segments = value.split("/");

  for (const segment of segments) {
    if (segment === "**") continue;
    if (segment.includes("**")) {
      throw new Error("Invalid path glob: '**' must be a standalone segment");
    }
  }
}

export function compilePathGlobRegexSource(pattern) {
  validatePathGlobPattern(pattern);

  const raw = String(pattern ?? "").split("/");
  const normalized = [];
  for (const segment of raw) {
    if (segment === "**" && normalized[normalized.length - 1] === "**") continue;
    normalized.push(segment);
  }

  const absolute = String(pattern ?? "").startsWith("/");
  const segments = absolute ? normalized.slice(1) : normalized;
  let out = absolute ? "/" : "";

  for (let i = 0; i < segments.length; i += 1) {
    const segment = segments[i];
    const prev = i > 0 ? segments[i - 1] : null;
    const next = i + 1 < segments.length ? segments[i + 1] : null;
    const prevSeg = prev !== null && prev !== "**";
    const nextSeg = next !== null && next !== "**";

    if (segment === "**") {
      if (prevSeg && nextSeg) out += "(?:/[^/]+)*/";
      else if (prevSeg && !nextSeg) out += "(?:/[^/]+)*";
      else if (!prevSeg && nextSeg) out += "(?:[^/]+/)*";
      else out += "(?:[^/]+(?:/[^/]+)*)?";
      continue;
    }

    if (i > 0 && prevSeg) out += "/";
    out += compileSegment(segment);
  }

  return out;
}
