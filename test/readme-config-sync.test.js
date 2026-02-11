import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { __testNormalizeConfig } from "../pow-config.js";

const extractSection = (readme, heading, nextHeading) => {
  const start = readme.indexOf(heading);
  if (start === -1) return "";
  const end = readme.indexOf(nextHeading, start + heading.length);
  return end === -1 ? readme.slice(start) : readme.slice(start, end);
};

const extractDocConfigKeys = (readme) => {
  const section = extractSection(readme, "### `config` keys (all supported)", "### `when` conditions");
  const keys = new Set();
  for (const line of section.split(/\r?\n/u)) {
    const match = line.match(/^\|\s*`([^`]+)`\s*\|/u);
    if (match) keys.add(match[1]);
  }
  return keys;
};

test("README config keys stay in sync with runtime normalizeConfig keys", async () => {
  const readme = await readFile("README.md", "utf8");
  const docKeys = extractDocConfigKeys(readme);
  const runtimeKeys = new Set(Object.keys(__testNormalizeConfig({})));

  assert.equal(docKeys.size > 0, true, "README config table must not be empty");
  assert.deepEqual(docKeys, runtimeKeys);
});

test("README removes stale fields and documents whitepaper knobs", async () => {
  const readme = await readFile("README.md", "utf8");

  assert.equal(readme.includes("POW_SPINE_K"), false);
  assert.equal(readme.includes("POW_FORCE_EDGE_1"), false);
  assert.equal(readme.includes("POW_FORCE_EDGE_LAST"), false);
  assert.equal(readme.includes('digest = SHA256("hashcash|v4|"'), true);
  assert.equal(readme.includes("__Host-pow_commit` (v4)"), false);

  assert.match(
    readme,
    /\| `POW_PAGE_BYTES` \| `number` \| `16384` \|[^\n]*multiple of 16[^\n]*\|/u
  );
  assert.match(
    readme,
    /\| `POW_MIX_ROUNDS` \| `number` \| `2` \|[^\n]*`1\.\.4`[^\n]*\|/u
  );
  assert.match(
    readme,
    /\| `POW_OPEN_BATCH` \| `number` \| `4` \|[^\n]*`1\.\.256`[^\n]*\|/u
  );
});

test("README documents MHG mix implementation-only optimizations", async () => {
  const readme = await readFile("README.md", "utf8");

  assert.match(readme, /implementation-level optimization/u);
  assert.match(readme, /does not change protocol semantics/u);
  assert.match(readme, /derive per-index PA\/PB once and reuse across mix rounds/u);
  assert.match(readme, /AES-CBC trim uses `subarray\(0, pageBytes\)` view-based slicing/u);
});
