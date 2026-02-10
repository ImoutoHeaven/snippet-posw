import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { stat } from "node:fs/promises";
import { runBuild, repoRoot } from "../lib/build-lock.js";

const powConfigSnippet = join(repoRoot, "dist", "pow_config_snippet.js");
const powCore1Snippet = join(repoRoot, "dist", "pow_core1_snippet.js");
const powCore2Snippet = join(repoRoot, "dist", "pow_core2_snippet.js");
const SNIPPET_BUDGET = 32 * 1024;

test("split snippets stay within 32KiB budget", async () => {
  await runBuild();
  const [powConfigInfo, core1Info, core2Info] = await Promise.all([
    stat(powConfigSnippet),
    stat(powCore1Snippet),
    stat(powCore2Snippet),
  ]);

  assert.ok(
    powConfigInfo.size <= SNIPPET_BUDGET,
    `dist/pow_config_snippet.js size ${powConfigInfo.size} exceeds budget ${SNIPPET_BUDGET}`
  );
  assert.ok(
    core1Info.size <= SNIPPET_BUDGET,
    `dist/pow_core1_snippet.js size ${core1Info.size} exceeds budget ${SNIPPET_BUDGET}`
  );
  assert.ok(
    core2Info.size <= SNIPPET_BUDGET,
    `dist/pow_core2_snippet.js size ${core2Info.size} exceeds budget ${SNIPPET_BUDGET}`
  );
});
