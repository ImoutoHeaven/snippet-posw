import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { stat } from "node:fs/promises";
import { runBuild, repoRoot } from "../lib/build-lock.js";

const powSnippet = join(repoRoot, "dist", "pow_snippet.js");
const POW_SNIPPET_BUDGET = 31250;

test("pow snippet stays within 31250-byte budget", async () => {
  await runBuild();
  const info = await stat(powSnippet);
  assert.ok(
    info.size <= POW_SNIPPET_BUDGET,
    `dist/pow_snippet.js size ${info.size} exceeds budget ${POW_SNIPPET_BUDGET}`
  );
});
