import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { readFile, stat, writeFile } from "node:fs/promises";
import { runBuild, distDir } from "../lib/build-lock.js";

const powConfigSnippet = join(distDir, "pow_config_snippet.js");
const powCore1Snippet = join(distDir, "pow_core1_snippet.js");
const powCore2Snippet = join(distDir, "pow_core2_snippet.js");
const legacyPowSnippet = join(distDir, "pow_snippet.js");

test("build emits pow-config and split core snippets", async () => {
  await runBuild({ cleanDist: true });

  const [configStat, core1Stat, core2Stat] = await Promise.all([
    stat(powConfigSnippet),
    stat(powCore1Snippet),
    stat(powCore2Snippet),
  ]);
  const limit = 32 * 1024;
  assert.ok(configStat.size > 0, "pow_config_snippet.js is empty");
  assert.ok(configStat.size <= limit, "pow_config_snippet.js exceeds 32KB");
  assert.ok(core1Stat.size > 0, "pow_core1_snippet.js is empty");
  assert.ok(core2Stat.size > 0, "pow_core2_snippet.js is empty");
  assert.ok(core1Stat.size <= limit, "pow_core1_snippet.js exceeds 32KB");
  assert.ok(core2Stat.size <= limit, "pow_core2_snippet.js exceeds 32KB");

  await writeFile(legacyPowSnippet, "// stale artifact\n", "utf8");
  await runBuild();
  await assert.rejects(
    stat(legacyPowSnippet),
    { code: "ENOENT" },
    "legacy pow_snippet.js should be absent after build"
  );

  const [configSource, core1Source, core2Source] = await Promise.all([
    readFile(powConfigSnippet, "utf8"),
    readFile(powCore1Snippet, "utf8"),
    readFile(powCore2Snippet, "utf8"),
  ]);
  assert.ok(!configSource.includes("__COMPILED_CONFIG__"));
  assert.ok(!core1Source.includes("__COMPILED_CONFIG__"));
  assert.ok(!core2Source.includes("__COMPILED_CONFIG__"));
  assert.ok(!core1Source.includes("__HTML_TEMPLATE__"));
  assert.ok(!core2Source.includes("__HTML_TEMPLATE__"));
});
