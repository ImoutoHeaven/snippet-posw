import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const buildTestModule = async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  const template = await readFile(join(repoRoot, "template.html"), "utf8");
  const compiledConfig = JSON.stringify([
    {
      host: { s: "^example\\.com$", f: "" },
      path: null,
      config: { POW_TOKEN: "test", powcheck: true, POW_BIND_TLS: false },
    },
  ]);
  const injected = powSource
    .replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template))
    .replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-test-"));
  const tmpPath = join(tmpDir, "pow-test.js");
  await writeFile(tmpPath, injected);
  return tmpPath;
};

test("unmatched host falls back to default config", async () => {
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return new Response("ok", { status: 200 });
  };

  const res = await handler(new Request("https://no-match.test/path"));
  assert.equal(res.status, 200);
  assert.equal(calls, 1);
});
