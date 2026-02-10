import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const readOptionalFile = async (filePath) => {
  try {
    return await readFile(filePath, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
};

const buildSplitCoreHarnessModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  const [
    core1SourceRaw,
    core2SourceRaw,
    transitSource,
    innerAuthSource,
    internalHeadersSource,
    apiEngineSource,
    businessGateSource,
    templateSource,
    mhgGraphSource,
    mhgMixSource,
    mhgMerkleSource,
  ] = await Promise.all([
    readFile(join(repoRoot, "pow-core-1.js"), "utf8"),
    readFile(join(repoRoot, "pow-core-2.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "transit-auth.js"), "utf8"),
    readOptionalFile(join(repoRoot, "lib", "pow", "inner-auth.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "internal-headers.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "api-engine.js")),
    readOptionalFile(join(repoRoot, "lib", "pow", "business-gate.js")),
    readOptionalFile(join(repoRoot, "template.html")),
    readFile(join(repoRoot, "lib", "mhg", "graph.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "mix-aes.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "merkle.js"), "utf8"),
  ]);

  const core1Source = replaceConfigSecret(core1SourceRaw, secret);
  const core2Source = replaceConfigSecret(core2SourceRaw, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-atomic-snapshot-split-"));
  await mkdir(join(tmpDir, "lib", "pow"), { recursive: true });
  await mkdir(join(tmpDir, "lib", "mhg"), { recursive: true });

  const writes = [
    writeFile(join(tmpDir, "pow-core-1.js"), core1Source),
    writeFile(join(tmpDir, "pow-core-2.js"), core2Source),
    writeFile(join(tmpDir, "lib", "pow", "transit-auth.js"), transitSource),
    writeFile(join(tmpDir, "lib", "mhg", "graph.js"), mhgGraphSource),
    writeFile(join(tmpDir, "lib", "mhg", "mix-aes.js"), mhgMixSource),
    writeFile(join(tmpDir, "lib", "mhg", "merkle.js"), mhgMerkleSource),
  ];
  if (innerAuthSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "inner-auth.js"), innerAuthSource));
  }
  if (internalHeadersSource !== null) {
    writes.push(
      writeFile(join(tmpDir, "lib", "pow", "internal-headers.js"), internalHeadersSource)
    );
  }
  if (apiEngineSource !== null) {
    writes.push(writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineSource));
  }
  if (businessGateSource !== null) {
    let businessGateInjected = businessGateSource;
    if (templateSource !== null) {
      businessGateInjected = businessGateInjected.replace(
        /__HTML_TEMPLATE__/gu,
        JSON.stringify(templateSource)
      );
    }
    writes.push(writeFile(join(tmpDir, "lib", "pow", "business-gate.js"), businessGateInjected));
  }

const harnessSource = `
import core1 from "./pow-core-1.js";
import core2 from "./pow-core-2.js";

const toRequest = (input, init) =>
  input instanceof Request ? input : new Request(input, init);

const isTransitRequest = (request) =>
  request.headers.has("X-Pow-Transit");

const splitTrace = {
  core1Calls: 0,
  core2Calls: 0,
  originCalls: 0,
};

export default {
  async fetch(request) {
    const upstreamFetch = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const nextRequest = toRequest(input, init);
      if (isTransitRequest(nextRequest)) {
        splitTrace.core2Calls += 1;
        return core2.fetch(nextRequest);
      }
      splitTrace.originCalls += 1;
      return upstreamFetch(input, init);
    };
    try {
      splitTrace.core1Calls += 1;
      return await core1.fetch(request);
    } finally {
      globalThis.fetch = upstreamFetch;
    }
  },
};

export const __splitTrace = splitTrace;
`;
  const harnessPath = join(tmpDir, "split-core-harness.js");
  writes.push(writeFile(harnessPath, harnessSource));

  await Promise.all(writes);
  return harnessPath;
};

const buildConfigModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  const source = await readFile(join(repoRoot, "pow-config.js"), "utf8");
  const compiledConfig = JSON.stringify([
    {
      host: { s: "^example\\.com$", f: "" },
      path: null,
      config: {
        POW_TOKEN: "pow-secret",
        powcheck: false,
        turncheck: false,
        recaptchaEnabled: false,
        RECAPTCHA_PAIRS: [{ sitekey: "rk", secret: "rs" }],
        TURNSTILE_SITEKEY: "turn-site",
        TURNSTILE_SECRET: "turn-secret",
        ATOMIC_CONSUME: true,
      },
    },
  ]);
  const injected = source.replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-config-atomic-budget-"));
  const tmpPath = join(tmpDir, "pow-config.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

const runConfigThroughSplitRoute = async (request) => {
  const [harnessPath, configPath] = await Promise.all([
    buildSplitCoreHarnessModule(),
    buildConfigModule(),
  ]);
  const [harnessMod, configMod] = await Promise.all([
    import(`${pathToFileURL(harnessPath).href}?v=${Date.now()}`),
    import(`${pathToFileURL(configPath).href}?v=${Date.now()}`),
  ]);
  const harnessHandler = harnessMod.default.fetch;
  const configHandler = configMod.default.fetch;

  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input, init) => {
      const nextRequest = input instanceof Request ? input : new Request(input, init);
      if (nextRequest.headers.has("X-Pow-Inner") || nextRequest.headers.has("X-Pow-Inner-Count")) {
        return harnessHandler(nextRequest);
      }
      return new Response("ok", { status: 200 });
    };
    const response = await configHandler(request);
    return {
      status: response.status,
      body: await response.text(),
      trace: { ...harnessMod.__splitTrace },
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
};

const runAtomicSnapshotBoundaryCase = async ({ oversize }) => {
  const url = oversize
    ? `https://example.com/protected?__ts=${"t".repeat(8193)}`
    : `https://example.com/protected?__ts=${"t".repeat(8192)}`;
  return runConfigThroughSplitRoute(
    new Request(url, {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
        Accept: "application/json",
      },
    })
  );
};

const runAtomicSnapshotMalformedCase = async () => {
  return runConfigThroughSplitRoute(
    new Request("https://example.com/protected?__tt=bad*ticket", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
        Accept: "application/json",
      },
    })
  );
};

test("atomic snapshot boundary stays fail-closed", async () => {
  const ok = await runAtomicSnapshotBoundaryCase({ oversize: false });
  assert.equal(ok.status, 200);
  assert.equal(ok.trace.core1Calls, 1);
  assert.equal(ok.trace.core2Calls, 1);
  assert.equal(ok.trace.originCalls, 1);

  const oversize = await runAtomicSnapshotBoundaryCase({ oversize: true });
  assert.equal(oversize.status, 431);
  assert.equal(oversize.body, "");
  assert.equal(oversize.trace.core1Calls, 0);
  assert.equal(oversize.trace.core2Calls, 0);
  assert.equal(oversize.trace.originCalls, 0);

  const malformed = await runAtomicSnapshotMalformedCase();
  assert.equal(malformed.status, 400);
  assert.equal(malformed.body, "");
  assert.equal(malformed.trace.core1Calls, 0);
  assert.equal(malformed.trace.core2Calls, 0);
  assert.equal(malformed.trace.originCalls, 0);
});
