import test from "node:test";
import assert from "node:assert/strict";
import { writeFile, mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { buildCompiledConfig } from "../lib/build-config.js";

const writeTempConfig = async (contents) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "pow-config-"));
  const filePath = path.join(dir, "pow-config.js");
  await writeFile(filePath, contents, "utf-8");
  return filePath;
};

test("buildCompiledConfig compiles matcher-object when conditions", async () => {
  const filePath = await writeTempConfig(`
const CONFIG = [
  {
    host: { eq: "example.com" },
    path: { glob: "/api/**" },
    when: { ua: { re: "bot", flags: "i" } },
    config: { powcheck: true },
  },
];
`);

  const compiled = JSON.parse(await buildCompiledConfig(filePath));

  assert.equal(compiled.length, 1);
  const entry = compiled[0];
  assert.equal(entry.host.kind, "eq");
  assert.equal(entry.path.kind, "glob");
  assert.equal(entry.when.kind, "atom");
  assert.equal(entry.when.matcher.kind, "re");
  assert.equal(entry.when.matcher.source, "bot");
  assert.equal(entry.when.matcher.flags, "i");
});

test("buildCompiledConfig rejects invalid when conditions", async () => {
  const filePath = await writeTempConfig(`
 const CONFIG = [
   { host: { eq: "example.com" }, path: { glob: "/api/**" }, when: { foo: { eq: "bar" } }, config: { powcheck: true } },
 ];
  `);

  await assert.rejects(() => buildCompiledConfig(filePath), /supported condition field/i);
});

test("buildCompiledConfig rejects legacy host/path values", async () => {
  const hostPath = await writeTempConfig(`
 const CONFIG = [
   { host: "example.com", config: { powcheck: true } },
 ];
 `);
  await assert.rejects(() => buildCompiledConfig(hostPath), /host.*matcher object/i);

  const pathPath = await writeTempConfig(`
 const CONFIG = [
   { host: { eq: "example.com" }, path: /api/, config: { powcheck: true } },
 ];
 `);
  await assert.rejects(() => buildCompiledConfig(pathPath), /path.*matcher object/i);
});

test("buildCompiledConfig rejects legacy pattern key", async () => {
  const filePath = await writeTempConfig(`
 const CONFIG = [
   { pattern: "example.com", config: { powcheck: true } },
  ];
 `);

  await assert.rejects(() => buildCompiledConfig(filePath), /pattern/i);
});

test("buildCompiledConfig rejects missing host", async () => {
  const missingHostPath = await writeTempConfig(`
 const CONFIG = [
   { config: { powcheck: true } },
 ];
 `);

  await assert.rejects(() => buildCompiledConfig(missingHostPath), /host/i);
});

test("buildCompiledConfig rejects invalid path matcher", async () => {
  const filePath = await writeTempConfig(`
 const CONFIG = [
   { host: { eq: "example.com" }, path: { exists: true }, config: { powcheck: true } },
 ];
 `);

  await assert.rejects(() => buildCompiledConfig(filePath), /path.*exists.*not allowed/i);
});

test("buildCompiledConfig rejects invalid path glob syntax", async () => {
  const pathGlobPath = await writeTempConfig(`
 const CONFIG = [
   { host: { eq: "example.com" }, path: { glob: "/foo/**bar" }, config: {} },
 ];
 `);
  await assert.rejects(
    () => buildCompiledConfig(pathGlobPath),
    /CONFIG\.path.*invalid path glob.*standalone segment/i,
  );

  const tripleStarPath = await writeTempConfig(`
 const CONFIG = [
   { host: { eq: "example.com" }, path: { glob: "/foo/***" }, config: {} },
 ];
 `);
  await assert.rejects(
    () => buildCompiledConfig(tripleStarPath),
    /CONFIG\.path.*invalid path glob/i,
  );

  const whenPathGlobPath = await writeTempConfig(`
 const CONFIG = [
   { host: { eq: "example.com" }, when: { path: { glob: "/foo/a**b" } }, config: {} },
 ];
 `);
  await assert.rejects(
    () => buildCompiledConfig(whenPathGlobPath),
    /CONFIG\.when\.path.*invalid path glob/i,
  );
});

test("buildCompiledConfig works without structuredClone", async () => {
  const original = globalThis.structuredClone;
  try {
    globalThis.structuredClone = undefined;
    const filePath = await writeTempConfig(`
const CONFIG = [
  { host: { eq: "example.com" }, config: { powcheck: true } },
];
`);

    const compiled = JSON.parse(await buildCompiledConfig(filePath));

    assert.equal(compiled.length, 1);
    assert.ok(compiled[0].host);
  } finally {
    if (original === undefined) {
      delete globalThis.structuredClone;
    } else {
      globalThis.structuredClone = original;
    }
  }
});

test("buildCompiledConfig emits matcher metadata for host/path globs", async () => {
  const filePath = await writeTempConfig(`
 const CONFIG = [
   { host: { eq: "example.com" }, path: { glob: "/foo/**" }, when: { ua: { glob: "*bot*" } }, config: { powcheck: true } },
   { host: { glob: "*.example.com" }, path: { eq: "/bar" }, config: { turncheck: true } },
   { host: { glob: "foo*bar.example.com" }, path: { eq: "/baz" }, config: { softban: true } },
   { host: { eq: "example.net" }, path: { glob: "/**" }, config: { allow: true } },
   { host: { eq: "example.com" }, config: { hostonly: true } },
   { host: { eq: "example.org" }, path: { glob: "/a/*/b/**" }, config: { multi: true } },
   { host: { eq: "example.org" }, path: { glob: "/**/x" }, config: { multi2: true } },
 ];
 `);

  const compiled = JSON.parse(await buildCompiledConfig(filePath));

  assert.equal(compiled.length, 7);

  const entry0 = compiled[0];
  assert.equal(entry0.hostType, "exact");
  assert.equal(entry0.hostExact, "example.com");
  assert.equal(entry0.pathType, "prefix");
  assert.equal(entry0.pathPrefix, "/foo");
  assert.deepEqual(entry0.whenNeeds, { ua: true });

  const entry1 = compiled[1];
  assert.equal(entry1.hostType, "wildcard");
  assert.deepEqual(entry1.hostLabels, ["*", "example", "com"]);
  assert.equal(entry1.hostLabelCount, 3);
  assert.equal(entry1.pathType, "exact");
  assert.equal(entry1.pathExact, "/bar");

  const entry2 = compiled[2];
  assert.equal(entry2.hostType, "regex");
  assert.equal(entry2.pathType, "exact");
  assert.equal(entry2.pathExact, "/baz");

  const entry3 = compiled[3];
  assert.equal(entry3.pathType, "regex");

  const entry4 = compiled[4];
  assert.equal(entry4.hostType, "exact");
  assert.equal(entry4.hostExact, "example.com");
  assert.equal(entry4.pathType, null);
  assert.equal(entry4.pathExact, null);
  assert.equal(entry4.pathPrefix, null);

  const entry5 = compiled[5];
  assert.equal(entry5.pathType, "regex");

  const entry6 = compiled[6];
  assert.equal(entry6.pathType, "regex");
});
