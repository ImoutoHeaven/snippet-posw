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

test("buildCompiledConfig compiles when conditions", async () => {
  const filePath = await writeTempConfig(`
const CONFIG = [
  { pattern: "example.com/api/**", when: { ua: /bot/i }, config: { powcheck: true } },
];
`);

  const compiled = JSON.parse(await buildCompiledConfig(filePath));

  assert.equal(compiled.length, 1);
  const entry = compiled[0];
  assert.equal(entry.when.ua.$re.s, "bot");
  assert.equal(entry.when.ua.$re.f, "i");
  assert.ok(entry.host && entry.host.s.length > 0);
  assert.ok(entry.path && entry.path.s.length > 0);
});

test("buildCompiledConfig rejects invalid when conditions", async () => {
  const filePath = await writeTempConfig(`
 const CONFIG = [
   { pattern: "example.com/api/**", when: { foo: "bar" }, config: { powcheck: true } },
 ];
 `);

  await assert.rejects(() => buildCompiledConfig(filePath), /unknown key/i);
});

test("buildCompiledConfig works without structuredClone", async () => {
  const original = globalThis.structuredClone;
  try {
    globalThis.structuredClone = undefined;
    const filePath = await writeTempConfig(`
const CONFIG = [
  { pattern: "example.com", config: { powcheck: true } },
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

test("buildCompiledConfig emits matcher metadata", async () => {
  const filePath = await writeTempConfig(`
const CONFIG = [
  { pattern: "example.com/foo/**", when: { ua: "bot" }, config: { powcheck: true } },
  { pattern: "*.example.com/bar", config: { turncheck: true } },
  { pattern: "foo*bar.example.com/baz", config: { softban: true } },
  { pattern: "example.net/**", config: { allow: true } },
  { pattern: "", config: { empty: true } },
  { pattern: "   ", config: { blank: true } },
  { pattern: "example.com", config: { hostonly: true } },
  { pattern: "example.org/a/*/b/**", config: { multi: true } },
  { pattern: "example.org/**/x", config: { multi2: true } },
];
`);

  const compiled = JSON.parse(await buildCompiledConfig(filePath));

  assert.equal(compiled.length, 9);

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
  assert.equal(entry4.hostType, null);
  assert.equal(entry4.pathType, null);

  const entry5 = compiled[5];
  assert.equal(entry5.hostType, null);
  assert.equal(entry5.pathType, null);

  const entry6 = compiled[6];
  assert.equal(entry6.hostType, "exact");
  assert.equal(entry6.hostExact, "example.com");
  assert.equal(entry6.pathType, null);
  assert.equal(entry6.pathExact, null);
  assert.equal(entry6.pathPrefix, null);

  const entry7 = compiled[7];
  assert.equal(entry7.pathType, "regex");

  const entry8 = compiled[8];
  assert.equal(entry8.pathType, "regex");
});
