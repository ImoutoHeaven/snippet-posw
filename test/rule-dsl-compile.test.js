import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { compileConfigEntry } from "../lib/rule-engine/compile.js";
import { buildCompiledConfig } from "../lib/build-config.js";

test("compiles glob and regex into IR", () => {
  const ir = compileConfigEntry({
    host: { glob: "*.example.com" },
    path: { re: "^/api/(v1|v2)/", flags: "" },
    when: { ua: { glob: "*bot*" } },
    config: { powcheck: true },
  });

  assert.equal(ir.host.kind, "glob");
  assert.equal(ir.path.kind, "re");
  assert.equal(ir.when.kind, "atom");
});

test("derives whenNeeds from compiled condition tree", () => {
  const ir = compileConfigEntry({
    host: { eq: "example.com" },
    when: {
      and: [
        { method: { in: ["GET", "POST"] } },
        { header: { "x-env": { eq: "prod" } } },
        { not: { cookie: { session: { exists: true } } } },
      ],
    },
    config: {},
  });

  assert.deepEqual(ir.whenNeeds, {
    method: true,
    header: true,
    cookie: true,
  });
});

test("emits host/path fast-match metadata where possible", () => {
  const entry = compileConfigEntry({
    host: { eq: "EXAMPLE.com" },
    path: { glob: "/api/**" },
    config: {},
  });

  assert.equal(entry.hostType, "exact");
  assert.equal(entry.hostExact, "example.com");
  assert.equal(entry.pathType, "prefix");
  assert.equal(entry.pathPrefix, "/api");
});

test("buildCompiledConfig validates then compiles IR", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "pow-config-"));
  const filePath = path.join(dir, "pow-config.js");
  await writeFile(
    filePath,
    `const CONFIG = [{ host: { eq: "example.com" }, when: { query: { q: { eq: "x" } } }, config: { powcheck: true } }];`,
    "utf-8",
  );

  const compiled = JSON.parse(await buildCompiledConfig(filePath));

  assert.equal(compiled.length, 1);
  assert.equal(compiled[0].host.kind, "eq");
  assert.equal(compiled[0].when.kind, "atom");
  assert.deepEqual(compiled[0].whenNeeds, { query: true });
  assert.equal(typeof compiled[0].config, "object");
});

test("compiler emits JSON-safe regex IR", () => {
  const ir = compileConfigEntry({
    host: { re: "^([a-z]+)\\.example\\.com$", flags: "i" },
    path: { re: "^/api/.*$", flags: "" },
    when: { ua: { re: "bot|crawler", flags: "i" } },
    config: {},
  });

  const serialized = JSON.stringify(ir);
  const parsed = JSON.parse(serialized);

  assert.equal(parsed.host.kind, "re");
  assert.equal(typeof parsed.host.source, "string");
  assert.equal(typeof parsed.host.flags, "string");
  assert.equal(Object.prototype.toString.call(parsed.host), "[object Object]");

  assert.equal(parsed.path.kind, "re");
  assert.equal(typeof parsed.path.source, "string");
  assert.equal(typeof parsed.path.flags, "string");

  assert.equal(parsed.when.kind, "atom");
  assert.equal(parsed.when.matcher.kind, "re");
  assert.equal(typeof parsed.when.matcher.source, "string");
  assert.equal(typeof parsed.when.matcher.flags, "string");
});

test("buildCompiledConfig rejects legacy matcher shape before compile", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "pow-config-"));
  const filePath = path.join(dir, "pow-config.js");
  await writeFile(
    filePath,
    `const CONFIG = [{ host: "example.com", config: {} }];`,
    "utf-8",
  );

  await assert.rejects(
    () => buildCompiledConfig(filePath),
    /host.*matcher object.*legacy strings/i,
  );
});

test("compileConfigEntry rejects invalid regex syntax", () => {
  assert.throws(
    () =>
      compileConfigEntry({
        host: { eq: "example.com" },
        path: { re: "(", flags: "" },
        config: {},
      }),
    /CONFIG\.path.*invalid regex/i,
  );
});

test("compileConfigEntry rejects invalid regex in non-map when atoms", () => {
  assert.throws(
    () =>
      compileConfigEntry({
        host: { eq: "example.com" },
        when: { ua: { re: "(", flags: "" } },
        config: {},
      }),
    /CONFIG\.when\.ua.*invalid regex/i,
  );

  assert.throws(
    () =>
      compileConfigEntry({
        host: { eq: "example.com" },
        when: { path: { re: "(", flags: "" } },
        config: {},
      }),
    /CONFIG\.when\.path.*invalid regex/i,
  );
});

test("ua.eq remains eq in IR and treats * literally", () => {
  const compiled = compileConfigEntry({
    host: { eq: "example.com" },
    when: { ua: { eq: "A*B" } },
    config: {},
  });

  assert.equal(compiled.when.kind, "atom");
  assert.equal(compiled.when.field, "ua");
  assert.deepEqual(compiled.when.matcher, { kind: "eq", value: "A*B" });
});
