import test from "node:test";
import assert from "node:assert/strict";

import {
  validatePathGlobPattern,
  compilePathGlobRegexSource,
} from "../lib/rule-engine/path-glob.js";

test("/**/api matches zero or more directory segments", () => {
  const source = compilePathGlobRegexSource("/**/api");
  const regex = new RegExp(`^${source}$`);
  assert.equal(regex.test("/api"), true);
  assert.equal(regex.test("/v1/api"), true);
});

test("/foo/**/bar matches zero/many intermediate segments", () => {
  const source = compilePathGlobRegexSource("/foo/**/bar");
  const regex = new RegExp(`^${source}$`);
  assert.equal(regex.test("/foo/bar"), true);
  assert.equal(regex.test("/foo/a/b/bar"), true);
});

test("rejects embedded globstar and 3+ star runs", () => {
  assert.throws(() => validatePathGlobPattern("/foo/**bar"), /path glob/i);
  assert.throws(() => validatePathGlobPattern("/foo/***"), /path glob/i);
  assert.throws(() => validatePathGlobPattern("/foo/a**b"), /path glob/i);
});

test("treats regex metacharacters literally inside path segments", () => {
  const source = compilePathGlobRegexSource("/a.+(b)/c[1]/{x}");
  const regex = new RegExp(`^${source}$`);
  assert.equal(regex.test("/a.+(b)/c[1]/{x}"), true);
  assert.equal(regex.test("/axxxb/c1/x"), false);
});

test("/**/ keeps trailing slash boundary with zero-segment support", () => {
  const source = compilePathGlobRegexSource("/**/");
  const regex = new RegExp(`^${source}$`);
  assert.equal(regex.test("/"), true);
  assert.equal(regex.test("/v1/"), true);
  assert.equal(regex.test("/v1"), false);
});

test("/foo/**/ keeps trailing slash boundary and allows zero segments", () => {
  const source = compilePathGlobRegexSource("/foo/**/");
  const regex = new RegExp(`^${source}$`);
  assert.equal(regex.test("/foo/"), true);
  assert.equal(regex.test("/foo/a/b/"), true);
  assert.equal(regex.test("/foo"), false);
});
