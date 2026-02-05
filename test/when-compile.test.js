import test from "node:test";
import assert from "node:assert/strict";

import {
  compileWhenCondition,
  collectWhenNeeds,
  validateWhenCondition,
} from "../lib/when-compile.js";

test("compileWhenCondition serializes regex values", () => {
  const input = {
    ua: /bot/i,
    and: [{ country: "CN" }, { path: /\.(css|js)$/ }],
    not: { header: { "x-test": /deny/ } },
  };

  const output = compileWhenCondition(input);

  assert.deepEqual(output, {
    ua: { $re: { s: "bot", f: "i" } },
    and: [
      { country: "CN" },
      { path: { $re: { s: "\\.(css|js)$", f: "" } } },
    ],
    not: { header: { "x-test": { $re: { s: "deny", f: "" } } } },
  });
});

test("validateWhenCondition rejects unknown fields", () => {
  assert.throws(
    () =>
      validateWhenCondition({
        country: "US",
        extra: true,
      }),
    /unknown key/i,
  );
});

test("validateWhenCondition rejects nested unknown keys", () => {
  assert.throws(
    () => validateWhenCondition({ and: [{ country: "US", extra: true }] }),
    /unknown key/i,
  );
});

test("validateWhenCondition rejects invalid types", () => {
  assert.throws(
    () => validateWhenCondition({ and: { country: "US" } }),
    /and/i,
  );
  assert.throws(
    () => validateWhenCondition({ not: /oops/ }),
    /not/i,
  );
  assert.throws(
    () => validateWhenCondition({ tls: "yes" }),
    /tls/i,
  );
  assert.throws(
    () => validateWhenCondition({ country: ["US", 3] }),
    /country/i,
  );
  assert.throws(
    () => validateWhenCondition({ header: { "x-test": { exists: "no" } } }),
    /exists/i,
  );
});

test("validateWhenCondition rejects RegExp outside leaf values", () => {
  assert.throws(() => validateWhenCondition(/top/), /regexp/i);
  assert.throws(() => validateWhenCondition({ and: [/nested/] }), /regexp/i);
});

test("validateWhenCondition accepts leaf RegExp values", () => {
  assert.doesNotThrow(() => validateWhenCondition({ ua: /Firefox/ }));
  assert.doesNotThrow(() =>
    validateWhenCondition({ header: { "user-agent": /bot/i } }),
  );
});

test("validateWhenCondition allows null or undefined", () => {
  assert.doesNotThrow(() => validateWhenCondition(null));
  assert.doesNotThrow(() => validateWhenCondition(undefined));
});

test("validateWhenCondition accepts compiled regex values", () => {
  assert.doesNotThrow(() =>
    validateWhenCondition({ ua: { $re: { s: "bot", f: "i" } } }),
  );
  assert.doesNotThrow(() =>
    validateWhenCondition({ header: { "user-agent": { $re: { s: "bot" } } } }),
  );
  assert.doesNotThrow(() =>
    validateWhenCondition({ query: { q: [{ $re: { s: "abc" } }, "def"] } }),
  );
});

test("collectWhenNeeds reports used fields", () => {
  const input = {
    and: [
      { ua: "bot" },
      { header: { "x-test": { exists: true } } },
      { or: [{ cookie: { a: "1" } }, { query: { q: /x/ } }] },
      { not: { tls: true } },
      { ip: "203.0.113.0/24" },
      { country: "US" },
      { asn: "13335" },
      { path: "/healthz" },
      { method: "GET" },
    ],
  };

  const needs = collectWhenNeeds(input);

  assert.deepEqual(needs, {
    ua: true,
    header: true,
    cookie: true,
    query: true,
    tls: true,
    ip: true,
    country: true,
    asn: true,
    path: true,
    method: true,
  });
});

test("collectWhenNeeds skips unknown keys", () => {
  const input = {
    and: [{ extra: true }, { ua: "bot" }, { not: { path: "/healthz" } }],
  };

  const needs = collectWhenNeeds(input);

  assert.deepEqual(needs, {
    ua: true,
    path: true,
  });
});

test("collectWhenNeeds ignores compiled regex nodes", () => {
  const input = {
    and: [
      { ua: "bot" },
      { or: [{ path: "/foo" }, { $re: { s: "x" } }] },
    ],
  };

  const needs = collectWhenNeeds(input);

  assert.deepEqual(needs, {
    ua: true,
    path: true,
  });
});
