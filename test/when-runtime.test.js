import test from "node:test";
import assert from "node:assert/strict";

globalThis.__COMPILED_CONFIG__ = [];
const powConfig = await import("../pow-config.js");
const { evaluateCondition, matchCidr } = powConfig.__test || {};

test("evaluateCondition handles implicit and/or/not", () => {
  assert.equal(typeof evaluateCondition, "function");
  const context = {
    ua: "SuperBot/1.0",
    path: "/API",
    method: "GET",
    country: "US",
    asn: "456",
    header: new Headers({ "x-allow": "1" }),
  };
  const condition = {
    country: "US",
    ua: "bot",
    and: [{ path: "/API" }, { method: "GET" }],
    or: [{ asn: "123" }, { asn: "456" }],
    not: { header: { "x-deny": { exists: true } } },
  };

  assert.equal(evaluateCondition(condition, context), true);
  assert.equal(evaluateCondition({ ...condition, ua: "crawler" }, context), false);
});

test("evaluateCondition matches ua as case-insensitive contains", () => {
  assert.equal(typeof evaluateCondition, "function");
  assert.equal(evaluateCondition({ ua: "bot" }, { ua: "MyBoT/2.0" }), true);
  assert.equal(evaluateCondition({ ua: "bot" }, { ua: "browser" }), false);
});

test("evaluateCondition matches path as case-sensitive exact", () => {
  assert.equal(typeof evaluateCondition, "function");
  assert.equal(evaluateCondition({ path: "/API" }, { path: "/API" }), true);
  assert.equal(evaluateCondition({ path: "/API" }, { path: "/api" }), false);
});

test("evaluateCondition returns false for unknown keys", () => {
  assert.equal(typeof evaluateCondition, "function");
  assert.equal(evaluateCondition({ unknown: "value" }, { ua: "bot" }), false);
});

test("matchCidr supports ipv4 and ipv6", () => {
  assert.equal(typeof matchCidr, "function");
  assert.equal(matchCidr("192.168.1.12", "192.168.1.0/24"), true);
  assert.equal(matchCidr("192.168.2.12", "192.168.1.0/24"), false);
  assert.equal(matchCidr("2001:db8::1", "2001:db8::/32"), true);
  assert.equal(matchCidr("2001:dead::1", "2001:db8::/32"), false);
});

test("evaluateCondition rejects invalid not values", () => {
  assert.equal(typeof evaluateCondition, "function");
  const context = { ua: "Agent" };
  assert.equal(evaluateCondition({ not: "invalid" }, context), false);
});

test("evaluateCondition treats empty object as match", () => {
  assert.equal(typeof evaluateCondition, "function");
  const context = { ua: "Agent" };
  assert.equal(evaluateCondition({}, context), true);
});

test("evaluateCondition handles header/cookie/query exists checks", () => {
  assert.equal(typeof evaluateCondition, "function");
  const context = {
    header: new Headers({ "x-flag": "on" }),
    cookie: new Map([
      ["session", "abc"],
      ["mode", "beta"],
    ]),
    query: new URLSearchParams("tag=alpha&tag=beta"),
  };

  assert.equal(evaluateCondition({ header: { "x-flag": { exists: true } } }, context), true);
  assert.equal(evaluateCondition({ header: { missing: { exists: true } } }, context), false);
  assert.equal(evaluateCondition({ cookie: { session: { exists: true } } }, context), true);
  assert.equal(evaluateCondition({ cookie: { missing: { exists: false } } }, context), true);
  assert.equal(evaluateCondition({ query: { tag: { exists: true } } }, context), true);
  assert.equal(evaluateCondition({ query: { missing: { exists: false } } }, context), true);
});

test("evaluateCondition matches header/cookie/query array and regex values", () => {
  assert.equal(typeof evaluateCondition, "function");
  const context = {
    header: new Headers({ "x-role": "admin" }),
    cookie: new Map([
      ["session", "abc"],
      ["mode", "beta"],
    ]),
    query: new URLSearchParams("tag=alpha&tag=beta"),
  };

  assert.equal(
    evaluateCondition({ header: { "x-role": ["user", "admin"] } }, context),
    true
  );
  assert.equal(evaluateCondition({ cookie: { mode: /bet/ } }, context), true);
  assert.equal(evaluateCondition({ query: { tag: /beta/ } }, context), true);
  assert.equal(
    evaluateCondition({ query: { tag: ["delta", "beta"] } }, context),
    true
  );
});

test("evaluateCondition matches any query value", () => {
  assert.equal(typeof evaluateCondition, "function");
  const context = {
    query: new URLSearchParams("tag=alpha&tag=beta"),
  };

  assert.equal(evaluateCondition({ query: { tag: "beta" } }, context), true);
  assert.equal(evaluateCondition({ query: { tag: "delta" } }, context), false);
});

test("pickConfigWithId filters configs by when", () => {
  const { __test } = powConfig;
  assert.equal(typeof __test?.setCompiledConfigForTest, "function");
  assert.equal(typeof __test?.pickConfigWithId, "function");
  const compiled = [
    {
      hostRegex: /example\.com/,
      pathRegex: null,
      when: { query: { tag: "beta" } },
      config: { id: "beta" },
    },
    {
      hostRegex: /example\.com/,
      pathRegex: null,
      when: { query: { tag: "delta" } },
      config: { id: "delta" },
    },
  ];
  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const request = new Request("https://example.com/?tag=alpha&tag=beta", {
      headers: { "user-agent": "TestAgent" },
    });
    const url = new URL(request.url);
    const selected = __test.pickConfigWithId(request, url, url.hostname, url.pathname);
    assert.equal(selected?.config?.id, "beta");
  } finally {
    restore();
  }
});

test("pickConfigWithId uses matcher metadata without changing results", () => {
  const { __test } = powConfig;
  assert.equal(typeof __test?.setCompiledConfigForTest, "function");
  assert.equal(typeof __test?.pickConfigWithId, "function");
  const compiled = [
    {
      host: { s: "^example\\.com$", f: "" },
      path: { s: "^/foo(?:/.*)?$", f: "" },
      hostType: "exact",
      hostExact: "example.com",
      pathType: "prefix",
      pathPrefix: "/foo",
      when: { ua: "bot" },
      whenNeeds: { ua: true },
      config: { powcheck: true },
    },
    {
      host: { s: "^[^.]*\\.example\\.com$", f: "" },
      path: { s: "^/bar$", f: "" },
      hostType: "wildcard",
      hostLabels: ["*", "example", "com"],
      hostLabelCount: 3,
      pathType: "exact",
      pathExact: "/bar",
      when: null,
      config: { turncheck: true },
    },
  ];
  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const request0 = new Request("https://example.com/foo", {
      headers: { "user-agent": "bot" },
    });
    const url0 = new URL(request0.url);
    const selected0 = __test.pickConfigWithId(
      request0,
      url0,
      url0.hostname,
      url0.pathname
    );
    assert.equal(selected0?.cfgId, 0);

    const request1 = new Request("https://a.example.com/bar", {
      headers: { "user-agent": "browser" },
    });
    const url1 = new URL(request1.url);
    const selected1 = __test.pickConfigWithId(
      request1,
      url1,
      url1.hostname,
      url1.pathname
    );
    assert.equal(selected1?.cfgId, 1);
  } finally {
    restore();
  }
});

test("pickConfigWithId matches cookie when whenNeeds is missing", () => {
  const { __test } = powConfig;
  assert.equal(typeof __test?.setCompiledConfigForTest, "function");
  assert.equal(typeof __test?.pickConfigWithId, "function");
  const compiled = [
    {
      host: { s: "^example\\.com$", f: "" },
      path: { s: "^/foo$", f: "" },
      hostType: "exact",
      hostExact: "example.com",
      pathType: "exact",
      pathExact: "/foo",
      when: { cookie: { session: "abc" } },
      config: { powcheck: true },
    },
  ];
  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const request = new Request("https://example.com/foo", {
      headers: { cookie: "session=abc" },
    });
    const url = new URL(request.url);
    const selected = __test.pickConfigWithId(request, url, url.hostname, url.pathname);
    assert.equal(selected?.cfgId, 0);
  } finally {
    restore();
  }
});

test("pickConfigWithId parses cookie for later rules", () => {
  const { __test } = powConfig;
  assert.equal(typeof __test?.setCompiledConfigForTest, "function");
  assert.equal(typeof __test?.pickConfigWithId, "function");
  const compiled = [
    {
      host: { s: "^example\\.com$", f: "" },
      path: { s: "^/foo$", f: "" },
      hostType: "exact",
      hostExact: "example.com",
      pathType: "exact",
      pathExact: "/foo",
      when: { ua: "bot" },
      whenNeeds: { ua: true },
      config: { id: "ua" },
    },
    {
      host: { s: "^example\\.com$", f: "" },
      path: { s: "^/foo$", f: "" },
      hostType: "exact",
      hostExact: "example.com",
      pathType: "exact",
      pathExact: "/foo",
      when: { cookie: { session: "abc" } },
      whenNeeds: { cookie: true },
      config: { id: "cookie" },
    },
  ];
  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const request = new Request("https://example.com/foo", {
      headers: { "user-agent": "browser", cookie: "session=abc" },
    });
    const url = new URL(request.url);
    const selected = __test.pickConfigWithId(request, url, url.hostname, url.pathname);
    assert.equal(selected?.config?.id, "cookie");
  } finally {
    restore();
  }
});

test("pickConfigWithId matches prefix root path", () => {
  const { __test } = powConfig;
  assert.equal(typeof __test?.setCompiledConfigForTest, "function");
  assert.equal(typeof __test?.pickConfigWithId, "function");
  const compiled = [
    {
      host: { s: "^example\\.com$", f: "" },
      path: { s: "^/(?:.*)?$", f: "" },
      hostType: "exact",
      hostExact: "example.com",
      pathType: "prefix",
      pathPrefix: "/",
      when: null,
      config: { turncheck: true },
    },
  ];
  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const request = new Request("https://example.com/foo");
    const url = new URL(request.url);
    const selected = __test.pickConfigWithId(request, url, url.hostname, url.pathname);
    assert.equal(selected?.cfgId, 0);
  } finally {
    restore();
  }
});

test("pickConfigWithId falls back to regex when metadata missing", () => {
  const { __test } = powConfig;
  assert.equal(typeof __test?.setCompiledConfigForTest, "function");
  assert.equal(typeof __test?.pickConfigWithId, "function");
  const compiled = [
    {
      host: { s: "^example\\.com$", f: "" },
      path: { s: "^/foo$", f: "" },
      hostType: "exact",
      hostExact: null,
      pathType: "exact",
      pathExact: null,
      when: null,
      config: { powcheck: true },
    },
  ];
  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const request = new Request("https://example.com/foo");
    const url = new URL(request.url);
    const selected = __test.pickConfigWithId(request, url, url.hostname, url.pathname);
    assert.equal(selected?.cfgId, 0);
  } finally {
    restore();
  }
});
