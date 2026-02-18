import test from "node:test";
import assert from "node:assert/strict";

globalThis.__COMPILED_CONFIG__ = [];
const powConfig = await import("../pow-config.js");
const { evaluateWhen, matchIpMatcher, pickConfigWithId, setCompiledConfigForTest } =
  powConfig.__test || {};

test("evaluateWhen handles implicit and/or/not for IR nodes", () => {
  assert.equal(typeof evaluateWhen, "function");
  const context = {
    ua: "SuperBot/1.0",
    path: "/API",
    method: "GET",
    country: "US",
    asn: "456",
    header: new Headers({ "x-allow": "1" }),
  };
  const condition = {
    kind: "and",
    children: [
      { kind: "atom", field: "country", matcher: { kind: "eq", value: "US" } },
      { kind: "atom", field: "ua", matcher: { kind: "glob", pattern: "*bot*", case: "insensitive" } },
      {
        kind: "and",
        children: [
          { kind: "atom", field: "path", matcher: { kind: "eq", value: "/API", case: "sensitive" } },
          { kind: "atom", field: "method", matcher: { kind: "eq", value: "GET" } },
        ],
      },
      {
        kind: "or",
        children: [
          { kind: "atom", field: "asn", matcher: { kind: "eq", value: "123" } },
          { kind: "atom", field: "asn", matcher: { kind: "eq", value: "456" } },
        ],
      },
      {
        kind: "not",
        child: {
          kind: "atom",
          field: "header",
          key: "x-deny",
          matcher: { kind: "exists", value: true },
        },
      },
    ],
  };

  assert.equal(evaluateWhen(condition, context), true);
  assert.equal(
    evaluateWhen(
      { ...condition, children: [...condition.children, { kind: "atom", field: "country", matcher: { kind: "eq", value: "CN" } }] },
      context,
    ),
    false,
  );
});

test("evaluateWhen matches ua and path with explicit case semantics", () => {
  assert.equal(typeof evaluateWhen, "function");
  assert.equal(
    evaluateWhen(
      { kind: "atom", field: "ua", matcher: { kind: "glob", pattern: "*bot*", case: "insensitive" } },
      { ua: "MyBoT/2.0" },
    ),
    true,
  );
  assert.equal(
    evaluateWhen(
      { kind: "atom", field: "path", matcher: { kind: "eq", value: "/API", case: "sensitive" } },
      { path: "/api" },
    ),
    false,
  );
});

test("evaluateWhen path glob single-star does not cross slash", () => {
  assert.equal(
    evaluateWhen(
      { kind: "atom", field: "path", matcher: { kind: "glob", pattern: "/foo/*", case: "sensitive" } },
      { path: "/foo/a" },
    ),
    true,
  );
  assert.equal(
    evaluateWhen(
      { kind: "atom", field: "path", matcher: { kind: "glob", pattern: "/foo/*", case: "sensitive" } },
      { path: "/foo/a/b" },
    ),
    false,
  );
});

test("evaluateWhen path trailing globstar matches prefix and descendants", () => {
  const condition = {
    kind: "atom",
    field: "path",
    matcher: { kind: "glob", pattern: "/api/**", case: "sensitive" },
  };
  assert.equal(evaluateWhen(condition, { path: "/api" }), true);
  assert.equal(evaluateWhen(condition, { path: "/api/x" }), true);
});

test("evaluateWhen path glob /**/api matches root-level and nested api", () => {
  const condition = {
    kind: "atom",
    field: "path",
    matcher: { kind: "glob", pattern: "/**/api", case: "sensitive" },
  };

  assert.equal(evaluateWhen(condition, { path: "/api" }), true);
  assert.equal(evaluateWhen(condition, { path: "/v1/api" }), true);
});

test("matchIpMatcher supports ipv4 and ipv6 cidr", () => {
  assert.equal(typeof matchIpMatcher, "function");
  assert.equal(matchIpMatcher({ kind: "cidr", value: "192.168.1.0/24" }, "192.168.1.12"), true);
  assert.equal(matchIpMatcher({ kind: "cidr", value: "192.168.1.0/24" }, "192.168.2.12"), false);
  assert.equal(matchIpMatcher({ kind: "cidr", value: "2001:db8::/32" }, "2001:db8::1"), true);
  assert.equal(matchIpMatcher({ kind: "cidr", value: "2001:db8::/32" }, "2001:dead::1"), false);
});

test("evaluateWhen covers exists/glob/re for header/cookie/query", () => {
  assert.equal(typeof evaluateWhen, "function");
  const context = {
    header: new Headers({ "x-role": "AdminUser" }),
    cookie: new Map([
      ["session", "s-123"],
      ["mode", "beta"],
    ]),
    query: new URLSearchParams("tag=alpha&tag=beta"),
  };

  const condition = {
    kind: "and",
    children: [
      { kind: "atom", field: "header", key: "x-role", matcher: { kind: "glob", pattern: "*admin*" } },
      { kind: "atom", field: "cookie", key: "session", matcher: { kind: "re", source: "^s-[0-9]+$", flags: "" } },
      { kind: "atom", field: "query", key: "tag", matcher: { kind: "exists", value: true } },
    ],
  };

  assert.equal(evaluateWhen(condition, context), true);
  assert.equal(
    evaluateWhen(
      { kind: "atom", field: "query", key: "missing", matcher: { kind: "exists", value: false } },
      context,
    ),
    true,
  );
});

test("evaluateWhen returns false for malformed nodes", () => {
  assert.equal(typeof evaluateWhen, "function");
  assert.equal(evaluateWhen({ kind: "unknown" }, {}), false);
  assert.equal(evaluateWhen({ kind: "and", children: {} }, {}), false);
  assert.equal(evaluateWhen({ kind: "or", children: {} }, {}), false);
  assert.equal(evaluateWhen({ kind: "atom", field: "ua" }, { ua: "bot" }), false);
});

test("pickConfigWithId filters configs by IR when condition", () => {
  assert.equal(typeof setCompiledConfigForTest, "function");
  assert.equal(typeof pickConfigWithId, "function");

  const compiled = [
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
      path: null,
      pathType: null,
      when: {
        kind: "atom",
        field: "query",
        key: "tag",
        matcher: { kind: "eq", value: "beta", case: "insensitive" },
      },
      whenNeeds: { query: true },
      config: { id: "beta" },
    },
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
      path: null,
      pathType: null,
      when: {
        kind: "atom",
        field: "query",
        key: "tag",
        matcher: { kind: "eq", value: "delta", case: "insensitive" },
      },
      whenNeeds: { query: true },
      config: { id: "delta" },
    },
  ];

  const restore = setCompiledConfigForTest(compiled);
  try {
    const request = new Request("https://example.com/?tag=alpha&tag=beta", {
      headers: { "user-agent": "TestAgent" },
    });
    const url = new URL(request.url);
    const selected = pickConfigWithId(request, url, url.hostname, url.pathname);
    assert.equal(selected?.config?.id, "beta");
  } finally {
    restore();
  }
});

test("pickConfigWithId uses matcher metadata and fallback matcher", () => {
  assert.equal(typeof setCompiledConfigForTest, "function");
  assert.equal(typeof pickConfigWithId, "function");

  const compiled = [
    {
      host: { kind: "eq", value: "example.com" },
      path: { kind: "glob", pattern: "/foo/**", case: "sensitive" },
      hostType: "exact",
      hostExact: "example.com",
      pathType: "prefix",
      pathPrefix: "/foo",
      when: {
        kind: "atom",
        field: "ua",
        matcher: { kind: "glob", pattern: "*bot*", case: "insensitive" },
      },
      whenNeeds: { ua: true },
      config: { id: "meta" },
    },
    {
      host: { kind: "glob", pattern: "*.example.com", case: "insensitive" },
      path: { kind: "eq", value: "/bar", case: "sensitive" },
      hostType: null,
      hostRegex: null,
      pathType: null,
      pathRegex: null,
      when: null,
      config: { id: "fallback" },
    },
  ];

  const restore = setCompiledConfigForTest(compiled);
  try {
    const request0 = new Request("https://example.com/foo", {
      headers: { "user-agent": "bot" },
    });
    const url0 = new URL(request0.url);
    const selected0 = pickConfigWithId(request0, url0, url0.hostname, url0.pathname);
    assert.equal(selected0?.config?.id, "meta");

    const request1 = new Request("https://a.example.com/bar", {
      headers: { "user-agent": "browser" },
    });
    const url1 = new URL(request1.url);
    const selected1 = pickConfigWithId(request1, url1, url1.hostname, url1.pathname);
    assert.equal(selected1?.config?.id, "fallback");
  } finally {
    restore();
  }
});

test("pickConfigWithId keeps lazy cookie parsing with whenNeeds", () => {
  assert.equal(typeof setCompiledConfigForTest, "function");
  assert.equal(typeof pickConfigWithId, "function");

  const compiled = [
    {
      host: { kind: "eq", value: "example.com" },
      path: { kind: "eq", value: "/foo", case: "sensitive" },
      hostType: "exact",
      hostExact: "example.com",
      pathType: "exact",
      pathExact: "/foo",
      when: {
        kind: "atom",
        field: "ua",
        matcher: { kind: "glob", pattern: "*bot*", case: "insensitive" },
      },
      whenNeeds: { ua: true },
      config: { id: "ua" },
    },
    {
      host: { kind: "eq", value: "example.com" },
      path: { kind: "eq", value: "/foo", case: "sensitive" },
      hostType: "exact",
      hostExact: "example.com",
      pathType: "exact",
      pathExact: "/foo",
      when: {
        kind: "atom",
        field: "cookie",
        key: "session",
        matcher: { kind: "eq", value: "abc", case: "insensitive" },
      },
      whenNeeds: { cookie: true },
      config: { id: "cookie" },
    },
  ];

  const restore = setCompiledConfigForTest(compiled);
  try {
    const request = new Request("https://example.com/foo", {
      headers: { "user-agent": "browser", cookie: "session=abc" },
    });
    const url = new URL(request.url);
    const selected = pickConfigWithId(request, url, url.hostname, url.pathname);
    assert.equal(selected?.config?.id, "cookie");
  } finally {
    restore();
  }
});
