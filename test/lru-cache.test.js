import test from "node:test";
import assert from "node:assert/strict";
import { LruCache } from "../lib/rule-engine/lru-cache.js";

test("evicts oldest entry when over capacity", () => {
  const cache = new LruCache(2);
  cache.set("a", 1);
  cache.set("b", 2);
  cache.set("c", 3);

  assert.equal(cache.get("a"), undefined);
  assert.equal(cache.get("b"), 2);
  assert.equal(cache.get("c"), 3);
});

test("get refreshes recency", () => {
  const cache = new LruCache(2);
  cache.set("a", 1);
  cache.set("b", 2);
  cache.get("a");
  cache.set("c", 3);

  assert.equal(cache.get("a"), 1);
  assert.equal(cache.get("b"), undefined);
});

test("falls back to default limit when constructor limit is invalid", () => {
  const invalidLimits = [undefined, null, 0, -1, 1.5, Number.NaN];
  for (const limit of invalidLimits) {
    const cache = new LruCache(limit);
    assert.equal(cache.limit, 256);
  }
});

test("set on existing key refreshes recency and updates value", () => {
  const cache = new LruCache(2);
  cache.set("a", 1);
  cache.set("b", 2);
  cache.set("a", 3);
  cache.set("c", 4);

  assert.equal(cache.get("a"), 3);
  assert.equal(cache.get("b"), undefined);
  assert.equal(cache.get("c"), 4);
});
