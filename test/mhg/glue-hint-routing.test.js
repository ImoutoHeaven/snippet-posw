import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

const setupDom = () => {
  const makeEl = () => ({
    style: { setProperty() {} },
    classList: { add() {}, remove() {} },
    appendChild() {},
    addEventListener() {},
    innerHTML: "",
    textContent: "",
  });
  globalThis.document = {
    title: "",
    head: makeEl(),
    documentElement: makeEl(),
    body: makeEl(),
    createElement: () => makeEl(),
    getElementById: () => makeEl(),
    querySelectorAll: () => [],
    addEventListener() {},
  };
  globalThis.window = {
    location: { href: "https://example.com/", reload() {}, replace() {} },
    parent: null,
    opener: null,
    innerWidth: 1200,
    innerHeight: 800,
    sessionStorage: { getItem() { return null; }, setItem() {}, removeItem() {}, clear() {} },
  };
  globalThis.window.parent = globalThis.window;
  Object.defineProperty(globalThis, "navigator", {
    value: { languages: ["en-US"], language: "en-US" },
    configurable: true,
  });
  globalThis.requestAnimationFrame = () => 0;
};

const loadRouteHintAction = async () => {
  setupDom();
  const glueUrl = `${pathToFileURL(join(repoRoot, "glue.js")).href}?v=${Date.now()}-${Math.random()}`;
  const mod = await import(glueUrl);
  return mod.routeHintAction;
};

test("stale triggers bounded reload", async () => {
  const routeHintAction = await loadRouteHintAction();
  const out = routeHintAction({ status: 403, hint: "stale" });
  assert.equal(out.action, "reload");
  assert.equal(out.bounded, true);
});

test("cheat hard-fails immediately", async () => {
  const routeHintAction = await loadRouteHintAction();
  const out = routeHintAction({ status: 403, hint: "cheat" });
  assert.equal(out.action, "hard_fail");
  assert.equal(out.bounded, false);
});

test("missing hint follows stale compatibility branch", async () => {
  const routeHintAction = await loadRouteHintAction();
  const out = routeHintAction({ status: 403, hint: null });
  assert.equal(out.action, "reload");
  assert.equal(out.bounded, true);
});

test("unknown hint hard-fails in glue routing", async () => {
  const routeHintAction = await loadRouteHintAction();
  const out = routeHintAction({ status: 403, hint: "weird" });
  assert.equal(out.action, "hard_fail");
  assert.equal(out.bounded, false);
});
