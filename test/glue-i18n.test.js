import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const setupDom = () => {
  const makeEl = () => ({
    style: { setProperty() {} },
    classList: { add() {}, remove() {} },
    appendChild() {},
    addEventListener() {},
    remove() {},
    innerHTML: "",
    textContent: "",
  });
  const store = new Map();
  const getEl = (id) => {
    if (!store.has(id)) store.set(id, makeEl());
    return store.get(id);
  };
  globalThis.document = {
    title: "",
    head: { appendChild() {} },
    documentElement: { appendChild() {} },
    body: { innerHTML: "", appendChild() {}, style: { setProperty() {} } },
    createElement: () => makeEl(),
    getElementById: (id) => getEl(id),
    querySelectorAll: () => [],
    addEventListener() {},
  };
  globalThis.window = {
    location: { href: "https://example.com/", replace() {}, reload() {} },
    parent: null,
    opener: null,
    innerWidth: 1200,
    innerHeight: 800,
  };
  globalThis.window.parent = globalThis.window;
  Object.defineProperty(globalThis, "navigator", {
    value: { languages: ["en-US"], language: "en-US" },
    configurable: true,
  });
  globalThis.setTimeout = (fn) => 0;
  globalThis.requestAnimationFrame = () => 0;
};

setupDom();
const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const glueUrl = `${pathToFileURL(join(repoRoot, "glue.js")).href}?v=${Date.now()}`;
const glue = await import(glueUrl);

test("resolveLocale selects supported languages", () => {
  assert.equal(glue.resolveLocale(["zh-CN", "en-US"]), "zh");
  assert.equal(glue.resolveLocale(["ja-JP", "en-US"]), "ja");
  assert.equal(glue.resolveLocale(["fr-FR"]), "en");
});

test("translate returns localized text and formats variables", () => {
  assert.equal(glue.translate("zh", "title_verifying"), "验证中...");
  assert.equal(glue.translate("ja", "title_verifying"), "確認中...");
  assert.equal(
    glue.translate("en", "connection_retry", { ms: 500 }),
    "Connection error. Retrying in 500ms..."
  );
});

test("translate falls back to key when missing", () => {
  assert.equal(glue.translate("ja", "missing_key"), "missing_key");
});

test("title uses shine class while verifying", () => {
  assert.match(document.body.innerHTML, /id="t"[^>]*class="[^"]*shine/);
});
