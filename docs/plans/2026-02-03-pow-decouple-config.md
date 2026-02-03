# Pow Config Decoupling Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** pow.js 完全依赖 pow-config 下发的完整配置与派生绑定，支持分片内联头，移除 pow.js 内的 DEFAULTS/CONFIG/COMPILED 与所有回退路径。

**Architecture:** pow-config 负责匹配/归一化/派生/签名并下发；pow.js 仅验签/解包/执行业务核心，所有配置直接来自内联头；分片内联头由 pow-config 切片、pow.js 重组并验签。

**Tech Stack:** Cloudflare Snippets (JS), Node.js (node:test), build.mjs/esbuild

---

### Task 1: 更新内联头测试夹具为完整配置

**Files:**
- Modify: `test/default-config.test.js`

**Step 1: 写入完整配置夹具（覆盖 pow.js 所用 key）**

```js
const FULL_CONFIG = {
  powcheck: false,
  turncheck: false,
  bindPathMode: "none",
  bindPathQueryName: "path",
  bindPathHeaderName: "",
  stripBindPathHeader: false,
  POW_VERSION: 3,
  POW_API_PREFIX: "/__pow",
  POW_DIFFICULTY_BASE: 8192,
  POW_DIFFICULTY_COEFF: 1.0,
  POW_MIN_STEPS: 512,
  POW_MAX_STEPS: 8192,
  POW_HASHCASH_BITS: 3,
  POW_SEGMENT_LEN: "48-64",
  POW_SAMPLE_K: 15,
  POW_SPINE_K: 2,
  POW_CHAL_ROUNDS: 12,
  POW_OPEN_BATCH: 15,
  POW_FORCE_EDGE_1: true,
  POW_FORCE_EDGE_LAST: true,
  POW_COMMIT_TTL_SEC: 120,
  POW_TICKET_TTL_SEC: 600,
  PROOF_TTL_SEC: 600,
  PROOF_RENEW_ENABLE: false,
  PROOF_RENEW_MAX: 2,
  PROOF_RENEW_WINDOW_SEC: 90,
  PROOF_RENEW_MIN_SEC: 30,
  ATOMIC_CONSUME: false,
  ATOMIC_TURN_QUERY: "__ts",
  ATOMIC_TICKET_QUERY: "__tt",
  ATOMIC_CONSUME_QUERY: "__ct",
  ATOMIC_TURN_HEADER: "x-turnstile",
  ATOMIC_TICKET_HEADER: "x-ticket",
  ATOMIC_CONSUME_HEADER: "x-consume",
  ATOMIC_COOKIE_NAME: "__Secure-pow_a",
  STRIP_ATOMIC_QUERY: true,
  STRIP_ATOMIC_HEADERS: true,
  INNER_AUTH_QUERY_NAME: "",
  INNER_AUTH_QUERY_VALUE: "",
  INNER_AUTH_HEADER_NAME: "",
  INNER_AUTH_HEADER_VALUE: "",
  stripInnerAuthQuery: false,
  stripInnerAuthHeader: false,
  POW_BIND_PATH: true,
  POW_BIND_IPRANGE: true,
  POW_BIND_COUNTRY: false,
  POW_BIND_ASN: false,
  POW_BIND_TLS: true,
  IPV4_PREFIX: 32,
  IPV6_PREFIX: 64,
  POW_COMMIT_COOKIE: "__Host-pow_commit",
  POW_ESM_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@412f7fcc71c319b62a614e4252280f2bb3d7302b/esm/esm.js",
  POW_GLUE_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@412f7fcc71c319b62a614e4252280f2bb3d7302b/glue.js",
};
```

**Step 2: 更新内联头 payload 使用完整配置**

```js
const { payload, mac } = buildInnerHeaders(
  {
    v: 1,
    id: 0,
    c: { ...FULL_CONFIG, POW_TOKEN: "test" },
    d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
  },
  "config-secret"
);
```

**Step 3: 运行测试**

Run: `node --test test/default-config.test.js`

---

### Task 2: pow-config 完整归一化 + 分片内联头注入

**Files:**
- Modify: `pow-config.js`
- Test: `test/inner-config.test.js`

**Step 1: 新增分片内联头测试（先写测试）**

- 在 `buildConfigModule` 里构造超长字符串（例如在 `POW_GLUE_URL` 末尾追加重复段），确保 payload 超过分片阈值。

```js
test("pow-config emits chunked inner headers for large payload", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildConfigModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let forwarded = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };

    const res = await handler(
      new Request("https://example.com/protected", {
        headers: { "CF-Connecting-IP": "1.2.3.4" },
      })
    );
    assert.equal(res.status, 200);

    const count = forwarded.headers.get("X-Pow-Inner-Count");
    assert.ok(count, "chunk count set");
    const n = Number.parseInt(count, 10);
    assert.ok(n > 1, "uses multiple chunks");

    let combined = "";
    for (let i = 0; i < n; i++) {
      const part = forwarded.headers.get(`X-Pow-Inner-${i}`);
      assert.ok(part, `chunk ${i} present`);
      combined += part;
    }
    const mac = forwarded.headers.get("X-Pow-Inner-Mac") || "";
    assert.ok(mac.length > 0, "mac set");

    const expectedMac = base64Url(
      crypto.createHmac("sha256", "config-secret").update(combined).digest()
    );
    assert.equal(mac, expectedMac);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
```

**Step 2: 运行测试（应失败）**

Run: `node --test test/inner-config.test.js`
Expected: FAIL

**Step 3: 实现配置归一化和分片头写入**

- 扩展 `normalizeConfig` 覆盖 pow.js 所有使用字段，并强制 `POW_API_PREFIX`/`POW_COMMIT_COOKIE` 为默认值（不可覆写）。
- 新增分片写入：`X-Pow-Inner-Count` + `X-Pow-Inner-0..N-1`，`X-Pow-Inner-Mac` 仍对完整 payload 计算。
- 增强清理逻辑：删除 `X-Pow-Inner*` 所有头。

**Step 4: 运行测试（应通过）**

Run: `node --test test/inner-config.test.js`
Expected: PASS

---

### Task 3: pow.js 支持分片内联头 + 清理所有 X-Pow-Inner* 头

**Files:**
- Modify: `pow.js`
- Test: `test/snippet-chain.test.js`

**Step 1: 写失败测试（端到端分片）**

- 在 `buildConfigModule` 里构造超长字符串触发分片；断言 originRequest 不含任何 `X-Pow-Inner*`。

```js
test("pow-config -> pow.js strips chunked inner headers", async () => {
  // 构造超大配置触发分片，走完整链路
  // 断言 originRequest 不含任何 X-Pow-Inner* 头
});
```

**Step 2: 运行测试（应失败）**

Run: `node --test test/snippet-chain.test.js`
Expected: FAIL

**Step 3: 实现分片重组与验签**

- `readInnerPayload`：优先单头；否则读取 `X-Pow-Inner-Count` 并按序拼接 `X-Pow-Inner-0..N-1`；再做 HMAC 验签与 JSON 解析。
- `stripInnerHeaders`：删除 `X-Pow-Inner`、`X-Pow-Inner-Mac` 与所有 `X-Pow-Inner-*` 头。

**Step 4: 运行测试（应通过）**

Run: `node --test test/snippet-chain.test.js`
Expected: PASS

---

### Task 4: pow.js 移除 DEFAULTS 并完全依赖内联配置

**Files:**
- Modify: `pow.js`

**Step 1: 删除 DEFAULTS/CONFIG/COMPILED 与相关回退路径**

- 删除 `DEFAULTS` 常量与所有 `DEFAULTS.*` 引用
- 删除只用于默认回退/派生绑定的 helper（如 `computeIpScope`/`buildTlsFingerprintHash`）

**Step 2: 全面改为使用 config.* 并做最小可用性校验**

- `POW_API_PREFIX`、`POW_COMMIT_COOKIE`、`ATOMIC_*`、`POW_*` 全部从 `config` 读取
- 关键字段缺失/类型不对 → 直接 `500` fail-closed

**Step 3: 运行关键测试**

Run: `node --test test/default-config.test.js test/pow-challenge-binding.test.js test/inner-config.test.js test/snippet-chain.test.js`
Expected: PASS

---

### Task 5: 更新 README 文档

**Files:**
- Modify: `README.md`

**Step 1: 更新说明**

- pow.js 不再包含 DEFAULTS/CONFIG/COMPILED，配置完全由 pow-config 下发
- 内联头支持分片：`X-Pow-Inner-Count` + `X-Pow-Inner-0..N-1`
- `POW_API_PREFIX`/`POW_COMMIT_COOKIE` 视为全局不变（由 pow-config 固定默认值下发）

**Step 2: 运行构建测试（可选）**

Run: `node --test test/build-snippets.test.js`
Expected: PASS
