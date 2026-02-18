# snippet-posw

Stateless PoW and Turnstile gate for Cloudflare Snippets and Workers.

This project provides a self-contained L7 front gate that:

- Exposes a PoW API under `/{POW_API_PREFIX}/*` (default: `/__pow/*`).
- Supports PoW-only, turnstile-only, or combined mode.
- Issues a single proof cookie (`__Host-proof`) when non-atomic flow succeeds.
- Keeps server state stateless in snippet runtime; optional one-time consume is delegated to the siteverify worker when enabled.

## Files

- `pow-config.js`: policy frontload layer (rule match + bypass/bindPath/atomic derivation + signed inner snapshot).
- `pow-core-1.js`: business-path gate execution layer (proof/challenge/atomic decisions), consumes `inner.s`, and forwards with transit.
- `pow-core-2.js`: PoW API + verification engine (`/__pow/*` + validated business passthrough), requires valid transit plus signed inner metadata.
- `glue.js`: browser-side UI + orchestration loaded by challenge pages.
- `esm/esm.js`: browser-side PoW solver (`computePoswCommit`).
- `siteverify_provider/src/worker.js`: siteverify aggregator worker with optional D1 consume ledger.
- `dist/pow_config_snippet.js`: config snippet build output.
- `dist/pow_core1_snippet.js`: core-1 snippet build output.
- `dist/pow_core2_snippet.js`: core-2 snippet build output.

## Configuration

Edit `CONFIG` in `pow-config.js` with matcher objects for `host`, optional `path`, and optional `when`:

```js
const CONFIG = [
  {
    host: { eq: "example.com" },
    path: { glob: "/api/**" },
    when: {
      and: [
        { method: { in: ["GET", "POST"] } },
        { header: { "x-env": { eq: "prod" } } },
        { cookie: { session: { exists: true } } },
        { query: { tag: { re: "^(alpha|beta)$", flags: "i" } } },
      ],
    },
    config: {
      POW_TOKEN: "replace-me",
      powcheck: true,
      turncheck: true,
      ATOMIC_CONSUME: true,
      AGGREGATOR_POW_ATOMIC_CONSUME: true,
    },
  },
];
```

Notes:

- `POW_TOKEN` is required when `powcheck` or `turncheck` is `true`.
- `host` is required on every entry and must be a matcher object.
- No legacy compatibility exists: bare strings and `RegExp` literals are rejected for `host`, `path`, and `when`.
- Set `CONFIG_SECRET` to the same non-placeholder value in `pow-config.js`, `pow-core-1.js`, and `pow-core-2.js`.
- When `turncheck: true`, set `TURNSTILE_SITEKEY` and `TURNSTILE_SECRET`.
- `AGGREGATOR_POW_ATOMIC_CONSUME` is the only switch that enables aggregator-managed PoW one-time consume semantics.
- Rule matching is first-match-wins; put more specific rules first.
- `pow-core-1.js` and `pow-core-2.js` are fail-closed on missing/invalid inner or transit metadata.

## Architecture split

- `pow-config` is the only policy decision point.
- `pow-core-1` is business-path execution and transit issuer.
- `pow-core-2` is PoW API and verification endpoint.
- No-compat policy is strict: no compat, no migrate, no dead code branches.

Deployment chain is strict: `pow-config -> pow-core-1 -> pow-core-2`.

## Config Reference

Each `CONFIG` entry looks like:

```js
{
  host: { glob: "*.example.com" },
  path: { glob: "/api/**" },
  when: { ua: { glob: "*bot*" } },
  config: { /* keys below */ }
}
```

### Matcher DSL (`host`, `path`, `when`)

All matching uses matcher objects. Legacy string and `RegExp` shorthand is not supported.

Text matchers (`host`, `path`, `ua`, `country`, `asn`, `method`, `header.*`, `cookie.*`, `query.*`):

- `{ eq: "value" }`
- `{ in: ["a", "b"] }`
- `{ glob: "pattern*" }`
- `{ re: "^expr$", flags: "i" }`
- `{ exists: true|false }` (only for `header.*`, `cookie.*`, and `query.*`)

Matcher operator semantics are strict:

- `eq` is exact literal equality (for example, `ua: { eq: "A*B" }` matches only `A*B`).
- `glob` is wildcard matching with field-specific boundaries:
  - `host.glob`: `*` matches any chars except `.` (does not cross DNS labels).
  - `path.glob`: `*` matches within one segment; `**` matches zero or more full directory segments.
  - `path.glob`: `**` is valid only as a standalone segment (for example: `/api/**`, `/**/api`, `/a/**/b`).
  - `path.glob`: invalid forms are rejected (`a**b`, `***`, `**a`, `a**`).
  - `path.glob`: invalid syntax is rejected at config compile time; malformed runtime IR fails closed (no match).
  - `path.glob` trailing `/**` matches zero extra segments, so `/api/**` matches both `/api` and `/api/x`.
  - generic text glob (for non-host/non-path text fields): `*` can match across any chars.
- `re` is regular expression matching.

IP matchers (`ip`):

- `{ eq: "203.0.113.4" }`
- `{ in: ["203.0.113.4", "203.0.113.5"] }`
- `{ cidr: "203.0.113.0/24" }`

Logic matchers in `when`:

- `{ and: [ ...conditions ] }`
- `{ or: [ ...conditions ] }`
- `{ not: { ...condition } }`

| Field | Type | Description |
|---|---|---|
| `host` | `matcher object` | Required text matcher. For `glob`, `*` does not cross `.`; use `eq` for exact host. |
| `path` | `matcher object` | Optional text matcher. For `glob`, `*` stays within one segment, `**` matches zero or more full directory segments only when used as a standalone segment, and trailing `/**` also matches the prefix itself. |
| `when` | `condition object` | Optional boolean logic over matcher objects for request attributes. |

### `config` keys (all supported)

| Key | Type | Default | Description |
|---|---|---|---|
| `powcheck` | `boolean` | `false` | Enable PoW gate (requires `__Host-proof` with `m & 1` when non-atomic). |
| `turncheck` | `boolean` | `false` | Enable Turnstile gate (requires `__Host-proof` with `m & 2` when non-atomic). |
| `bindPathMode` | `"none", "query", "header"` | `"none"` | Path binding derivation mode for proxy-style routes. |
| `bindPathQueryName` | `string` | `"path"` | Query key used when `bindPathMode: "query"`. |
| `bindPathHeaderName` | `string` | `""` | Header key used when `bindPathMode: "header"`. |
| `stripBindPathHeader` | `boolean` | `false` | Remove bind-path header before origin proxy when enabled. |
| `POW_VERSION` | `number` | `3` | Ticket version. |
| `POW_API_PREFIX` | `string` | `"/__pow"` | Global API prefix for PoW endpoints. |
| `POW_DIFFICULTY_BASE` | `number` | `8192` | Base step count. |
| `POW_DIFFICULTY_COEFF` | `number` | `1.0` | Difficulty multiplier (steps ~= base * coeff). |
| `POW_MIN_STEPS` | `number` | `512` | Minimum step clamp. |
| `POW_MAX_STEPS` | `number` | `8192` | Maximum step clamp. |
| `POW_HASHCASH_BITS` | `number` | `0` | Root-bound hashcash bits (`0` disables). |
| `POW_PAGE_BYTES` | `number` | `16384` | MHG page size; normalized to a multiple of 16 (minimum 16). |
| `POW_MIX_ROUNDS` | `number` | `2` | MHG AES mix rounds per page (`1..4`, clamped). |
| `POW_SEGMENT_LEN` | `string, number` | `2` | Segment length as fixed `N` or range `"min-max"` (`1..16`). |
| `POW_SAMPLE_K` | `number` | `4` | Extra sampled indices per round. |
| `POW_CHAL_ROUNDS` | `number` | `10` | Challenge rounds. |
| `POW_OPEN_BATCH` | `number` | `4` | Indices per `/open` batch (`1..256`, clamped). |
| `POW_COMMIT_TTL_SEC` | `number` | `120` | TTL for `__Host-pow_commit`. |
| `POW_MAX_GEN_TIME_SEC` | `number` | `300` | Maximum generation-stage seconds. |
| `POW_TICKET_TTL_SEC` | `number` | `600` | Ticket TTL. |
| `PROOF_TTL_SEC` | `number` | `600` | Proof cookie TTL. |
| `PROOF_RENEW_ENABLE` | `boolean` | `false` | Enable sliding renewal for `__Host-proof`. |
| `PROOF_RENEW_MAX` | `number` | `2` | Max renewal count. |
| `PROOF_RENEW_WINDOW_SEC` | `number` | `90` | Renew only near expiry. |
| `PROOF_RENEW_MIN_SEC` | `number` | `30` | Minimum interval between renewals. |
| `ATOMIC_CONSUME` | `boolean` | `false` | Enable atomic transport contract on protected business requests. |
| `AGGREGATOR_POW_ATOMIC_CONSUME` | `boolean` | `false` | Enable aggregator-managed one-time consume for PoW atomic mode. |
| `ATOMIC_TURN_QUERY` | `string` | `"__ts"` | Query parameter carrying atomic turnstile token envelope. |
| `ATOMIC_TICKET_QUERY` | `string` | `"__tt"` | Query parameter carrying ticket for atomic flows. |
| `ATOMIC_CONSUME_QUERY` | `string` | `"__ct"` | Query parameter carrying consume token for atomic flows. |
| `ATOMIC_TURN_HEADER` | `string` | `"x-turnstile"` | Header carrying atomic turnstile token envelope. |
| `ATOMIC_TICKET_HEADER` | `string` | `"x-ticket"` | Header carrying ticket for atomic flows. |
| `ATOMIC_CONSUME_HEADER` | `string` | `"x-consume"` | Header carrying consume token for atomic flows. |
| `ATOMIC_COOKIE_NAME` | `string` | `"__Secure-pow_a"` | Short-lived cookie used for atomic navigation fallback. |
| `STRIP_ATOMIC_QUERY` | `boolean` | `true` | Strip atomic query params before origin proxying. |
| `STRIP_ATOMIC_HEADERS` | `boolean` | `true` | Strip atomic headers before origin proxying. |
| `INNER_AUTH_QUERY_NAME` | `string` | `""` | Query key for internal bypass (requires value pair). |
| `INNER_AUTH_QUERY_VALUE` | `string` | `""` | Query value for internal bypass (requires name pair). |
| `INNER_AUTH_HEADER_NAME` | `string` | `""` | Header key for internal bypass (requires value pair). |
| `INNER_AUTH_HEADER_VALUE` | `string` | `""` | Header value for internal bypass (requires name pair). |
| `stripInnerAuthQuery` | `boolean` | `true` | Strip internal bypass query key when match succeeds. |
| `stripInnerAuthHeader` | `boolean` | `true` | Strip internal bypass header when match succeeds. |
| `POW_BIND_PATH` | `boolean` | `false` | Bind ticket to canonical path hash. |
| `POW_BIND_IPRANGE` | `boolean` | `true` | Bind ticket to IP CIDR (from `CF-Connecting-IP`). |
| `POW_BIND_COUNTRY` | `boolean` | `true` | Bind ticket to `request.cf.country`. |
| `POW_BIND_ASN` | `boolean` | `true` | Bind ticket to `request.cf.asn`. |
| `POW_BIND_TLS` | `boolean` | `true` | Bind ticket to TLS fingerprint fields from `request.cf`. |
| `IPV4_PREFIX` | `number` | `32` | IPv4 prefix used by IP binding (`0..32`). |
| `IPV6_PREFIX` | `number` | `128` | IPv6 prefix used by IP binding (`0..128`). |
| `POW_COMMIT_COOKIE` | `string` | `"__Host-pow_commit"` | Global commit cookie name. |
| `POW_ESM_URL` | `string` | (repo-pinned) | ESM worker URL for browser PoW solve logic. |
| `POW_GLUE_URL` | `string` | (repo-pinned) | ESM glue runtime URL for challenge orchestration. |
| `SITEVERIFY_URLS` | `string[]` | `[]` | Optional aggregator shard list; requests are deterministically routed by `ticketMac`. |
| `SITEVERIFY_AUTH_KID` | `string` | `"v1"` | siteverify auth key id. |
| `SITEVERIFY_AUTH_SECRET` | `string` | `""` | siteverify auth secret. |
| `TURNSTILE_SITEKEY` | `string` | — | Turnstile site key. |
| `TURNSTILE_SECRET` | `string` | — | Turnstile secret key. |
| `POW_TOKEN` | `string` | — | HMAC secret for ticket and cookie MACs. |

### `when` conditions

Each `CONFIG` entry may include an optional `when` field with boolean logic (`and`, `or`, `not`) over `country`, `asn`, `ip`, `method`, `ua`, `path`, `tls`, `header`, `cookie`, and `query`, and every leaf must be a matcher object.

## Proof Cookie (`__Host-proof`)

The proof cookie format is `v1.{ticketB64}.{iat}.{last}.{n}.{m}.{mac}` where mask `m` uses only:

- `1` = PoW
- `2` = Turnstile
- `3` = PoW + Turnstile

A request is allowed when `(m & requiredMask) == requiredMask`.

## Turnstile and Atomic Flow

- `/__pow/cap` exists only for turnstile captcha-only non-atomic flow.
- Combined non-atomic flow verifies turnstile during final `POST /__pow/open`.
- Non-atomic PoW-only flow with `AGGREGATOR_POW_ATOMIC_CONSUME=true` verifies consume via aggregator in final `POST /__pow/open` even when `turncheck=false`.
- Atomic flow verifies on the business path with strict consume token validation.
- Atomic input transport priority remains cookie > header > query.

### Atomic transport details (PoW-only)

- When atomic PoW-only succeeds, `glue.js` forwards consume via one of: postMessage payload (`type: "POW_ATOMIC", mode: "pow"`), short-lived atomic cookie, or query fallback.
- Query/header names remain config-driven (`ATOMIC_CONSUME_QUERY` / `ATOMIC_CONSUME_HEADER`, defaults: `__ct` / `x-consume`).
- `pow-config` accepts consume-only atomic headers (`x-consume`) without requiring `x-turnstile`.
- `pow-config` also accepts cookie mode `1|c||<consume>` (empty captcha token) for PoW-only atomic redirects.

## 8-path matrix (PoW x Atomic x Turnstile)

This hard-cut model is an 8-path matrix with only three toggles: PoW (P), Atomic (A), Turnstile (T).

| # | P | A | T | Path Description | `pow-config` subrequests | `pow-core-1` subrequests | `pow-core-2` subrequests | Siteverify Timing | Core Interaction |
|---|---|---|---|---|---:|---:|---:|---|---|
| 0 | Off | Off | Off | No protection | 1 | 1 | 1 | None | Pass-through |
| 1 | Off | Off | On | Non-atomic turnstile-only | 1 | 1 | 1 | `/__pow/cap` verify | `POST /__pow/cap` |
| 2 | Off | On | Off | Invalid toggle (degenerates to #0) | 1 | 1 | 1 | None | Pass-through |
| 3 | Off | On | On | Atomic turnstile-only business consume | 1 | 1 | 2 | Business path verify + origin | Business request |
| 4 | On | Off | Off | PoW-only | 1 | 1 | 0 | None | `/commit`, `/challenge`, `/open` |
| 5 | On | Off | On | Non-atomic PoW + turnstile | 1 | 1 | 1 | Final `/__pow/open` verify | PoW API |
| 6 | On | On | Off | PoW-only atomic with aggregator consume | 1 | 1 | 2 | Business consume verify + origin | PoW API + Business |
| 7 | On | On | On | Atomic PoW + turnstile | 1 | 1 | 2 | Business verify + origin | PoW API + Business |

Subrequest matrix (API + business paths):

| Flow | `pow-config` subrequests | `pow-core-1` subrequests | `pow-core-2` subrequests | Total |
|---|---:|---:|---:|---:|
| Non-atomic `/__pow/cap` | 1 | 1 | 1 | 3 |
| Non-atomic combined final `/__pow/open` | 1 | 1 | 1 | 3 |
| Atomic turnstile-only business request | 1 | 1 | 2 | 4 |
| Atomic PoW business request (with or without turnstile) | 1 | 1 | 2 | 4 |

### Aggregator consume contract

- `AGGREGATOR_POW_ATOMIC_CONSUME=true` allows pow-only atomic consume and preserves turnstile atomic behavior.
- `SITEVERIFY_URLS` configures one or many aggregators: snippet hashes `ticketMac` and deterministically picks one shard.
- Local PoW validity and consume-MAC verification remain in snippet runtime.
- Aggregator receives only one-time consume contract material (`consumeKey`, `expireAt`) and enforces single-use semantics.

### Siteverify aggregator contract

`pow-core-2` integrates with a siteverify aggregator and consumes fixed-shape responses.

- Auth is strict: auth failure => 404.
- Non-auth responses are fixed 200 with ok/reason.
- Provider diagnostics are preserved: rawResponse always returned.
- Provider transport failures are normalized: provider network failure maps to provider `httpStatus=502`.
- PoW consume requires D1 binding name `POW_NONCE_DB`.
- Missing `POW_NONCE_DB` on consume requests returns `reason: "pow_nonce_db_missing"`.
- Schema bootstrap is opt-in via `INIT_TABLES` (top-level const in `siteverify_provider/src/worker.js`, optionally overridden by env `INIT_TABLES === true`).

### MHG mix hot-path optimizations

This is implementation-level optimization work and does not change protocol semantics.

- derive per-index PA/PB once and reuse across mix rounds.
- AES-CBC trim uses `subarray(0, pageBytes)` view-based slicing.

## Root-bound Hashcash (`POW_HASHCASH_BITS`)

This is a lightweight commitment-bound extra PoW condition checked on the last sampled index:

- `digest = SHA256("hashcash|v4|" || merkleRoot || chain[L])`
- Verification requires leading zero bits `>= POW_HASHCASH_BITS`.

## Build

```bash
npm install
npm run build
```

Snippet output is written to `dist/`.

Budget policy: `32 KiB` is a hard limit for each snippet. `23 KiB` is the best-effort target for `pow_core1_snippet.js` and `pow_core2_snippet.js`.

## Deploy

1. Set `CONFIG_SECRET` in `pow-config.js`, `pow-core-1.js`, and `pow-core-2.js`.
2. Build and deploy snippets in order: `pow-config -> pow-core-1 -> pow-core-2`.
3. Keep `/__pow/*` reachable from clients during challenge flow.
