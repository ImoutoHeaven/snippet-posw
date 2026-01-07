# snippet-posw

Stateless PoW / Turnstile gate for Cloudflare **Snippets / Workers**.

This project provides a self-contained L7 “front firewall” that:

- Exposes a PoW API under `/{POW_API_PREFIX}/*` (default: `/__pow/*`).
- Optionally verifies Turnstile under `/{POW_API_PREFIX}/turn`.
- Gates matched requests:
  - `powcheck: true` → requires `__Host-pow_sol`
  - `turncheck: true` → requires `__Host-turn_sol`
  - both enabled → requires both
- Stays **stateless** on the server side (no KV/DO/DB): everything is derived/verified with HMAC and short-lived cookies.

## Files

- `pow.js`: source snippet (PoW API + PoW gate).
- `glue.js`: browser-side UI + orchestration (loaded by the challenge page).
- `esm/esm.js`: browser-side PoW solver (`computePoswCommit`).
- `template.html`: minimal challenge page template injected into the build.
- `build.mjs`: build script (esbuild + HTML minify) → `dist/pow_snippet.js`.
- `dist/pow_snippet.js`: ready-to-paste Cloudflare Snippet output.

## Configuration

Edit `CONFIG` in `pow.js` to match your host/path patterns and enable **PoW** and/or **Turnstile**:

```js
const CONFIG = [
  { pattern: "example.com/**", config: { POW_TOKEN: "replace-me", powcheck: true } },
];
```

Notes:

- `POW_TOKEN` is required when `powcheck: true` (this snippet does not fall back to any other secret).
- When `turncheck: true`, you must also set:
  - `TURNSTILE_SITEKEY`
  - `TURNSTILE_SECRET`
- `pattern` matching is first-match-wins; put more specific rules first.

## Config Reference

Each `CONFIG` entry looks like:

```js
{ pattern: "example.com/**", config: { /* keys below */ } }
```

### `pattern` syntax

| Field | Type | Description |
|---|---|---|
| `pattern` | `string` | Host pattern with optional path glob: `host` or `host/path`. Host `*` matches a single label fragment (does not cross `.`). Path supports `*` (no `/`) and `**` (may include `/`); a trailing `/**` also matches the base path (e.g. `/foo/**` matches `/foo` and `/foo/...`). |

### `config` keys (all supported)

| Key | Type | Default | Description |
|---|---|---|---|
| `powcheck` | `boolean` | `false` | Enable PoW gate (requires `__Host-pow_sol`). |
| `turncheck` | `boolean` | `false` | Enable Turnstile gate (requires `__Host-turn_sol` and enables `POST /__pow/turn`). |
| `POW_TOKEN` | `string` | — | HMAC secret for ticket binding + cookie MACs. Required when `powcheck` or `turncheck` is `true`. |
| `TURNSTILE_SITEKEY` | `string` | — | Turnstile site key (client-side). Required when `turncheck: true`. |
| `TURNSTILE_SECRET` | `string` | — | Turnstile secret key (used for `siteverify`, includes `remoteip`). Required when `turncheck: true`. |
| `POW_GLUE_URL` | `string` | (repo-pinned) | ES module URL imported by the challenge page (client UI + orchestration). |
| `POW_ESM_URL` | `string` | (repo-pinned) | ES module URL for the PoW solver (`computePoswCommit`). Required when `powcheck: true`. |
| `POW_VERSION` | `number` | `3` | Ticket version (changing breaks existing cookies). |
| `POW_DIFFICULTY_BASE` | `number` | `8192` | Base step count. |
| `POW_DIFFICULTY_COEFF` | `number` | `1.0` | Difficulty multiplier (steps ≈ `base * coeff`). |
| `POW_MIN_STEPS` | `number` | `512` | Minimum step count (clamps computed steps). |
| `POW_MAX_STEPS` | `number` | `8192` | Maximum step count (clamps computed steps). |
| `POW_HASHCASH_BITS` | `number` | `3` | Extra hashcash check on the last index (0 disables). |
| `POW_SEGMENT_LEN` | `string \| number` | `"48-64"` | Segment length: fixed `N` or range `"min-max"` (each clamped to `1..64`). |
| `POW_SAMPLE_K` | `number` | `15` | Extra sampled indices per round (total extra ≈ `POW_SAMPLE_K * POW_CHAL_ROUNDS`). |
| `POW_SPINE_K` | `number` | `2` | Number of “spine” constraints per batch (`0` disables). |
| `POW_CHAL_ROUNDS` | `number` | `12` | Challenge rounds (controls how many indices are requested). |
| `POW_OPEN_BATCH` | `number` | `15` | Indices per `/open` batch (clamped to `1..32`). |
| `POW_FORCE_EDGE_1` | `boolean` | `true` | Always include index `1` in sampled indices. |
| `POW_FORCE_EDGE_LAST` | `boolean` | `true` | Always include the last index (forced on when `POW_HASHCASH_BITS > 0`). |
| `POW_COMMIT_TTL_SEC` | `number` | `120` | TTL for `__Host-pow_commit` (commit cookie). |
| `POW_TICKET_TTL_SEC` | `number` | `600` | TTL for challenge tickets. |
| `POW_SOL_TTL_SEC` | `number` | `600` | TTL for solution cookies (`__Host-pow_sol` / `__Host-turn_sol`). |
| `POW_SOL_SLIDING` | `boolean` | `false` | Enable sliding renewal for solution cookies. |
| `POW_SOL_RENEW_MAX` | `number` | `0` | Max renewal count (hard cap; signed). |
| `POW_SOL_RENEW_WINDOW_SEC` | `number` | `300` | Only renew when `exp - now <= window`. |
| `POW_SOL_RENEW_MIN_SEC` | `number` | `-1` | Minimum seconds between renewals; `-1` means “auto” (`POW_TICKET_TTL_SEC - 180`, clamped). |
| `POW_BIND_PATH` | `boolean` | `true` | Bind to canonical path hash; when enabled and `bindPathMode` is `query`/`header`, missing/invalid bindPath returns `400`. |
| `bindPathMode` | `"none"\|"query"\|"header"` | `"none"` | How to derive canonical path for binding (proxy-style endpoints). |
| `bindPathQueryName` | `string` | `"path"` | Query param name when `bindPathMode: "query"`. |
| `bindPathHeaderName` | `string` | `""` | Header name when `bindPathMode: "header"`. |
| `stripBindPathHeader` | `boolean` | `false` | If `true` and `bindPathMode: "header"`, delete the header before proxying upstream. |
| `POW_BIND_IPRANGE` | `boolean` | `true` | Bind to client IP CIDR (uses `CF-Connecting-IP`). |
| `IPV4_PREFIX` | `number` | `32` | IPv4 CIDR prefix length for IP binding (`0..32`). |
| `IPV6_PREFIX` | `number` | `64` | IPv6 CIDR prefix length for IP binding (`0..128`). |
| `POW_BIND_COUNTRY` | `boolean` | `false` | Bind to `request.cf.country`. |
| `POW_BIND_ASN` | `boolean` | `false` | Bind to `request.cf.asn`. |
| `POW_BIND_TLS` | `boolean` | `true` | Bind to TLS fingerprint derived from `request.cf.tlsClientExtensionsSha1` + `tlsClientCiphersSha1`. |

### Turnstile

Turnstile is implemented as a stateless gate:

- Challenge page renders Turnstile with `cData = ticket.mac`.
- The snippet calls Turnstile `siteverify` (1 subrequest) and enforces:
  - `success === true`
  - returned `cdata === ticket.mac` (binding)
- On success, the snippet issues `__Host-turn_sol` (separate from `__Host-pow_sol`).

Examples:

```js
// Turnstile only
{ pattern: "example.com/**", config: {
  POW_TOKEN: "replace-me",
  turncheck: true,
  TURNSTILE_SITEKEY: "0x4AAAAAA....",
  TURNSTILE_SECRET: "0x4AAAAAA....",
} },

// PoW + Turnstile
{ pattern: "example.com/**", config: {
  POW_TOKEN: "replace-me",
  powcheck: true,
  turncheck: true,
  TURNSTILE_SITEKEY: "0x4AAAAAA....",
  TURNSTILE_SECRET: "0x4AAAAAA....",
} },
```

### bindPath (for proxy-style endpoints)

If you have an endpoint whose *effective* target path is carried in a parameter/header (e.g. `/info?path=/some/object`), you can bind PoW to that target path **without** changing rule matching or difficulty selection:

- `bindPathMode: "query"` + `bindPathQueryName`
- `bindPathMode: "header"` + `bindPathHeaderName` (+ optional `stripBindPathHeader: true`)

When enabled, missing/invalid bindPath input returns `400`.

### Sliding renewal (managed-challenge-like)

To keep users passing the gate while they stay active (without redirects), enable sliding renewal for `__Host-pow_sol`.

When the client presents a valid cookie that is close to expiry, the snippet re-issues it with a new expiry and an incremented, **signed** renewal counter.

Config keys:

- `POW_SOL_SLIDING: true`
- `POW_SOL_RENEW_MAX`: max renew count (hard cap; cannot be bypassed by the client)
- `POW_SOL_RENEW_WINDOW_SEC`: only renew when `exp - now <= window` to avoid setting cookies on every request
- `POW_SOL_RENEW_MIN_SEC`: minimum time since last renewal; default `POW_TICKET_TTL_SEC - 180` (clamped)

Cookie format (v4):

- `v4.{ticketB64}.{iat}.{last}.{n}.{mac}`

`iat` stays constant across renewals, `last` tracks the last renewal timestamp, and the total lifetime is capped to at most `POW_SOL_TTL_SEC * (POW_SOL_RENEW_MAX + 1)` since `iat`.

## Build

```bash
npm install
npm run build
```

Output: `dist/pow_snippet.js` (checks the Cloudflare Snippet 32KB limit).

## Deploy

1. Build and copy `dist/pow_snippet.js` into Cloudflare **Snippets** (or deploy as a Worker).
2. Ensure it runs **before** any downstream auth/business snippets (if you use multiple snippets).
3. Keep `/__pow/*` reachable from browsers during the challenge flow.

---

## Design Notes

### Goals

- **Stateless**: no KV / DO / DB; everything is derived and verified with HMAC and short-lived cookies.
- **Priced access**: passing the gate mints a verifiable token (cookie), which can be treated as a “quota currency”.
- **Physical throughput ceiling**: the protocol enforces multi-round **serial** network round-trips (“RTT-lock”), so even extreme compute cannot bypass the latency bottleneck.

### High-level flow

1. Match a rule from `CONFIG` (first match wins) and merge with defaults.
2. If `powcheck` and/or `turncheck` is enabled and the request is missing required cookie(s):
   - Navigation/HTML requests get an HTML challenge page.
   - Non-navigation requests get `403` with a short `{ code }`.
3. PoW uses a stateless CCR API: `POST /__pow/commit` → `POST /__pow/challenge` → multiple `POST /__pow/open`.
4. On success, the snippet issues `__Host-pow_sol` (and/or `__Host-turn_sol`) as the access ticket.

### CCR: Commit → Challenge → Response/Open

PoW is implemented as a “CCR” handshake (commit first, then the server samples, then the client opens proofs):

1. **Commit**: the browser computes the PoSW commitment (`rootB64 + nonce`) and calls `POST /__pow/commit`.
   - The snippet verifies the ticket binding and mints a short-lived `__Host-pow_commit` cookie (contains `ticketB64/rootB64/pathHash/nonce/exp/spineSeed/mac`).
2. **Challenge**: the browser calls `POST /__pow/challenge`.
   - The snippet uses deterministic RNG derived from the commit to generate sampled `indices`, per-index `segLen`, and optional “midpoint proof” positions (`spinePos`), plus a `token` bound to the current batch cursor.
3. **Open**: the browser calls `POST /__pow/open` with `opens` for the sampled indices.
   - The snippet verifies and advances the cursor; repeats until done, then issues `__Host-pow_sol`.

Key properties:

- **No server-side session**: all “state” is either recomputed or carried in signed cookie/token.
- **Strict serial progression (RTT-lock)**: each `/open` depends on the previous cursor/token, so clients cannot parallelize or reorder batches.

### PoSW + Merkle: why sampling works

- The browser builds a strictly sequential hash chain of length `L` (“PoSW chain”).
- It commits to the full chain with a Merkle root (`rootB64`).
- For each sampled index `i`, the browser reveals:
  - `hPrev = chain[i - segLen]` with its Merkle proof
  - `hCurr = chain[i]` with its Merkle proof
  - optional midpoint `hMid` proof for extra constraints (`spinePos`)
- The snippet verifies:
  - **in-segment sequential derivation** (`hPrev` → … → `hCurr` in exactly `segLen` steps)
  - **Merkle membership proofs** for revealed chain values

This makes “skipping work”, “sparse computation”, or “fabricating opens” a losing bet: the attacker must hope sampled segments never cover their “bad steps / bad intervals”.

### RTT-lock and throughput ceiling

With default parameters:

- Total sampled indices: `S = 2 + POW_SAMPLE_K * POW_CHAL_ROUNDS = 182`
- `POW_OPEN_BATCH = 15` ⇒ number of `/open` calls: `m = ceil(S / 15) = 13`
- Total serial PoW API requests: `M_api = 1(/commit) + 1(/challenge) + m(/open) = 15`

So a single IP’s token minting throughput is bounded by:

- `tokens/s ≤ 1 / (M_api * RTT)`

This limit comes from network latency (physics), not local compute.

### “Exchange rate” with Cloudflare WAF Rate Limit

A practical ops pattern is to put a WAF Rate Limit (e.g. `50 req / 10s / per IP`) in front of both `/__pow/*` and protected paths.

Since minting one `pow_sol` consumes at least `M_api = 15` serial requests:

- `1 pow_sol ≈ 15 rate-limit units`
- Under `50/10s/IP`, each IP can mint at most `floor(50/15) = 3` tokens per 10 seconds (in the ideal case)

This effectively turns Cloudflare’s rate limiter into a *stateful* quota counter, while the snippet remains stateless.

### Parallelization and “chain break” economics

PoSW itself is not a magical “anti-parallel” primitive. Attackers may try to split the chain at some breakpoint and compute segments in parallel, gambling that samples never cross the breakpoint.

This implementation reduces the expected value of such attacks by:

- verifying *contiguous segments* (`(i - segLen, i]`) — any sample crossing the breakpoint fails immediately
- using deterministic, more evenly-covered sampling to reduce “lucky gaps”

### Operational tuning tips

- Prefer adjusting `POW_DIFFICULTY_COEFF` and/or lowering `POW_OPEN_BATCH` (stronger RTT-lock) instead of blindly increasing `POW_SAMPLE_K`/`POW_CHAL_ROUNDS`.
- Keep a WAF/RL budget that includes both `/__pow/*` and protected endpoints so token minting “spends” budget at a predictable rate.

### Managed Challenge (optional)

If you enable Turnstile (`turncheck: true`) with `cData` binding, Managed Challenge often adds little value and is usually unnecessary. Prefer tuning PoW/Turnstile + WAF Rate Limit; keep Managed Challenge only if you want an extra, independent hurdle.
