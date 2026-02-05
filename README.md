# snippet-posw

Stateless PoW / Turnstile gate for Cloudflare **Snippets / Workers**.

This project provides a self-contained L7 front gate that:

- Exposes a PoW API under `/{POW_API_PREFIX}/*` (default: `/__pow/*`).
- Supports **PoW-only**, **Turnstile-only**, or **combined** mode.
- Issues a single proof cookie (`__Host-proof`) on success.
- Stays **stateless** on the server side (no KV/DO/DB): all checks are derived/verified with HMAC and short-lived cookies.

## Files

- `pow-config.js`: front snippet (match config + derived binding values + signed inner header).
- `pow.js`: core gate snippet (PoW API + gate), requires the signed inner header.
- `glue.js`: browser-side UI + orchestration (loaded by the challenge page).
- `esm/esm.js`: browser-side PoW solver (`computePoswCommit`).
- `template.html`: minimal challenge page template injected into the build.
- `build.mjs`: build script (esbuild + HTML minify) → `dist/pow_config_snippet.js` + `dist/pow_snippet.js`.
- `dist/pow_config_snippet.js`: config snippet output.
- `dist/pow_snippet.js`: gate snippet output.

## Configuration

Edit `CONFIG` in `pow-config.js` to match your host/path rules and enable **PoW** and/or **Turnstile**:

```js
const CONFIG = [
  { host: "example.com", path: "/**", config: { POW_TOKEN: "replace-me", powcheck: true } },
];
```

Notes:

- `POW_TOKEN` is required when `powcheck` or `turncheck` is `true`.
- `host` is required on every entry; legacy `pattern` is not supported.
- Set `CONFIG_SECRET` to the same non-placeholder value in both `pow-config.js` and `pow.js`.
- When `turncheck: true`, you must also set:
  - `TURNSTILE_SITEKEY`
  - `TURNSTILE_SECRET`
- Rule matching is first-match-wins; put more specific rules first.
- `pow.js` does not embed `DEFAULTS/CONFIG/COMPILED`; configuration is entirely supplied by `pow-config`.
- The inner header supports sharding via `X-Pow-Inner-Count` + `X-Pow-Inner-0..N-1`.
- `POW_API_PREFIX` and `POW_COMMIT_COOKIE` are treated as global constants; `pow-config` supplies fixed defaults and per-entry overrides are ignored.
- `pow.js` has no fallback: missing/invalid inner header or failed signature returns `500`.

## Config Reference

Each `CONFIG` entry looks like:

```js
{ host: "example.com", path: "/**", config: { /* keys below */ } }
```

### `host`/`path` syntax

| Field | Type | Description |
|---|---|---|
| `host` | `string` | Host glob. `*` matches a single label segment (does not cross `.`). |
| `path` | `string` | Optional path glob. Supports `*` (no `/`) and `**` (may include `/`); a trailing `/**` also matches the base path (e.g. `/foo/**` matches `/foo` and `/foo/...`). Omit to match all paths on the host. |

### `config` keys (all supported)

| Key | Type | Default | Description |
|---|---|---|---|
| `powcheck` | `boolean` | `false` | Enable PoW gate (requires `__Host-proof` with `m & 1`). |
| `turncheck` | `boolean` | `false` | Enable Turnstile gate (requires `__Host-proof` with `m & 2`). |
| `POW_TOKEN` | `string` | — | HMAC secret for ticket binding + cookie MACs. Required when `powcheck` or `turncheck` is `true`. |
| `TURNSTILE_SITEKEY` | `string` | — | Turnstile site key (client-side). Required when `turncheck: true`. |
| `TURNSTILE_SECRET` | `string` | — | Turnstile secret key (used for `siteverify`, includes `remoteip`). Required when `turncheck: true`. |
| `ATOMIC_CONSUME` | `boolean` | `false` | Enable business-path atomic consume for Turnstile (and PoW+Turnstile). Disables `/__pow/turn`; in combined mode `/__pow/open` returns `consume` instead of setting `__Host-proof`. When Turnstile is required, proof cookies are ignored. |
| `ATOMIC_TURN_QUERY` | `string` | `"__ts"` | Query param for Turnstile token (atomic). |
| `ATOMIC_TICKET_QUERY` | `string` | `"__tt"` | Query param for ticket (`turn` + atomic). |
| `ATOMIC_CONSUME_QUERY` | `string` | `"__ct"` | Query param for consume token (combined + atomic). |
| `ATOMIC_TURN_HEADER` | `string` | `"x-turnstile"` | Header for Turnstile token (atomic). |
| `ATOMIC_TICKET_HEADER` | `string` | `"x-ticket"` | Header for ticket (`turn` + atomic). |
| `ATOMIC_CONSUME_HEADER` | `string` | `"x-consume"` | Header for consume token (combined + atomic). |
| `ATOMIC_COOKIE_NAME` | `string` | `"__Secure-pow_a"` | Short-lived cookie name for atomic navigation redirects; cleared after use. |
| `STRIP_ATOMIC_QUERY` | `boolean` | `true` | Remove atomic query params before proxying. |
| `STRIP_ATOMIC_HEADERS` | `boolean` | `true` | Remove atomic headers before proxying. |
| `POW_API_PREFIX` | `string` | `"/__pow"` | Global API prefix for PoW endpoints (fixed default from `pow-config`; per-entry override is ignored). |
| `POW_GLUE_URL` | `string` | (repo-pinned) | ES module URL imported by the challenge page (client UI + orchestration). |
| `POW_ESM_URL` | `string` | (repo-pinned) | ES module URL for the PoW solver (`computePoswCommit`). Required when `powcheck: true`. |
| `POW_VERSION` | `number` | `3` | Ticket version (changing breaks existing cookies). |
| `POW_DIFFICULTY_BASE` | `number` | `8192` | Base step count. |
| `POW_DIFFICULTY_COEFF` | `number` | `1.0` | Difficulty multiplier (steps ≈ `base * coeff`). |
| `POW_MIN_STEPS` | `number` | `512` | Minimum step count (clamps computed steps). |
| `POW_MAX_STEPS` | `number` | `8192` | Maximum step count (clamps computed steps). |
| `POW_HASHCASH_BITS` | `number` | `3` | Extra “root-bound hashcash” check on the last index (0 disables). |
| `POW_SEGMENT_LEN` | `string, number` | `"48-64"` | Segment length: fixed `N` or range `"min-max"` (each clamped to `1..64`). |
| `POW_SAMPLE_K` | `number` | `15` | Extra sampled indices per round (total extra ≈ `POW_SAMPLE_K * POW_CHAL_ROUNDS`). |
| `POW_SPINE_K` | `number` | `2` | Number of “spine” constraints per batch (`0` disables). |
| `POW_CHAL_ROUNDS` | `number` | `12` | Challenge rounds (controls how many indices are requested). |
| `POW_OPEN_BATCH` | `number` | `15` | Indices per `/open` batch (clamped to `1..32`). |
| `POW_FORCE_EDGE_1` | `boolean` | `true` | Always include index `1` in sampled indices. |
| `POW_FORCE_EDGE_LAST` | `boolean` | `true` | Always include the last index (forced on when `POW_HASHCASH_BITS > 0`). |
| `POW_COMMIT_TTL_SEC` | `number` | `120` | TTL for `__Host-pow_commit` (commit cookie). |
| `POW_TICKET_TTL_SEC` | `number` | `600` | TTL for challenge tickets. |
| `PROOF_TTL_SEC` | `number` | `600` | TTL for `__Host-proof`. |
| `PROOF_RENEW_ENABLE` | `boolean` | `false` | Enable sliding renewal for `__Host-proof`. |
| `PROOF_RENEW_MAX` | `number` | `2` | Max renewal count (hard cap; signed). |
| `PROOF_RENEW_WINDOW_SEC` | `number` | `90` | Only renew when `exp - now <= window`. |
| `PROOF_RENEW_MIN_SEC` | `number` | `30` | Minimum seconds between renewals. |
| `POW_BIND_PATH` | `boolean` | `true` | Bind to canonical path hash; when enabled and `bindPathMode` is `query`/`header`, missing/invalid bindPath returns `400`. |
| `bindPathMode` | `"none", "query", "header"` | `"none"` | How to derive canonical path for binding (proxy-style endpoints). |
| `bindPathQueryName` | `string` | `"path"` | Query param name when `bindPathMode: "query"`. |
| `bindPathHeaderName` | `string` | `""` | Header name when `bindPathMode: "header"`. |
| `stripBindPathHeader` | `boolean` | `false` | If `true` and `bindPathMode: "header"`, delete the header before proxying upstream. |
| `POW_BIND_IPRANGE` | `boolean` | `true` | Bind to client IP CIDR (uses `CF-Connecting-IP`). |
| `IPV4_PREFIX` | `number` | `32` | IPv4 CIDR prefix length for IP binding (`0..32`). |
| `IPV6_PREFIX` | `number` | `64` | IPv6 CIDR prefix length for IP binding (`0..128`). |
| `POW_BIND_COUNTRY` | `boolean` | `false` | Bind to `request.cf.country`. |
| `POW_BIND_ASN` | `boolean` | `false` | Bind to `request.cf.asn`. |
| `POW_BIND_TLS` | `boolean` | `true` | Bind to TLS fingerprint derived from `request.cf.tlsClientExtensionsSha1` + `tlsClientCiphersSha1`. |
| `INNER_AUTH_QUERY_NAME` | `string` | `""` | Query param name for internal bypass. Requires `INNER_AUTH_QUERY_VALUE`. |
| `INNER_AUTH_QUERY_VALUE` | `string` | `""` | Query param value for internal bypass. Requires `INNER_AUTH_QUERY_NAME`. |
| `INNER_AUTH_HEADER_NAME` | `string` | `""` | Header name for internal bypass. Requires `INNER_AUTH_HEADER_VALUE`. |
| `INNER_AUTH_HEADER_VALUE` | `string` | `""` | Header value for internal bypass. Requires `INNER_AUTH_HEADER_NAME`. |
| `stripInnerAuthQuery` | `boolean` | `false` | Remove the bypass query param before proxying (only when bypass matched). |
| `stripInnerAuthHeader` | `boolean` | `false` | Remove the bypass header before proxying (only when bypass matched). |

### `when` conditions

Each `CONFIG` entry may include an optional `when` field to gate the rule on request properties. Supported fields include `country`, `asn`, `ip`, `method`, `ua`, `path`, `tls`, `header`, `cookie`, and `query`. The `when` expression supports boolean logic and nesting:

- `and`: array of conditions, all must match
- `or`: array of conditions, any may match
- `not`: single condition to negate
- multiple keys inside the same condition object are an implicit AND (all keys must match)

String matching semantics:

- `ua`: string values use case-insensitive substring match; regex values are tested as-is
- `path`: string values use case-sensitive exact match; regex values are tested as-is
- `country`, `asn`, `method`: string values use case-insensitive exact match

Arrays and regex:

- `ua`, `path`, `header`, `cookie`, `query` accept a string, regex, or array of those; arrays match if any entry matches
- `query` values are multi-valued; when present, any value that matches is accepted

Existence checks:

- `header`, `cookie`, `query` support `{ exists: true }` or `{ exists: false }` on a key to test presence

IP matching:

- `ip` accepts a single IP, CIDR, or an array of those
- CIDR supports IPv4 and IPv6

Examples:

```js
{ host: "example.com", path: "/**", when: {
  and: [
    { ua: "mobile" },
    { header: { "x-debug": { exists: false } } },
    { ip: ["203.0.113.0/24", "2001:db8::/32"] },
  ],
}, config: { powcheck: true } }
```

```js
{ host: "example.com", path: "/**", when: {
  or: [
    { path: "/healthz" },
    { query: { "probe": { exists: true } } },
  ],
}, config: { turncheck: true } }
```

## Proof Cookie (`__Host-proof`)

The gate issues a single proof cookie with a mode mask:

- Format: `v1.{ticketB64}.{iat}.{last}.{n}.{m}.{mac}`
- `m` mask:
  - `1` = PoW
  - `2` = Turnstile
  - `3` = PoW + Turnstile

Proof and commit cookies (`__Host-proof`, `__Host-pow_commit`) are issued with `SameSite=Lax`.

A request is allowed when `(m & requiredMask) == requiredMask`.
When `ATOMIC_CONSUME` is enabled and Turnstile is required, proof cookies are ignored; atomic tokens on the business request are mandatory.

## Internal bypass

You can bypass the gate for internal traffic by matching a specific query param or header. When a match occurs, the snippet returns `fetch(request)` and skips PoW/Turnstile checks. This is useful for internal APIs because Snippet rules cannot match on headers or query strings. You can also strip the bypass credential before proxying.

Configuration (exact match required):

- Query param: `INNER_AUTH_QUERY_NAME` + `INNER_AUTH_QUERY_VALUE`
- Header: `INNER_AUTH_HEADER_NAME` + `INNER_AUTH_HEADER_VALUE`

Example:

```js
{ host: "example.com", path: "/**", config: {
  POW_TOKEN: "replace-me",
  powcheck: true,
  INNER_AUTH_QUERY_NAME: "auth",
  INNER_AUTH_QUERY_VALUE: "my-internal-token",
  INNER_AUTH_HEADER_NAME: "X-Inner-Auth",
  INNER_AUTH_HEADER_VALUE: "X-Inner-Auth-Value",
  stripInnerAuthQuery: true,
  stripInnerAuthHeader: true,
} }
```

Notes:

- Both name and value must be set for a match.
- If both query and header are configured, **both must match** to bypass.
- If only one is configured, that single match is sufficient.
- The bypass only applies to protected paths (non-`/__pow/*` requests).
- If `stripInnerAuthQuery`/`stripInnerAuthHeader` are `true`, the matched credential is removed before proxying.

## Turnstile integration

- Turnstile renders with `cData = ticket.mac`.

Default (`ATOMIC_CONSUME=false`):

- **Turn-only** (`powcheck=false, turncheck=true`): client calls `POST /__pow/turn` → server `siteverify` → `__Host-proof (m=2)`.
- **Combined** (`powcheck=true, turncheck=true`): `/__pow/turn` is disabled (404); `siteverify` happens only in the final `POST /__pow/open`.

Atomic consume (`ATOMIC_CONSUME=true`):

- **Turn-only**: `/__pow/turn` is disabled (404). Client attaches `turnToken + ticket` to the business request and the snippet verifies + forwards the original request.
- **Combined**: `/__pow/open` returns `{ done: true, consume: "v2..." }` and does **not** set `__Host-proof`. Client attaches `turnToken + consume` to the business request; the snippet verifies consume (HMAC + tb), binding, then `siteverify`.
- **Transport**: cookie > header > query (header preferred over query when both present). Navigation tries a short-lived cookie first (Max-Age 5s, Path = target), then falls back to query; embedded flows use `postMessage` for header replay. Tokens are stripped when `STRIP_ATOMIC_QUERY/STRIP_ATOMIC_HEADERS` are `true`. The cookie is cleared after use.
- **Navigation failure**: if atomic validation fails, navigation requests fall back to the challenge page (non-navigation still returns 403).
- **Embedding**: the challenge page forbids iframe embedding (CSP/XFO). Atomic `postMessage` is restricted to same-origin parent/opener and uses a concrete origin.

### Early-bind (combined mode)

In combined mode, PoW is bound to the Turnstile token:

- `tb = base64url(sha256(turnstile_token).slice(0, 12))`
- PoW seed uses `bindingString + "|" + tb`.
- `__Host-pow_commit` (v4) carries `tb` and the final `/open` verifies `turnToken → tb`.

This guarantees **one token → one PoW**, preventing “1 PoW + N tokens”.

### Turnstile limitations (captcha-solver proxying)

Some captcha-solving platforms now support SOCKS5 proxies supplied by the client. In that setup, PoW and RTT-lock are performed on the attacker's machine, while Turnstile token minting, `cData`, and the SOCKS5 proxy are handled by the solver. Turnstile effectively degrades to **friction** plus a **single-use consumption lock**.

If the attacker pays for a high-end SOCKS5 proxy and makes the solver appear as the *same egress IP*, then:

- IP can be matched (via the proxy).
- `cData` can be matched (client-supplied parameter).
- TLS fingerprint **cannot** be matched (solver uses a different stack, e.g., Chrome vs. Python).

Because Turnstile does **not** return the verified IP/TLS fingerprint, TLS binding becomes ineffective in this extreme case, and defense degrades to pure economic friction.
Turnstile almost certainly has access to these signals but chooses not to expose or enforce them, which is hard not to find suspicious.

Ideally Turnstile would expose server-enforced flags such as:

- `force-verify-remoteip: true`
- `tls-fingerprint: <payload>`
- `force-verify-tls-fingerprint: true`

and return only `success: true/false`. Today it does not. `cData` is opaque and cannot prevent attacker-supplied input, since it is **client-provided**, not extracted by Cloudflare. Treat `cData` as a low-cost check, not a silver bullet.

### `tb` design (Turnstile binding tag)

`tb` is a compact binding tag derived from the Turnstile token:

- `tb = base64url(sha256(turnstile_token).slice(0, 12))` (96-bit tag, 16 chars base64url).
- Used to bind PoW/consume tokens to a specific Turnstile token without carrying the full token.
- Stored inside signed artifacts: `__Host-pow_commit` (v4) and `consume` (v2).
- Recomputed on the server from `turnToken` and compared (`tb` must match).
- For non-Turnstile flows, `tb = "any"`.

`tb` is not secret; integrity is enforced by HMAC on the enclosing token/cookie.

## CCR: Commit → Challenge → Open

PoW uses a stateless CCR API:

1. **Commit**: the browser computes the PoSW commitment (`rootB64 + nonce`) and calls `POST /__pow/commit`.
   - The snippet verifies the ticket binding and mints a short-lived `__Host-pow_commit` cookie.
   - In combined mode, `/commit` must include `token` (Turnstile token) to bind `tb`.
2. **Challenge**: the browser calls `POST /__pow/challenge`.
   - The snippet uses deterministic RNG derived from the commit to generate sampled `indices`, `segLen`, optional `spinePos`, and a batch `token`.
3. **Open**: the browser calls `POST /__pow/open` with `opens` for the sampled indices.
   - The snippet verifies and advances the cursor; repeats until done, then issues `__Host-proof` (non-atomic).
   - In combined mode, the final `/open` must include `turnToken` and triggers `siteverify` (non-atomic).
   - In atomic combined mode, the final `/open` returns `consume` and `siteverify` moves to the business path.

Key properties:

- **No server-side session**: all state is either recomputed or carried in signed cookie/token.
- **Strict serial progression (RTT-lock)**: each `/open` depends on the previous cursor/token, so clients cannot parallelize or reorder batches.

## Sliding renewal (proof cookie)

When enabled, the gate can renew `__Host-proof` on navigation requests:

- `PROOF_RENEW_ENABLE: true`
- `PROOF_RENEW_MAX`: max renewal count
- `PROOF_RENEW_WINDOW_SEC`: only renew near expiry
- `PROOF_RENEW_MIN_SEC`: minimum seconds between renewals

The renewal re-issues a fresh ticket + proof with the same mask `m`, and is capped by a hard max lifetime.

## Root-bound Hashcash (`POW_HASHCASH_BITS`)

This is **not** a standard Hashcash stamp format. It is a lightweight, *commitment-bound* extra PoW condition:

- It is only checked when the sampled index is the **last step** (`i = L`).
- The server computes:
  - `digest = SHA256("hashcash|v3|" || merkleRoot || chain[L])`
  - and requires `leadingZeroBits(digest) >= POW_HASHCASH_BITS`.

Why it exists:

- It provides an **exponential cost knob** with minimal server overhead (one SHA-256 and a leading-zero count).
- Because it is bound to `merkleRoot` and `chain[L]`, it cannot be “pre-stamped” independently of the actual PoSW chain commitment.
- Increasing `POW_HASHCASH_BITS` increases the expected client work by roughly `~ 2^bits`, because the client must retry with a different nonce (which changes the whole chain commitment) until the condition holds.

## PoSW + Merkle: why sampling works

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

## RTT-lock and throughput ceiling

With default parameters:

- Total sampled indices: `S = 2 + POW_SAMPLE_K * POW_CHAL_ROUNDS = 182`
- `POW_OPEN_BATCH = 15` ⇒ number of `/open` calls: `m = ceil(S / 15) = 13`
- Total serial PoW API requests: `M_api = 1(/commit) + 1(/challenge) + m(/open) = 15`

So a single IP’s token minting throughput is bounded by:

- `tokens/s ≤ 1 / (M_api * RTT)`

This limit comes from network latency (physics), not local compute.

## “Exchange rate” with Cloudflare WAF Rate Limit

A practical ops pattern is to put a WAF Rate Limit (e.g. `50 req / 10s / per IP`) in front of both `/__pow/*` and protected paths.

Since minting one proof consumes at least `M_api = 15` serial requests:

- `1 proof ≈ 15 rate-limit units`
- Under `50/10s/IP`, each IP can mint at most `floor(50/15) = 3` tokens per 10 seconds (in the ideal case)

This effectively turns Cloudflare’s rate limiter into a *stateful* quota counter, while the snippet remains stateless.

## Parallelization and “chain break” economics

PoSW itself is not a magical “anti-parallel” primitive. Attackers may try to split the chain at some breakpoint and compute segments in parallel, gambling that samples never cross the breakpoint.

This implementation reduces the expected value of such attacks by:

- verifying *contiguous segments* (`(i - segLen, i]`) — any sample crossing the breakpoint fails immediately
- using deterministic, more evenly-covered sampling to reduce “lucky gaps”

## Operational tuning tips

- Prefer adjusting `POW_DIFFICULTY_COEFF` and/or lowering `POW_OPEN_BATCH` (stronger RTT-lock) instead of blindly increasing `POW_SAMPLE_K`/`POW_CHAL_ROUNDS`.
- Keep a WAF/RL budget that includes both `/__pow/*` and protected endpoints so token minting “spends” budget at a predictable rate.

## Build

```bash
npm install
npm run build
```

Output: `dist/pow_config_snippet.js` + `dist/pow_snippet.js` (each checks the Cloudflare Snippet 32KB limit).

## Deploy

1. Set `CONFIG_SECRET` in `pow-config.js` and `pow.js` (must match, not `replace-me`).
2. Build and copy `dist/pow_config_snippet.js` and `dist/pow_snippet.js` into Cloudflare **Snippets**.
3. Ensure `pow-config` runs **before** `pow.js`, and both run before any downstream auth/business snippets.
4. Keep `/__pow/*` reachable from browsers during the challenge flow.

## Managed Challenge (optional)

If you enable Turnstile with `cData` binding, Managed Challenge often adds little value and is usually unnecessary. Prefer tuning PoW/Turnstile + WAF Rate Limit; keep Managed Challenge only if you want an extra, independent hurdle.
