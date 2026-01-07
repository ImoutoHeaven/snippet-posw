# snippet-posw

Stateless Proof-of-Work (PoW) gate for Cloudflare **Snippets / Workers**.

This project provides a self-contained L7 “front firewall” that:

- Exposes a PoW API under `/{POW_API_PREFIX}/*` (default: `/__pow/*`).
- Gates matched requests: if the client does not have a valid `__Host-pow_sol` cookie, it serves an HTML challenge page (navigation) or returns `403 { code: "pow_required" }` (non-navigation).
- Stays **stateless** on the server side (no KV/DO/DB): everything is derived/verified with HMAC and short-lived cookies.

## Files

- `pow.js`: source snippet (PoW API + PoW gate).
- `template.html`: minimal challenge page template injected into the build.
- `build.mjs`: build script (esbuild + HTML minify) → `dist/pow_snippet.js`.
- `dist/pow_snippet.js`: ready-to-paste Cloudflare Snippet output.

## Configuration

Edit `CONFIG` in `pow.js` to match your host/path patterns and enable PoW:

```js
const CONFIG = [
  { pattern: "example.com/**", config: { POW_TOKEN: "replace-me", powcheck: true } },
];
```

Notes:

- `POW_TOKEN` is required when `powcheck: true` (this snippet does not fall back to any other secret).
- `pattern` matching is first-match-wins; put more specific rules first.
- This snippet is intentionally **business-agnostic**: it does not rewrite paths and does not implement `?sign=` validation.

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
