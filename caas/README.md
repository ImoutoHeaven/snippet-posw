# snippets-caas

Challenge-as-a-Service (CaaS) for Cloudflare **Snippets / Workers**.

This project provides a separate-domain challenge service (e.g. `caas.example.com`) that:

- Issues stateless challenge tokens (`chal`, `state`, `proofToken`) via HMAC.
- Seals arbitrary application context (`ctx`) with AES-GCM and returns it only after successful attestation.
- Uses **postMessage-first** UI with **redirect fallback**.
- Supports **Turnstile-only**, **PoW-only**, or **combined** mode.

## Files

- `caas.js`: CaaS snippet/worker implementation.
- `template.html`: minimal landing HTML template (inlined into `caas.js` by the build).
- `glue.js`: landing frontend (postMessage handshake, Turnstile, optional PoW).
- `frontend/caas-client.js`: browser helper for embedding the landing page and exchanging messages.
- `sdk/node.js`: Node.js (18+) server SDK for calling `server/*`.
- `examples/node-demo.mjs`: minimal end-to-end demo (local backend + static page).
- `build.mjs`: build script (outputs `dist/caas_snippet.js`, checks the 32KB snippet limit).

## Configuration

Configure `CONFIG` in `caas.js`:

- Single-site: set `CONFIG` to an object.
- Multi-site: set `CONFIG` to an array of `{ pattern, config }` entries (first-match-wins; pattern syntax matches the Gate snippet).

### `pattern` syntax

| Field | Type | Description |
|---|---|---|
| `pattern` | `string` | Host pattern with optional path glob: `host` or `host/path`. Host `*` matches a single label fragment (does not cross `.`). Path supports `*` (no `/`) and `**` (may include `/`). |

### `config` keys (all supported)

| Key | Type | Default | Description |
|---|---|---|---|
| `API_PREFIX` | `string` | `"/__pow/v1"` | API/UI prefix. Can be set per-site in multi-site mode. |
| `POW_TOKEN` | `string` | — | Master secret used for HMAC + AES-GCM key derivation. Required. |
| `SERVICE_TOKEN` | `string` | — | Bearer token for `POST {API_PREFIX}/server/*`. Required. |
| `TURNSTILE_SITEKEY` | `string` | — | Turnstile site key (client-side). Required when `requireTurn: true`. |
| `TURNSTILE_SECRET` | `string` | — | Turnstile secret key (server-side `siteverify`). Required when `requireTurn: true`. |
| `ALLOWED_PARENT_ORIGINS` | `string[]` | `[]` | Allowlist for embedding + postMessage origin checks (required for UI usage). |
| `ALLOWED_CLIENT_ORIGINS` | `string[]` | `[]` | Optional CORS allowlist for `/client/*` calls. |
| `CAAS_GLUE_URL` | `string` | (repo-pinned) | ES module URL for landing UI glue (required for UI). |
| `CAAS_POW_ESM_URL` | `string` | (repo-pinned) | ES module URL for the PoW solver (required when `requirePow: true`). |
| `CHAL_TTL_SEC` | `number` | `300` | TTL for `chal` tokens. |
| `STATE_TTL_SEC` | `number` | `300` | TTL for UI state tokens. |
| `PROOF_TTL_SEC` | `number` | `600` | TTL for proof tokens. |
| `CTX_B64_MAX_LEN` | `number` | `32768` | Max length of `ctxB64` input (base64url). |
| `CHAL_B64_MAX_LEN` | `number` | `65536` | Max length of `chal` payload (base64url). |
| `STATE_B64_MAX_LEN` | `number` | `4096` | Max length of `state` payload (base64url). |
| `LANDING_CHAL_MAX_LEN` | `number` | `4096` | Max `chal` length allowed in redirect hash (`0` disables hash). |
| `POW_STEPS` | `number` | `2048` | Default PoW steps. |
| `POW_MIN_STEPS` | `number` | `512` | Min PoW steps (clamp). |
| `POW_MAX_STEPS` | `number` | `8192` | Max PoW steps (clamp). |
| `POW_HASHCASH_BITS` | `number` | `3` | Root-bound hashcash bits (0 disables). |
| `POW_SEGMENT_LEN` | `string | number` | `"48-64"` | Segment length spec. |
| `POW_SAMPLE_K` | `number` | `15` | Extra sampled indices per round. |
| `POW_SPINE_K` | `number` | `2` | Spine constraints per batch. |
| `POW_CHAL_ROUNDS` | `number` | `12` | Challenge rounds. |
| `POW_OPEN_BATCH` | `number` | `15` | Indices per `/open` batch. |
| `POW_FORCE_EDGE_1` | `boolean` | `true` | Force index `1` in sampling. |
| `POW_FORCE_EDGE_LAST` | `boolean` | `true` | Force last index in sampling. |
| `POW_COMMIT_TTL_SEC` | `number` | `300` | TTL for PoW commit tokens. |

## Token model

- **chal**: `c1.<payloadB64>.<mac>`
- **state**: `s1.<payloadB64>.<mac>`
- **proofToken**: `p1.<m>.<chalId>.<iat>.<exp>.<mac>`
  - `m` mask: `1=pow`, `2=turn`, `3=pow+turn`
- **ctx**: AES-GCM sealed payload carried in `chal` and returned only after successful attestation.

## Endpoints (v1)

Default `API_PREFIX` is `/__pow/v1` (configurable via `CONFIG.API_PREFIX`).

- Server (requires `Authorization: Bearer <SERVICE_TOKEN>`):
  - `POST {API_PREFIX}/server/generate`
  - `POST {API_PREFIX}/server/attest`
- Client/UI:
  - `POST {API_PREFIX}/client/turn` (turn-only mode)
  - `POST {API_PREFIX}/client/pow/commit`
  - `POST {API_PREFIX}/client/pow/open`
  - `GET {API_PREFIX}/ui/landing?state=...`

### Mode rules

- **Turn-only**: `requireTurn=true`, `requirePow=false`
  - Uses `/client/turn` → returns `proofToken (m=2)`.
- **PoW-only**: `requirePow=true`, `requireTurn=false`
  - Uses `/client/pow/*` → returns `proofToken (m=1)`.
- **Combined**: `requireTurn=true`, `requirePow=true`
  - `/client/turn` is **disabled** (404).
  - `proofToken (m=3)` is issued only from `/client/pow/open` on the final batch.

## Combined mode: early-bind

When Turnstile and PoW are both required:

- The client must obtain a Turnstile token **before** PoW.
- PoW seed is bound with `tb = base64url(sha256(token).slice(0, 12))`.
- `/client/pow/commit` and `/client/pow/open` carry `turnToken`.
- Final `/open` verifies `turnToken → tb`, then runs `siteverify` and issues `proofToken (m=3)`.

This guarantees **one token → one PoW** and prevents reuse.

## Backend integration (caller)

Typical flow:

1) Your backend calls `server/generate` to mint a `chal` and UI URLs.
2) The browser completes the challenge (landing UI) and returns `proofToken`.
3) Your backend calls `server/attest` to decrypt `ctx`, then applies business checks and one-time consumption.

If you use the provided browser helper (`frontend/caas-client.js`), expose two app endpoints that wrap CaaS:

- `POST /api/caas/generate` → calls `POST {API_PREFIX}/server/generate`
- `POST /api/caas/attest` → calls `POST {API_PREFIX}/server/attest` and returns your application-specific decision

### Node (18+) example using `sdk/node.js`

```js
import { createCaasClient } from "./sdk/node.js";

const caas = createCaasClient({
  caasOrigin: "https://caas.example.com",
  serviceToken: process.env.CAAS_SERVICE_TOKEN,
  apiPrefix: "/__pow/v1",
});

const nowSec = () => Math.floor(Date.now() / 1000);
const b64uJson = (obj) => Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
const b64uJsonDecode = (b64) => JSON.parse(Buffer.from(b64, "base64url").toString("utf8"));

// generate
const ctx = {
  v: 1,
  act: "download",
  rid: "file_123",
  sub: "user_456",
  jti: "random_128bit",
  iat: nowSec(),
  exp: nowSec() + 300,
};
const ctxB64 = b64uJson(ctx);
const gen = await caas.generate({
  ctxB64,
  ttlSec: 300,
  policy: { requireTurn: true, requirePow: false },
  turn: {
    enable: true,
    parentOrigin: "https://app.example.com",
    allowRedirect: true,
    returnUrl: "https://app.example.com/callback",
  },
  pow: { enable: false },
});

// attest (after frontend returns proofToken)
const attest = await caas.attest({ chal: gen.chal, proofToken });
const ctxPlain = b64uJsonDecode(attest.ctxB64);
```

Notes:

- CaaS is stateless: replay prevention should be enforced by the caller (e.g. `ctx.jti` with Redis `SETNX`).
- Any “business binding” (IP/country/fingerprint/account) should be carried in `ctx` and checked by the caller.

## Frontend integration

Use `frontend/caas-client.js` (postMessage-first, iframe/popup).

```js
import { caasRun } from "/caas-client.js";

const res = await caasRun({
  generateUrl: "/api/caas/generate",
  attestUrl: "/api/caas/attest",
  payload: { act: "download", rid: "file_123", sub: "user_456", requirePow: false },
  mode: "iframe", // or "popup"
});
```

Redirect fallback:

- Ensure your backend sets `turn.allowRedirect: true` and a `turn.returnUrl`.
- If the flow redirects back to your `returnUrl`, parse `location.hash` for `proof=` and send it to your backend to run `attest`.
- `landingUrlRedirect` is omitted when `chal` exceeds `LANDING_CHAL_MAX_LEN`.

## Limits and sizing

- `CTX_B64_MAX_LEN` controls the maximum input size for `ctxB64`.
- `CHAL_B64_MAX_LEN` controls the maximum `chal` payload size (base64url).
- `LANDING_CHAL_MAX_LEN` controls whether `chal` is allowed in URL hash redirects.

Larger ctx values increase `chal` size. For large payloads, prefer postMessage flows (iframe/popup) and disable redirect hashes.

## Build

```bash
node caas/build.mjs
```

Output: `dist/caas_snippet.js`.

## Demo (Node 18+)

```bash
CAAS_ORIGIN="https://caas.example.com" \
CAAS_SERVICE_TOKEN="replace-me" \
node caas/examples/node-demo.mjs
```

Open `http://localhost:8788/`.
