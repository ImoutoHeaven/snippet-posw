# snippets-caas

Challenge-as-a-Service (CaaS) for Cloudflare Snippets/Workers.

## What it does

- Designed for **separate-domain deployment** (e.g. `caas.example.com`) and backend-driven integration.
- Stateless tokens:
  - `chal` / `state` / `proofToken` are verified via HMAC.
  - `ctx` is sealed with AES-GCM and returned only after successful attestation.
- UI flow is **postMessage-first** (iframe/popup) with **redirect fallback**.
- Policies supported: Turnstile only, PoW only, or Turnstile + PoW.

## Configuration

Configure `CONFIG` in `caas.js`:

- Single-site: set `CONFIG` to an object.
- Multi-site: set `CONFIG` to an array of `{ pattern, config }` entries (first-match-wins; pattern syntax matches the Gate snippet).

- `POW_TOKEN`: master secret used for HMAC + AES-GCM key derivation (required).
- `SERVICE_TOKEN`: bearer token for `POST /__pow/v1/server/*` (required).
- `TURNSTILE_SITEKEY` / `TURNSTILE_SECRET`: required when `requireTurn: true`.
- `ALLOWED_PARENT_ORIGINS`: allowlist for embedding + postMessage validation (required for UI usage).
- `CAAS_GLUE_URL`: ES module URL for the landing page glue code (required for UI).
- `CAAS_POW_ESM_URL`: ES module URL for the PoW solver (required when `requirePow: true`).

## Endpoints (v1)

- Server (requires `Authorization: Bearer <SERVICE_TOKEN>`):
  - `POST /__pow/v1/server/generate`
  - `POST /__pow/v1/server/attest`
- Client/UI:
  - `POST /__pow/v1/client/turn`
  - `POST /__pow/v1/client/pow/commit`
  - `POST /__pow/v1/client/pow/open`
  - `GET /__pow/v1/ui/landing?state=...`

## Backend integration (caller)

Typical flow:

1) Your backend calls `server/generate` to mint a `chal` and a UI URL.
2) The browser completes the challenge (landing UI) and receives `turnProofToken` and/or `powProofToken`.
3) Your backend calls `server/attest` to decrypt `ctx`, then applies business checks and one-time consumption.

If you use the provided browser helper (`frontend/caas-client.js`), expose two app endpoints that wrap CaaS:

- `POST /api/caas/generate` → calls `POST /__pow/v1/server/generate`
- `POST /api/caas/attest` → calls `POST /__pow/v1/server/attest` and returns your application-specific decision

See `examples/node-demo.mjs` for a minimal end-to-end implementation.

Node (18+) example using `sdk/node.js`:

```js
import { createCaasClient } from "./sdk/node.js";

const caas = createCaasClient({
  caasOrigin: "https://caas.example.com",
  serviceToken: process.env.CAAS_SERVICE_TOKEN,
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
  turn: { enable: true, parentOrigin: "https://app.example.com", allowRedirect: true, returnUrl: "https://app.example.com/callback" },
  pow: { enable: false },
});

// attest (after frontend returns proof tokens)
const attest = await caas.attest({ chal: gen.chal, turnProofToken, powProofToken });
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
- If the flow redirects back to your `returnUrl`, parse `location.hash` for `turn=` / `pow=` and send them to your backend to run `attest`.

## Files

- `caas.js`: CaaS snippet/worker implementation.
- `template.html`: minimal landing HTML template (inlined into `caas.js` by the build).
- `glue.js`: landing frontend (postMessage handshake, Turnstile, optional PoW).
- `frontend/caas-client.js`: browser helper for embedding the landing page and exchanging messages.
- `sdk/node.js`: Node.js (18+) server SDK for calling `server/*`.
- `examples/node-demo.mjs`: minimal end-to-end demo (local backend + static page).
- `build.mjs`: build script (outputs `dist/caas_snippet.js`, checks the 32KB snippet limit).

## Build

```bash
node caas/build.mjs
```

Output: `dist/caas_snippet.js`

## Demo (Node 18+)

```bash
CAAS_ORIGIN="https://caas.example.com" \
CAAS_SERVICE_TOKEN="replace-me" \
node caas/examples/node-demo.mjs
```

Open `http://localhost:8788/`.
