import http from "node:http";
import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { createCaasClient } from "../sdk/node.js";

const CAAS_ORIGIN = process.env.CAAS_ORIGIN || "https://caas.example.com";
const SERVICE_TOKEN = process.env.CAAS_SERVICE_TOKEN || "replace-me";
const PORT = Number(process.env.PORT || 8788);

const caas = createCaasClient({ caasOrigin: CAAS_ORIGIN, serviceToken: SERVICE_TOKEN });

const usedJtis = new Map(); // demo only
const nowSec = () => Math.floor(Date.now() / 1000);
const b64u = (buf) =>
  Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const json = (res, status, body) => {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(text);
};

const readJson = async (req) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString("utf-8");
  return text ? JSON.parse(text) : null;
};

const serve = async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === "GET" && url.pathname === "/") {
    const html = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<button id="btn">Run CaaS</button>
<pre id="out"></pre>
<script type="module">
import { caasRun } from "/caas-client.js";
const out = document.getElementById("out");
document.getElementById("btn").onclick = async () => {
  out.textContent = "running...";
  try {
    const res = await caasRun({
      payload: { act: "demo", rid: "file_123", sub: "user_456", requirePow: false },
      mode: "iframe",
    });
    out.textContent = JSON.stringify(res, null, 2);
  } catch (e) {
    out.textContent = String(e && (e.stack || e.message) || e);
  }
};
</script>`;
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(html);
    return;
  }

  if (req.method === "GET" && url.pathname === "/caas-client.js") {
    const js = await readFile(new URL("../frontend/caas-client.js", import.meta.url), "utf-8");
    res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8" });
    res.end(js);
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/caas/generate") {
    const body = await readJson(req);
    const act = String(body?.act ?? "");
    const rid = String(body?.rid ?? "");
    const sub = String(body?.sub ?? "");
    const requirePow = body?.requirePow === true;

    const jti = b64u(randomBytes(16));
    const ctx = {
      v: 1,
      act,
      rid,
      sub,
      jti,
      iat: nowSec(),
      exp: nowSec() + 300,
    };
    const ctxB64 = b64u(Buffer.from(JSON.stringify(ctx), "utf-8"));

    const resp = await caas.generate({
      ctxB64,
      ttlSec: 300,
      policy: { requireTurn: true, requirePow },
      turn: {
        enable: true,
        parentOrigin: `http://localhost:${PORT}`,
        returnUrl: `http://localhost:${PORT}/`,
        allowRedirect: true,
      },
      pow: { enable: requirePow },
    });
    json(res, 200, resp);
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/caas/attest") {
    const body = await readJson(req);
    const chal = String(body?.chal ?? "");
    const proofToken = typeof body?.proofToken === "string" ? body.proofToken : "";

    const attest = await caas.attest({ chal, proofToken });
    const ctxJson = JSON.parse(Buffer.from(attest.ctxB64, "base64url").toString("utf-8"));

    const key = `caas:jti:${ctxJson.jti}`;
    if (usedJtis.has(key)) {
      json(res, 409, { ok: false, error: "replay" });
      return;
    }
    usedJtis.set(key, ctxJson.exp);

    json(res, 200, { ok: true, grant: { sub: ctxJson.sub, rid: ctxJson.rid, act: ctxJson.act } });
    return;
  }

  res.writeHead(404);
  res.end("not found");
};

http
  .createServer((req, res) => {
    serve(req, res).catch((err) => {
      res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
      res.end(String(err && (err.stack || err.message) || err));
    });
  })
  .listen(PORT, () => {
    console.log(`demo listening on http://localhost:${PORT}`);
    console.log(`CAAS_ORIGIN=${CAAS_ORIGIN}`);
  });
