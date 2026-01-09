const encoder = new TextEncoder();

const b64uDecode = (value) => {
  const raw = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = raw + "===".slice((raw.length + 3) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

const b64uDecodeUtf8 = (value) => new TextDecoder().decode(b64uDecode(value));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const loadTurnstile = async () => {
  if (globalThis.turnstile && typeof globalThis.turnstile.render === "function") return;
  await new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    s.async = true;
    s.defer = true;
    s.onload = resolve;
    s.onerror = reject;
    document.head.appendChild(s);
  });
  if (!globalThis.turnstile || typeof globalThis.turnstile.render !== "function") {
    throw new Error("turnstile not available");
  }
};

const getParentTarget = () => {
  if (window.parent && window.parent !== window) return window.parent;
  if (window.opener && !window.opener.closed) return window.opener;
  return null;
};

const awaitMessage = (predicate, timeoutMs) =>
  new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("timeout"));
    }, Math.max(1000, timeoutMs || 60000));
    const onMessage = (event) => {
      try {
        const ok = predicate(event);
        if (!ok) return;
        cleanup();
        resolve(event);
      } catch (e) {
        cleanup();
        reject(e);
      }
    };
    const cleanup = () => {
      clearTimeout(timer);
      window.removeEventListener("message", onMessage);
    };
    window.addEventListener("message", onMessage);
  });

const parseChalPayload = (chal) => {
  const parts = String(chal || "").split(".");
  if (parts.length !== 3 || parts[0] !== "c1") return null;
  try {
    const payloadJson = JSON.parse(b64uDecodeUtf8(parts[1]));
    return payloadJson && typeof payloadJson === "object" ? payloadJson : null;
  } catch {
    return null;
  }
};

const readChalFromFragment = () => {
  const raw = typeof location.hash === "string" ? location.hash : "";
  const q = raw.startsWith("#") ? raw.slice(1) : raw;
  if (!q) return "";
  try {
    const params = new URLSearchParams(q.startsWith("?") ? q.slice(1) : q);
    const chal = params.get("chal");
    if (!chal) return "";
    try {
      history.replaceState(null, "", location.pathname + location.search);
    } catch {}
    return String(chal);
  } catch {
    return "";
  }
};

async function solveTurn({ apiPrefix, chal, chalId, sitekey, powPromise }) {
  await loadTurnstile();
  const container = document.createElement("div");
  container.style.cssText = "margin:24px auto;max-width:320px;";
  document.body.appendChild(container);

  const maxAttempts = 5;
  let widgetId = null;
  const nextToken = () =>
    new Promise((resolve, reject) => {
      container.hidden = false;
      container.innerHTML = "";
      widgetId = globalThis.turnstile.render(container, {
        sitekey,
        cData: chalId,
        callback: resolve,
        "error-callback": () => reject(new Error("turnstile failed")),
        "expired-callback": () => reject(new Error("turnstile expired")),
      });
    });

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let token;
    try {
      token = await nextToken();
    } catch (e) {
      if (attempt >= maxAttempts) throw e;
      continue;
    }
    container.hidden = true;
    const powProofToken = powPromise ? await powPromise : "";
    const body = { chal, turnstileToken: token };
    if (powPromise) body.powProofToken = powProofToken;
    const res = await fetch(`${apiPrefix}/client/turn`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const j = await res.json().catch(() => null);
    if (res.ok && j && j.ok === true && typeof j.turnProofToken === "string") {
      if (powPromise) {
        container.hidden = true;
      }
      return j.turnProofToken;
    }
    if (attempt >= maxAttempts) {
      throw new Error("turn attest failed");
    }
    if (container.hidden) {
      container.hidden = false;
    }
    if (globalThis.turnstile && typeof globalThis.turnstile.reset === "function") {
      try {
        globalThis.turnstile.reset(widgetId);
      } catch {}
    }
  }
  throw new Error("turn attest failed");
}

async function solvePow({ apiPrefix, chal, chalId, powEsmUrl }) {
  const payload = parseChalPayload(chal);
  const pow = payload && payload.pow;
  const powEnabled = pow && pow.enabled === true;
  const params = pow && pow.params;
  const steps = Number(params && params.steps);
  if (!powEnabled || !Number.isFinite(steps) || steps <= 0) {
    throw new Error("pow not enabled");
  }

  const module = await import(powEsmUrl);
  const computePoswCommit = module && module.computePoswCommit;
  if (typeof computePoswCommit !== "function") {
    throw new Error("computePoswCommit missing");
  }

  const bindingString = `chalId=${chalId}`;
  const hashcashBits = Number(params && params.hashcashBits) || 0;
  const segmentLen = 64;

  const status = document.createElement("pre");
  status.style.cssText = "white-space:pre-wrap;word-break:break-word;font:12px/1.4 monospace;";
  document.body.appendChild(status);

  const commit = await computePoswCommit(bindingString, steps, {
    hashcashBits,
    segmentLen,
    yieldEvery: 256,
    onStatus: (kind, attempt) => {
      status.textContent = `pow: ${kind} (${attempt})`;
    },
  });

  const commitRes = await fetch(`${apiPrefix}/client/pow/commit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chal,
      rootB64: commit.rootB64,
      nonce: commit.nonce,
    }),
  });
  let state = await commitRes.json().catch(() => null);
  if (!commitRes.ok || !state) throw new Error("pow commit failed");

  while (state && state.done === false) {
    const opens = await commit.open(state.indices, { segLens: state.segs, spinePos: state.spinePos });
    const openRes = await fetch(`${apiPrefix}/client/pow/open`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chal,
        commitToken: state.commitToken,
        sid: state.sid,
        cursor: state.cursor,
        token: state.token,
        spinePos: state.spinePos,
        opens,
      }),
    });
    state = await openRes.json().catch(() => null);
    if (!openRes.ok || !state) throw new Error("pow open failed");
    status.textContent = `pow: cursor ${state.cursor}`;
    await sleep(0);
  }

  if (!state || state.done !== true || typeof state.powProofToken !== "string") {
    throw new Error("pow solve failed");
  }
  return state.powProofToken;
}

export default async function main(cfgB64) {
  const cfg = JSON.parse(b64uDecodeUtf8(cfgB64));
  const apiPrefix = String(cfg.apiPrefix || "/__pow/v1");
  const chalId = String(cfg.chalId || "");
  const nonce = String(cfg.nonce || "");
  const parentOrigin = String(cfg.parentOrigin || "");
  const allowRedirect = cfg.allowRedirect === true;
  const returnUrl = cfg.returnUrl ? String(cfg.returnUrl) : "";
  const sitekey = String(cfg.turnSitekey || "");
  const powEsmUrl = String(cfg.powEsmUrl || "");
  const chalFromState = typeof cfg.chal === "string" ? cfg.chal : "";

  if (!chalId || !nonce) throw new Error("bad cfg");

  const parent = getParentTarget();
  let chal = chalFromState;
  if (!chal) chal = readChalFromFragment();

  if (!chal) {
    if (!parent || !parentOrigin) {
      if (allowRedirect && returnUrl) {
        location.href = returnUrl;
        return;
      }
      throw new Error("no parent for postMessage");
    }

    parent.postMessage({ type: "caas:ready", chalId, nonce }, parentOrigin);

    const msg = await awaitMessage(
      (ev) =>
        ev &&
        ev.origin === parentOrigin &&
        ev.source === parent &&
        ev.data &&
        ev.data.type === "caas:chal" &&
        ev.data.chalId === chalId &&
        ev.data.nonce === nonce &&
        typeof ev.data.chal === "string",
      60000
    );
    chal = msg.data.chal;
  }

  const payload = parseChalPayload(chal);
  const policy = payload && payload.policy;
  const requireTurn = policy && policy.requireTurn === true;
  const requirePow = policy && policy.requirePow === true;

  const proof = { chalId, nonce };

  const powPromise = requirePow
    ? (() => {
        if (!powEsmUrl) throw new Error("pow esm url missing");
        return solvePow({ apiPrefix, chal, chalId, powEsmUrl });
      })()
    : null;
  const turnPromise = requireTurn
    ? (() => {
        if (!sitekey) throw new Error("turn sitekey missing");
        return solveTurn({ apiPrefix, chal, chalId, sitekey, powPromise });
      })()
    : null;
  if (powPromise) {
    proof.powProofToken = await powPromise;
  }
  if (turnPromise) {
    proof.turnProofToken = await turnPromise;
  }

  if (parent && parentOrigin) {
    parent.postMessage({ type: "caas:proof", ...proof }, parentOrigin);
    return;
  }

  if (allowRedirect && returnUrl) {
    const url = new URL(returnUrl);
    url.hash = new URLSearchParams({
      turn: proof.turnProofToken || "",
      pow: proof.powProofToken || "",
    }).toString();
    location.href = url.toString();
    return;
  }

  document.body.textContent = JSON.stringify(proof);
}
