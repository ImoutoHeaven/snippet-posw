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

// --- UI Logic (Aligned with Gate glue.js) ---

let ui;
const lines = [];
const MAX_VISIBLE_LINES = 6;

const initUi = () => {
  const style = document.createElement("style");
  style.textContent = [
    ":root{--bg:#09090b;--card-bg:#18181b;--border:#27272a;--text:#e4e4e7;--sub:#a1a1aa;--accent:#fff;--font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;--mono:ui-monospace,'SFMono-Regular',Menlo,Monaco,Consolas,monospace;}",
    "html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:var(--bg);color:var(--text);font-family:var(--font);display:flex;justify-content:center;align-items:center;-webkit-font-smoothing:antialiased;}",
    ".card{background:var(--card-bg);border:1px solid var(--border);border-radius:12px;padding:32px;width:90%;max-width:360px;text-align:center;box-shadow:0 0 0 1px rgba(255,255,255,0.05),0 4px 12px rgba(0,0,0,0.4);animation:fade-in 0.6s cubic-bezier(0.16,1,0.3,1) both;transition:height 0.3s ease;}",
    "h1{margin:0 0 24px;font-size:15px;font-weight:500;color:var(--accent);letter-spacing:-0.01em;}",
    "#log{font-family:var(--mono);font-size:13px;color:var(--sub);text-align:left;height:120px;overflow:hidden;position:relative;mask-image:linear-gradient(to bottom,transparent,black 30%);-webkit-mask-image:linear-gradient(to bottom,transparent,black 30%);display:flex;flex-direction:column;justify-content:flex-end;}",
    "#ts{margin-top:16px;display:flex;justify-content:center;}#ts[hidden]{display:none!important;}",
    ".log-line{padding:3px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}",
    "@keyframes fade-in{from{opacity:0;transform:scale(0.98)}to{opacity:1;transform:scale(1)}}"
  ].join("");
  (document.head || document.documentElement).appendChild(style);
  document.body.innerHTML =
    '<div class="card"><h1 id="t">Verifying...</h1><div id="log"></div><div id="ts"></div></div>';
  return {
    logEl: document.getElementById("log"),
    tEl: document.getElementById("t"),
    tsEl: document.getElementById("ts"),
  };
};

const render = () => {
  if (!ui || !ui.logEl) return;
  const total = lines.length;
  const start = Math.max(0, total - MAX_VISIBLE_LINES);
  const visible = lines.slice(start);
  ui.logEl.innerHTML = visible
    .map((msg) => `<div class="log-line">${msg}</div>`)
    .join("");
};

const log = (msg) => {
  lines.push(msg);
  render();
  return lines.length - 1;
};

const update = (idx, msg) => {
  if (idx < 0 || idx >= lines.length) return;
  lines[idx] = msg;
  render();
};

const setStatus = (ok) => {
  if (!ui || !ui.tEl) return;
  if (ok) {
    ui.tEl.textContent = "Success";
    ui.tEl.style.color = "#4ade80";
  } else {
    ui.tEl.textContent = "Failed";
    ui.tEl.style.color = "#f87171";
  }
};

// --- Logic ---

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
  log("Loading Turnstile...");
  await loadTurnstile();
  const container = ui.tsEl;

  const maxAttempts = 5;
  let widgetId = null;
  const nextToken = () =>
    new Promise((resolve, reject) => {
      container.style.display = "block";
      container.innerHTML = "";
      widgetId = globalThis.turnstile.render(container, {
        sitekey,
        cData: chalId,
        theme: "dark",
        callback: (token) => {
          container.style.display = "none";
          resolve(token);
        },
        "error-callback": () => reject(new Error("turnstile failed")),
        "expired-callback": () => reject(new Error("turnstile expired")),
      });
    });

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let token;
    try {
      log("Waiting for Turnstile...");
      token = await nextToken();
    } catch (e) {
      if (attempt >= maxAttempts) throw e;
      continue;
    }
    const powProofToken = powPromise ? await powPromise : "";
    const body = { chal, turnstileToken: token };
    if (powPromise) body.powProofToken = powProofToken;
    const submitLine = log("Submitting Turnstile...");
    const res = await fetch(`${apiPrefix}/client/turn`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const j = await res.json().catch(() => null);
    if (res.ok && j && j.ok === true && typeof j.turnProofToken === "string") {
      update(submitLine, "Submitting Turnstile... done");
      if (powPromise) {
        container.style.display = "none";
      }
      return j.turnProofToken;
    }
    update(submitLine, "Turnstile rejected. Retrying...");
    if (attempt >= maxAttempts) {
      throw new Error("turn attest failed");
    }
    container.style.display = "block";
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

  log("Loading solver...");
  const module = await import(powEsmUrl);
  const computePoswCommit = module && module.computePoswCommit;
  if (typeof computePoswCommit !== "function") {
    throw new Error("computePoswCommit missing");
  }

  const bindingString = `chalId=${chalId}`;
  const hashcashBits = Number(params && params.hashcashBits) || 0;
  const segmentLen = 64;

  const spinIndex = log("Computing hash chain...");
  const spinChars = "|/-\";
  let spinFrame = 0;
  let attemptCount = 0;
  const spinTimer = setInterval(() => {
    let msg = "Computing hash chain...";
    if (attemptCount > 0) {
      msg = "Screening hash (attempt " + attemptCount + ")...";
    }
    update(spinIndex, msg + " " + spinChars[spinFrame++ % spinChars.length]);
  }, 120);

  try {
    const commit = await computePoswCommit(bindingString, steps, {
      hashcashBits,
      segmentLen,
      yieldEvery: 256,
      onStatus: (kind, val) => {
        if (kind === "retry") attemptCount = val;
      },
    });
    clearInterval(spinTimer);
    update(
      spinIndex,
      attemptCount > 0 ? "Screening hash... done" : "Computing hash chain... done"
    );

    log("Submitting commit...");
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

    let round = 0;
    let verifyLine = -1;
    while (state && state.done === false) {
      round++;
      const verifyMsg = "Verifying #" + round + "...";
      if (verifyLine === -1) verifyLine = log(verifyMsg);
      else update(verifyLine, verifyMsg);

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
      await sleep(0);
    }
    if (verifyLine !== -1) update(verifyLine, "Verifying... done");

    if (!state || state.done !== true || typeof state.powProofToken !== "string") {
      throw new Error("pow solve failed");
    }
    return state.powProofToken;
  } finally {
    clearInterval(spinTimer);
  }
}

export default async function main(cfgB64) {
  ui = initUi();
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

  log("Initializing...");

  if (!chalId || !nonce) {
    setStatus(false);
    log("Error: Bad Configuration");
    return;
  }

  const parent = getParentTarget();
  let chal = chalFromState;
  if (!chal) chal = readChalFromFragment();

  if (!chal) {
    if (!parent || !parentOrigin) {
      if (allowRedirect && returnUrl) {
        window.location.replace(returnUrl);
        return;
      }
      setStatus(false);
      log("Error: No parent for postMessage");
      return;
    }

    log("Contacting application...");
    parent.postMessage({ type: "caas:ready", chalId, nonce }, parentOrigin);

    try {
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
    } catch {
      setStatus(false);
      log("Error: Handshake Timeout");
      return;
    }
  }

  const payload = parseChalPayload(chal);
  const policy = payload && payload.policy;
  const requireTurn = policy && policy.requireTurn === true;
  const requirePow = policy && policy.requirePow === true;

  const proof = { chalId, nonce };

  try {
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
  } catch (e) {
    setStatus(false);
    log("Error: " + (e && e.message ? e.message : String(e)));
    return;
  }

  setStatus(true);
  log("Verification complete.");

  if (parent && parentOrigin) {
    parent.postMessage({ type: "caas:proof", ...proof }, parentOrigin);
    return;
  }

  if (allowRedirect && returnUrl) {
    log("Redirecting...");
    const url = new URL(returnUrl);
    url.hash = new URLSearchParams({
      turn: proof.turnProofToken || "",
      pow: proof.powProofToken || "",
    }).toString();
    window.location.replace(url.toString());
    return;
  }

  document.body.innerHTML = `<div class="card"><h1>Success</h1><pre style="text-align:left;font-size:12px;overflow:auto;">${JSON.stringify(proof, null, 2)}</pre></div>`;
}