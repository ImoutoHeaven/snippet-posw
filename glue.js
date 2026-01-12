const decodeB64Url = (str) => {
  try {
    let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4;
    if (pad) b64 += "=".repeat(4 - pad);
    return new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
  } catch {
    return null;
  }
};

const encoder = new TextEncoder();
const base64UrlEncodeNoPad = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const sha256Bytes = async (value) => {
  const bytes = encoder.encode(String(value ?? ""));
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
};
const tbFromToken = async (token) =>
  base64UrlEncodeNoPad((await sha256Bytes(token)).slice(0, 12));

const parseAtomicCfg = (raw) => {
  const parts = typeof raw === "string" && raw ? raw.split("|") : [];
  return {
    atomic: parts[0] === "1",
    q: {
      ts: parts[1] || "__ts",
      tt: parts[2] || "__tt",
      ct: parts[3] || "__ct",
    },
    h: {
      ts: parts[4] || "x-turnstile",
      tt: parts[5] || "x-ticket",
      ct: parts[6] || "x-consume",
    },
    c: parts[7] || "__Host-pow_a",
  };
};

const normalizeApiPrefix = (prefix) => {
  if (!prefix || typeof prefix !== "string") return "/__pow";
  return prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
};

const postJson = async (url, body, retries = 3) => {
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await fetch(url, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      });
      if (res.status === 403) throw new Error("403");
      if (!res.ok) {
        if (res.status >= 500 && i < retries) throw new Error("retry");
        throw new Error("Request Failed");
      }
      try {
        return await res.json();
      } catch {
        return {};
      }
    } catch (err) {
      if (err && err.message === "403") throw err;
      if (i === retries) throw err;
      const delay = 500 * Math.pow(2, i);
      log("Connection error. Retrying in " + delay + "ms...");
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  return {};
};

const setAtomicCookie = (name, value, maxAge) => {
  if (!name || !value) return false;
  document.cookie = `${name}=${value}; Max-Age=${maxAge}; Path=/; Secure; SameSite=Lax`;
  return document.cookie.includes(`${name}=`);
};

const canUseCookie = (name, value) =>
  Boolean(name && value && value.length + name.length + 1 <= 3800);

const addQuery = (url, kv) => {
  const next = new URL(url, window.location.href);
  for (const [key, value] of Object.entries(kv || {})) {
    if (key && value) next.searchParams.set(key, value);
  }
  return next.toString();
};

const postAtomicMessage = (payload) => {
  const msg = { type: "POW_ATOMIC", ...(payload || {}) };
  try {
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage(msg, "*");
    }
  } catch {}
  try {
    if (window.parent && window.parent !== window) {
      window.parent.postMessage(msg, "*");
    }
  } catch {}
};

const createWorkerRpc = (worker, onProgress) => {
  let rid = 0;
  const pending = new Map();
  const rejectAll = (err) => {
    for (const entry of pending.values()) {
      entry.reject(err);
    }
    pending.clear();
  };
  const handleMessage = (event) => {
    const data = event && event.data ? event.data : {};
    if (data.type === "PROGRESS") {
      if (typeof onProgress === "function") onProgress(data);
      return;
    }
    const entry = pending.get(data.rid);
    if (!entry) return;
    pending.delete(data.rid);
    if (data.type === "ERROR") {
      entry.reject(new Error(data.message || "Worker error"));
      return;
    }
    entry.resolve(data);
  };
  worker.addEventListener("message", handleMessage);
  worker.addEventListener("messageerror", () => {
    rejectAll(new Error("Worker message error"));
  });
  worker.addEventListener("error", () => {
    rejectAll(new Error("Worker error"));
  });

  const call = (type, payload) => {
    const id = ++rid;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      worker.postMessage({ ...(payload || {}), type, rid: id });
    });
  };

  const cancel = () => {
    try {
      worker.postMessage({ type: "CANCEL" });
    } catch {}
  };

  const dispose = () => {
    cancel();
    rejectAll(new Error("Worker disposed"));
    try {
      worker.postMessage({ type: "DISPOSE" });
    } catch {}
    worker.terminate();
  };

  return { call, cancel, dispose };
};


const initUi = () => {
  const style = document.createElement("style");
  style.textContent = [
    ":root{--bg:#09090b;--card-bg:#18181b;--border:#27272a;--text:#e4e4e7;--sub:#a1a1aa;--accent:#fff;--yellow:#fbbf24;--green:#4ade80;--font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;--mono:ui-monospace,'SFMono-Regular',Menlo,Monaco,Consolas,monospace;}",
    "html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:var(--bg);color:var(--text);font-family:var(--font);display:flex;justify-content:center;align-items:center;-webkit-font-smoothing:antialiased;}",
    ".card{background:var(--card-bg);border:1px solid var(--border);border-radius:12px;padding:32px;width:90%;max-width:360px;text-align:center;box-shadow:0 0 0 1px rgba(255,255,255,0.05),0 4px 12px rgba(0,0,0,0.4);animation:fade-in 0.6s cubic-bezier(0.16,1,0.3,1) both;transition:height 0.3s ease;}",
    "h1{margin:0 0 24px;font-size:15px;font-weight:500;color:var(--accent);letter-spacing:-0.01em;}",
    "#log{font-family:var(--mono);font-size:13px;color:var(--sub);text-align:left;height:120px;overflow:hidden;position:relative;mask-image:linear-gradient(to bottom,transparent,black 30%);-webkit-mask-image:linear-gradient(to bottom,transparent,black 30%);display:flex;flex-direction:column;justify-content:flex-end;}",
    "#ts{margin-top:16px;display:flex;justify-content:center;max-height:0;opacity:0;overflow:hidden;transition:max-height 0.4s cubic-bezier(0.16,1,0.3,1),opacity 0.3s ease,margin-top 0.4s cubic-bezier(0.16,1,0.3,1);}#ts.show{max-height:400px;opacity:1;margin-top:16px;}#ts.hide{max-height:0;opacity:0;margin-top:0;}",
    ".log-line{padding:3px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}.log-line .yellow{color:var(--yellow);}.log-line .green{color:var(--green);}",
    "#ticker{position:fixed;bottom:0;left:0;width:100%;height:28px;background:rgba(39,39,42,0.98);border-top:1px solid var(--border);overflow:hidden;z-index:1000;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);opacity:0;transition:opacity 0.6s ease;}#ticker.show{opacity:1;}#ticker.hide{opacity:0;}",
    "#ticker-text{position:absolute;top:50%;white-space:nowrap;font-size:12px;color:var(--sub);letter-spacing:0.08em;font-family:var(--font);}#ticker-text.scrolling{animation:scroll-left 18s linear forwards;}",
    "@keyframes fade-in{from{opacity:0;transform:scale(0.98)}to{opacity:1;transform:scale(1)}}",
    "@keyframes scroll-left{from{transform:translate(100vw,-50%);}to{transform:translate(-100%,-50%);}}"
  ].join("");
  (document.head || document.documentElement).appendChild(style);
  document.body.innerHTML =
    '<div class="card"><h1 id="t">Verifying...</h1><div id="log"></div><div id="ts"></div></div><div id="ticker"><div id="ticker-text">This process is automatic unless turnstile asks you to click the box, you will be redirected after verification is done.</div></div>';
  return {
    logEl: document.getElementById("log"),
    tEl: document.getElementById("t"),
    tsEl: document.getElementById("ts"),
    tickerEl: document.getElementById("ticker"),
    tickerTextEl: document.getElementById("ticker-text"),
  };
};

const ui = initUi();
const lines = [];
const MAX_VISIBLE_LINES = 6;
document.title = "Verifying...";

// Start ticker animation after 1.5 seconds
setTimeout(() => {
  if (ui.tickerEl && ui.tickerTextEl) {
    ui.tickerEl.classList.add("show");
    ui.tickerTextEl.classList.add("scrolling");

    // Hide ticker after animation completes
    ui.tickerTextEl.addEventListener("animationend", () => {
      ui.tickerEl.classList.remove("show");
      ui.tickerEl.classList.add("hide");
      setTimeout(() => {
        ui.tickerEl.style.display = "none";
      }, 600);
    }, { once: true });
  }
}, 1500);

const render = () => {
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
  if (ok) {
    ui.tEl.textContent = "Redirecting...";
    ui.tEl.style.color = "#4ade80";
  } else {
    ui.tEl.textContent = "Failed";
    ui.tEl.style.color = "#f87171";
  }
};

log("Initializing...");

const getTicketMac = (ticketB64) => {
  const raw = decodeB64Url(String(ticketB64 || ""));
  if (!raw) return null;
  const parts = raw.split(".");
  if (parts.length !== 6) return null;
  return parts[5] || null;
};

let turnstilePromise;
const loadTurnstile = () => {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (turnstilePromise) return turnstilePromise;
  turnstilePromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.onload = () => resolve(window.turnstile);
    script.onerror = () => reject(new Error("Turnstile Load Failed"));
    (document.head || document.documentElement).appendChild(script);
  });
  return turnstilePromise;
};

const runTurnstile = async (ticketB64, sitekey, submitToken) => {
  const ticketMac = getTicketMac(ticketB64);
  if (!ticketMac) throw new Error("Bad Ticket");
  log("Loading Turnstile...");
  const ts = await loadTurnstile();
  if (!ts || typeof ts.render !== "function") {
    throw new Error("Turnstile Missing");
  }
  const el = ui.tsEl;
  if (el) {
    el.innerHTML = "";
  }
  log("Waiting for Turnstile...");
  const container = document.createElement("div");
  if (el) {
    el.appendChild(container);
    // Force reflow before adding .show class to trigger transition
    void el.offsetHeight;
    requestAnimationFrame(() => {
      el.classList.add("show");
      el.classList.remove("hide");
    });
  }
  let tokenResolve;
  let tokenReject;
  const nextToken = () =>
    new Promise((resolve, reject) => {
      tokenResolve = resolve;
      tokenReject = reject;
    });
  let tokenPromise = nextToken();
  let widgetId = null;
  try {
    widgetId = ts.render(container, {
      sitekey,
      theme: "dark",
      cData: ticketMac,
      callback: (t) => {
        if (el) {
          el.classList.add("hide");
          el.classList.remove("show");
        }
        if (tokenResolve) tokenResolve(t);
      },
      "error-callback": () => tokenReject && tokenReject(new Error("Turnstile Failed")),
      "expired-callback": () => tokenReject && tokenReject(new Error("Turnstile Expired")),
    });
  } catch (e) {
    throw e;
  }
  const maxAttempts = 5;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let token;
    try {
      token = await tokenPromise;
    } catch (e) {
      if (e && e.message === "Turnstile Expired") {
        log("Turnstile expired. Retrying...");
        if (el) {
          void el.offsetHeight;
          requestAnimationFrame(() => {
            el.classList.add("show");
            el.classList.remove("hide");
          });
        }
        tokenPromise = nextToken();
        if (ts && typeof ts.reset === "function") ts.reset(widgetId);
        continue;
      }
      throw e;
    }
    if (el) {
      el.classList.add("hide");
      el.classList.remove("show");
    }
    const submitLine = submitToken ? log("Submitting Turnstile...") : -1;
    try {
      if (submitToken) await submitToken(token);
      if (submitLine !== -1) update(submitLine, "Submitting Turnstile... <span class=\"green\">done</span>");
      log("Turnstile... <span class=\"green\">done</span>");
      if (el) {
        el.classList.add("hide");
        el.classList.remove("show");
        setTimeout(() => {
          if (el.classList.contains("hide")) {
            el.innerHTML = "";
          }
        }, 400);
      }
      if (ts && typeof ts.remove === "function" && widgetId !== null) {
        try {
          ts.remove(widgetId);
        } catch {}
      }
      return token;
    } catch (e) {
      if (submitToken && e && e.message === "403") {
        update(submitLine, "Turnstile rejected. Please try again.");
        if (el) {
          void el.offsetHeight;
          requestAnimationFrame(() => {
            el.classList.add("show");
            el.classList.remove("hide");
          });
        }
        if (attempt >= maxAttempts) throw new Error("Turnstile Rejected");
        tokenPromise = nextToken();
        if (ts && typeof ts.reset === "function") ts.reset(widgetId);
        continue;
      }
      throw e;
    }
  }
  return null;
};

const runPowFlow = async (
  apiPrefix,
  bindingB64,
  steps,
  ticketB64,
  pathHash,
  hashcashBits,
  segmentLen,
  esmUrlB64,
  turnToken
) => {
  log("Loading solver...");
  const esmUrl = decodeB64Url(String(esmUrlB64 || ""));
  const module = await import(esmUrl);
  const workerUrl = module.workerUrl;
  if (!workerUrl) {
    throw new Error("Worker Missing");
  }
  const authBinding = decodeB64Url(String(bindingB64 || ""));
  if (!authBinding) {
    throw new Error("Bad Binding");
  }
  const powBinding = turnToken ? `${authBinding}|${await tbFromToken(turnToken)}` : authBinding;

  const workerCode = await fetch(workerUrl).then(r => r.text());
  const blob = new Blob([workerCode], { type: "application/javascript" });
  const blobUrl = URL.createObjectURL(blob);
  const worker = new Worker(blobUrl, { type: "module" });
  let spinTimer;
  let verifySpinTimer;
  try {
    let spinIndex = -1;
    let spinFrame = 0;
    const spinChars = "|/-\\";
    let attemptCount = 0;
    let verifyLine = -1;
    let verifySpinFrame = 0;
    const verifySpinChars = "|/-\\";
    let verifyBaseMsg = "";

    const rpc = createWorkerRpc(worker, (progress) => {
      if (progress.phase === "chain" && spinIndex === -1) {
        spinIndex = log("Computing hash chain...");
        spinTimer = setInterval(() => {
          let msg = "Computing hash chain...";
          if (attemptCount > 0) {
            msg = "Screening hash (attempt " + attemptCount + ")...";
          }
          const spinner = '<span class="yellow">' + spinChars[spinFrame++ % spinChars.length] + "</span>";
          update(spinIndex, msg + " " + spinner);
        }, 120);
      }
      if (progress.phase === "hashcash" && typeof progress.attempt === "number") {
        attemptCount = progress.attempt;
      }
    });

    await rpc.call("INIT", {
      bindingString: powBinding,
      steps,
      hashcashBits,
      segmentLen,
      yieldEvery: 1024,
      progressEvery: 1024,
    });

    const commitRes = await rpc.call("COMMIT");
    if (spinTimer) clearInterval(spinTimer);
    if (spinIndex !== -1) {
      const doneText = attemptCount > 0
        ? "Screening hash... <span class=\"green\">done</span>"
        : "Computing hash chain... <span class=\"green\">done</span>";
      update(spinIndex, doneText);
    }

    log("Submitting commit...");
    const commitBody = {
      ticketB64,
      rootB64: commitRes.rootB64,
      pathHash,
      nonce: commitRes.nonce,
    };
    if (turnToken) commitBody.token = turnToken;
    await postJson(apiPrefix + "/commit", commitBody);

    log("Requesting challenge...");
    let state = await postJson(apiPrefix + "/challenge", {});
    if (
      !state ||
      !Array.isArray(state.indices) ||
      typeof state.sid !== "string" ||
      typeof state.cursor !== "number" ||
      typeof state.token !== "string"
    ) {
      throw new Error("Challenge Failed");
    }

    let round = 0;
    while (state && state.done !== true) {
      round++;
      if (!Array.isArray(state.indices) || state.indices.length === 0) {
        throw new Error("Challenge Failed");
      }
      verifyBaseMsg = "Verifying #" + round + " (" + state.indices.length + ")...";
      if (verifyLine === -1) {
        verifyLine = log(verifyBaseMsg);
        verifySpinTimer = setInterval(() => {
          const spinner = '<span class="yellow">' + verifySpinChars[verifySpinFrame++ % verifySpinChars.length] + "</span>";
          update(verifyLine, verifyBaseMsg + " " + spinner);
        }, 120);
      }
      const indices = state.indices;
      const segs =
        Array.isArray(state.segs) && state.segs.length === indices.length
          ? state.segs
          : null;
      const spinePos = Array.isArray(state.spinePos) ? state.spinePos : null;
      if (!segs || !spinePos) {
        throw new Error("Challenge Failed");
      }
      const segLens = segs.map((v) => Number(v));
      const openRes = await rpc.call("OPEN", { indices, segLens, spinePos });
      const openBody = {
        sid: state.sid,
        cursor: state.cursor,
        token: state.token,
        spinePos,
        opens: openRes.opens,
      };
      if (turnToken) openBody.turnToken = turnToken;
      state = await postJson(apiPrefix + "/open", openBody);
      if (state && state.done === true) break;
      if (
        !state ||
        !Array.isArray(state.indices) ||
        typeof state.sid !== "string" ||
        typeof state.cursor !== "number" ||
        typeof state.token !== "string"
      ) {
        throw new Error("Challenge Failed");
      }
    }
    if (verifySpinTimer) clearInterval(verifySpinTimer);
    if (verifyLine !== -1) update(verifyLine, "Verifying... <span class=\"green\">done</span>");
    log("PoW... <span class=\"green\">done</span>");
    rpc.dispose();
    return state;
  } finally {
    if (spinTimer) clearInterval(spinTimer);
    if (verifySpinTimer) clearInterval(verifySpinTimer);
    worker.terminate();
    URL.revokeObjectURL(blobUrl);
  }
};

export default async function runPow(
  bindingB64,
  steps,
  ticketB64,
  pathHash,
  hashcashBits,
  segmentLen,
  reloadUrlB64,
  apiPrefixB64,
  esmUrlB64,
  turnSiteKeyB64,
  atomicCfg
) {
  try {
    const apiPrefix = normalizeApiPrefix(decodeB64Url(String(apiPrefixB64 || "")));
    const target = decodeB64Url(String(reloadUrlB64 || "")) || "/";

    const needPow = Number(steps) > 0;
    const turnSiteKey = decodeB64Url(String(turnSiteKeyB64 || "")) || "";
    const needTurn = !!turnSiteKey;
    const cfg = parseAtomicCfg(atomicCfg);
    const atomicEnabled = cfg.atomic;
    const Q_TURN = cfg.q.ts;
    const Q_TICKET = cfg.q.tt;
    const Q_CONSUME = cfg.q.ct;
    const H_TURN = cfg.h.ts;
    const H_TICKET = cfg.h.tt;
    const H_CONSUME = cfg.h.ct;
    const C_NAME = cfg.c;

    if (!needPow && !needTurn) throw new Error("No Challenge");

    const embedded = window.parent !== window;

    if (needTurn && !needPow) {
      if (atomicEnabled) {
        const turnToken = await runTurnstile(ticketB64, turnSiteKey);
        const query = { [Q_TURN]: turnToken, [Q_TICKET]: ticketB64 };
        const headers = { [H_TURN]: turnToken, [H_TICKET]: ticketB64 };
        if (embedded) {
          postAtomicMessage({ mode: "turn", turnToken, ticketB64, headers, query });
          log("Access granted. You may close this window.");
          setStatus(true);
          document.title = "Done";
          return;
        }
        const cookieValue = `1|t|${turnToken}|${ticketB64}`;
        if (canUseCookie(C_NAME, cookieValue) && setAtomicCookie(C_NAME, cookieValue, 10)) {
          log("Access granted. <span class=\"yellow\">Redirecting...</span>");
          setStatus(true);
          document.title = "Redirecting";
          window.location.replace(target);
          return;
        }
        log("Access granted. <span class=\"yellow\">Redirecting...</span>");
        setStatus(true);
        document.title = "Redirecting";
        window.location.replace(addQuery(target, query));
        return;
      }
      await runTurnstile(ticketB64, turnSiteKey, async (token) => {
        await postJson(apiPrefix + "/turn", { ticketB64, pathHash, token });
      });
    } else if (needPow && !needTurn) {
      await runPowFlow(
        apiPrefix,
        bindingB64,
        steps,
        ticketB64,
        pathHash,
        hashcashBits,
        segmentLen,
        esmUrlB64,
        ""
      );
    } else {
      const turnToken = await runTurnstile(ticketB64, turnSiteKey);
      log("Turnstile solved. Starting PoW...");
      const state = await runPowFlow(
        apiPrefix,
        bindingB64,
        steps,
        ticketB64,
        pathHash,
        hashcashBits,
        segmentLen,
        esmUrlB64,
        turnToken
      );
      if (atomicEnabled) {
        const consume = state && state.consume;
        if (!consume) throw new Error("Consume Missing");
        const query = { [Q_TURN]: turnToken, [Q_CONSUME]: consume };
        const headers = { [H_TURN]: turnToken, [H_CONSUME]: consume };
        if (embedded) {
          postAtomicMessage({ mode: "combine", turnToken, consume, headers, query });
          log("Access granted. You may close this window.");
          setStatus(true);
          document.title = "Done";
          return;
        }
        const cookieValue = `1|c|${turnToken}|${consume}`;
        if (canUseCookie(C_NAME, cookieValue) && setAtomicCookie(C_NAME, cookieValue, 10)) {
          log("Access granted. <span class=\"yellow\">Redirecting...</span>");
          setStatus(true);
          document.title = "Redirecting";
          window.location.replace(target);
          return;
        }
        log("Access granted. <span class=\"yellow\">Redirecting...</span>");
        setStatus(true);
        document.title = "Redirecting";
        window.location.replace(addQuery(target, query));
        return;
      }
    }
    log("Access granted. <span class=\"yellow\">Redirecting...</span>");
    setStatus(true);
    document.title = "Redirecting";
    window.location.replace(target);
  } catch (e) {
    if (e && e.message === "403") {
      log("Session expired. Reloading...");
      setTimeout(() => window.location.reload(), 1000);
      return;
    }
    log("ERROR: " + (e && e.message ? e.message : String(e)));
    setStatus(false);
  }
}
