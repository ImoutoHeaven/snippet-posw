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

const initUi = () => {
  const style = document.createElement("style");
  style.textContent = [
    ":root{--bg:#09090b;--card-bg:#18181b;--border:#27272a;--text:#e4e4e7;--sub:#a1a1aa;--accent:#fff;--font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;--mono:ui-monospace,'SFMono-Regular',Menlo,Monaco,Consolas,monospace;}",
    "html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:var(--bg);color:var(--text);font-family:var(--font);display:flex;justify-content:center;align-items:center;-webkit-font-smoothing:antialiased;}",
    ".card{background:var(--card-bg);border:1px solid var(--border);border-radius:12px;padding:32px;width:90%;max-width:360px;text-align:center;box-shadow:0 0 0 1px rgba(255,255,255,0.05),0 4px 12px rgba(0,0,0,0.4);animation:fade-in 0.6s cubic-bezier(0.16,1,0.3,1) both;}",
    "h1{margin:0 0 24px;font-size:15px;font-weight:500;color:var(--accent);letter-spacing:-0.01em;}",
    "#log{font-family:var(--mono);font-size:13px;color:var(--sub);text-align:left;height:120px;overflow:hidden;position:relative;mask-image:linear-gradient(to bottom,transparent,black 30%);-webkit-mask-image:linear-gradient(to bottom,transparent,black 30%);display:flex;flex-direction:column;justify-content:flex-end;}",
    "#ts{margin-top:16px;display:flex;justify-content:center;}",
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

const ui = initUi();
const lines = [];
const MAX_VISIBLE_LINES = 6;
document.title = "Verifying...";

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

const runTurnstile = async (apiPrefix, ticketB64, pathHash, sitekey) => {
  const ticketMac = getTicketMac(ticketB64);
  if (!ticketMac) throw new Error("Bad Ticket");
  log("Loading Turnstile...");
  const ts = await loadTurnstile();
  if (!ts || typeof ts.render !== "function") {
    throw new Error("Turnstile Missing");
  }
  const el = ui.tsEl;
  if (el) el.innerHTML = "";
  log("Waiting for Turnstile...");
  const container = document.createElement("div");
  if (el) el.appendChild(container);
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
      callback: (t) => tokenResolve && tokenResolve(t),
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
        tokenPromise = nextToken();
        if (ts && typeof ts.reset === "function") ts.reset(widgetId);
        continue;
      }
      throw e;
    }
    const submitLine = log("Submitting Turnstile...");
    try {
      await postJson(apiPrefix + "/turn", { ticketB64, pathHash, token });
      update(submitLine, "Submitting Turnstile... done");
      log("Turnstile... done");
      return;
    } catch (e) {
      if (e && e.message === "403") {
        update(submitLine, "Turnstile rejected. Please try again.");
        if (attempt >= maxAttempts) throw new Error("Turnstile Rejected");
        tokenPromise = nextToken();
        if (ts && typeof ts.reset === "function") ts.reset(widgetId);
        continue;
      }
      throw e;
    }
  }
};

const runPowFlow = async (
  apiPrefix,
  bindingB64,
  steps,
  ticketB64,
  pathHash,
  hashcashBits,
  segmentLen,
  esmUrlB64
) => {
  log("Loading solver...");
  const esmUrl = decodeB64Url(String(esmUrlB64 || ""));
  const module = await import(esmUrl);
  const computePoswCommit = module.computePoswCommit;
  if (typeof computePoswCommit !== "function") {
    throw new Error("Solver Missing");
  }
  const binding = decodeB64Url(String(bindingB64 || ""));
  const spinIndex = log("Computing hash chain...");
  const spinChars = "|/-\\";
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
    const commit = await computePoswCommit(binding, steps, {
      hashcashBits,
      segmentLen,
      onStatus: (type, val) => {
        if (type === "retry") attemptCount = val;
      },
    });
    clearInterval(spinTimer);
    update(
      spinIndex,
      attemptCount > 0 ? "Screening hash... done" : "Computing hash chain... done"
    );
    log("Submitting commit...");
    await postJson(apiPrefix + "/commit", {
      ticketB64,
      rootB64: commit.rootB64,
      pathHash,
      nonce: commit.nonce,
    });
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
      log("Verifying #" + round + " (" + state.indices.length + ")...");
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
      const opens = await commit.open(indices, { segLens, spinePos });
      state = await postJson(apiPrefix + "/open", {
        sid: state.sid,
        cursor: state.cursor,
        token: state.token,
        spinePos,
        opens,
      });
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
    log("PoW... done");
  } finally {
    clearInterval(spinTimer);
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
  turnSiteKeyB64
) {
  try {
    const apiPrefix = normalizeApiPrefix(decodeB64Url(String(apiPrefixB64 || "")));
    const target = decodeB64Url(String(reloadUrlB64 || "")) || "/";

    const needPow = Number(steps) > 0;
    const turnSiteKey = decodeB64Url(String(turnSiteKeyB64 || "")) || "";
    const needTurn = !!turnSiteKey;

    const tasks = [];
    if (needPow) {
      tasks.push(
        runPowFlow(
          apiPrefix,
          bindingB64,
          steps,
          ticketB64,
          pathHash,
          hashcashBits,
          segmentLen,
          esmUrlB64
        )
      );
    }
    if (needTurn) {
      tasks.push(runTurnstile(apiPrefix, ticketB64, pathHash, turnSiteKey));
    }
    if (!tasks.length) throw new Error("No Challenge");

    await Promise.all(tasks);
    log("Access granted. Redirecting...");
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
