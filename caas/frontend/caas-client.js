export async function caasRun({
  generateUrl = "/api/caas/generate",
  attestUrl = "/api/caas/attest",
  payload,
  mode = "iframe",
  timeoutMs = 120000,
} = {}) {
  if (!payload || typeof payload !== "object") throw new Error("payload required");

  const genRes = await fetch(generateUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!genRes.ok) throw new Error(`generate failed (${genRes.status})`);
  const gen = await genRes.json();

  const ui = gen && (gen.ui || gen.turn);
  if (!ui || ui.enabled !== true || !ui.landingUrl) {
    throw new Error("invalid generate response (ui)");
  }

  const landingUrl = ui.landingUrl;
  const landingUrlRedirect = ui.landingUrlRedirect || null;
  const chal = gen.chal;

  const { proof, redirected } = await runLandingHandshake({
    landingUrl,
    landingUrlRedirect,
    chal,
    mode,
    timeoutMs,
  });
  if (redirected) return { redirected: true };

  const attestRes = await fetch(attestUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ...payload,
      chal,
      ...proof,
    }),
  });
  const attestText = await attestRes.text();
  let attestJson;
  try {
    attestJson = attestText ? JSON.parse(attestText) : null;
  } catch {
    attestJson = null;
  }
  if (!attestRes.ok) {
    const err = new Error(`attest failed (${attestRes.status})`);
    err.body = attestText;
    throw err;
  }
  return attestJson;
}

async function runLandingHandshake({
  landingUrl,
  landingUrlRedirect,
  chal,
  mode,
  timeoutMs,
}) {
  const allowPopup = mode === "popup";
  const allowIframe = mode === "iframe";

  const start = Date.now();
  const deadline = start + Math.max(1000, Number(timeoutMs) || 120000);

  const waitUntil = (predicate, intervalMs = 50) =>
    new Promise((resolve, reject) => {
      const tick = () => {
        if (Date.now() > deadline) return reject(new Error("landing timeout"));
        try {
          const v = predicate();
          if (v) return resolve(v);
        } catch {}
        setTimeout(tick, intervalMs);
      };
      tick();
    });

  let childWin = null;
  let iframe = null;
  const expectedOrigin = new URL(String(landingUrl), location.href).origin;

  const cleanup = () => {
    if (iframe && iframe.parentNode) iframe.parentNode.removeChild(iframe);
    iframe = null;
    if (childWin && !childWin.closed) childWin.close();
    childWin = null;
    window.removeEventListener("message", onMessage);
  };

  let ready = null;
  let proof = null;

  const onMessage = (event) => {
    if (!event || event.origin !== expectedOrigin) return;
    if (childWin && event.source !== childWin) return;
    const data = event && event.data;
    if (!data || typeof data !== "object") return;
    if (data.type === "caas:ready") {
      ready = { event, data };
      return;
    }
    if (data.type === "caas:proof") {
      proof = { event, data };
      return;
    }
  };
  window.addEventListener("message", onMessage);

  const openIframe = () => {
    iframe = document.createElement("iframe");
    iframe.src = landingUrl;
    iframe.style.width = "360px";
    iframe.style.height = "420px";
    iframe.style.border = "0";
    iframe.allow = "clipboard-write; clipboard-read";
    document.body.appendChild(iframe);
    childWin = iframe.contentWindow;
  };

  const openPopup = () => {
    childWin = window.open(landingUrl, "_blank", "popup,width=420,height=520");
    if (!childWin) throw new Error("popup blocked");
  };

  try {
    if (allowIframe) openIframe();
    else if (allowPopup) openPopup();
    else throw new Error("no interactive mode");
  } catch (e) {
    cleanup();
    if (!landingUrlRedirect) throw e;
    location.href = landingUrlRedirect;
    return { proof: null, redirected: true };
  }

  await waitUntil(() => ready);
  const { event: readyEvent, data: readyData } = ready;

  if (!readyData || typeof readyData.chalId !== "string" || typeof readyData.nonce !== "string") {
    cleanup();
    throw new Error("invalid ready message");
  }

  const targetWin = readyEvent.source;
  const targetOrigin = expectedOrigin;
  if (!targetWin || typeof targetWin.postMessage !== "function") {
    cleanup();
    throw new Error("invalid landing window");
  }

  targetWin.postMessage(
    { type: "caas:chal", chal, chalId: readyData.chalId, nonce: readyData.nonce },
    targetOrigin
  );

  await waitUntil(() => proof);
  const { data: proofData, event: proofEvent } = proof;
  if (proofEvent.origin !== targetOrigin) {
    cleanup();
    throw new Error("origin mismatch");
  }
  if (proofData.nonce !== readyData.nonce || proofData.chalId !== readyData.chalId) {
    cleanup();
    throw new Error("handshake mismatch");
  }

  const out = {};
  if (typeof proofData.proofToken === "string") out.proofToken = proofData.proofToken;
  cleanup();
  return { proof: out, redirected: false };
}
