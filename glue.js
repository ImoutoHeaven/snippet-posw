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

const I18N = {
  en: {
    title_verifying: "Verifying...",
    title_redirecting: "Redirecting...",
    title_done: "Done",
    title_failed: "Failed",
    initializing: "Initializing...",
    connection_retry: "Connection error. Retrying in {ms}ms...",
    request_failed: "Request Failed",
    bad_ticket: "Bad Ticket",
    turnstile_load_failed: "Turnstile Load Failed",
    loading_turnstile: "Loading Turnstile...",
    turnstile_missing: "Turnstile Missing",
    waiting_turnstile: "Waiting for Turnstile...",
    turnstile_expired_retry: "Turnstile expired. Retrying...",
    submitting_turnstile: "Submitting Turnstile...",
    submitting_turnstile_done: "Submitting Turnstile... {done}",
    turnstile_done: "Turnstile... {done}",
    turnstile_rejected_retry: "Turnstile rejected. Please try again.",
    turnstile_rejected: "Turnstile Rejected",
    turnstile_failed: "Turnstile Failed",
    turnstile_expired: "Turnstile Expired",
    loading_solver: "Loading solver...",
    worker_missing: "Worker Missing",
    bad_binding: "Bad Binding",
    computing_hash_chain: "Computing hash chain...",
    screening_hash_attempt: "Screening hash (attempt {n})...",
    screening_hash_done: "Screening hash... {done}",
    computing_hash_chain_done: "Computing hash chain... {done}",
    submitting_commit: "Submitting commit...",
    requesting_challenge: "Requesting challenge...",
    challenge_failed: "Challenge Failed",
    verifying_batch: "Verifying #{round} ({count})...",
    verifying_done: "Verifying... {done}",
    pow_done: "PoW... {done}",
    no_challenge: "No Challenge",
    turnstile_solved_pow: "Turnstile solved. Starting PoW...",
    consume_missing: "Consume Missing",
    access_granted_close: "Access granted. You may close this window.",
    access_granted_redirecting: "Access granted. {redirect}",
    session_expired_reload: "Session expired. Reloading...",
    error_prefix: "ERROR: {message}",
    done: "done",
    redirecting: "Redirecting...",
    failed: "Failed",
    no_workers: "No workers",
    commit_failed: "Commit failed",
    worker_error: "Worker error",
    worker_message_error: "Worker message error",
  },
  zh: {
    title_verifying: "验证中...",
    title_redirecting: "正在跳转...",
    title_done: "完成",
    title_failed: "失败",
    initializing: "初始化中...",
    connection_retry: "连接错误，{ms}ms 后重试...",
    request_failed: "请求失败",
    bad_ticket: "票据无效",
    turnstile_load_failed: "Turnstile 加载失败",
    loading_turnstile: "加载 Turnstile...",
    turnstile_missing: "Turnstile 不可用",
    waiting_turnstile: "等待 Turnstile...",
    turnstile_expired_retry: "Turnstile 已过期，正在重试...",
    submitting_turnstile: "提交 Turnstile...",
    submitting_turnstile_done: "提交 Turnstile... {done}",
    turnstile_done: "Turnstile... {done}",
    turnstile_rejected_retry: "Turnstile 被拒绝，请重试。",
    turnstile_rejected: "Turnstile 被拒绝",
    turnstile_failed: "Turnstile 失败",
    turnstile_expired: "Turnstile 已过期",
    loading_solver: "加载求解器...",
    worker_missing: "Worker 不可用",
    bad_binding: "绑定无效",
    computing_hash_chain: "计算哈希链...",
    screening_hash_attempt: "筛选哈希（第 {n} 次）...",
    screening_hash_done: "筛选哈希... {done}",
    computing_hash_chain_done: "计算哈希链... {done}",
    submitting_commit: "提交 commit...",
    requesting_challenge: "请求 challenge...",
    challenge_failed: "Challenge 失败",
    verifying_batch: "校验第 {round} 轮（{count}）...",
    verifying_done: "校验中... {done}",
    pow_done: "PoW... {done}",
    no_challenge: "没有挑战",
    turnstile_solved_pow: "Turnstile 已完成，开始 PoW...",
    consume_missing: "缺少 consume",
    access_granted_close: "已通过验证，可关闭此窗口。",
    access_granted_redirecting: "已通过验证。{redirect}",
    session_expired_reload: "会话已过期，正在刷新...",
    error_prefix: "错误：{message}",
    done: "完成",
    redirecting: "正在跳转...",
    failed: "失败",
    no_workers: "没有可用的 worker",
    commit_failed: "Commit 失败",
    worker_error: "Worker 错误",
    worker_message_error: "Worker 消息错误",
  },
  ja: {
    title_verifying: "確認中...",
    title_redirecting: "リダイレクト中...",
    title_done: "完了",
    title_failed: "失敗",
    initializing: "初期化中...",
    connection_retry: "接続エラー。{ms}ms 後に再試行します...",
    request_failed: "リクエスト失敗",
    bad_ticket: "無効なチケット",
    turnstile_load_failed: "Turnstile の読み込みに失敗しました",
    loading_turnstile: "Turnstile を読み込み中...",
    turnstile_missing: "Turnstile が見つかりません",
    waiting_turnstile: "Turnstile を待機中...",
    turnstile_expired_retry: "Turnstile の有効期限切れ。再試行します...",
    submitting_turnstile: "Turnstile を送信中...",
    submitting_turnstile_done: "Turnstile を送信中... {done}",
    turnstile_done: "Turnstile... {done}",
    turnstile_rejected_retry: "Turnstile が拒否されました。再試行してください。",
    turnstile_rejected: "Turnstile が拒否されました",
    turnstile_failed: "Turnstile 失敗",
    turnstile_expired: "Turnstile の有効期限切れ",
    loading_solver: "ソルバーを読み込み中...",
    worker_missing: "Worker が見つかりません",
    bad_binding: "無効なバインド",
    computing_hash_chain: "ハッシュチェーンを計算中...",
    screening_hash_attempt: "ハッシュを選別中（{n} 回目）...",
    screening_hash_done: "ハッシュ選別... {done}",
    computing_hash_chain_done: "ハッシュチェーン... {done}",
    submitting_commit: "commit を送信中...",
    requesting_challenge: "チャレンジを要求中...",
    challenge_failed: "チャレンジ失敗",
    verifying_batch: "検証 #{round}（{count}）...",
    verifying_done: "検証中... {done}",
    pow_done: "PoW... {done}",
    no_challenge: "チャレンジなし",
    turnstile_solved_pow: "Turnstile 解決。PoW を開始...",
    consume_missing: "consume がありません",
    access_granted_close: "認証に成功しました。このウィンドウを閉じてください。",
    access_granted_redirecting: "認証に成功しました。{redirect}",
    session_expired_reload: "セッション期限切れ。再読み込み中...",
    error_prefix: "エラー: {message}",
    done: "完了",
    redirecting: "リダイレクト中...",
    failed: "失敗",
    no_workers: "利用可能な worker がありません",
    commit_failed: "commit 失敗",
    worker_error: "Worker エラー",
    worker_message_error: "Worker メッセージエラー",
  },
};

const normalizeLocale = (value) => {
  if (!value) return "";
  const lower = String(value).toLowerCase();
  if (lower.startsWith("zh")) return "zh";
  if (lower.startsWith("ja")) return "ja";
  if (lower.startsWith("en")) return "en";
  return "";
};

const resolveLocale = (languages) => {
  const list = Array.isArray(languages) ? languages : languages ? [languages] : [];
  for (const lang of list) {
    const normalized = normalizeLocale(lang);
    if (normalized) return normalized;
  }
  return "en";
};

const readNavigatorLanguages = () => {
  if (typeof navigator === "undefined") return [];
  if (Array.isArray(navigator.languages) && navigator.languages.length > 0) {
    return navigator.languages;
  }
  if (typeof navigator.language === "string" && navigator.language) {
    return [navigator.language];
  }
  return [];
};

let activeLocale = resolveLocale(readNavigatorLanguages());
const getLocale = () => activeLocale;
const setLocale = (next) => {
  const normalized = normalizeLocale(next);
  if (normalized) activeLocale = normalized;
};

const translate = (locale, key, vars) => {
  const dict = I18N[locale] || I18N.en;
  const fallback = I18N.en;
  const template = dict[key] || fallback[key] || key;
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/gu, (match, name) => {
    if (!Object.prototype.hasOwnProperty.call(vars, name)) return match;
    return String(vars[name]);
  });
};

const t = (key, vars) => translate(activeLocale, key, vars);

const wrapSpan = (klass, text) => `<span class="${klass}">${text}</span>`;
const doneMark = () => wrapSpan("green", t("done"));
const yellowMark = (text) => wrapSpan("yellow", text);

const ERROR_KEY_BY_MESSAGE = {
  "Request Failed": "request_failed",
  "Bad Ticket": "bad_ticket",
  "Turnstile Load Failed": "turnstile_load_failed",
  "Turnstile Missing": "turnstile_missing",
  "Turnstile Failed": "turnstile_failed",
  "Turnstile Expired": "turnstile_expired",
  "Turnstile Rejected": "turnstile_rejected",
  "Worker Missing": "worker_missing",
  "Bad Binding": "bad_binding",
  "Challenge Failed": "challenge_failed",
  "No Challenge": "no_challenge",
  "Consume Missing": "consume_missing",
  "No workers": "no_workers",
  "Commit failed": "commit_failed",
  "Worker error": "worker_error",
  "Worker message error": "worker_message_error",
};

const escapeHtml = (value) =>
  String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const localizeErrorMessage = (message) => {
  const key = ERROR_KEY_BY_MESSAGE[message];
  return escapeHtml(key ? t(key) : message);
};

const encoder = new TextEncoder();
const base64UrlEncodeNoPad = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const sha256Bytes = async (value) => {
  const bytes = encoder.encode(String(value ?? ""));
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
};
const captchaTagV1 = async (turnToken) => {
  const material = `ctag|v1|t=${turnToken}`;
  return base64UrlEncodeNoPad((await sha256Bytes(material)).slice(0, 12));
};

const parseCanonicalCaptchaEnvelope = (captchaToken) => {
  if (typeof captchaToken !== "string") return null;
  const raw = captchaToken.trim();
  if (!raw) return null;
  let envelope;
  try {
    envelope = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) return null;
  if (typeof envelope.turnstile !== "string" || !envelope.turnstile) return null;
  if (Object.keys(envelope).some((key) => key !== "turnstile")) return null;
  return { turnstile: envelope.turnstile };
};

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
    c: parts[7] || "__Secure-pow_a",
  };
};

const normalizeApiPrefix = (prefix) => {
  if (!prefix || typeof prefix !== "string") return "/__pow";
  return prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
};

const STALE_RELOAD_STORAGE_KEY = "__pow_stale_reload_v1";
const STALE_RELOAD_WINDOW_MS = 15000;
const STALE_RELOAD_MAX_ATTEMPTS = 2;

const sessionStorageSafe = () => {
  try {
    if (typeof window === "undefined" || !window.sessionStorage) return null;
    return window.sessionStorage;
  } catch {
    return null;
  }
};

const shouldAttemptStaleReload = (nowMs = Date.now()) => {
  const storage = sessionStorageSafe();
  if (!storage) return false;
  let count = 0;
  try {
    const raw = storage.getItem(STALE_RELOAD_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      const ts = Number(parsed && parsed.ts);
      const parsedCount = Number(parsed && parsed.count);
      if (Number.isFinite(ts) && nowMs - ts <= STALE_RELOAD_WINDOW_MS) {
        count = Number.isFinite(parsedCount) && parsedCount > 0 ? Math.floor(parsedCount) : 0;
      }
    }
  } catch {}

  if (count >= STALE_RELOAD_MAX_ATTEMPTS) return false;

  try {
    storage.setItem(
      STALE_RELOAD_STORAGE_KEY,
      JSON.stringify({ ts: nowMs, count: count + 1 })
    );
  } catch {
    return false;
  }
  return true;
};

const buildApiError = (url, res) => {
  let endpoint = String(url || "");
  let path = endpoint;
  try {
    const parsed = new URL(endpoint, window.location.href);
    endpoint = parsed.toString();
    path = parsed.pathname;
  } catch {}
  const err = new Error(`HTTP ${res.status}`);
  err.name = "ApiError";
  err.status = Number(res.status || 0);
  err.hint =
    res && res.headers && typeof res.headers.get === "function"
      ? String(res.headers.get("x-pow-h") || "").trim().toLowerCase()
      : "";
  err.endpoint = endpoint;
  err.path = path;
  return err;
};

const isApiError = (err) => Boolean(err && err.name === "ApiError" && Number(err.status));

const routeHintAction = ({ status, hint }) => {
  if (Number(status) !== 403) {
    return { action: "hard_fail", bounded: false };
  }
  const normalized = String(hint || "").trim().toLowerCase();
  if (normalized === "cheat") {
    return { action: "hard_fail", bounded: false };
  }
  if (normalized === "stale" || !normalized) {
    return { action: "reload", bounded: true };
  }
  return { action: "hard_fail", bounded: false };
};

const isNetworkTransportError = (err) => {
  if (!err) return false;
  if (typeof DOMException !== "undefined" && err instanceof DOMException) {
    return err.name === "AbortError";
  }
  if (err instanceof TypeError) return true;
  const name = String(err.name || "").toLowerCase();
  if (name === "aborterror") return true;
  const msg = String(err.message || "").toLowerCase();
  return /(network|fetch|connection|reset|econn|timed?\s*out|stream)/.test(msg);
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
      if (!res.ok) {
        throw buildApiError(url, res);
      }
      try {
        return await res.json();
      } catch {
        return {};
      }
    } catch (err) {
      if (isApiError(err)) throw err;
      if (!isNetworkTransportError(err)) throw err;
      if (i === retries) throw err;
      const delay = 500 * Math.pow(2, i);
      log(t("connection_retry", { ms: delay }));
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  return {};
};

const setAtomicCookie = (name, value, maxAge, path) => {
  if (!name || !value) return false;
  const cookiePath = path && path.startsWith("/") ? path : "/";
  document.cookie = `${name}=${value}; Max-Age=${maxAge}; Path=${cookiePath}; Secure; SameSite=Lax`;
  return document.cookie.includes(`${name}=`);
};

const canUseCookie = (name, value) =>
  Boolean(name && value && value.length + name.length + 1 <= 3800);

const cookiePathForTarget = (target) => {
  try {
    const url = new URL(target, window.location.href);
    return url.pathname || "/";
  } catch {
    return "/";
  }
};

const addQuery = (url, kv) => {
  const next = new URL(url, window.location.href);
  for (const [key, value] of Object.entries(kv || {})) {
    if (key && value) next.searchParams.set(key, value);
  }
  return next.toString();
};

const originFromLocation = (location) => {
  try {
    if (!location) return null;
    if (typeof location.origin === "string" && location.origin) return location.origin;
    if (typeof location.href === "string" && location.href) {
      return new URL(location.href, window.location.href).origin;
    }
    return null;
  } catch {
    return null;
  }
};

const selfOrigin = () => {
  try {
    return new URL(window.location.href).origin;
  } catch {
    return null;
  }
};

const postAtomicMessage = (payload) => {
  const msg = { type: "POW_ATOMIC", ...(payload || {}) };
  const expectedOrigin = selfOrigin();
  const postTo = (target) => {
    try {
      if (!target || typeof target.postMessage !== "function") return;
      if (target.closed) return;
      const targetOrigin = originFromLocation(target.location);
      if (!expectedOrigin || targetOrigin !== expectedOrigin) return;
      target.postMessage(msg, expectedOrigin);
    } catch {}
  };
  postTo(window.opener);
  if (window.parent && window.parent !== window) {
    postTo(window.parent);
  }
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
    ":root{--bg:#050607;--card-bg:rgba(24,24,27,0.75);--border:rgba(255,255,255,0.1);--text:#f4f4f8;--sub:#9ca3af;--accent:#fff;--yellow:#fbbf24;--green:#4ade80;--font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;--mono:ui-monospace,'SFMono-Regular',Menlo,Monaco,Consolas,monospace;--glow-x:50%;--glow-y:0%;--glow-r:62;--glow-g:110;--glow-b:255;--breathe-opacity:1;--reflect-top:0;--reflect-bottom:0;--reflect-left:0;--reflect-right:0;}",
    "html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:var(--bg);color:var(--text);font-family:var(--font);display:flex;justify-content:center;align-items:center;-webkit-font-smoothing:antialiased;}",
    "body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(circle at var(--glow-x) var(--glow-y), rgba(var(--glow-r),var(--glow-g),var(--glow-b),0.35),transparent 55%),radial-gradient(circle at calc(100% - var(--glow-x)) calc(100% - var(--glow-y)), rgba(var(--glow-r),var(--glow-g),var(--glow-b),0.2),transparent 55%);opacity:var(--breathe-opacity);}",
    "body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(ellipse var(--glow-h-width-top,6.75%) var(--glow-v-height-top,18px) at var(--glow-x) 0%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--reflect-top)) 0%,transparent 70%) top/100% var(--glow-v-height-top,18px) no-repeat,radial-gradient(ellipse var(--glow-h-width-bottom,6.75%) var(--glow-v-height-bottom,18px) at var(--glow-x) 100%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--reflect-bottom)) 0%,transparent 70%) bottom/100% var(--glow-v-height-bottom,18px) no-repeat,radial-gradient(ellipse var(--glow-h-width-left,18px) var(--glow-v-height-left,6.75%) at 0% var(--glow-y),rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--reflect-left)) 0%,transparent 70%) left/var(--glow-h-width-left,18px) 100% no-repeat,radial-gradient(ellipse var(--glow-h-width-right,18px) var(--glow-v-height-right,6.75%) at 100% var(--glow-y),rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--reflect-right)) 0%,transparent 70%) right/var(--glow-h-width-right,18px) 100% no-repeat;}",
    ".card{background:rgba(15,23,42,0.4);border:1px solid rgba(148,163,184,0.2);border-radius:12px;padding:32px;width:90%;max-width:360px;text-align:center;animation:fade-in 0.6s cubic-bezier(0.16,1,0.3,1) both;transition:height 0.3s ease,border-color 0.2s ease;backdrop-filter:blur(12px) saturate(130%);-webkit-backdrop-filter:blur(12px) saturate(130%);position:relative;z-index:1;}",
    ".card::after{content:'';position:absolute;top:0;left:0;right:0;bottom:0;pointer-events:none;border-radius:inherit;background:radial-gradient(ellipse var(--elem-glow-h-width-top,15%) 1px at var(--elem-glow-x,50%) 0%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--elem-reflect-top,0)) 0%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),calc(var(--elem-reflect-top,0) * 0.3)) 50%,transparent 100%) top/100% 1px no-repeat,radial-gradient(ellipse var(--elem-glow-h-width-bottom,15%) 1px at var(--elem-glow-x,50%) 100%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--elem-reflect-bottom,0)) 0%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),calc(var(--elem-reflect-bottom,0) * 0.3)) 50%,transparent 100%) bottom/100% 1px no-repeat,radial-gradient(ellipse 1px var(--elem-glow-v-height-left,15%) at 0% var(--elem-glow-y,50%),rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--elem-reflect-left,0)) 0%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),calc(var(--elem-reflect-left,0) * 0.3)) 50%,transparent 100%) left/1px 100% no-repeat,radial-gradient(ellipse 1px var(--elem-glow-v-height-right,15%) at 100% var(--elem-glow-y,50%),rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--elem-reflect-right,0)) 0%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),calc(var(--elem-reflect-right,0) * 0.3)) 50%,transparent 100%) right/1px 100% no-repeat;}",
    "h1{margin:0 0 24px;font-size:15px;font-weight:500;color:var(--accent);letter-spacing:-0.01em;}",
    "#t.shine{color:transparent;background-image:linear-gradient(90deg,#c4c4c9 0%,#ffffff 50%,#c4c4c9 100%);background-size:200% 100%;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;animation:title-shine 3.2s ease-in-out infinite;}",
    "#log{font-family:var(--mono);font-size:13px;color:var(--sub);text-align:left;height:120px;overflow:hidden;position:relative;mask-image:linear-gradient(to bottom,transparent,black 30%);-webkit-mask-image:linear-gradient(to bottom,transparent,black 30%);display:flex;flex-direction:column;justify-content:flex-end;background:transparent;border:none;border-radius:0;padding:0;}",
    "#ts{margin-top:16px;display:flex;justify-content:center;max-height:0;opacity:0;overflow:hidden;transition:max-height 0.4s cubic-bezier(0.16,1,0.3,1),opacity 0.3s ease,margin-top 0.4s cubic-bezier(0.16,1,0.3,1);position:relative;z-index:2;}#ts.show{max-height:400px;opacity:1;margin-top:16px;}#ts.hide{max-height:0;opacity:0;margin-top:0;}",
    ".log-line{padding:3px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:0 0 auto;}.log-line .yellow{color:var(--yellow);}.log-line .green{color:var(--green);}",
    "@keyframes fade-in{from{opacity:0;transform:scale(0.98)}to{opacity:1;transform:scale(1)}}",
    "@keyframes title-shine{0%{background-position:200% 0;}100%{background-position:-200% 0;}}"
  ].join("");
  (document.head || document.documentElement).appendChild(style);
  const titleText = t("title_verifying");
  document.body.innerHTML =
    `<div class="card"><h1 id="t" class="shine">${titleText}</h1><div id="log"></div><div id="ts"></div></div>`;

  // --- Advanced Glow Effect Implementation (from landing) ---
  const glowState = {
    // Animation frame
    glowAnimationFrame: null,
    lastFrameTime: Date.now(),

    // Position and movement
    currentGlowX: 0.5,
    currentGlowY: 0,
    targetGlowX: 0.5,
    targetGlowY: 0,
    currentSpeedX: 0,
    currentSpeedY: 0,

    // Mode control
    isAutoGlow: true,
    isResting: false,
    restStartTime: 0,
    currentRestDuration: Math.random() * 8000,

    // Mouse tracking
    latestMouseX: 0,
    latestMouseY: 0,
    lastMouseSampleTime: 0,
    mouseIdleTimer: null,
    MOUSE_SAMPLE_INTERVAL: 1000,

    // Visibility management
    visibilityTimer: null,
    isRenderingStopped: false,
    fadeInPhase: 1,
    FADE_IN_DURATION: 2.5,

    // Color system
    colorTable: [
      { r: 62, g: 110, b: 255 },
      { r: 0, g: 191, b: 255 },
      { r: 64, g: 224, b: 208 },
      { r: 138, g: 43, b: 226 },
      { r: 147, g: 51, b: 234 },
      { r: 199, g: 21, b: 133 },
      { r: 255, g: 20, b: 147 },
      { r: 72, g: 61, b: 139 }
    ],
    currentColorIndex: 0,
    targetColorIndex: 1,
    colorTransitionPhase: Math.random(),
    colorTransitionDuration: 0,

    // Breathing animation
    breathePhase: Math.random(),
    breatheCycleDuration: 0,
    breatheMinOpacity: 0,
    breatheMaxOpacity: 0,
    targetBreatheCycleDuration: 0,
    targetBreatheMinOpacity: 0,
    targetBreatheMaxOpacity: 0,
    BREATHE_SMOOTHING_SPEED: 1.8,

    // Speed system
    MAX_SPEED: 0.08,
    WANDER_ACCELERATION: 0.12,
    MOUSE_ACCELERATION: 0.04,
    WANDER_REACHED_THRESHOLD: 0.01,

    // Helper functions
    getRandomBreatheMin() {
      return 0.5 + Math.random() * 0.2;
    },

    getRandomBreatheMax() {
      return 1.0 + Math.random() * 0.2;
    },

    getRandomBreatheDuration() {
      return 2 + Math.random() * 10;
    },

    getRandomColorIndex() {
      return Math.floor(Math.random() * this.colorTable.length);
    },

    getNextColorIndex(excludeIndex) {
      if (this.colorTable.length <= 1) return excludeIndex;
      let nextIndex = this.getRandomColorIndex();
      while (nextIndex === excludeIndex) {
        nextIndex = this.getRandomColorIndex();
      }
      return nextIndex;
    },

    getRandomColorTransitionDuration() {
      return 10 + Math.random() * 35;
    },

    getRandomWanderTarget() {
      return {
        x: 0.1 + Math.random() * 0.8,
        y: 0.05 + Math.random() * 0.2
      };
    },

    syncBreatheOpacity() {
      const body = document.body;
      if (!body) return;
      const breatheValue = 0.5 + 0.5 * Math.sin(this.breathePhase * Math.PI * 2 - Math.PI / 2);
      const currentOpacity = this.breatheMinOpacity + (this.breatheMaxOpacity - this.breatheMinOpacity) * breatheValue;
      body.style.setProperty('--breathe-opacity', (currentOpacity * this.fadeInPhase).toFixed(3));
    },

    applyGlowColor() {
      const body = document.body;
      if (!body) return;
      const currentColor = this.colorTable[this.currentColorIndex] || this.colorTable[0];
      const targetColor = this.colorTable[this.targetColorIndex] || currentColor;
      const r = Math.round(currentColor.r + (targetColor.r - currentColor.r) * this.colorTransitionPhase);
      const g = Math.round(currentColor.g + (targetColor.g - currentColor.g) * this.colorTransitionPhase);
      const b = Math.round(currentColor.b + (targetColor.b - currentColor.b) * this.colorTransitionPhase);
      body.style.setProperty('--glow-r', r);
      body.style.setProperty('--glow-g', g);
      body.style.setProperty('--glow-b', b);
    },

    updateElementsEdgeGlow(glowX, glowY) {
      const w = window.innerWidth;
      const h = window.innerHeight;
      const elements = document.querySelectorAll('.card');

      elements.forEach(element => {
        const rect = element.getBoundingClientRect();
        const relativeX = ((glowX - rect.left) / rect.width) * 100;
        const relativeY = ((glowY - rect.top) / rect.height) * 100;

        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        const dx = glowX - centerX;
        const dy = glowY - centerY;
        const distance = Math.sqrt(dx * dx + dy * dy);

        const maxDistance = Math.sqrt(w * w + h * h) * 0.5;
        const normalizedDistance = distance / maxDistance;

        const ELEMENT_GLOW_RADIUS = 0.4;
        const ELEMENT_MAX_INTENSITY = 0.2;
        const ELEMENT_REFLECTION_COEFFICIENT = 0.7;

        const baseIntensity = Math.max(0, 1 - normalizedDistance / ELEMENT_GLOW_RADIUS) * ELEMENT_MAX_INTENSITY;

        const distToTop = Math.abs(glowY - rect.top) / rect.height;
        const distToBottom = Math.abs(glowY - rect.bottom) / rect.height;
        const distToLeft = Math.abs(glowX - rect.left) / rect.width;
        const distToRight = Math.abs(glowX - rect.right) / rect.width;

        const edgeThreshold = 2.0;
        const proximityTop = distToTop < edgeThreshold ? Math.pow(1 - distToTop / edgeThreshold, 1.5) : 0;
        const proximityBottom = distToBottom < edgeThreshold ? Math.pow(1 - distToBottom / edgeThreshold, 1.5) : 0;
        const proximityLeft = distToLeft < edgeThreshold ? Math.pow(1 - distToLeft / edgeThreshold, 1.5) : 0;
        const proximityRight = distToRight < edgeThreshold ? Math.pow(1 - distToRight / edgeThreshold, 1.5) : 0;

        const reflectTop = baseIntensity * ELEMENT_REFLECTION_COEFFICIENT * proximityTop;
        const reflectBottom = baseIntensity * ELEMENT_REFLECTION_COEFFICIENT * proximityBottom;
        const reflectLeft = baseIntensity * ELEMENT_REFLECTION_COEFFICIENT * proximityLeft;
        const reflectRight = baseIntensity * ELEMENT_REFLECTION_COEFFICIENT * proximityRight;

        element.style.setProperty('--elem-glow-x', relativeX.toFixed(2) + '%');
        element.style.setProperty('--elem-glow-y', relativeY.toFixed(2) + '%');
        element.style.setProperty('--elem-reflect-top', reflectTop.toFixed(3));
        element.style.setProperty('--elem-reflect-bottom', reflectBottom.toFixed(3));
        element.style.setProperty('--elem-reflect-left', reflectLeft.toFixed(3));
        element.style.setProperty('--elem-reflect-right', reflectRight.toFixed(3));

        const baseWidth = 10;
        const maxWidth = 30;
        const glowHWidthTop = baseWidth + reflectTop * (maxWidth - baseWidth);
        const glowHWidthBottom = baseWidth + reflectBottom * (maxWidth - baseWidth);
        const glowVHeightLeft = baseWidth + reflectLeft * (maxWidth - baseWidth);
        const glowVHeightRight = baseWidth + reflectRight * (maxWidth - baseWidth);

        element.style.setProperty('--elem-glow-h-width-top', glowHWidthTop + '%');
        element.style.setProperty('--elem-glow-h-width-bottom', glowHWidthBottom + '%');
        element.style.setProperty('--elem-glow-v-height-left', glowVHeightLeft + '%');
        element.style.setProperty('--elem-glow-v-height-right', glowVHeightRight + '%');
      });
    },

    updateGlowPosition(x, y) {
      const xPercent = (x / window.innerWidth * 100).toFixed(1);
      const yPercent = (y / window.innerHeight * 100).toFixed(1);
      document.body.style.setProperty('--glow-x', xPercent + '%');
      document.body.style.setProperty('--glow-y', yPercent + '%');
      this.currentGlowX = x / window.innerWidth;
      this.currentGlowY = y / window.innerHeight;

      const normalizedX = Math.max(0, Math.min(1, this.currentGlowX));
      const normalizedY = Math.max(0, Math.min(1, this.currentGlowY));

      const GLOW_MAX_INTENSITY = 0.35;
      const GLOW_RADIUS = 0.55;
      const REFLECTION_COEFFICIENT = 0.6;

      const distanceToTop = normalizedY;
      const distanceToBottom = 1 - normalizedY;
      const distanceToLeft = normalizedX;
      const distanceToRight = 1 - normalizedX;

      const glowIntensityAtTop = GLOW_MAX_INTENSITY * Math.max(0, 1 - distanceToTop / GLOW_RADIUS);
      const glowIntensityAtBottom = GLOW_MAX_INTENSITY * Math.max(0, 1 - distanceToBottom / GLOW_RADIUS);
      const glowIntensityAtLeft = GLOW_MAX_INTENSITY * Math.max(0, 1 - distanceToLeft / GLOW_RADIUS);
      const glowIntensityAtRight = GLOW_MAX_INTENSITY * Math.max(0, 1 - distanceToRight / GLOW_RADIUS);

      const edgeThreshold = 0.3;
      const proximityTop = normalizedY < edgeThreshold ? Math.pow(1 - normalizedY / edgeThreshold, 2) : 0;
      const proximityBottom = normalizedY > (1 - edgeThreshold) ? Math.pow((normalizedY - (1 - edgeThreshold)) / edgeThreshold, 2) : 0;
      const proximityLeft = normalizedX < edgeThreshold ? Math.pow(1 - normalizedX / edgeThreshold, 2) : 0;
      const proximityRight = normalizedX > (1 - edgeThreshold) ? Math.pow((normalizedX - (1 - edgeThreshold)) / edgeThreshold, 2) : 0;

      const MAX_REFLECT_INTENSITY = 0.5;
      const reflectTop = Math.min(MAX_REFLECT_INTENSITY, glowIntensityAtTop * REFLECTION_COEFFICIENT * proximityTop);
      const reflectBottom = Math.min(MAX_REFLECT_INTENSITY, glowIntensityAtBottom * REFLECTION_COEFFICIENT * proximityBottom);
      const reflectLeft = Math.min(MAX_REFLECT_INTENSITY, glowIntensityAtLeft * REFLECTION_COEFFICIENT * proximityLeft);
      const reflectRight = Math.min(MAX_REFLECT_INTENSITY, glowIntensityAtRight * REFLECTION_COEFFICIENT * proximityRight);

      document.body.style.setProperty('--reflect-top', reflectTop.toFixed(3));
      document.body.style.setProperty('--reflect-bottom', reflectBottom.toFixed(3));
      document.body.style.setProperty('--reflect-left', reflectLeft.toFixed(3));
      document.body.style.setProperty('--reflect-right', reflectRight.toFixed(3));

      const glowHWidthTop = 6.75 + reflectTop * 11.25;
      const glowVHeightTop = 18 + reflectTop * 54;
      const glowHWidthBottom = 6.75 + reflectBottom * 11.25;
      const glowVHeightBottom = 18 + reflectBottom * 54;
      const glowHWidthLeft = 18 + reflectLeft * 54;
      const glowVHeightLeft = 6.75 + reflectLeft * 11.25;
      const glowHWidthRight = 18 + reflectRight * 54;
      const glowVHeightRight = 6.75 + reflectRight * 11.25;

      document.body.style.setProperty('--glow-h-width-top', glowHWidthTop + '%');
      document.body.style.setProperty('--glow-v-height-top', glowVHeightTop + 'px');
      document.body.style.setProperty('--glow-h-width-bottom', glowHWidthBottom + '%');
      document.body.style.setProperty('--glow-v-height-bottom', glowVHeightBottom + 'px');
      document.body.style.setProperty('--glow-h-width-left', glowHWidthLeft + 'px');
      document.body.style.setProperty('--glow-v-height-left', glowVHeightLeft + '%');
      document.body.style.setProperty('--glow-h-width-right', glowHWidthRight + 'px');
      document.body.style.setProperty('--glow-v-height-right', glowVHeightRight + '%');

      this.updateElementsEdgeGlow(x, y);
    },

    initializeGlowState() {
      const initialPosition = this.getRandomWanderTarget();
      const wanderTarget = this.getRandomWanderTarget();
      this.currentGlowX = initialPosition.x;
      this.currentGlowY = initialPosition.y;
      this.targetGlowX = wanderTarget.x;
      this.targetGlowY = wanderTarget.y;
      this.updateGlowPosition(initialPosition.x * window.innerWidth, initialPosition.y * window.innerHeight);
    },

    moveTowardsTarget(currentX, currentY, targetX, targetY, deltaTime, acceleration) {
      const dx = targetX - currentX;
      const dy = targetY - currentY;
      const distance = Math.sqrt(dx * dx + dy * dy);

      if (distance < this.WANDER_REACHED_THRESHOLD) {
        this.currentSpeedX = 0;
        this.currentSpeedY = 0;
        return { x: targetX, y: targetY, reached: true };
      }

      const targetSpeedX = (dx / distance) * this.MAX_SPEED;
      const targetSpeedY = (dy / distance) * this.MAX_SPEED;

      this.currentSpeedX += (targetSpeedX - this.currentSpeedX) * acceleration;
      this.currentSpeedY += (targetSpeedY - this.currentSpeedY) * acceleration;

      const moveX = this.currentSpeedX * deltaTime;
      const moveY = this.currentSpeedY * deltaTime;
      const newX = Math.max(0, Math.min(1, currentX + moveX));
      const newY = Math.max(0, Math.min(1, currentY + moveY));

      const newDx = targetX - newX;
      const newDy = targetY - newY;
      const newDistance = Math.sqrt(newDx * newDx + newDy * newDy);

      if (newDistance < this.WANDER_REACHED_THRESHOLD) {
        this.currentSpeedX = 0;
        this.currentSpeedY = 0;
        return { x: targetX, y: targetY, reached: true };
      }

      return { x: newX, y: newY, reached: false };
    },

    enableAutoGlow() {
      if (this.isAutoGlow) return;
      this.isAutoGlow = true;
      const newTarget = this.getRandomWanderTarget();
      this.targetGlowX = newTarget.x;
      this.targetGlowY = newTarget.y;
    },

    setMouseTarget(x, y) {
      this.isAutoGlow = false;
      this.targetGlowX = x / window.innerWidth;
      this.targetGlowY = y / window.innerHeight;
    },

    handleMouseMove(e) {
      if (document.hidden) return;

      const isInBounds = e.clientX >= 0 && e.clientX <= window.innerWidth &&
                         e.clientY >= 0 && e.clientY <= window.innerHeight;

      if (isInBounds) {
        glowState.latestMouseX = e.clientX;
        glowState.latestMouseY = e.clientY;

        if (glowState.isAutoGlow) {
          glowState.isAutoGlow = false;
          glowState.lastMouseSampleTime = Date.now();
          glowState.setMouseTarget(glowState.latestMouseX, glowState.latestMouseY);
        }

        clearTimeout(glowState.mouseIdleTimer);
        glowState.mouseIdleTimer = setTimeout(() => {
          glowState.enableAutoGlow();
        }, 6000);
      } else {
        clearTimeout(glowState.mouseIdleTimer);
        glowState.enableAutoGlow();
      }
    },

    handleVisibilityChange() {
      if (document.hidden) {
        clearTimeout(glowState.mouseIdleTimer);
        glowState.enableAutoGlow();

        glowState.visibilityTimer = setTimeout(() => {
          glowState.isRenderingStopped = true;
          cancelAnimationFrame(glowState.glowAnimationFrame);

          document.body.style.setProperty('--breathe-opacity', '0');
          document.body.style.setProperty('--reflect-top', '0');
          document.body.style.setProperty('--reflect-bottom', '0');
          document.body.style.setProperty('--reflect-left', '0');
          document.body.style.setProperty('--reflect-right', '0');
        }, 10000);
      } else {
        clearTimeout(glowState.visibilityTimer);

        if (glowState.isRenderingStopped) {
          glowState.isRenderingStopped = false;
          glowState.fadeInPhase = 0;
          glowState.lastFrameTime = Date.now();
          glowState.animateGlow();
        }
      }
    },

    animateGlow() {
      if (glowState.isRenderingStopped) return;

      const now = Date.now();
      const rawDeltaTime = (now - glowState.lastFrameTime) / 1000;
      const deltaTime = Math.min(0.1, rawDeltaTime);
      glowState.lastFrameTime = now;

      const w = window.innerWidth;
      const h = window.innerHeight;

      if (glowState.fadeInPhase < 1) {
        glowState.fadeInPhase += deltaTime / glowState.FADE_IN_DURATION;
        glowState.fadeInPhase = Math.min(glowState.fadeInPhase, 1);
      }

      glowState.colorTransitionPhase += deltaTime / glowState.colorTransitionDuration;
      if (glowState.colorTransitionPhase >= 1) {
        glowState.currentColorIndex = glowState.targetColorIndex;
        glowState.targetColorIndex = glowState.getNextColorIndex(glowState.currentColorIndex);
        glowState.colorTransitionPhase = 0;
        glowState.colorTransitionDuration = 10 + Math.random() * 35;
      }

      glowState.applyGlowColor();

      const breatheSmoothing = deltaTime > 0 ? 1 - Math.exp(-glowState.BREATHE_SMOOTHING_SPEED * deltaTime) : 0;
      if (breatheSmoothing > 0) {
        glowState.breatheMinOpacity += (glowState.targetBreatheMinOpacity - glowState.breatheMinOpacity) * breatheSmoothing;
        glowState.breatheMaxOpacity += (glowState.targetBreatheMaxOpacity - glowState.breatheMaxOpacity) * breatheSmoothing;
        glowState.breatheCycleDuration += (glowState.targetBreatheCycleDuration - glowState.breatheCycleDuration) * breatheSmoothing;
      }

      const safeCycleDuration = Math.max(0.5, glowState.breatheCycleDuration);
      glowState.breathePhase += deltaTime / safeCycleDuration;
      if (glowState.breathePhase >= 1) {
        glowState.breathePhase %= 1;
        glowState.targetBreatheMinOpacity = 0.5 + Math.random() * 0.2;
        glowState.targetBreatheMaxOpacity = 1.0 + Math.random() * 0.2;
        glowState.targetBreatheCycleDuration = 2 + Math.random() * 10;
      }

      glowState.syncBreatheOpacity();

      if (glowState.isAutoGlow) {
        if (glowState.isResting) {
          if (now - glowState.restStartTime >= glowState.currentRestDuration) {
            glowState.isResting = false;
            const newTarget = glowState.getRandomWanderTarget();
            glowState.targetGlowX = newTarget.x;
            glowState.targetGlowY = newTarget.y;
            glowState.currentSpeedX = 0;
            glowState.currentSpeedY = 0;
          }
        } else {
          const result = glowState.moveTowardsTarget(
            glowState.currentGlowX, glowState.currentGlowY,
            glowState.targetGlowX, glowState.targetGlowY,
            deltaTime, glowState.WANDER_ACCELERATION
          );
          if (result.reached) {
            glowState.isResting = true;
            glowState.restStartTime = now;
            glowState.currentRestDuration = Math.random() * 8000;
          }
          glowState.updateGlowPosition(result.x * w, result.y * h);
        }
      } else {
        if (now - glowState.lastMouseSampleTime >= glowState.MOUSE_SAMPLE_INTERVAL) {
          glowState.setMouseTarget(glowState.latestMouseX, glowState.latestMouseY);
          glowState.lastMouseSampleTime = now;
        }
        const result = glowState.moveTowardsTarget(
          glowState.currentGlowX, glowState.currentGlowY,
          glowState.targetGlowX, glowState.targetGlowY,
          deltaTime, glowState.MOUSE_ACCELERATION
        );
        glowState.updateGlowPosition(result.x * w, result.y * h);
      }

      glowState.glowAnimationFrame = requestAnimationFrame(() => glowState.animateGlow());
    }
  };

  // Initialize glow effect
  glowState.breatheCycleDuration = glowState.getRandomBreatheDuration();
  glowState.breatheMinOpacity = glowState.getRandomBreatheMin();
  glowState.breatheMaxOpacity = glowState.getRandomBreatheMax();
  glowState.targetBreatheCycleDuration = glowState.breatheCycleDuration;
  glowState.targetBreatheMinOpacity = glowState.breatheMinOpacity;
  glowState.targetBreatheMaxOpacity = glowState.breatheMaxOpacity;
  glowState.colorTransitionDuration = glowState.getRandomColorTransitionDuration();
  glowState.currentColorIndex = glowState.getRandomColorIndex();
  glowState.targetColorIndex = glowState.getNextColorIndex(glowState.currentColorIndex);
  glowState.initializeGlowState();
  glowState.applyGlowColor();
  glowState.syncBreatheOpacity();
  glowState.lastFrameTime = Date.now();
  glowState.glowAnimationFrame = requestAnimationFrame(() => glowState.animateGlow());

  document.addEventListener('mousemove', (e) => glowState.handleMouseMove(e));
  document.addEventListener('visibilitychange', () => glowState.handleVisibilityChange());

  return {
    logEl: document.getElementById("log"),
    tEl: document.getElementById("t"),
    tsEl: document.getElementById("ts"),
  };
};

const ui = initUi();
const lines = [];
const MAX_VISIBLE_LINES = 6;
document.title = t("title_verifying");

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
  if (ui.tEl && ui.tEl.classList && typeof ui.tEl.classList.remove === "function") {
    ui.tEl.classList.remove("shine");
  }
  if (ok) {
    ui.tEl.textContent = t("title_redirecting");
    ui.tEl.style.color = "#4ade80";
  } else {
    ui.tEl.textContent = t("title_failed");
    ui.tEl.style.color = "#f87171";
  }
};

log(t("initializing"));

const getTicketMac = (ticketB64) => {
  const raw = decodeB64Url(String(ticketB64 || ""));
  if (!raw) return null;
  const parts = raw.split(".");
  if (parts.length !== 7) return null;
  return parts[6] || null;
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
    script.onerror = () => {
      turnstilePromise = null;
      reject(new Error("Turnstile Load Failed"));
    };
    (document.head || document.documentElement).appendChild(script);
  });
  return turnstilePromise;
};

const runTurnstile = async (ticketB64, sitekey, submitToken) => {
  const ticketMac = getTicketMac(ticketB64);
  if (!ticketMac) throw new Error("Bad Ticket");
  log(t("loading_turnstile"));
  const ts = await loadTurnstile();
  if (!ts || typeof ts.render !== "function") {
    throw new Error("Turnstile Missing");
  }
  const el = ui.tsEl;
  if (el) {
    el.innerHTML = "";
  }
  log(t("waiting_turnstile"));
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
        log(t("turnstile_expired_retry"));
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
    const submitLine = submitToken ? log(t("submitting_turnstile")) : -1;
    try {
      if (submitToken) await submitToken(token);
      if (submitLine !== -1) {
        update(submitLine, t("submitting_turnstile_done", { done: doneMark() }));
      }
      log(t("turnstile_done", { done: doneMark() }));
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
      throw e;
    }
  }
  return null;
};

const buildCaptchaEnvelope = (tokens) => {
  const out = {};
  if (tokens && typeof tokens.turnstile === "string" && tokens.turnstile) {
    out.turnstile = tokens.turnstile;
  }
  return JSON.stringify(out);
};

const runCaptcha = async (ticketB64, captchaCfg, submitToken) => {
  const hasTurn = Boolean(
    captchaCfg &&
      captchaCfg.turnstile &&
      typeof captchaCfg.turnstile.sitekey === "string" &&
      captchaCfg.turnstile.sitekey
  );
  if (!hasTurn) {
    throw new Error("No Challenge");
  }
  const turnToken = await runTurnstile(
    ticketB64,
    captchaCfg.turnstile.sitekey,
    submitToken
      ? async (token) => submitToken(buildCaptchaEnvelope({ turnstile: token }))
      : undefined
  );
  return buildCaptchaEnvelope({ turnstile: turnToken });
};

const runPowFlow = async (
  apiPrefix,
  bindingB64,
  steps,
  ticketB64,
  pathHash,
  hashcashBits,
  segmentLen,
  pageBytes,
  mixRounds,
  esmUrlB64,
  captchaToken
) => {
  log(t("loading_solver"));
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
  let powBinding = authBinding;
  if (captchaToken) {
    const parsedCaptcha = parseCanonicalCaptchaEnvelope(captchaToken);
    if (!parsedCaptcha) throw new Error("Bad Binding");
    const captchaTag = await captchaTagV1(parsedCaptcha.turnstile);
    powBinding = `${authBinding}|${captchaTag}`;
  }

  const workerCode = await fetch(workerUrl).then((r) => r.text());
  const blob = new Blob([workerCode], { type: "application/javascript" });
  const blobUrl = URL.createObjectURL(blob);
  let spinTimer;
  let verifySpinTimer;
  let worker = null;
  let rpc = null;
  let rpcs = [];
  let extraWorkers = [];
  let didCommit = false;
  try {
    let spinIndex = -1;
    let spinFrame = 0;
    const spinChars = "|/-\\";
    let attemptCount = 0;
    let verifyLine = -1;
    let verifySpinFrame = 0;
    const verifySpinChars = "|/-\\";
    let verifyBaseMsg = "";

    const ensureHashingLine = () => {
      if (spinIndex !== -1) return;
      spinIndex = log(t("computing_hash_chain"));
      spinTimer = setInterval(() => {
        let msg = t("computing_hash_chain");
        if (attemptCount > 0) {
          msg = t("screening_hash_attempt", { n: attemptCount });
        }
        const spinner =
          '<span class="yellow">' + spinChars[spinFrame++ % spinChars.length] + "</span>";
        update(spinIndex, msg + " " + spinner);
      }, 120);
    };

    let activeWorker = null;
    const onProgress = (source, progress) => {
      if (source !== activeWorker) return;
      if (progress.phase === "chain" || progress.phase === "hashcash") {
        ensureHashingLine();
      }
      if (progress.phase === "hashcash" && typeof progress.attempt === "number") {
        attemptCount = progress.attempt;
      }
    };

    const makeWorkerRpc = () => {
      const workerInstance = new Worker(blobUrl, { type: "module" });
      const workerRpc = createWorkerRpc(workerInstance, (progress) =>
        onProgress(workerInstance, progress)
      );
      workerRpc.worker = workerInstance;
      return workerRpc;
    };

    const raceFirstSuccess = (promises) =>
      new Promise((resolve, reject) => {
        let pending = promises.length;
        if (pending === 0) {
          reject(new Error("No workers"));
          return;
        }
        let lastError;
        for (const promise of promises) {
          Promise.resolve(promise)
            .then(resolve)
            .catch((err) => {
              lastError = err;
              pending -= 1;
              if (pending === 0) {
                reject(lastError || new Error("Commit failed"));
              }
            });
        }
      });

    const initPayload = {
      bindingString: powBinding,
      ticketB64,
      steps,
      hashcashBits,
      segmentLen,
      pageBytes,
      mixRounds,
      yieldEvery: 1024,
      progressEvery: 1024,
    };

    const workerCount = Number(hashcashBits) >= 2 ? 4 : 1;
    rpcs = [];
    for (let i = 0; i < workerCount; i++) {
      const wRpc = makeWorkerRpc();
      try {
        await wRpc.call("INIT", initPayload);
      } catch (err) {
        try {
          wRpc.dispose();
        } catch {}
        throw err;
      }
      rpcs.push(wRpc);
    }

    const raceRpcs = workerCount > 1 ? rpcs : rpcs.slice(0, 1);
    if (raceRpcs.length === 0) throw new Error("Worker Missing");

    activeWorker = raceRpcs[0].worker;
    ensureHashingLine();

    const commitRes = await raceFirstSuccess(
      raceRpcs.map((entry, index) =>
        entry
          .call("COMMIT")
          .then((result) => ({ result, index }))
      )
    );

    didCommit = true;
    const winner = raceRpcs[commitRes.index];
    worker = winner.worker;
    rpc = winner;
    activeWorker = winner.worker;

    extraWorkers = raceRpcs.filter((entry, idx) => idx !== commitRes.index);
    for (const extra of extraWorkers) {
      extra.dispose();
    }

    if (spinTimer) clearInterval(spinTimer);
    if (spinIndex !== -1) {
      const doneText =
        attemptCount > 0
          ? t("screening_hash_done", { done: doneMark() })
          : t("computing_hash_chain_done", { done: doneMark() });
      update(spinIndex, doneText);
    }

    log(t("submitting_commit"));
    const commitBody = {
      ticketB64,
      rootB64: commitRes.result.rootB64,
      pathHash,
      nonce: commitRes.result.nonce,
    };
    if (captchaToken) commitBody.captchaToken = captchaToken;
    await postJson(apiPrefix + "/commit", commitBody);

    log(t("requesting_challenge"));
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
      verifyBaseMsg = t("verifying_batch", { round, count: state.indices.length });
      if (verifyLine === -1) {
        verifyLine = log(verifyBaseMsg);
        verifySpinTimer = setInterval(() => {
          const spinner =
            '<span class="yellow">' + verifySpinChars[verifySpinFrame++ % verifySpinChars.length] + "</span>";
          update(verifyLine, verifyBaseMsg + " " + spinner);
        }, 120);
      }
      const indices = state.indices;
      const segs =
        Array.isArray(state.segs) && state.segs.length === indices.length
          ? state.segs
          : null;
      if (!segs) {
        throw new Error("Challenge Failed");
      }
      const openRes = await rpc.call("OPEN", { indices, segs });
      const openBody = {
        sid: state.sid,
        cursor: state.cursor,
        token: state.token,
        opens: openRes.opens,
      };
      if (captchaToken) openBody.captchaToken = captchaToken;
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
    if (verifyLine !== -1) update(verifyLine, t("verifying_done", { done: doneMark() }));
    log(t("pow_done", { done: doneMark() }));
    return state;
  } finally {
    if (spinTimer) clearInterval(spinTimer);
    if (verifySpinTimer) clearInterval(verifySpinTimer);
    for (const extra of extraWorkers) {
      try {
        extra.dispose();
      } catch {}
    }
    if (rpc) {
      try {
        rpc.dispose();
      } catch {}
    }
    if (worker) worker.terminate();
    for (const entry of rpcs) {
      if (entry && entry.worker && entry.worker !== worker) {
        try {
          entry.worker.terminate();
        } catch {}
      }
    }
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
  captchaCfgB64,
  atomicCfg,
  pageBytes = 64,
  mixRounds = 2
) {
  try {
    const apiPrefix = normalizeApiPrefix(decodeB64Url(String(apiPrefixB64 || "")));
    const target = decodeB64Url(String(reloadUrlB64 || "")) || "/";

    const needPow = Number(steps) > 0;
    const captchaCfgRaw = decodeB64Url(String(captchaCfgB64 || "")) || "";
    let captchaCfg = {};
    if (captchaCfgRaw) {
      try {
        const parsed = JSON.parse(captchaCfgRaw);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          captchaCfg = parsed;
        }
      } catch {}
    }
    const needTurn = Boolean(
      captchaCfg &&
        captchaCfg.turnstile &&
        typeof captchaCfg.turnstile.sitekey === "string" &&
        captchaCfg.turnstile.sitekey
    );
    const needCaptcha = needTurn;
    const cfg = parseAtomicCfg(atomicCfg);
    const atomicEnabled = cfg.atomic;
    const Q_CAPTCHA = cfg.q.ts;
    const Q_TICKET = cfg.q.tt;
    const Q_CONSUME = cfg.q.ct;
    const H_CAPTCHA = cfg.h.ts;
    const H_TICKET = cfg.h.tt;
    const H_CONSUME = cfg.h.ct;
    const C_NAME = cfg.c;

    if (!needPow && !needCaptcha) throw new Error("No Challenge");

    const embedded = window.parent !== window;

    if (!needPow && needCaptcha) {
      if (atomicEnabled) {
        const captchaToken = await runCaptcha(ticketB64, captchaCfg);
        const query = { [Q_CAPTCHA]: captchaToken, [Q_TICKET]: ticketB64 };
        const headers = { [H_CAPTCHA]: captchaToken, [H_TICKET]: ticketB64 };
        if (embedded) {
          postAtomicMessage({ mode: "turn", captchaToken, ticketB64, headers, query });
          log(t("access_granted_close"));
          setStatus(true);
          document.title = t("title_done");
          return;
        }
        const cookieValue = `1|t|${captchaToken}|${ticketB64}`;
        const cookiePath = cookiePathForTarget(target);
        if (
          canUseCookie(C_NAME, cookieValue) &&
          setAtomicCookie(C_NAME, cookieValue, 5, cookiePath)
        ) {
          log(t("access_granted_redirecting", { redirect: yellowMark(t("redirecting")) }));
          setStatus(true);
          document.title = t("title_redirecting");
          window.location.replace(target);
          return;
        }
        log(t("access_granted_redirecting", { redirect: yellowMark(t("redirecting")) }));
        setStatus(true);
        document.title = t("title_redirecting");
        window.location.replace(addQuery(target, query));
        return;
      }
      await runCaptcha(ticketB64, captchaCfg, async (captchaToken) => {
        await postJson(apiPrefix + "/cap", { ticketB64, pathHash, captchaToken });
      });
    } else if (needPow && !needCaptcha) {
      const state = await runPowFlow(
        apiPrefix,
        bindingB64,
        steps,
        ticketB64,
        pathHash,
        hashcashBits,
        segmentLen,
        pageBytes,
        mixRounds,
        esmUrlB64,
        ""
      );
      if (atomicEnabled) {
        const consume = state && state.consume;
        if (!consume) throw new Error("Consume Missing");
        const query = { [Q_CONSUME]: consume };
        const headers = { [H_CONSUME]: consume };
        if (embedded) {
          postAtomicMessage({ mode: "pow", consume, headers, query });
          log(t("access_granted_close"));
          setStatus(true);
          document.title = t("title_done");
          return;
        }
        const cookieValue = `1|c||${consume}`;
        const cookiePath = cookiePathForTarget(target);
        if (
          canUseCookie(C_NAME, cookieValue) &&
          setAtomicCookie(C_NAME, cookieValue, 5, cookiePath)
        ) {
          log(t("access_granted_redirecting", { redirect: yellowMark(t("redirecting")) }));
          setStatus(true);
          document.title = t("title_redirecting");
          window.location.replace(target);
          return;
        }
        log(t("access_granted_redirecting", { redirect: yellowMark(t("redirecting")) }));
        setStatus(true);
        document.title = t("title_redirecting");
        window.location.replace(addQuery(target, query));
        return;
      }
    } else {
      const captchaToken = await runCaptcha(ticketB64, captchaCfg);
      if (needTurn) {
        log(t("turnstile_solved_pow"));
      }
      const state = await runPowFlow(
        apiPrefix,
        bindingB64,
        steps,
        ticketB64,
        pathHash,
        hashcashBits,
        segmentLen,
        pageBytes,
        mixRounds,
        esmUrlB64,
        captchaToken
      );
      if (atomicEnabled) {
        const consume = state && state.consume;
        if (!consume) throw new Error("Consume Missing");
        const query = { [Q_CAPTCHA]: captchaToken, [Q_CONSUME]: consume };
        const headers = { [H_CAPTCHA]: captchaToken, [H_CONSUME]: consume };
        if (embedded) {
          postAtomicMessage({ mode: "combine", captchaToken, consume, headers, query });
          log(t("access_granted_close"));
          setStatus(true);
          document.title = t("title_done");
          return;
        }
        const cookieValue = `1|c|${captchaToken}|${consume}`;
        const cookiePath = cookiePathForTarget(target);
        if (
          canUseCookie(C_NAME, cookieValue) &&
          setAtomicCookie(C_NAME, cookieValue, 5, cookiePath)
        ) {
          log(t("access_granted_redirecting", { redirect: yellowMark(t("redirecting")) }));
          setStatus(true);
          document.title = t("title_redirecting");
          window.location.replace(target);
          return;
        }
        log(t("access_granted_redirecting", { redirect: yellowMark(t("redirecting")) }));
        setStatus(true);
        document.title = t("title_redirecting");
        window.location.replace(addQuery(target, query));
        return;
      }
    }
    log(t("access_granted_redirecting", { redirect: yellowMark(t("redirecting")) }));
    setStatus(true);
    document.title = t("title_redirecting");
    window.location.replace(target);
  } catch (e) {
    const hintRoute = routeHintAction({ status: e && e.status, hint: e && e.hint });
    if (hintRoute.action === "reload") {
      if (shouldAttemptStaleReload()) {
        log(t("session_expired_reload"));
        setTimeout(() => window.location.reload(), 1000);
        return;
      }
      log(t("error_prefix", { message: localizeErrorMessage("Request Failed") }));
      setStatus(false);
      return;
    }
    const raw = e && e.message ? e.message : String(e);
    log(t("error_prefix", { message: localizeErrorMessage(raw) }));
    setStatus(false);
  }
}

export { resolveLocale, routeHintAction, translate, getLocale, setLocale, t };
