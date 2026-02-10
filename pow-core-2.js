import { verifyTransit } from "./lib/pow/transit-auth.js";
import { readInnerPayload } from "./lib/pow/inner-auth.js";
import { stripPowInternalHeaders } from "./lib/pow/internal-headers.js";
import { handlePowApi } from "./lib/pow/api-engine.js";

const CONFIG_SECRET = "replace-me";
const DEFAULT_API_PREFIX = "/__pow";

const normalizePath = (pathname) => {
  if (typeof pathname !== "string") return null;
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  if (decoded.length === 0) return "/";
  return decoded.startsWith("/") ? decoded : `/${decoded}`;
};

const isApiPath = (pathname, apiPrefix) => {
  if (apiPrefix === "/") return false;
  return pathname.startsWith(`${apiPrefix}/`);
};

const normalizeApiPrefix = (value) => {
  if (typeof value !== "string") return DEFAULT_API_PREFIX;
  const trimmed = value.trim();
  if (!trimmed) return DEFAULT_API_PREFIX;
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  const normalized = withSlash.replace(/\/+$/u, "");
  return normalized || DEFAULT_API_PREFIX;
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const pathname = normalizePath(url.pathname);
    if (!pathname) {
      return new Response(null, { status: 400 });
    }
    const nowSeconds = Math.floor(Date.now() / 1000);
    const inner = await readInnerPayload(request, CONFIG_SECRET);
    const routingApiPrefix = normalizeApiPrefix(inner?.c?.POW_API_PREFIX);
    const allowedKind = isApiPath(pathname, routingApiPrefix) ? "api" : "biz";

    const transit = await verifyTransit({
      request,
      secret: CONFIG_SECRET,
      method: request.method,
      pathname,
      allowedKind,
    });
    if (!transit) {
      return new Response(null, { status: 500 });
    }

    if (inner && transit.apiPrefix !== routingApiPrefix) {
      return new Response(null, { status: 500 });
    }

    const stripped = stripPowInternalHeaders(request);

    if (allowedKind === "api") {
      if (!inner) {
        return new Response(null, { status: 500 });
      }
      const innerCtx = {
        config: inner.c,
        powSecret: inner.c?.POW_TOKEN,
        derived: inner.d,
        cfgId: inner.id,
        strategy: inner.s,
      };
      return handlePowApi(stripped, url, nowSeconds, innerCtx);
    }

    return fetch(stripped);
  },
};
