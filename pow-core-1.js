import {
  issueTransit,
  stripTransitHeaders,
  TRANSIT_HEADER,
  TRANSIT_MAC_HEADER,
  TRANSIT_EXPIRE_HEADER,
  TRANSIT_API_PREFIX_HEADER,
} from "./lib/pow/transit-auth.js";
import { readInnerPayload } from "./lib/pow/inner-auth.js";
import { handleBusinessGate } from "./lib/pow/business-gate.js";

const CONFIG_SECRET = "replace-me";
const DEFAULT_API_PREFIX = "/__pow";
const POW_INNER_HEADER_PREFIX = "x-pow-inner";

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

const normalizeApiPrefix = (value) => {
  if (typeof value !== "string") return DEFAULT_API_PREFIX;
  const trimmed = value.trim();
  if (!trimmed) return DEFAULT_API_PREFIX;
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  const normalized = withSlash.replace(/\/+$/u, "");
  return normalized || DEFAULT_API_PREFIX;
};

const isApiPath = (pathname, apiPrefix) => {
  if (apiPrefix === "/") return false;
  return pathname.startsWith(`${apiPrefix}/`);
};

const copyPowInnerHeaders = (sourceRequest, headers) => {
  for (const [headerName, headerValue] of sourceRequest.headers.entries()) {
    if (headerName.toLowerCase().startsWith(POW_INNER_HEADER_PREFIX)) {
      headers.set(headerName, headerValue);
    }
  }
};

export default {
  async fetch(request) {
    const inner = await readInnerPayload(request, CONFIG_SECRET);
    if (!inner) {
      return new Response(null, { status: 500 });
    }

    const url = new URL(request.url);
    const pathname = normalizePath(url.pathname);
    if (!pathname) {
      return new Response(null, { status: 400 });
    }
    const apiPrefix = normalizeApiPrefix(inner.c?.POW_API_PREFIX);
    const kind = isApiPath(pathname, apiPrefix) ? "api" : "biz";

    if (kind === "biz") {
      return handleBusinessGate({
        request,
        url,
        nowSeconds: Math.floor(Date.now() / 1000),
        inner,
        forward: async (forwardRequest) => {
          const transit = await issueTransit({
            secret: CONFIG_SECRET,
            method: forwardRequest.method,
            pathname,
            kind: "biz",
            apiPrefix,
            ttlSec: 3,
          });
          if (!transit) {
            return new Response(null, { status: 500 });
          }
          const stripped = stripTransitHeaders(forwardRequest);
          const headers = new Headers(stripped.headers);
          copyPowInnerHeaders(request, headers);
          headers.set(TRANSIT_HEADER, transit.headers[TRANSIT_HEADER]);
          headers.set(TRANSIT_MAC_HEADER, transit.headers[TRANSIT_MAC_HEADER]);
          headers.set(TRANSIT_EXPIRE_HEADER, transit.headers[TRANSIT_EXPIRE_HEADER]);
          headers.set(TRANSIT_API_PREFIX_HEADER, transit.headers[TRANSIT_API_PREFIX_HEADER]);
          return fetch(new Request(stripped, { headers }));
        },
      });
    }

    const transit = await issueTransit({
      secret: CONFIG_SECRET,
      method: request.method,
      pathname,
      kind,
      apiPrefix,
      ttlSec: 3,
    });
    if (!transit) {
      return new Response(null, { status: 500 });
    }

    const transitStripped = stripTransitHeaders(request);
    const headers = new Headers(transitStripped.headers);
    headers.set(TRANSIT_HEADER, transit.headers[TRANSIT_HEADER]);
    headers.set(TRANSIT_MAC_HEADER, transit.headers[TRANSIT_MAC_HEADER]);
    headers.set(TRANSIT_EXPIRE_HEADER, transit.headers[TRANSIT_EXPIRE_HEADER]);
    headers.set(TRANSIT_API_PREFIX_HEADER, transit.headers[TRANSIT_API_PREFIX_HEADER]);

    return fetch(new Request(transitStripped, { headers }));
  },
};
