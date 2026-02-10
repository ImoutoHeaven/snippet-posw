const POW_INNER_HEADER_PREFIX = "x-pow-inner";
const POW_TRANSIT_HEADER_PREFIX = "x-pow-transit";

export const stripPowInternalHeaders = (request) => {
  const headers = new Headers(request.headers);
  for (const key of Array.from(headers.keys())) {
    const normalized = key.toLowerCase();
    if (
      normalized.startsWith(POW_INNER_HEADER_PREFIX) ||
      normalized.startsWith(POW_TRANSIT_HEADER_PREFIX)
    ) {
      headers.delete(key);
    }
  }
  return new Request(request, { headers });
};
