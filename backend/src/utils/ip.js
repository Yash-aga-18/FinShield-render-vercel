// src/utils/ip.js

/*
 * Resolves the client IP from an Express request.
 *
 * Uses req.ip, which respects the app's "trust proxy" setting:
 * - TRUST_PROXY configured (deployed behind nginx/load balancer): Express
 *   safely derives the client IP from X-Forwarded-For, trusting only the
 *   configured number of hops.
 * - TRUST_PROXY not set (direct exposure): the socket address is used and
 *   client-supplied X-Forwarded-For headers are ignored (spoof-proof).
 */
const LOCALHOST_ADDRESSES = new Set(["::1", "::ffff:127.0.0.1"]);

export const getClientIp = (req) => {
  const raw = String(req?.ip || req?.socket?.remoteAddress || "").trim();

  if (!raw) {
    return "";
  }

  if (LOCALHOST_ADDRESSES.has(raw)) {
    return "127.0.0.1";
  }

  return raw;
};
