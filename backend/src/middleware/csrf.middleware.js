// src/middleware/csrf.middleware.js

import { createHmac, randomBytes, timingSafeEqual } from "crypto";
import { logAuditEvent, AUDIT_EVENTS } from "../utils/auditLog.js";

const CSRF_COOKIE = "csrf_token";
const isProduction = process.env.NODE_ENV === "production";

/**
 * Returns centralized cookie options for non-HttpOnly CSRF cookie.
 */
export const getCsrfCookieOptions = () => ({
  httpOnly: false, // Must be client-readable for custom HTTP header placement
  secure: isProduction,
  sameSite: isProduction ? "strict" : "lax",
  path: "/",
  // Token lifetime tracks the refresh token: the CSRF cookie must outlive a
  // session, because login itself needs it (preventing login CSRF). A short
  // cookie forces constant re-bootstraps — each one a chance for a cache to
  // swallow the Set-Cookie and starve the client of its token.
  maxAge: 60 * 60 * 1000 * 24 * 7,
});

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

// The only route that may bootstrap a CSRF token. Everything else — including
// login and register — must present a valid token (prevents login CSRF).
const EXEMPT_PATHS = new Set([
  "/api/auth/csrf-token",
]);

/**
 * HMAC signing binds every CSRF token to this server: a cookie tossed by a
 * subdomain or forged by an attacker fails signature validation even if the
 * double-submit cookie/header values match.
 */
const csrfSecret = createHmac(
  "sha256",
  process.env.JWT_ACCESS_SECRET || "finshield-insecure-dev-secret"
).update("finshield-csrf-binding").digest();

const signNonce = (nonce) =>
  createHmac("sha256", csrfSecret).update(nonce).digest("hex");

const issueToken = () => {
  const nonce = randomBytes(32).toString("hex");
  return `${nonce}.${signNonce(nonce)}`;
};

const safeEqual = (a, b) => {
  const aBuffer = Buffer.from(a, "utf8");
  const bBuffer = Buffer.from(b, "utf8");
  return aBuffer.length === bBuffer.length && timingSafeEqual(aBuffer, bBuffer);
};

const isValidToken = (token) => {
  if (typeof token !== "string") {
    return false;
  }

  const parts = token.split(".");
  if (parts.length !== 2 || parts[0].length !== 64 || parts[1].length !== 64) {
    return false;
  }

  return safeEqual(parts[1], signNonce(parts[0]));
};

/**
 * Constant-time comparison between cookie and header tokens.
 * Both must be server-signed and carry the same nonce.
 */
const tokensMatch = (a, b) => {
  if (!isValidToken(a) || !isValidToken(b)) {
    return false;
  }

  return safeEqual(a.split(".")[0], b.split(".")[0]);
};

/**
 * Issues or refreshes a CSRF token to the client.
 */
export const issueCsrfToken = (req, res) => {
  let token = req.cookies?.[CSRF_COOKIE];

  if (!isValidToken(token)) {
    token = issueToken();
    res.cookie(CSRF_COOKIE, token, getCsrfCookieOptions());
  }

  // The token is never echoed in the JSON body: the client reads it directly
  // from the non-HttpOnly csrf_token cookie (double-submit cookie pattern).
  // Nothing sensitive is exposed to response inspection tools.

  // This route MUST NOT be cached. The JSON body is constant, so its ETag is
  // too — a browser or CDN revalidating against that ETag gets a 304 or a
  // cached copy with Set-Cookie stripped, and the client's next POST then
  // goes out without x-csrf-token (CSRF_TOKEN_MISSING on login, of all
  // places). no-store keeps the Set-Cookie attached to every response.
  res.set("Cache-Control", "private, no-store");

  return res.status(200).json({
    success: true,
    message: "CSRF token issued. Read it from the csrf_token cookie.",
  });
};

/**
 * Enforces signed Double-Submit Cookie CSRF defense on state-changing requests
 */
const csrfMiddleware = (req, res, next) => {
  // 1. Skip read-only HTTP methods
  if (SAFE_METHODS.has(req.method)) {
    return next();
  }

  // 2. Extract normalized request path from originalUrl (ignoring query strings)
  const normalizedPath = req.originalUrl ? req.originalUrl.split("?")[0] : req.path;

  // 3. Skip validation for the token bootstrap route
  if (EXEMPT_PATHS.has(normalizedPath)) {
    return next();
  }

  // 4. Extract token values from request context
  const cookieToken = req.cookies?.[CSRF_COOKIE];
  const headerToken = req.get("x-csrf-token") || req.get("X-CSRF-Token");

  // 5. Reject missing token scenario
  if (!cookieToken || !headerToken) {
    logAuditEvent({
      event: AUDIT_EVENTS.CSRF_FAILURE,
      userId: req.user?.id || null,
      sessionId: req.user?.sessionId || null,
      req,
      metadata: { reason: "missing_csrf_token", path: normalizedPath },
    });

    return res.status(403).json({
      success: false,
      error: "CSRF_TOKEN_MISSING",
      message: "CSRF token validation failed. Token is missing.",
    });
  }

  // 6. Perform constant-time token comparison check
  if (!tokensMatch(cookieToken, headerToken)) {
    logAuditEvent({
      event: AUDIT_EVENTS.CSRF_FAILURE,
      userId: req.user?.id || null,
      sessionId: req.user?.sessionId || null,
      req,
      metadata: { reason: "invalid_csrf_token", path: normalizedPath },
    });

    return res.status(403).json({
      success: false,
      error: "CSRF_TOKEN_INVALID",
      message: "CSRF token validation failed. Invalid token.",
    });
  }

  return next();
};

export default csrfMiddleware;
