// src/middleware/auth.middleware.js

import { verifyAccessToken } from "../utils/jwt.js";
import { redisClient } from "../config/redis.js";
import { redisSessionKey, sessionIdleCutoff } from "../utils/security.js";
import { getCookieNames } from "../utils/cookies.js";
import Session from "../models/session.model.js";

/**
 * Authentication Middleware
 * Validates access tokens from Authorization headers or HTTP-only cookies,
 * enforces immediate revocation across Redis and MongoDB fallback,
 * and updates session lastUsedAt with 5-minute throttling.
 */
const authMiddleware = async (req, res, next) => {
  try {
    // 1. Extract token strictly from Authorization header OR Access Token cookies
    const authHeader = req.headers.authorization || req.headers.Authorization;
    let token = null;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    } else {
      const cookieNames = getCookieNames();
      token = req.cookies?.[cookieNames.access] || req.cookies?.access_token || req.cookies?.accessToken;
    }

    // 2. Reject if no token is provided
    if (!token) {
      return res.status(401).json({
        success: false,
        error: "UNAUTHORIZED",
        message: "Access denied. Authentication is required.",
      });
    }

    // 3. Verify access token signature, expiration, issuer, audience, and token type
    let payload;
    try {
      payload = verifyAccessToken(token);
    } catch {
      return res.status(401).json({
        success: false,
        error: "UNAUTHORIZED",
        message: "Invalid or expired access token.",
      });
    }

    // 4. Extract user ID and session ID from verified payload
    const userId = String(payload?.sub || payload?.id || "");
    const sessionId = String(payload?.sid || payload?.sessionId || "");

    if (!userId) {
      return res.status(401).json({
        success: false,
        error: "INVALID_TOKEN_STRUCTURE",
        message: "Invalid token payload structure.",
      });
    }

    if (!sessionId) {
      return res.status(401).json({
        success: false,
        error: "MISSING_SESSION_ID",
        message: "Access token is missing session information.",
      });
    }

    let isSessionValid = false;

    // 5A. Check Primary Session Store (Redis)
    if (redisClient?.isOpen) {
      try {
        const sessionData = await redisClient.get(redisSessionKey(sessionId));

        if (sessionData) {
          const parsedSession = JSON.parse(sessionData);

          // Revocation tombstone: the session was revoked and this key was
          // deliberately kept (not DEL'd) so a racing cache fill can never
          // resurrect it. No MongoDB fallback — revocation is final.
          if (parsedSession.revoked) {
            return res.status(401).json({
              success: false,
              error: "SESSION_INACTIVE",
              message: "Session is no longer active or has been revoked.",
            });
          }

          if (String(parsedSession.userId) === userId) {
            isSessionValid = true;
          }
        }
      } catch (redisErr) {
        if (process.env.NODE_ENV !== "test") {
          console.error("Redis session lookup failed, falling back to MongoDB:", redisErr.message);
        }
      }
    }

    // 5B. Fallback / Verification Check against Secondary Store (MongoDB)
    if (!isSessionValid) {
      // Idle timeout: sessions untouched for SESSION_IDLE_TIMEOUT_HOURS are
      // dead here too — a Redis cache miss must not resurrect an abandoned
      // session (null cutoff = idle timeout disabled).
      const idleCutoff = sessionIdleCutoff();
      const dbSession = await Session.findOne({
        sessionId,
        userId,
        revokedAt: null,
        expiresAt: { $gt: new Date() },
        ...(idleCutoff ? { lastUsedAt: { $gt: idleCutoff } } : {}),
      })
        .select("+refreshTokenHash") // refreshTokenHash is select:false by default
        .lean();

      if (!dbSession) {
        return res.status(401).json({
          success: false,
          error: "SESSION_INACTIVE",
          message: "Session is no longer active or has been revoked.",
        });
      }

      // Re-populate Redis cache if Redis is online but missed. Awaited so a
      // cold-start burst of parallel requests cannot stampede MongoDB with
      // identical session lookups (the first request fills the cache; the
      // rest hit it). NX: never overwrite a REVOKED tombstone written by a
      // revocation that committed between this request's Mongo read and the
      // cache fill — otherwise the fill would resurrect a dead session.
      if (redisClient?.isOpen) {
        const ttl = Math.max(1, Math.floor((new Date(dbSession.expiresAt).getTime() - Date.now()) / 1000));
        try {
          await redisClient.set(
            redisSessionKey(sessionId),
            JSON.stringify({
              userId,
              sessionId,
              refreshTokenHash: dbSession.refreshTokenHash,
            }),
            { EX: ttl, NX: true },
          );
        } catch {
          // Cache fill is best-effort; authentication itself already succeeded.
        }
      }
    }

    // 6. Attach verified user context to request object
    req.user = {
      _id: userId,
      id: userId,
      email: payload.email || null,
      role: payload.role === "admin" ? "admin" : "user",
      sessionId,
    };

    // 7. Throttled background session update (5-minute threshold)
    const FIVE_MINUTES_AGO = new Date(Date.now() - 5 * 60 * 1000);
    void Session.updateOne(
      {
        sessionId,
        revokedAt: null,
        lastUsedAt: { $lt: FIVE_MINUTES_AGO },
      },
      {
        $set: { lastUsedAt: new Date() },
      }
    ).catch(() => {});

    // 8. Proceed to route handler
    return next();
  } catch (error) {
    if (process.env.NODE_ENV !== "test") {
      console.error("Authentication middleware failure:", error);
    }

    return res.status(401).json({
      success: false,
      error: "UNAUTHORIZED",
      message: "An error occurred during authentication verification.",
    });
  }
};

export default authMiddleware;

/**
 * Authorization Middleware — restricts a route to admin users.
 * Must run after authMiddleware (relies on req.user.role from the token).
 */
export const requireAdmin = (req, res, next) => {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      success: false,
      error: "FORBIDDEN",
      message: "Admin privileges are required to access this resource.",
    });
  }

  return next();
};