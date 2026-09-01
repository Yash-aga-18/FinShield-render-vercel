// src/controllers/session.controller.js

import Session from "../models/session.model.js";
import { redisClient } from "../config/redis.js";
import { logAuditEvent, AUDIT_EVENTS } from "../utils/auditLog.js";
import { clearAuthCookies } from "../utils/cookies.js";
import { acquireRedisLock, releaseRedisLock } from "../utils/redisLock.js";
import { userSessionLockKey, toDisplayId, markSessionRevokedInRedis, sessionIdleCutoff } from "../utils/security.js";
import { numberFromEnv } from "../utils/env.js";

/* ============================================================
   GET ACTIVE SESSIONS (Strictly user-isolated)
   ============================================================ */
export const getActiveSessions = async (req, res, next) => {
  try {
    const userId = String(req.user._id || req.user.id);
    const currentSessionId = String(req.user.sessionId || req.user.id);

    const sessions = await Session.find({
      userId,
      revokedAt: null,
      expiresAt: { $gt: new Date() },
      // Idle-stale sessions are dead on their next refresh — don't list them.
      ...(sessionIdleCutoff() ? { lastUsedAt: { $gt: sessionIdleCutoff() } } : {}),
    })
      .select("sessionId device ipAddress userAgent createdAt lastUsedAt expiresAt")
      .sort({ lastUsedAt: -1 })
      .lean();

    const formattedSessions = sessions.map((session) => ({
      id: toDisplayId(session.sessionId),
      device: session.device,
      ipAddress: session.ipAddress,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt,
      expiresAt: session.expiresAt,
      current: session.sessionId === currentSessionId,
    }));

    return res.status(200).json({
      success: true,
      totalSessions: formattedSessions.length,
      // Surfaced so the UI can show "2 of 3 devices used".
      maxActiveSessions: Number(process.env.MAX_ACTIVE_SESSIONS || 3),
      sessions: formattedSessions,
    });
  } catch (error) {
    next(error);
  }
};

/* ============================================================
   SESSION HISTORY (Strictly user-isolated)
   Past sessions that were revoked or expired, most recent first.
   Capped to the last 20 so the page stays light.
   ============================================================ */
export const getSessionHistory = async (req, res, next) => {
  try {
    const userId = String(req.user._id || req.user.id);

    const filter = {
      userId,
      $or: [{ revokedAt: { $ne: null } }, { expiresAt: { $lte: new Date() } }],
    };

    // HISTORY_DEFAULT_LIMIT / HISTORY_MAX_LIMIT tune the past-sessions page
    // size (defaults: 20 per page, hard cap 100).
    const page = Math.max(1, Number.parseInt(req.query?.page, 10) || 1);
    const limit = Math.min(
      numberFromEnv("HISTORY_MAX_LIMIT", 100),
      Math.max(1, Number.parseInt(req.query?.limit, 10) || numberFromEnv("HISTORY_DEFAULT_LIMIT", 20)),
    );

    // Ended = revoked OR expired. Anything still alive is NOT history.
    const [ended, total] = await Promise.all([
      Session.find(filter)
        .select("sessionId device ipAddress createdAt lastUsedAt expiresAt revokedAt")
        .sort({ lastUsedAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Session.countDocuments(filter),
    ]);

    const history = ended.map((session) => ({
      id: toDisplayId(session.sessionId),
      device: session.device,
      ipAddress: session.ipAddress,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt,
      endedAt: session.revokedAt || session.expiresAt,
      reason: session.revokedAt ? "revoked" : "expired",
    }));

    return res.status(200).json({
      success: true,
      page,
      limit,
      total: total,
      totalPages: Math.ceil(total / limit),
      totalHistory: history.length,
      history,
    });
  } catch (error) {
    next(error);
  }
};

/* ============================================================
   REVOKE SPECIFIC SESSION (NoSQL & Horizontal Isolation Hardened)
   ============================================================ */
export const revokeSession = async (req, res, next) => {
  try {
    const rawSessionId = req.params?.sessionId;

    if (
      !rawSessionId ||
      typeof rawSessionId !== "string" ||
      rawSessionId === "undefined"
    ) {
      return res.status(400).json({
        success: false,
        error: "INVALID_SESSION_ID",
        message: "A valid session ID parameter is required.",
      });
    }

    const sessionId = rawSessionId.trim();

    if (sessionId.length < 8 || sessionId.length > 128) {
      return res.status(400).json({
        success: false,
        error: "INVALID_SESSION_ID",
        message: "Session ID format is invalid.",
      });
    }

    const userId = String(req.user._id || req.user.id || req.user.sub);

    const lockKey = userSessionLockKey(userId);
    const lockToken = await acquireRedisLock(lockKey);

    if (!lockToken) {
      return res.status(409).json({
        success: false,
        error: "SESSION_OPERATION_BUSY",
        message: "Another session operation is currently being processed.",
      });
    }

    try {
      // The client supplies the public displayId (HMAC of the internal session
      // ID). New sessions store it indexed for a single-lookup resolution;
      // a fallback scan over this user's active sessions covers rows created
      // before the displayId column existed.
      let session = await Session.findOne({
        userId,
        revokedAt: null,
        displayId: sessionId,
      });

      if (!session) {
        const activeSessions = await Session.find({
          userId,
          revokedAt: null,
          expiresAt: { $gt: new Date() },
        })
          .select("sessionId")
          .lean();

        const target = activeSessions.find(
          (candidate) => toDisplayId(candidate.sessionId) === sessionId
        );

        if (target) {
          session = await Session.findOne({ userId, sessionId: target.sessionId, revokedAt: null });
        }
      }

      if (!session) {
        return res.status(404).json({
          success: false,
          error: "SESSION_NOT_FOUND",
          message: "Session not found or already revoked.",
        });
      }

      session.revokedAt = new Date();
      await session.save();

      const targetSessionId = session.sessionId || String(session._id);

      // Tombstone (not DEL) so a concurrent cache fill can't resurrect the
      // session — see markSessionRevokedInRedis.
      await markSessionRevokedInRedis(targetSessionId);

      logAuditEvent({
        event: AUDIT_EVENTS.SESSION_REVOKED,
        userId,
        sessionId: targetSessionId,
        req,
        metadata: { reason: "user_requested" },
      });

      return res.status(200).json({
        success: true,
        message: "Session revoked successfully.",
      });
    } finally {
      await releaseRedisLock(lockKey, lockToken);
    }
  } catch (error) {
    next(error);
  }
};

/* ============================================================
   REVOKE ALL SESSIONS / LOGOUT ALL
   ============================================================ */
export const revokeAllSessions = async (req, res, next) => {
  try {
    const userId = String(req.user._id || req.user.id);
    const lockKey = userSessionLockKey(userId);
    const lockToken = await acquireRedisLock(lockKey);

    if (!lockToken) {
      return res.status(409).json({
        success: false,
        error: "SESSION_OPERATION_BUSY",
        message: "Another session operation is currently being processed.",
      });
    }

    try {
      const sessions = await Session.find({
        userId,
        revokedAt: null,
      }).select("sessionId");

      const sessionIds = sessions.map((session) => session.sessionId);

      if (sessionIds.length > 0) {
        await Session.updateMany(
          { userId, revokedAt: null },
          { $set: { revokedAt: new Date() } }
        );

        // Tombstones, not DELs — see markSessionRevokedInRedis.
        await markSessionRevokedInRedis(sessionIds);
      }

      logAuditEvent({
        event: AUDIT_EVENTS.LOGOUT_ALL,
        userId,
        req,
        metadata: { revokedCount: sessionIds.length },
      });

      clearAuthCookies(res);

      return res.status(200).json({
        success: true,
        message: "All sessions revoked successfully",
        revokedCount: sessionIds.length,
      });
    } finally {
      await releaseRedisLock(lockKey, lockToken);
    }
  } catch (error) {
    next(error);
  }
};
