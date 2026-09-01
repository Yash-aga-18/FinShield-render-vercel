// src/controllers/admin.controller.js

import mongoose from "mongoose";
const { isValidObjectId } = mongoose;
import Session from "../models/session.model.js";
import User from "../models/user.model.js";
import { logAuditEvent, flushAuditLogs, verifyAuditChain, AUDIT_EVENTS } from "../utils/auditLog.js";
import { acquireRedisLock, releaseRedisLock } from "../utils/redisLock.js";
import { userSessionLockKey, toDisplayId, markSessionRevokedInRedis, sessionIdleCutoff } from "../utils/security.js";
import { sendAdminActionEmail } from "../utils/mailer.js";
import { numberFromEnv } from "../utils/env.js";

/* Email confirmation to the acting admin after a destructive action.
   Fire-and-forget: a mail provider outage must never fail the action,
   which has already been committed by the time this runs. */
const notifyAdminAsync = (adminId, payload) => {
  void (async () => {
    try {
      const admin = await User.findById(adminId).select("email").lean();
      if (admin?.email) {
        await sendAdminActionEmail(admin.email, payload);
      }
    } catch (error) {
      console.warn(`[admin] Failed to send admin notification email: ${error.message}`);
    }
  })();
};

/* ============================================================
   ADMIN: LIST ALL ACTIVE SESSIONS ACROSS ALL USERS
   ============================================================ */
export const getAllActiveSessions = async (req, res, next) => {
  try {
    const page = Math.max(1, Number.parseInt(req.query?.page, 10) || 1);
    // ADMIN_SESSIONS_DEFAULT_LIMIT / ADMIN_SESSIONS_MAX_LIMIT tune the
    // all-sessions page size (defaults: 50 per page, hard cap 100).
    const limit = Math.min(
      numberFromEnv("ADMIN_SESSIONS_MAX_LIMIT", 100),
      Math.max(
        1,
        Number.parseInt(req.query?.limit, 10) ||
          numberFromEnv("ADMIN_SESSIONS_DEFAULT_LIMIT", 50),
      ),
    );

    // Sort controls for the admin UI: which column and which direction.
    // Whitelisted map — the raw query value never reaches Mongo directly.
    const SORT_FIELDS = {
      lastUsed: "lastUsedAt",
      signedIn: "createdAt",
      risk: "riskScore",
      expires: "expiresAt",
    };
    const sortField = SORT_FIELDS[req.query?.sort] ? req.query.sort : "lastUsed";
    const sortOrder = req.query?.order === "asc" ? 1 : -1;

    const query = {
      revokedAt: null,
      expiresAt: { $gt: new Date() },
      // Idle-stale sessions are dead on their next refresh — don't list them.
      ...(sessionIdleCutoff() ? { lastUsedAt: { $gt: sessionIdleCutoff() } } : {}),
    };

    const [sessions, total] = await Promise.all([
      Session.find(query)
        .select("userId sessionId displayId device ipAddress createdAt lastUsedAt expiresAt riskScore riskLevel")
        .sort({ [SORT_FIELDS[sortField]]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Session.countDocuments(query),
    ]);

    // Resolve the owning user's name/email in one query.
    const userIds = [...new Set(sessions.map((s) => String(s.userId)))];
    const users = await User.find({ _id: { $in: userIds } })
      .select("name email")
      .lean();
    const userById = new Map(users.map((u) => [String(u._id), u]));

    const formattedSessions = sessions.map((session) => ({
      id: session.displayId || toDisplayId(session.sessionId),
      userId: String(session.userId),
      userName: userById.get(String(session.userId))?.name ?? "Unknown",
      userEmail: userById.get(String(session.userId))?.email ?? "unknown",
      device: session.device,
      ipAddress: session.ipAddress,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt,
      expiresAt: session.expiresAt,
      // Null on sessions created before risk was stored on the session.
      riskScore: session.riskScore ?? null,
      riskLevel: session.riskLevel ?? null,
    }));

    return res.status(200).json({
      success: true,
      page,
      limit,
      sort: sortField,
      order: sortOrder === 1 ? "asc" : "desc",
      total,
      totalPages: Math.ceil(total / limit),
      sessions: formattedSessions,
    });
  } catch (error) {
    next(error);
  }
};

/* ============================================================
   ADMIN: REVOKE ANY USER'S SESSION
   ============================================================ */
export const adminRevokeSession = async (req, res, next) => {
  try {
    const rawSessionId = req.params?.sessionId;

    if (!rawSessionId || typeof rawSessionId !== "string" || rawSessionId === "undefined") {
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

    // Resolve by displayId (indexed fast path) with a fallback scan over
    // all active sessions, mirroring the user-facing revoke logic.
    let session = await Session.findOne({ revokedAt: null, displayId: sessionId });

    if (!session) {
      const activeSessions = await Session.find({
        revokedAt: null,
        expiresAt: { $gt: new Date() },
      })
        .select("sessionId")
        .lean();

      const target = activeSessions.find(
        (candidate) => toDisplayId(candidate.sessionId) === sessionId
      );

      if (target) {
        session = await Session.findOne({ sessionId: target.sessionId, revokedAt: null });
      }
    }

    if (!session) {
      return res.status(404).json({
        success: false,
        error: "SESSION_NOT_FOUND",
        message: "Session not found or already revoked.",
      });
    }

    const targetUserId = String(session.userId);
    const lockKey = userSessionLockKey(targetUserId);
    const lockToken = await acquireRedisLock(lockKey);

    if (!lockToken) {
      return res.status(409).json({
        success: false,
        error: "SESSION_OPERATION_BUSY",
        message: "Another session operation is currently being processed.",
      });
    }

    try {
      session.revokedAt = new Date();
      await session.save();

      const targetSessionId = session.sessionId || String(session._id);

      // Tombstone (not DEL) so a concurrent cache fill can't resurrect the
      // session — see markSessionRevokedInRedis.
      await markSessionRevokedInRedis(targetSessionId);

      logAuditEvent({
        event: AUDIT_EVENTS.SESSION_REVOKED,
        userId: targetUserId,
        sessionId: targetSessionId,
        req,
        metadata: { reason: "admin_action", adminId: String(req.user._id || req.user.id) },
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
   ADMIN: REVOKE ALL SESSIONS FOR A GIVEN USER
   ============================================================ */
export const adminRevokeUserSessions = async (req, res, next) => {
  try {
    const targetUserId = String(req.params?.userId || "");

    if (!isValidObjectId(targetUserId)) {
      return res.status(400).json({ success: false, error: "INVALID_USER_ID", message: "Invalid user ID format" });
    }

    const lockKey = userSessionLockKey(targetUserId);
    const lockToken = await acquireRedisLock(lockKey);

    if (!lockToken) {
      return res.status(409).json({
        success: false,
        error: "SESSION_OPERATION_BUSY",
        message: "Another session operation is currently being processed.",
      });
    }

    try {
      const sessions = await Session.find({ userId: targetUserId, revokedAt: null })
        .select("sessionId")
        .lean();
      const sessionIds = sessions.map((s) => s.sessionId);

      if (sessionIds.length > 0) {
        await Session.updateMany(
          { userId: targetUserId, revokedAt: null },
          { $set: { revokedAt: new Date() } }
        );

        // Tombstones, not DELs — see markSessionRevokedInRedis.
        await markSessionRevokedInRedis(sessionIds);
      }

      logAuditEvent({
        event: AUDIT_EVENTS.SESSION_REVOKED,
        userId: targetUserId,
        req,
        metadata: {
          reason: "admin_revoke_all",
          adminId: String(req.user._id || req.user.id),
          revokedCount: sessionIds.length,
        },
      });

      notifyAdminAsync(String(req.user._id || req.user.id), {
        action: "sessions_revoked",
        targetEmail: (await User.findById(targetUserId).select("email").lean())?.email ?? targetUserId,
        revokedCount: sessionIds.length,
      });

      return res.status(200).json({
        success: true,
        message: `Revoked ${sessionIds.length} session(s).`,
      });
    } finally {
      await releaseRedisLock(lockKey, lockToken);
    }
  } catch (error) {
    next(error);
  }
};

/* ============================================================
   ADMIN: PROMOTE / DEMOTE (change a user's role)
   ============================================================ */
export const adminChangeUserRole = async (req, res, next) => {
  try {
    const targetUserId = String(req.params?.userId || "");
    const { role } = req.body ?? {};

    if (!isValidObjectId(targetUserId)) {
      return res.status(400).json({ success: false, error: "INVALID_USER_ID", message: "Invalid user ID format" });
    }

    if (role !== "admin" && role !== "user") {
      return res.status(400).json({
        success: false,
        error: "INVALID_ROLE",
        message: 'Role must be either "admin" or "user".',
      });
    }

    const adminId = String(req.user._id || req.user.id);

    if (targetUserId === adminId) {
      return res.status(400).json({
        success: false,
        error: "CANNOT_CHANGE_OWN_ROLE",
        message: "Admins cannot change their own role. Ask another admin.",
      });
    }

    const lockKey = userSessionLockKey(targetUserId);
    const lockToken = await acquireRedisLock(lockKey);

    if (!lockToken) {
      return res.status(409).json({
        success: false,
        error: "SESSION_OPERATION_BUSY",
        message: "Another session operation is currently being processed.",
      });
    }

    try {
      const user = await User.findById(targetUserId).select("name email role");

      if (!user) {
        return res.status(404).json({ success: false, error: "USER_NOT_FOUND", message: "User not found" });
      }

      if (user.role === role) {
        return res.status(400).json({
          success: false,
          error: "ROLE_UNCHANGED",
          message: `${user.email} already has the "${role}" role.`,
        });
      }

      // Never demote the bootstrap admin (DEFAULT_ADMIN_EMAIL) — it is the
      // guaranteed way back into the panel if every other admin is demoted,
      // deleted, or locked out.
      const defaultAdminEmail = (process.env.DEFAULT_ADMIN_EMAIL || "").trim().toLowerCase();
      if (role === "user" && defaultAdminEmail && user.email.toLowerCase() === defaultAdminEmail) {
        return res.status(400).json({
          success: false,
          error: "CANNOT_DEMOTE_DEFAULT_ADMIN",
          message: "The default admin account cannot be demoted. It is the guaranteed recovery path into the admin panel.",
        });
      }

      // Demoting the LAST admin would strand the panel with no admin able to
      // promote anyone back. (DEFAULT_ADMIN_EMAIL normally covers this, but
      // the bootstrap account can be deleted.)
      if (role === "user" && user.role === "admin") {
        const adminCount = await User.countDocuments({ role: "admin" });
        if (adminCount <= 1) {
          return res.status(400).json({
            success: false,
            error: "CANNOT_DEMOTE_LAST_ADMIN",
            message: "This is the only remaining admin. Promote another admin before demoting them.",
          });
        }
      }

      const previousRole = user.role;
      user.role = role;
      await user.save();

      // The role is baked into the access token at sign-in, so a demoted
      // admin would keep admin powers until their token refreshes. Revoking
      // their sessions closes that window: they re-sign-in as a plain user.
      let revokedCount = 0;
      if (role === "user") {
        const sessions = await Session.find({ userId: targetUserId, revokedAt: null })
          .select("sessionId")
          .lean();
        const sessionIds = sessions.map((s) => s.sessionId);

        if (sessionIds.length > 0) {
          await Session.updateMany(
            { userId: targetUserId, revokedAt: null },
            { $set: { revokedAt: new Date() } },
          );
          // Tombstones, not DELs — see markSessionRevokedInRedis.
          await markSessionRevokedInRedis(sessionIds);
          revokedCount = sessionIds.length;
        }
      }

      logAuditEvent({
        event: AUDIT_EVENTS.USER_ROLE_CHANGED,
        userId: targetUserId,
        req,
        metadata: {
          reason: "admin_action",
          adminId,
          previousRole,
          newRole: role,
          revokedSessions: revokedCount,
        },
      });

      notifyAdminAsync(adminId, {
        action: "role_changed",
        targetEmail: user.email,
        newRole: role,
      });

      return res.status(200).json({
        success: true,
        message:
          role === "admin"
            ? `${user.email} is now an admin. They get admin access the next time they sign in.`
            : `${user.email} is no longer an admin. Their ${revokedCount} active session(s) were revoked — they must sign in again.`,
        revokedCount,
      });
    } finally {
      await releaseRedisLock(lockKey, lockToken);
    }
  } catch (error) {
    next(error);
  }
};

/* ============================================================
   ADMIN: DELETE A USER (revokes all their sessions first)
   ============================================================ */
export const adminDeleteUser = async (req, res, next) => {
  try {
    const targetUserId = String(req.params?.userId || "");

    if (!isValidObjectId(targetUserId)) {
      return res.status(400).json({ success: false, error: "INVALID_USER_ID", message: "Invalid user ID format" });
    }

    const adminId = String(req.user._id || req.user.id);

    if (targetUserId === adminId) {
      return res.status(400).json({
        success: false,
        error: "CANNOT_DELETE_SELF",
        message: "Admins cannot delete their own account from the admin panel.",
      });
    }

    const lockKey = userSessionLockKey(targetUserId);
    const lockToken = await acquireRedisLock(lockKey);

    if (!lockToken) {
      return res.status(409).json({
        success: false,
        error: "SESSION_OPERATION_BUSY",
        message: "Another session operation is currently being processed.",
      });
    }

    try {
      const sessions = await Session.find({ userId: targetUserId, revokedAt: null })
        .select("sessionId")
        .lean();
      const sessionIds = sessions.map((s) => s.sessionId);

      if (sessionIds.length > 0) {
        await Session.updateMany(
          { userId: targetUserId, revokedAt: null },
          { $set: { revokedAt: new Date() } }
        );

        // Tombstones, not DELs — see markSessionRevokedInRedis.
        await markSessionRevokedInRedis(sessionIds);
      }

      const user = await User.findByIdAndDelete(targetUserId);

      if (!user) {
        return res.status(404).json({ success: false, error: "USER_NOT_FOUND", message: "User not found" });
      }

      logAuditEvent({
        event: AUDIT_EVENTS.USER_DELETED,
        userId: targetUserId,
        req,
        metadata: { reason: "admin_action", adminId },
      });

      notifyAdminAsync(adminId, {
        action: "user_deleted",
        targetEmail: user.email,
      });

      return res.status(200).json({
        success: true,
        message: `User ${user.email} and all their sessions were deleted.`,
      });
    } finally {
      await releaseRedisLock(lockKey, lockToken);
    }
  } catch (error) {
    next(error);
  }
};

/* ============================================================
   ADMIN: AUDIT TRAIL INTEGRITY CHECK
   Read-only verdict, never a repair tool. Every audit entry is
   hash-chained to the previous one; this recomputes the whole
   chain so edits or deletions made directly in the database —
   which bypass every in-app guard — surface here. Nobody, admins
   included, can rewrite history from the panel: a broken chain
   can only be investigated, not "fixed".
   ============================================================ */
export const verifyAuditIntegrity = async (req, res, next) => {
  try {
    // Check what is persisted, not what is still queued.
    await flushAuditLogs();
    const integrity = await verifyAuditChain();

    // The check itself is auditable too.
    logAuditEvent({
      event: AUDIT_EVENTS.AUDIT_INTEGRITY_CHECKED,
      userId: String(req.user._id || req.user.id),
      req,
      metadata: { reason: integrity.valid ? "intact" : integrity.reason },
    });

    return res.status(200).json({ success: true, integrity });
  } catch (error) {
    return next(error);
  }
};
