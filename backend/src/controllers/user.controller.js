// src/controllers/user.controller.js

import mongoose from "mongoose";
import bcrypt from "bcrypt";
import { z } from "zod";
import User from "../models/user.model.js";
import Session from "../models/session.model.js";
import AuditLog from "../models/auditLog.model.js";
import { logAuditEvent, AUDIT_EVENTS } from "../utils/auditLog.js";
import { clearAuthCookies } from "../utils/cookies.js";
import { acquireRedisLock, releaseRedisLock } from "../utils/redisLock.js";
import { userSessionLockKey, markSessionRevokedInRedis, maskPhoneNumber } from "../utils/security.js";
import { redisClient } from "../config/redis.js";
import { numberFromEnv } from "../utils/env.js";
import { NAME_MIN_LENGTH, NAME_MAX_LENGTH } from "../utils/namePolicy.js";
import { PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH } from "../utils/passwordPolicy.js";
import { issueOtp, verifyOtp, verifyStepUpToken, stepUpCookieName, OtpError, OTP_TTL_SECONDS } from "../utils/otp.js";

// BCRYPT_ROUNDS: password hashing cost (default 12). Each +1 roughly
// doubles the hash time — keep auth.controller.js's value in sync via .env.
const BCRYPT_ROUNDS = numberFromEnv("BCRYPT_ROUNDS", 12, { minimum: 4, maximum: 15 });

/**
 * Validates whether a given string is a valid MongoDB ObjectId
 */
const isValidObjectId = (id) => typeof id === "string" && mongoose.Types.ObjectId.isValid(id);

/**
 * Phone numbers leave the API masked — last 4 digits only, like
 * "+•••••••1111" — the same treatment session IPs get. The full value
 * exists only in the database (and, for the owner, in their own phone).
 */
const withMaskedPhone = (user) =>
  user && typeof user === "object" && user.phoneNumber
    ? { ...user, phoneNumber: maskPhoneNumber(user.phoneNumber) }
    : user;

/* ============================================================
   ADMIN DUAL-CHANNEL UPDATE CONFIRMATION
   When an admin updates anything security-relevant (phone, email, password),
   the change is confirmed on BOTH channels — SEQUENTIALLY, one code per
   screen: the emailed step-up code (demanded by the route middleware) first,
   then a text to the CURRENT verified number. Nothing is texted before the
   emailed half passes.
   ============================================================ */

/* Text a confirmation code to the admin's CURRENT verified number. Returns
   the issue result (or null for non-admins / admins with no phone — the
   emailed confirmation stands alone, same fallback as admin login). */
const issueAdminUpdateSms = (user, req) => {
  if (user.role !== "admin" || !(user.phoneNumber && user.phoneVerified)) return null;
  return issueOtp({ user, purpose: "update_sms", req, channel: "sms" });
};

/* Shape of the adminSms block in stage responses: required=true means a
   texted code is expected at this stage. */
const adminSmsChallenge = (user, sms) =>
  sms
    ? {
        required: true,
        maskedPhone: maskPhoneNumber(user.phoneNumber),
        expiresInSeconds: sms.expiresInSeconds,
        resendCooldownSeconds: sms.resendCooldownSeconds,
        ...(sms.deliveryWarning ? { deliveryWarning: sms.deliveryWarning } : {}),
        ...(sms.devCode ? { devCode: sms.devCode } : {}),
      }
    : { required: false };

/* Shared failure response for the verify steps. */
const updateCodeFailureResponse = (res, failure) => {
  const statusByError = { INVALID: 401, EXPIRED: 400, LOCKED: 429 };
  return res.status(statusByError[failure?.error] || 400).json({
    success: false,
    error: failure?.error ?? "INVALID",
    message:
      failure?.error === "INVALID"
        ? "That code is incorrect."
        : failure?.error === "LOCKED"
          ? "Too many incorrect attempts. Request a new code."
          : "That code has expired. Request a new one.",
    ...(failure?.attemptsLeft !== undefined ? { attemptsLeft: failure.attemptsLeft } : {}),
  });
};

/**
 * GET /api/users/me — Fetch self profile
 */
export const getUserProfile = async (req, res, next) => {
  try {
    const rawUserId = req.user?._id || req.user?.id;
    const userId = String(rawUserId);

    if (!isValidObjectId(userId)) {
      return res.status(400).json({ success: false, error: "INVALID_USER_ID", message: "Invalid user ID format" });
    }

    const user = await User.findById(userId).select("-passwordHash -__v").lean();

    if (!user) {
      return res.status(404).json({ success: false, error: "USER_NOT_FOUND", message: "User not found" });
    }

    // Drives the frontend's change-password form: Google-only accounts show
    // "set password" instead of "current + new".
    const hasPassword = await User.findById(userId).select("passwordHash").lean();

    return res.status(200).json({
      success: true,
      user: withMaskedPhone({ ...user, hasPassword: Boolean(hasPassword?.passwordHash) }),
    });
  } catch (error) {
    next(error);
  }
};

/**
 * GET /api/users/:id — Fetch user by ID
 */
export const getUserById = async (req, res, next) => {
  try {
    const { id } = req.params;

    if (!isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: "INVALID_USER_ID", message: "Invalid user ID format" });
    }

    const user = await User.findById(id).select("-passwordHash -__v").lean();

    if (!user) {
      return res.status(404).json({ success: false, error: "USER_NOT_FOUND", message: "User not found" });
    }

    return res.status(200).json({ success: true, user: withMaskedPhone(user) });
  } catch (error) {
    next(error);
  }
};

/**
 * GET /api/users/:id/activity — Admin: account details + activity log.
 * Returns the account summary (registered, last login, session counts,
 * masked phone, sign-in method) plus their N most recent audit events.
 * Read-only; the phone number stays masked like every other PII surface.
 */
export const getUserActivity = async (req, res, next) => {
  try {
    const { id } = req.params;

    if (!isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: "INVALID_USER_ID", message: "Invalid user ID format" });
    }

    // ACTIVITY_EVENTS_LIMIT: audit events returned per page for one user
    // (default 20, capped at 50).
    const limit = Math.min(
      numberFromEnv("ACTIVITY_EVENTS_MAX_LIMIT", 50),
      Math.max(1, Number.parseInt(req.query?.limit, 10) || numberFromEnv("ACTIVITY_EVENTS_DEFAULT_LIMIT", 20)),
    );

    const user = await User.findById(id)
      .select("name email role isVerified createdAt lastLoginAt phoneNumber phoneVerified googleId")
      .lean();

    if (!user) {
      return res.status(404).json({ success: false, error: "USER_NOT_FOUND", message: "User not found" });
    }

    const [activeSessions, totalSessions, events] = await Promise.all([
      Session.countDocuments({ userId: id, revokedAt: null, expiresAt: { $gt: new Date() } }),
      Session.countDocuments({ userId: id }),
      AuditLog.find({ userId: id })
        .select("event severity ipAddress method path createdAt metadata.reason metadata.device metadata.riskLevel")
        .sort({ createdAt: -1 })
        .limit(limit)
        .lean(),
    ]);

    return res.status(200).json({
      success: true,
      user: {
        id: String(user._id),
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
        createdAt: user.createdAt,
        lastLoginAt: user.lastLoginAt,
        // Masked even for admins — same PII treatment as the profile
        // endpoints. `null` means no number is linked to the account.
        phoneNumber: user.phoneNumber ? maskPhoneNumber(user.phoneNumber) : null,
        phoneVerified: Boolean(user.phoneVerified),
        hasGoogle: Boolean(user.googleId),
        activeSessions,
        totalSessions,
      },
      events: events.map((e) => ({
        id: String(e._id),
        event: e.event,
        severity: e.severity,
        ipAddress: e.ipAddress,
        device: e.metadata?.device ?? null,
        reason: e.metadata?.reason ?? null,
        riskLevel: e.metadata?.riskLevel ?? null,
        createdAt: e.createdAt,
      })),
    });
  } catch (error) {
    next(error);
  }
};

/**
 * PUT /api/users/me — Update self profile (Strict allow-list & string sanitization)
 */
export const updateUserProfile = async (req, res, next) => {
  try {
    const rawUserId = req.user?._id || req.user?.id;
    const userId = String(rawUserId);

    if (!isValidObjectId(userId)) {
      return res.status(400).json({ success: false, error: "INVALID_USER_ID", message: "Invalid user ID format" });
    }

    const { name, email } = req.body;

    // Email is immutable: it anchors identity, OAuth linkage, and audit
    // trails. Profile updates may only change the display name.
    if (email !== undefined) {
      return res.status(400).json({
        success: false,
        error: "EMAIL_IMMUTABLE",
        message: "Email addresses cannot be changed",
      });
    }

    // Zod validates the allow-listed, optional update fields. Only this
    // field can ever reach the $set below, so mass-assignment of role,
    // email, or passwordHash is structurally impossible.
    const updateSchema = z.object({
      // Same character policy as registration: letters, spaces, hyphens and
      // apostrophes — no digits, periods or symbols. Length limits come from
      // NAME_MIN_LENGTH / NAME_MAX_LENGTH in .env.
      name: z
        .string()
        .trim()
        .min(NAME_MIN_LENGTH)
        .max(NAME_MAX_LENGTH)
        .regex(/^[\p{L}][\p{L}\s'-]*$/u)
        .optional(),
    });

    const parsed = updateSchema.safeParse({ name, email });
    if (!parsed.success) {
      const field = parsed.error.issues[0]?.path?.[0];
      const messages = {
        name: `Enter a valid name (${NAME_MIN_LENGTH}–${NAME_MAX_LENGTH} characters, letters, spaces, hyphens and apostrophes only)`,
        email: "Invalid email format",
      };
      return res.status(400).json({
        success: false,
        error: "INVALID_INPUT",
        message: messages[field] || "Invalid profile update payload",
      });
    }

    const updates = {};
    if (parsed.data.name !== undefined) updates.name = parsed.data.name;

    // Read the current profile first so the audit trail can say WHAT changed
    // (old → new), and so a no-op update is logged as nothing at all.
    const existing = await User.findById(userId).select("name").lean();
    if (!existing) {
      return res.status(404).json({ success: false, error: "USER_NOT_FOUND", message: "User not found" });
    }

    const changedFields = [];
    if (updates.name !== undefined && updates.name !== existing.name) {
      changedFields.push(`name: "${existing.name}" → "${updates.name}"`);
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: updates },
      { returnDocument: "after", runValidators: true }
    )
      .select("-passwordHash -__v")
      .lean();

    if (!updatedUser) {
      return res.status(404).json({ success: false, error: "USER_NOT_FOUND", message: "User not found" });
    }

    // Every profile mutation leaves a trail alongside the password/role/
    // session events — "who changed their name, and to what".
    if (changedFields.length > 0) {
      logAuditEvent({
        event: AUDIT_EVENTS.PROFILE_UPDATED,
        userId,
        req,
        metadata: {
          // reason is what the activity feed displays.
          reason: `Profile updated — ${changedFields.join(", ")}`,
          changes: changedFields.join(", "),
        },
      });
    }

    return res.status(200).json({ success: true, user: withMaskedPhone(updatedUser) });
  } catch (error) {
    next(error);
  }
};

/**
 * PUT /api/users/me/password — Change own password (email + SMS confirmed).
 * Order matters: the current/new passwords are validated FIRST (current must
 * match, new must differ) — only then is any code owed, so a mailed or texted
 * code is never spent on a request that would fail on the passwords alone.
 * The emailed half is strict step-up (a fresh code confirmed within the
 * 5-minute sudo window — the trusted-device cookie never satisfies it),
 * checked here rather than in route middleware for exactly that ordering.
 * ADMIN accounts with a verified phone additionally confirm by text
 * (update_sms), sequential — the emailed code first, then the text; step 1
 * (no smsCode) validates and texts, step 2 (with smsCode) applies. Regular
 * users apply right after step-up. The change hashes the new password with
 * bcrypt and revokes every OTHER session (the current session stays valid so
 * the user isn't signed out mid-change).
 */
export const changePassword = async (req, res, next) => {
  try {
    const rawUserId = req.user?._id || req.user?.id;
    const userId = String(rawUserId);

    if (!isValidObjectId(userId)) {
      return res.status(400).json({ success: false, error: "INVALID_USER_ID", message: "Invalid user ID format" });
    }

    const { currentPassword, newPassword, smsCode } = req.body ?? {};

    // bcrypt truncates input at 72 bytes; cap earlier so oversized inputs
    // are rejected instead of silently shortened. currentPassword is
    // OPTIONAL — Google-only accounts have no password to verify. The
    // limits come from passwordPolicy.js so register/reset/change all
    // enforce the same rule (this endpoint used to cap at 72 while
    // registration allowed 128 — a password set at registration could then
    // never be verified here).
    const passwordSchema = z.string().min(PASSWORD_MIN_LENGTH).max(PASSWORD_MAX_LENGTH);
    const currentParsed =
      currentPassword === undefined || currentPassword === ""
        ? { success: true, data: null }
        : passwordSchema.safeParse(currentPassword);
    const newParsed = passwordSchema.safeParse(newPassword);

    if (!currentParsed.success || !newParsed.success) {
      return res.status(400).json({
        success: false,
        error: "INVALID_INPUT",
        message: `Passwords must be between ${PASSWORD_MIN_LENGTH} and ${PASSWORD_MAX_LENGTH} characters`,
      });
    }

    const user = await User.findById(userId).select(
      "name email role passwordHash googleId phoneNumber phoneVerified",
    );

    if (!user) {
      return res.status(404).json({ success: false, error: "USER_NOT_FOUND", message: "User not found" });
    }

    // Two cases share this endpoint:
    //  1. A user WITH a password verifies currentPassword and replaces it.
    //  2. A Google-only account (no password yet) sets an initial password —
    //     there is nothing to verify, but they must already be signed in,
    //     which authMiddleware guarantees.
    if (!user.passwordHash) {
      if (currentPassword) {
        return res.status(400).json({
          success: false,
          error: "NO_PASSWORD_SET",
          message: "This account has no password yet — leave the current password field empty to set one",
        });
      }
    } else {
      const currentMatches = await bcrypt.compare(currentParsed.data, user.passwordHash);

      if (!currentMatches) {
        return res.status(401).json({
          success: false,
          error: "INVALID_CREDENTIALS",
          message: "Current password is incorrect",
        });
      }

      const samePassword = await bcrypt.compare(newParsed.data, user.passwordHash);

      if (samePassword) {
        return res.status(400).json({
          success: false,
          error: "PASSWORD_UNCHANGED",
          message: "The new password must be different from the current one",
        });
      }
    }

    // Everything about the passwords themselves is validated — NOW the codes
    // are owed, in order. First the emailed half: strict step-up (a fresh
    // code from the last 5 minutes; the 30-day trusted-device cookie does
    // NOT pass). The 401 here is what makes the frontend open its emailed-
    // code dialog and retry — and because it sits below the validation, a
    // wrong or unchanged password never triggers an email.
    if (!verifyStepUpToken(req.cookies?.[stepUpCookieName()], userId)) {
      return res.status(401).json({
        success: false,
        error: "STEP_UP_REQUIRED",
        message: "This action requires confirmation. Check your email for a verification code.",
      });
    }

    // Second the texted half — ADM ONLY (their accounts can act on every
    // user in the system; a regular user's emailed confirmation is enough).
    // Nothing is texted before the emailed code above has passed.
    const adminSmsDue = user.role === "admin" && Boolean(user.phoneNumber && user.phoneVerified);
    if (adminSmsDue) {
      if (smsCode) {
        const verified = await verifyOtp({ user, purpose: "update_sms", code: smsCode });
        if (!verified.valid) {
          logAuditEvent({
            event: AUDIT_EVENTS.OTP_FAILED,
            userId: user._id,
            req,
            metadata: { purpose: "update_sms", reason: verified.error },
          });
          return updateCodeFailureResponse(res, verified);
        }

        logAuditEvent({
          event: AUDIT_EVENTS.OTP_VERIFIED,
          userId: user._id,
          req,
          metadata: { purpose: "update_sms" },
        });
      } else {
        // Step 1: text the confirmation code (step 2 re-sends everything).
        const otp = await issueOtp({ user, purpose: "update_sms", req, channel: "sms" });
        if (otp.error) {
          const status = otp.error === OtpError.COOLDOWN ? 429 : 503;
          return res.status(status).json({
            success: false,
            error: otp.error,
            message:
              otp.error === OtpError.COOLDOWN
                ? "A code was recently sent. Please wait before requesting another."
                : "Text delivery is temporarily unavailable. Try again shortly.",
            ...(otp.error === OtpError.COOLDOWN && otp.retryAfterSeconds
              ? { retryAfterSeconds: otp.retryAfterSeconds }
              : {}),
          });
        }
        return res.status(200).json({
          success: true,
          requireOtp: true,
          message: `We texted a code to ${maskPhoneNumber(user.phoneNumber)}. Enter it to finish the password change.`,
          maskedPhone: maskPhoneNumber(user.phoneNumber),
          expiresInSeconds: otp.expiresInSeconds,
          resendCooldownSeconds: otp.resendCooldownSeconds,
          ...(otp.deliveryWarning ? { deliveryWarning: otp.deliveryWarning } : {}),
          ...(otp.devCode ? { devCode: otp.devCode } : {}),
        });
      }
    }

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
      user.passwordHash = await bcrypt.hash(newParsed.data, BCRYPT_ROUNDS);
      await user.save();

      // Revoke every session EXCEPT the one making the request.
      const currentSessionId = String(req.user?.sessionId || "");
      const sessions = await Session.find({ userId, revokedAt: null }).select("sessionId").lean();
      const toRevoke = sessions.filter((s) => s.sessionId !== currentSessionId);

      if (toRevoke.length > 0) {
        await Session.updateMany(
          { _id: { $in: toRevoke.map((s) => s._id) } },
          { $set: { revokedAt: new Date() } },
        );

        // Tombstones, not DELs — see markSessionRevokedInRedis.
        await markSessionRevokedInRedis(toRevoke.map((s) => s.sessionId));
      }

      logAuditEvent({
        event: AUDIT_EVENTS.PASSWORD_CHANGED,
        userId,
        req,
        metadata: {
          reason: "Password changed",
          // How many OTHER sessions were signed out by this change. The
          // password itself never comes near the audit trail.
          revokedCount: toRevoke.length,
        },
      });

      return res.status(200).json({
        success: true,
        message: `Password updated. ${toRevoke.length} other session(s) were signed out.`,
      });
    } finally {
      await releaseRedisLock(lockKey, lockToken);
    }
  } catch (error) {
    next(error);
  }
};

/**
 * POST /api/users/me/phone — Add or change the phone number.
 * FIRST number: two phases, email before SMS — phase A mails an
 * account-ownership code (nothing is texted until the mailbox is confirmed;
 * texts cost money), phase B (emailCode) confirms it and only then texts the
 * code to the NEW number. Changing an EXISTING number is also staged, one
 * code per screen: for admins the CURRENT number is texted first (their
 * confirmation half), and only once that passes does the NEW number get its
 * text; regular users skip straight to the new-number text (the emailed
 * step-up code owed to the route middleware already confirmed their email
 * half). The number is not saved until the new-number code is confirmed —
 * anyone can type any number; ownership is only proven by receiving the code
 * on it.
 */
export const setPhoneNumber = async (req, res, next) => {
  try {
    const rawUserId = req.user?._id || req.user?.id;
    const userId = String(rawUserId);

    if (!isValidObjectId(userId)) {
      return res.status(400).json({ success: false, error: "INVALID_USER_ID", message: "Invalid user ID format" });
    }

    const { phoneNumber, code, adminSmsCode, emailCode } = req.body;

    // India-only for now: +91 followed by a 10-digit mobile number starting
    // with 6-9 (Indian mobiles never start 0-5). The frontend locks its
    // country picker to +91; loosen this when more countries open up.
    // Normalized (spaces/dashes stripped) so "+91 98765 43210" and
    // "+919876543210" store identically.
    const normalized =
      typeof phoneNumber === "string" ? phoneNumber.replace(/[\s()-]/g, "") : phoneNumber;
    const phoneParsed = z.string().regex(/^\+91[6-9]\d{9}$/).safeParse(normalized);

    if (!phoneParsed.success) {
      return res.status(400).json({
        success: false,
        error: "INVALID_INPUT",
        message: "Enter a valid Indian mobile number — exactly 10 digits starting with 6-9",
      });
    }

    const newPhone = phoneParsed.data;

    // email IS needed here: the first-add phase A code is mailed to it.
    const user = await User.findById(userId).select("name email role phoneNumber phoneVerified");
    if (!user) {
      return res.status(404).json({ success: false, error: "USER_NOT_FOUND", message: "User not found" });
    }

    // Re-entering the number already on the account is a no-op — and worse,
    // it would re-run the whole code flow (email + texts) to "verify" the
    // number already verified. Same rule as the email-change guard.
    if (user.phoneNumber === newPhone) {
      return res.status(400).json({
        success: false,
        error: "PHONE_UNCHANGED",
        message: "That is already the phone number on your account",
      });
    }

    // One number per account: a phone is an identity factor, not a label.
    const taken = await User.exists({ phoneNumber: newPhone, _id: { $ne: user._id } });
    if (taken) {
      return res.status(409).json({
        success: false,
        error: "PHONE_ALREADY_IN_USE",
        message: "This phone number is already linked to another account",
      });
    }

    // Shared response for a failed SMS issue (cooldown or provider outage).
    const smsErrorResponse = (result) =>
      res.status(result.error === OtpError.COOLDOWN ? 429 : 503).json({
        success: false,
        error: result.error,
        message:
          result.error === OtpError.COOLDOWN
            ? "A code was recently sent. Please wait before requesting another."
            : "Text delivery is temporarily unavailable. Try again shortly.",
        ...(result.error === OtpError.COOLDOWN && result.retryAfterSeconds
          ? { retryAfterSeconds: result.retryAfterSeconds }
          : {}),
      });

    // No texted code yet: get codes out.
    if (!code) {
      const firstAdd = !user.phoneNumber;

      if (firstAdd) {
        // Phase marker: set once the emailed code is confirmed, so a resend
        // re-texts the phone instead of restarting at the email phase.
        const emailConfirmedKey = `phoneadd:${userId}`;
        const emailConfirmed = redisClient?.isOpen ? await redisClient.get(emailConfirmedKey) : null;

        if (emailCode) {
          // Phase B entry: confirm the emailed account-ownership code.
          const result = await verifyOtp({ user, purpose: "phone_add", code: emailCode });
          if (!result.valid) {
            logAuditEvent({
              event: AUDIT_EVENTS.OTP_FAILED,
              userId: user._id,
              req,
              metadata: { purpose: "phone_add", reason: result.error },
            });
            return updateCodeFailureResponse(res, result);
          }
          logAuditEvent({
            event: AUDIT_EVENTS.OTP_VERIFIED,
            userId: user._id,
            req,
            metadata: { purpose: "phone_add" },
          });
          await redisClient.setEx(emailConfirmedKey, Math.ceil(OTP_TTL_SECONDS), "1");
        } else if (!emailConfirmed) {
          // Phase A: mail the code — no SMS goes out yet.
          const emailOtp = await issueOtp({
            user,
            purpose: "phone_add",
            req,
            actionLabel: "add a phone number to your account",
          });
          if (emailOtp.error) {
            const status = emailOtp.error === OtpError.COOLDOWN ? 429 : 503;
            return res.status(status).json({
              success: false,
              error: emailOtp.error,
              message:
                emailOtp.error === OtpError.COOLDOWN
                  ? "A code was recently sent. Please wait before requesting another."
                  : "Verification is temporarily unavailable. Try again shortly.",
              ...(emailOtp.retryAfterSeconds ? { retryAfterSeconds: emailOtp.retryAfterSeconds } : {}),
            });
          }
          return res.status(200).json({
            success: true,
            requireOtp: true,
            stage: "email",
            message: `We emailed a code to ${user.email}. Enter it to continue.`,
            emailChallenge: {
              required: true,
              email: user.email,
              expiresInSeconds: emailOtp.expiresInSeconds,
              resendCooldownSeconds: emailOtp.resendCooldownSeconds,
              ...(emailOtp.deliveryWarning ? { deliveryWarning: emailOtp.deliveryWarning } : {}),
              ...(emailOtp.devCode ? { devCode: emailOtp.devCode } : {}),
            },
          });
        }

        // Email half done — NOW text the code to the new number. (An admin
        // adding their first number has no current number yet, so there is
        // no adminSms half at this point.)
        const otp = await issueOtp({ user, purpose: "phone_verify", req, channel: "sms", phone: newPhone });
        if (otp.error) return smsErrorResponse(otp);
        return res.status(200).json({
          success: true,
          requireOtp: true,
          stage: "sms",
          message: `Email confirmed. We texted a code to ${maskPhoneNumber(newPhone)}. Enter it to finish.`,
          expiresInSeconds: otp.expiresInSeconds,
          resendCooldownSeconds: otp.resendCooldownSeconds,
          ...(otp.deliveryWarning ? { deliveryWarning: otp.deliveryWarning } : {}),
          ...(otp.devCode ? { devCode: otp.devCode } : {}),
        });
      }

      // Changing an existing number — for admins it's staged, one code per
      // screen: the CURRENT number is texted first (their confirmation half),
      // and only once that passes does the NEW number get its text. Regular
      // users skip straight to the new-number text.
      const adminSmsDue = user.role === "admin" && Boolean(user.phoneNumber && user.phoneVerified);

      if (adminSmsDue) {
        // Phase marker: set once the current-number code is confirmed, so a
        // resend re-texts the NEW number instead of restarting at the
        // current-number phase.
        const adminConfirmedKey = `phonechg:${userId}`;
        const adminConfirmed = redisClient?.isOpen ? await redisClient.get(adminConfirmedKey) : null;

        if (adminSmsCode) {
          // Confirm the current-number code, then text the new number.
          const result = await verifyOtp({ user, purpose: "update_sms", code: adminSmsCode });
          if (!result.valid) {
            logAuditEvent({
              event: AUDIT_EVENTS.OTP_FAILED,
              userId: user._id,
              req,
              metadata: { purpose: "update_sms", reason: result.error },
            });
            return updateCodeFailureResponse(res, result);
          }
          logAuditEvent({
            event: AUDIT_EVENTS.OTP_VERIFIED,
            userId: user._id,
            req,
            metadata: { purpose: "update_sms" },
          });
          await redisClient.setEx(adminConfirmedKey, Math.ceil(OTP_TTL_SECONDS), "1");

          const otp = await issueOtp({ user, purpose: "phone_verify", req, channel: "sms", phone: newPhone });
          if (otp.error) return smsErrorResponse(otp);
          return res.status(200).json({
            success: true,
            requireOtp: true,
            stage: "sms",
            message: `Current number confirmed. We texted a code to ${maskPhoneNumber(newPhone)}. Enter it to finish.`,
            expiresInSeconds: otp.expiresInSeconds,
            resendCooldownSeconds: otp.resendCooldownSeconds,
            ...(otp.deliveryWarning ? { deliveryWarning: otp.deliveryWarning } : {}),
            ...(otp.devCode ? { devCode: otp.devCode } : {}),
          });
        }

        if (!adminConfirmed) {
          // Current-number phase: text the admin's current number FIRST.
          const adminSms = await issueAdminUpdateSms(user, req);
          if (adminSms?.error) return smsErrorResponse(adminSms);
          return res.status(200).json({
            success: true,
            requireOtp: true,
            stage: "admin_sms",
            message: `We texted a code to ${maskPhoneNumber(user.phoneNumber)} — your current number. Enter it to continue.`,
            adminSms: adminSmsChallenge(user, adminSms),
          });
        }
        // Current number already confirmed (a resend) — fall through to the
        // new-number text below.
      }

      const otp = await issueOtp({ user, purpose: "phone_verify", req, channel: "sms", phone: newPhone });
      if (otp.error) return smsErrorResponse(otp);
      return res.status(200).json({
        success: true,
        requireOtp: true,
        stage: "sms",
        // Masked even though the user just typed the number themselves — the
        // response body is no place for a full phone number.
        message: `We texted a code to ${maskPhoneNumber(newPhone)}. Enter it to confirm the number.`,
        expiresInSeconds: otp.expiresInSeconds,
        resendCooldownSeconds: otp.resendCooldownSeconds,
        ...(otp.deliveryWarning ? { deliveryWarning: otp.deliveryWarning } : {}),
        ...(otp.devCode ? { devCode: otp.devCode } : {}),
      });
    }

    // Final step: the texted code proves the NEW number is in the user's
    // hands (admins confirmed their current number in the stage before).
    const verified = await verifyOtp({ user, purpose: "phone_verify", code });
    if (!verified.valid) {
      logAuditEvent({
        event: AUDIT_EVENTS.OTP_FAILED,
        userId: user._id,
        req,
        metadata: { purpose: "phone_verify", reason: verified.error },
      });
      return updateCodeFailureResponse(res, verified);
    }

    const previous = user.phoneNumber;
    user.phoneNumber = newPhone;
    user.phoneVerified = true;
    await user.save();

    logAuditEvent({
      event: AUDIT_EVENTS.OTP_VERIFIED,
      userId: user._id,
      req,
      metadata: { purpose: "phone_verify" },
    });
    // The full number never enters the audit trail — last 4 digits only.
    logAuditEvent({
      event: AUDIT_EVENTS.PROFILE_UPDATED,
      userId: user._id,
      req,
      metadata: {
        reason: `Phone number ${previous ? "changed" : "added"} (ending ${newPhone.slice(-4)})`,
        changes: `phone: ${previous ? `…${previous.slice(-4)}` : "none"} → …${newPhone.slice(-4)}`,
      },
    });

    return res.status(200).json({
      success: true,
      message: "Phone number verified and saved.",
      user: { phoneNumber: maskPhoneNumber(user.phoneNumber), phoneVerified: user.phoneVerified },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * DELETE /api/users/me/phone — Remove the phone number (two steps).
 * Step 1 (no code): text a code to the number being removed. Step 2 (with
 * code): confirm and drop it. The strict step-up emailed code is demanded by
 * the route middleware for both steps, so removal is confirmed on both
 * channels. For admins this also drops the texted half of the sign-in
 * challenge until a new number is added.
 */
export const removePhoneNumber = async (req, res, next) => {
  try {
    const rawUserId = req.user?._id || req.user?.id;
    const userId = String(rawUserId);

    if (!isValidObjectId(userId)) {
      return res.status(400).json({ success: false, error: "INVALID_USER_ID", message: "Invalid user ID format" });
    }

    // A body-less DELETE is legal (step 1) — no body means no code.
    const { code } = req.body ?? {};

    const user = await User.findById(userId).select("name email role phoneNumber phoneVerified");
    if (!user) {
      return res.status(404).json({ success: false, error: "USER_NOT_FOUND", message: "User not found" });
    }

    if (!user.phoneNumber) {
      return res.status(400).json({
        success: false,
        error: "NO_PHONE_SET",
        message: "No phone number is linked to this account",
      });
    }

    // Step 1 (no code): text a code to the number being removed. Removing the
    // number drops the SMS channel, so possession is proven one last time
    // before it goes — together with the emailed step-up code the route
    // middleware demands, the removal is confirmed on both channels. This
    // also proves the text half for admins (the number being removed IS
    // their current number, so no separate update_sms is issued).
    if (!code) {
      const otp = await issueOtp({ user, purpose: "phone_remove", req, channel: "sms" });
      if (otp.error) {
        const status = otp.error === OtpError.COOLDOWN ? 429 : 503;
        return res.status(status).json({
          success: false,
          error: otp.error,
          message:
            otp.error === OtpError.COOLDOWN
              ? "A code was recently sent. Please wait before requesting another."
              : "Text delivery is temporarily unavailable. Try again shortly.",
          ...(otp.error === OtpError.COOLDOWN && otp.retryAfterSeconds
            ? { retryAfterSeconds: otp.retryAfterSeconds }
            : {}),
        });
      }
      return res.status(200).json({
        success: true,
        requireOtp: true,
        message: `We texted a code to ${maskPhoneNumber(user.phoneNumber)}. Enter it to remove the number.`,
        maskedPhone: maskPhoneNumber(user.phoneNumber),
        expiresInSeconds: otp.expiresInSeconds,
        resendCooldownSeconds: otp.resendCooldownSeconds,
        ...(otp.deliveryWarning ? { deliveryWarning: otp.deliveryWarning } : {}),
        ...(otp.devCode ? { devCode: otp.devCode } : {}),
      });
    }

    // Step 2: the texted code confirms the removal.
    const verified = await verifyOtp({ user, purpose: "phone_remove", code });
    if (!verified.valid) {
      logAuditEvent({
        event: AUDIT_EVENTS.OTP_FAILED,
        userId: user._id,
        req,
        metadata: { purpose: "phone_remove", reason: verified.error },
      });
      return updateCodeFailureResponse(res, verified);
    }

    const last4 = user.phoneNumber.slice(-4);
    // $unset (not null): a stored null would collide in the sparse unique
    // index once a second user also clears their number.
    await User.findByIdAndUpdate(userId, {
      $unset: { phoneNumber: "" },
      $set: { phoneVerified: false },
    });

    logAuditEvent({
      event: AUDIT_EVENTS.OTP_VERIFIED,
      userId: user._id,
      req,
      metadata: { purpose: "phone_remove" },
    });

    logAuditEvent({
      event: AUDIT_EVENTS.PROFILE_UPDATED,
      userId: user._id,
      req,
      metadata: {
        reason: `Phone number removed (was ending ${last4})`,
        changes: `phone: …${last4} → none`,
      },
    });

    return res.status(200).json({
      success: true,
      message:
        user.role === "admin"
          ? "Phone number removed. Sign-in now needs only the emailed code — add a number to restore the texted check."
          : "Phone number removed.",
    });
  } catch (error) {
    next(error);
  }
};

/**
 * POST /api/users/me/email — Change the account email (staged, one code per
 * screen). Step 1 (no code): mail a verification code to the NEW address —
 * nothing is texted yet. Step 2 (with code): confirm the code from THAT
 * inbox; for admins with a verified phone this issues the text to the
 * CURRENT number (stage "sms") instead of applying — regular users apply
 * right here. Final step (with smsCode, admins): the texted code applies the
 * change. The pending address is parked in Redis (same TTL as the code)
 * until then, and uniqueness is re-checked at apply time so a parallel
 * registration can't collide.
 */
export const setEmailAddress = async (req, res, next) => {
  try {
    const rawUserId = req.user?._id || req.user?.id;
    const userId = String(rawUserId);

    if (!isValidObjectId(userId)) {
      return res.status(400).json({ success: false, error: "INVALID_USER_ID", message: "Invalid user ID format" });
    }

    const { newEmail, code, smsCode } = req.body ?? {};

    const emailParsed = z.string().trim().toLowerCase().pipe(z.email()).safeParse(newEmail);
    if (!emailParsed.success) {
      return res.status(400).json({
        success: false,
        error: "INVALID_INPUT",
        message: "Enter a valid email address",
      });
    }

    const user = await User.findById(userId).select("name email role phoneNumber phoneVerified");
    if (!user) {
      return res.status(404).json({ success: false, error: "USER_NOT_FOUND", message: "User not found" });
    }

    // The pending address lives next to its code; the verify step reads it
    // back so the code is always applied to exactly the address it was
    // mailed to.
    const pendingEmailKey = `emailchange:${userId}`;
    // Phase marker for admins: set once the NEW-inbox code is confirmed, so
    // a resend re-texts the current number instead of restarting at the
    // emailed phase.
    const smsStageKey = `emailstage:${userId}`;
    const adminSmsDue = user.role === "admin" && Boolean(user.phoneNumber && user.phoneVerified);
    const smsStage = redisClient?.isOpen ? await redisClient.get(smsStageKey) : null;

    // Shared failure response for a failed SMS issue.
    const smsErrorResponse = (result) =>
      res.status(result.error === OtpError.COOLDOWN ? 429 : 503).json({
        success: false,
        error: result.error,
        message:
          result.error === OtpError.COOLDOWN
            ? "A code was recently sent. Please wait before requesting another."
            : "Text delivery is temporarily unavailable. Try again shortly.",
        ...(result.error === OtpError.COOLDOWN && result.retryAfterSeconds
          ? { retryAfterSeconds: result.retryAfterSeconds }
          : {}),
      });

    // Apply the pending address. Reached either directly (regular user, the
    // emailed code was just confirmed) or after the admin's texted code.
    const applyEmailChange = async () => {
      const pending = redisClient?.isOpen ? await redisClient.get(pendingEmailKey) : null;
      if (!pending) {
        return res.status(400).json({
          success: false,
          error: "EXPIRED",
          message: "No pending email change — request a new code.",
        });
      }

      // Re-check uniqueness at apply time: another account may have claimed
      // the address between the code being sent and confirmed.
      const taken = await User.exists({ email: pending, _id: { $ne: user._id } });
      if (taken) {
        await redisClient.del(pendingEmailKey);
        return res.status(409).json({
          success: false,
          error: "EMAIL_ALREADY_IN_USE",
          message: "An account with this email already exists",
        });
      }

      const previousEmail = user.email;
      user.email = pending;
      await user.save();
      await redisClient.del(pendingEmailKey);
      if (redisClient?.isOpen) await redisClient.del(smsStageKey);

      logAuditEvent({
        event: AUDIT_EVENTS.PROFILE_UPDATED,
        userId: user._id,
        req,
        metadata: {
          reason: `Email changed (${previousEmail} → ${pending})`,
          changes: `email: ${previousEmail} → ${pending}`,
        },
      });

      return res.status(200).json({
        success: true,
        message: "Email address updated.",
        user: { email: pending },
      });
    };

    // Final stage (admins): the texted code applies the change.
    if (smsCode) {
      const verified = await verifyOtp({ user, purpose: "update_sms", code: smsCode });
      if (!verified.valid) {
        logAuditEvent({
          event: AUDIT_EVENTS.OTP_FAILED,
          userId: user._id,
          req,
          metadata: { purpose: "update_sms", reason: verified.error },
        });
        return updateCodeFailureResponse(res, verified);
      }
      logAuditEvent({
        event: AUDIT_EVENTS.OTP_VERIFIED,
        userId: user._id,
        req,
        metadata: { purpose: "update_sms" },
      });
      return await applyEmailChange();
    }

    // Step 1 (re)send. A bare call after the emailed half was confirmed
    // re-texts the admin's current number; otherwise the code goes to the
    // NEW inbox.
    if (!code) {
      if (smsStage && adminSmsDue) {
        const adminSms = await issueAdminUpdateSms(user, req);
        if (adminSms?.error) return smsErrorResponse(adminSms);
        return res.status(200).json({
          success: true,
          requireOtp: true,
          stage: "sms",
          message: `We texted a new code to ${maskPhoneNumber(user.phoneNumber)} — your current number.`,
          adminSms: adminSmsChallenge(user, adminSms),
        });
      }

      if (emailParsed.data === user.email) {
        return res.status(400).json({
          success: false,
          error: "EMAIL_UNCHANGED",
          message: "That is already your account email",
        });
      }

      const taken = await User.exists({ email: emailParsed.data });
      if (taken) {
        return res.status(409).json({
          success: false,
          error: "EMAIL_ALREADY_IN_USE",
          message: "An account with this email already exists",
        });
      }

      if (!redisClient?.isOpen) {
        return res.status(503).json({
          success: false,
          error: "OTP_PROTECTION_UNAVAILABLE",
          message: "Verification is temporarily unavailable. Try again shortly.",
        });
      }

      // A fresh start clears any stale SMS-phase marker from an earlier
      // attempt at a different address.
      await redisClient.del(smsStageKey);

      const otp = await issueOtp({
        user,
        purpose: "email_verify",
        req,
        email: emailParsed.data,
        actionLabel: "confirm your new email address",
      });
      if (otp.error) {
        return res.status(otp.error === OtpError.COOLDOWN ? 429 : 503).json({
          success: false,
          error: otp.error,
          message:
            otp.error === OtpError.COOLDOWN
              ? "A code was recently sent. Please wait before requesting another."
              : "Verification is temporarily unavailable. Try again shortly.",
          ...(otp.retryAfterSeconds ? { retryAfterSeconds: otp.retryAfterSeconds } : {}),
        });
      }

      await redisClient.setEx(pendingEmailKey, otp.expiresInSeconds, emailParsed.data);

      return res.status(200).json({
        success: true,
        requireOtp: true,
        stage: "email",
        message: `We sent a code to ${emailParsed.data}. Enter it to confirm the change.`,
        expiresInSeconds: otp.expiresInSeconds,
        resendCooldownSeconds: otp.resendCooldownSeconds,
        ...(otp.deliveryWarning ? { deliveryWarning: otp.deliveryWarning } : {}),
        ...(otp.devCode ? { devCode: otp.devCode } : {}),
      });
    }

    // Step 2: the code from the NEW inbox confirms the address. For admins
    // this is where the text to the CURRENT number goes out (stage "sms");
    // regular users apply immediately.
    const verified = await verifyOtp({ user, purpose: "email_verify", code });
    if (!verified.valid) {
      logAuditEvent({
        event: AUDIT_EVENTS.OTP_FAILED,
        userId: user._id,
        req,
        metadata: { purpose: "email_verify", reason: verified.error },
      });
      return updateCodeFailureResponse(res, verified);
    }

    logAuditEvent({
      event: AUDIT_EVENTS.OTP_VERIFIED,
      userId: user._id,
      req,
      metadata: { purpose: "email_verify" },
    });

    if (adminSmsDue) {
      if (redisClient?.isOpen) {
        await redisClient.setEx(smsStageKey, Math.ceil(OTP_TTL_SECONDS), "1");
      }
      const adminSms = await issueAdminUpdateSms(user, req);
      if (adminSms?.error) return smsErrorResponse(adminSms);
      return res.status(200).json({
        success: true,
        requireOtp: true,
        stage: "sms",
        message: `Email confirmed. We texted a code to ${maskPhoneNumber(user.phoneNumber)} — your current number. Enter it to finish the change.`,
        adminSms: adminSmsChallenge(user, adminSms),
      });
    }

    return await applyEmailChange();
  } catch (error) {
    next(error);
  }
};

/**
 * DELETE /api/users/me — Delete self account
 * Revokes every active session (MongoDB + Redis cache) before removing the
 * user so no orphaned tokens survive account deletion.
 */
export const deleteUserProfile = async (req, res, next) => {
  try {
    const rawUserId = req.user?._id || req.user?.id;
    const userId = String(rawUserId);

    if (!isValidObjectId(userId)) {
      return res.status(400).json({ success: false, error: "INVALID_USER_ID", message: "Invalid user ID format" });
    }

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
      const sessions = await Session.find({ userId, revokedAt: null }).select("sessionId").lean();
      const sessionIds = sessions.map((session) => session.sessionId);

      if (sessionIds.length > 0) {
        await Session.updateMany(
          { userId, revokedAt: null },
          { $set: { revokedAt: new Date() } }
        );

        // Tombstones, not DELs — see markSessionRevokedInRedis.
        await markSessionRevokedInRedis(sessionIds);
      }

      const user = await User.findByIdAndDelete(userId);

      if (!user) {
        return res.status(404).json({ success: false, error: "USER_NOT_FOUND", message: "User not found" });
      }

      logAuditEvent({
        event: AUDIT_EVENTS.SESSION_REVOKED,
        userId,
        req,
        metadata: { reason: "account_deleted", revokedCount: sessionIds.length },
      });

      clearAuthCookies(res);

      return res.status(200).json({ success: true, message: "User profile deleted successfully" });
    } finally {
      await releaseRedisLock(lockKey, lockToken);
    }
  } catch (error) {
    next(error);
  }
};

/**
 * GET /api/users — Fetch users (Admin/Utility, paginated)
 * USERS_LIST_DEFAULT_LIMIT / USERS_LIST_MAX_LIMIT tune the page size
 * (defaults: 20 per page, hard cap 100).
 */
export const getAllUsers = async (req, res, next) => {
  try {
    const page = Math.max(1, Number.parseInt(req.query?.page, 10) || 1);
    const limit = Math.min(
      numberFromEnv("USERS_LIST_MAX_LIMIT", 100),
      Math.max(1, Number.parseInt(req.query?.limit, 10) || numberFromEnv("USERS_LIST_DEFAULT_LIMIT", 20)),
    );

    // Sort controls for the admin UI: which column and which direction.
    // Whitelisted map — the raw query value never reaches Mongo directly.
    // "active" and "risk" sort on values COMPUTED in the aggregation below
    // (active-session count / the riskiest active session), so the $sort
    // stage must come after the $addFields that create them.
    const SORT_FIELDS = {
      name: "name",
      email: "email",
      registered: "createdAt",
      lastLogin: "lastLoginAt",
      active: "activeSessions",
      risk: "riskScore",
    };
    const sortField = SORT_FIELDS[req.query?.sort] ? req.query.sort : "registered";
    const sortOrder = req.query?.order === "asc" ? 1 : -1;

    // Optional name/email search — substring, case-insensitive, with the
    // regex metacharacters escaped so "a.b" doesn't match "axb".
    const search = typeof req.query?.search === "string" ? req.query.search.trim() : "";
    const searchRe = search
      ? new RegExp(search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i")
      : null;
    const match = searchRe ? { $or: [{ name: searchRe }, { email: searchRe }] } : {};

    const [rows, total] = await Promise.all([
      User.aggregate([
        ...(searchRe ? [{ $match: match }] : []),
        // Per-user stats built from their ACTIVE sessions: how many are
        // alive, and the risk score of the riskiest one — the number the
        // admin panel's Risk column shows for the account.
        {
          $lookup: {
            from: "sessions",
            let: { uid: "$_id" },
            pipeline: [
              {
                $match: {
                  $expr: {
                    $and: [
                      { $eq: ["$userId", "$$uid"] },
                      { $eq: ["$revokedAt", null] },
                      { $gt: ["$expiresAt", new Date()] },
                    ],
                  },
                },
              },
              { $project: { riskScore: 1, riskLevel: 1 } },
            ],
            as: "activeSessionDocs",
          },
        },
        {
          $addFields: {
            activeSessions: { $size: "$activeSessionDocs" },
            // The highest-risk active session. Sessions created before risk
            // was stored carry no score — they're filtered out, so a user
            // whose only sessions are old ones shows null (rendered as an
            // em dash) instead of a guessed 0.
            topRiskSession: {
              $arrayElemAt: [
                {
                  $sortArray: {
                    input: {
                      $filter: {
                        input: "$activeSessionDocs",
                        as: "s",
                        cond: { $ne: ["$$s.riskScore", null] },
                      },
                    },
                    sortBy: { riskScore: -1 },
                  },
                },
                0,
              ],
            },
          },
        },
        {
          $addFields: {
            riskScore: { $ifNull: ["$topRiskSession.riskScore", null] },
            riskLevel: { $ifNull: ["$topRiskSession.riskLevel", null] },
          },
        },
        {
          $project: {
            activeSessionDocs: 0,
            topRiskSession: 0,
            passwordHash: 0,
            __v: 0,
          },
        },
        // _id as a tiebreaker so pages stay stable when many rows share a
        // value (e.g. every user with no login has lastLoginAt: null).
        { $sort: { [SORT_FIELDS[sortField]]: sortOrder, _id: 1 } },
        { $skip: (page - 1) * limit },
        { $limit: limit },
      ]),
      User.countDocuments(match),
    ]);

    return res.status(200).json({
      success: true,
      page,
      limit,
      sort: sortField,
      order: req.query?.order === "asc" ? "asc" : "desc",
      total,
      totalPages: Math.ceil(total / limit),
      users: rows.map((u) => withMaskedPhone({ ...u, id: String(u._id) })),
    });
  } catch (error) {
    next(error);
  }
};