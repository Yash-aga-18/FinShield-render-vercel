// src/controllers/auth.controller.js

import mongoose from "mongoose";
import crypto from "crypto";
import bcrypt from "bcrypt";
import { z } from "zod";

import passport from "../config/passport.js";
import User from "../models/user.model.js";
import Session from "../models/session.model.js";

import { generateAccessToken, generateRefreshToken, verifyRefreshToken } from "../utils/jwt.js";
import { setAuthCookies, clearAuthCookies, getBaseCookieOptions, getCookieNames } from "../utils/cookies.js";
import { logAuditEvent, AUDIT_EVENTS } from "../utils/auditLog.js";
import { getDeviceLabel } from "../utils/device.js";
import { getClientIp } from "../utils/ip.js";
import { hashToken, detectLoginAnomalies, userSessionLockKey, sessionRefreshLockKey, redisSessionKey, toDisplayId, maskPhoneNumber, markSessionRevokedInRedis, sessionIdleCutoff } from "../utils/security.js";
import { calculateRisk, RISK_ACTION } from "../utils/risk.js";
import { acquireRedisLock, releaseRedisLock } from "../utils/redisLock.js";

import { getFailedLoginAttempts, recordFailedLogin, clearLoginAttempts, getAccountMaxFailures } from "../middleware/rateLimiter.middleware.js";
import { redisClient } from "../config/redis.js";
import { buildResetUrl, sendPasswordResetEmail, shouldExposeResetLink, sendSigninDetectedEmail } from "../utils/mailer.js";
import { issueOtp, verifyOtp, verifyTrustedDeviceToken, trustedDeviceCookieName, OtpError } from "../utils/otp.js";
import { RISK_LEVEL } from "../utils/risk.js";
import { durationFromEnv, numberFromEnv } from "../utils/env.js";
import { NAME_MIN_LENGTH, NAME_MAX_LENGTH } from "../utils/namePolicy.js";
import { PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH } from "../utils/passwordPolicy.js";
import { ADMIN_LOGIN_REQUIRES_SMS, OTP_CODE_LENGTH } from "../utils/otp.js";

// How long a session's Redis cache entry lives before falling back to
// MongoDB. Follows the refresh-token lifetime by default ("7d").
const REFRESH_SESSION_TTL_SECONDS = durationFromEnv(
  "SESSION_CACHE_TTL",
  7 * 24 * 60 * 60,
  { legacyName: "REFRESH_SESSION_TTL_SECONDS" },
);

// BCRYPT_ROUNDS: password hashing cost (default 12). Each +1 roughly
// doubles the time to hash — 10 is fast-ish, 14 starts to hurt latency.
const BCRYPT_ROUNDS = numberFromEnv("BCRYPT_ROUNDS", 12, { minimum: 4, maximum: 15 });

// Single-window policy: how many browser windows/tabs may hold the app at
// once (the frontend enforces it client-side, newest windows win). 0 turns
// the guard off entirely. Served on the public input-rules endpoint so the
// frontend always reads the same number the .env sets.
const MAX_APP_WINDOWS = numberFromEnv("MAX_APP_WINDOWS", 1, { minimum: 0, maximum: 10 });

// __Host- prefixed in production (browsers enforce Secure + Path=/ + no Domain)
const oauthStateCookieName = () =>
  process.env.NODE_ENV === "production" ? "__Host-oauth_state_google" : "oauth_state_google";

// bcrypt truncates input at 72 bytes; capping earlier rejects oversized
// payloads before the expensive hash work (DoS protection). The cap lives in
// passwordPolicy.js so register/reset/change all agree.
const MAX_PASSWORD_LENGTH = PASSWORD_MAX_LENGTH;

// Names may contain letters (any script), spaces, hyphens and apostrophes —
// the characters real names use. Digits, periods and symbols like @#$ are
// rejected up front rather than stored.
const NAME_PATTERN = /^[\p{L}][\p{L}\s'-]*$/u;

const registerSchema = z.object({
  name: z.string().trim().min(NAME_MIN_LENGTH).max(NAME_MAX_LENGTH).regex(NAME_PATTERN),
  email: z.string().trim().toLowerCase().pipe(z.email()),
  password: z.string().min(PASSWORD_MIN_LENGTH).max(MAX_PASSWORD_LENGTH),
});

const REGISTER_FIELD_ERRORS = {
  name: `Enter a valid name (${NAME_MIN_LENGTH}–${NAME_MAX_LENGTH} characters, letters, spaces, hyphens and apostrophes only)`,
  email: "Enter a valid email address",
  password: `Enter a password of at least ${PASSWORD_MIN_LENGTH} characters`,
};

const loginSchema = z.object({
  email: z.string().trim().toLowerCase().pipe(z.email()),
  password: z.string().min(1).max(MAX_PASSWORD_LENGTH),
});

const getIpAddress = (req) => getClientIp(req) || "127.0.0.1";

// Lazily-computed bcrypt hash used to equalize response timing when the
// login email does not exist, preventing user-enumeration via timing side
// channels (real compares always run at full bcrypt cost).
// Computed asynchronously at first use so the event loop is never blocked.
let timingEqualizerHashPromise = null;
const getTimingEqualizerHash = () => {
  if (!timingEqualizerHashPromise) {
    timingEqualizerHashPromise = bcrypt.hash("finshield-timing-equalizer", BCRYPT_ROUNDS);
  }
  return timingEqualizerHashPromise;
};

const fetchActiveSessions = async (userId) => {
  // Idle-stale sessions don't count as active: they fail the idle timeout on
  // their next refresh, so they must not occupy a MAX_ACTIVE_SESSIONS slot.
  const idleCutoff = sessionIdleCutoff();
  return Session.find({
    userId,
    revokedAt: null,
    expiresAt: { $gt: new Date() },
    ...(idleCutoff ? { lastUsedAt: { $gt: idleCutoff } } : {}),
  })
    .select("sessionId device ipAddress userAgent createdAt lastUsedAt expiresAt")
    .sort({ lastUsedAt: -1 })
    .lean();
};

/* ============================================================
   SHARED SESSION PROVISIONING (password login + Google OAuth)
   Enforces the session limit, scores risk, creates the session in
   MongoDB + Redis, writes the audit trail, and sets auth cookies.
   Returns { handled: true } when an error response was already sent,
   otherwise the created session data for the caller to respond with.
   ============================================================ */
export const provisionUserSession = async ({
  user,
  req,
  res,
  provider = null,
  failedAttempts = 0,
  onStepUp = null,
  isTrustedDevice = false,
}) => {
  // Fail closed: without Redis there is no distributed locking or session
  // cache, so concurrent session provisioning cannot be safely authorized.
  if (!redisClient?.isOpen) {
    res.status(503).json({
      success: false,
      error: "AUTH_PROTECTION_UNAVAILABLE",
      message: "Authentication protection service is temporarily unavailable.",
    });
    return { handled: true };
  }

  const lockKey = userSessionLockKey(user._id.toString());
  const lockToken = await acquireRedisLock(lockKey);

  if (!lockToken) {
    res.status(409).json({
      success: false,
      error: "SESSION_OPERATION_BUSY",
      message: "Another session change is currently being processed. Please try again.",
    });
    return { handled: true };
  }

  try {
    // MAX_ACTIVE_SESSIONS: concurrent signed-in devices per user (default 3).
    const maxActiveSessions = numberFromEnv("MAX_ACTIVE_SESSIONS", 3);
    const activeSessions = await fetchActiveSessions(user._id);

    if (activeSessions.length >= maxActiveSessions) {
      logAuditEvent({
        event: AUDIT_EVENTS.SESSION_LIMIT_EXCEEDED,
        userId: user._id,
        req,
        metadata: {
          reason: "maximum_active_sessions",
          ...(provider ? { provider } : {}),
          attemptCount: activeSessions.length,
        },
      });

      res.status(409).json({
        success: false,
        error: "SESSION_LIMIT_REACHED",
        message: "Maximum active session limit reached.",
        maxActiveSessions,
        activeSessions,
      });
      return { handled: true };
    }

    const userAgent = req.get("user-agent") || "";
    const ipAddress = getIpAddress(req);
    const device = getDeviceLabel(userAgent);

    const anomalies = await detectLoginAnomalies({ userId: user._id, ipAddress, device, Session });
    const risk = calculateRisk({
      newDevice: anomalies.newDevice,
      newIp: anomalies.newIp,
      failedAttempts,
    });

    // Dev visibility: one line per sign-in showing how the risk engine saw
    // it, so "why did/didn't I get an OTP or a new-sign-in email?" is
    // answerable straight from the server console instead of by guesswork.
    if (process.env.NODE_ENV !== "production") {
      console.log(
        `[risk] ${user.email} — device: ${anomalies.newDevice ? "NEW" : "known"}, ` +
          `ip: ${anomalies.newIp ? "NEW" : "known"}, score ${risk.score} (${risk.level})`,
      );
    }

    if (risk.action === RISK_ACTION.BLOCK_LOGIN || risk.action === RISK_ACTION.REVOKE_AND_BLOCK) {
      logAuditEvent({
        event: AUDIT_EVENTS.LOGIN_FAILED,
        userId: user._id,
        req,
        metadata: {
          reason: provider ? "oauth_risk_engine_block" : "risk_engine_block",
          ...(provider ? { provider } : {}),
          riskScore: risk.score,
          riskLevel: risk.level,
        },
      });

      res.status(403).json({
        success: false,
        error: "LOGIN_BLOCKED",
        message: provider
          ? "Google login was blocked because the security risk was too high."
          : "Login was blocked because the security risk was too high.",
        risk: { score: risk.score, level: risk.level, signals: risk.signals },
      });
      return { handled: true };
    }

    // Step-up band: MEDIUM risk needs a second factor before the session is
    // issued — unless this browser is a trusted device. Only the password
    // login path registers a callback; OAuth and OTP-verified logins pass
    // none and skip this branch (the OTP already proved control of the email).
    // Admins are special: their login ALWAYS pays the OTP toll, whatever the
    // risk score says and even on a trusted device — the account can delete
    // any user in the system.
    const adminMfaRequired = user.role === "admin";
    if (
      onStepUp &&
      (adminMfaRequired ||
        (!isTrustedDevice &&
          risk.action === RISK_ACTION.ALLOW_AND_AUDIT &&
          risk.level === RISK_LEVEL.MEDIUM))
    ) {
      logAuditEvent({
        event: AUDIT_EVENTS.LOGIN_FAILED,
        userId: user._id,
        req,
        metadata: {
          reason: adminMfaRequired ? "admin_mfa_required" : "step_up_required",
          ...(provider ? { provider } : {}),
          riskScore: risk.score,
          riskLevel: risk.level,
        },
      });
      await onStepUp({ risk, reason: adminMfaRequired ? "admin_mfa" : "risk_step_up" });
      return { handled: true };
    }

    await clearLoginAttempts(req);

    if (anomalies.newDevice) {
      logAuditEvent({
        event: AUDIT_EVENTS.NEW_DEVICE_DETECTED,
        userId: user._id,
        req,
        metadata: { device, ...(provider ? { provider } : {}) },
      });
    }

    if (anomalies.newIp) {
      logAuditEvent({
        event: AUDIT_EVENTS.SUSPICIOUS_IP_DETECTED,
        userId: user._id,
        req,
        metadata: { reason: "new_ip", ...(provider ? { provider } : {}) },
      });
    }

    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + REFRESH_SESSION_TTL_SECONDS * 1000);
    const accessToken = generateAccessToken(user, sessionId);
    const refreshToken = generateRefreshToken(user, sessionId);
    const refreshTokenHash = hashToken(refreshToken);

    const session = await Session.create({
      userId: user._id,
      sessionId,
      displayId: toDisplayId(sessionId),
      refreshTokenHash,
      ipAddress,
      userAgent,
      device,
      lastUsedAt: new Date(),
      expiresAt,
      // The score that admitted this sign-in — shown in the admin session
      // list so a risky device is visible long after the login event.
      riskScore: risk.score,
      riskLevel: risk.level,
    });

    // Last-login stamp + account-level risk for the admin panel's user
    // views. The risk lives on the USER as well as the session so accounts
    // with no active sessions still show the score of their most recent
    // sign-in instead of a blank. Best-effort: a failure here must not
    // fail the login itself.
    await User.updateOne(
      { _id: user._id },
      { $set: { lastLoginAt: new Date(), riskScore: risk.score, riskLevel: risk.level } },
    ).catch(() => {});

    if (redisClient?.isOpen) {
      await redisClient.setEx(
        redisSessionKey(sessionId),
        REFRESH_SESSION_TTL_SECONDS,
        JSON.stringify({ userId: user._id.toString(), sessionId, refreshTokenHash })
      );
    }

    logAuditEvent({
      event: AUDIT_EVENTS.LOGIN_SUCCESS,
      userId: user._id,
      sessionId,
      req,
      metadata: {
        ...(provider ? { provider } : {}),
        riskScore: risk.score,
        riskLevel: risk.level,
      },
    });

    logAuditEvent({
      event: AUDIT_EVENTS.SESSION_CREATED,
      userId: user._id,
      sessionId,
      req,
      metadata: provider ? { provider } : {},
    });

    // Every successful sign-in emails the owner — like Google's "sign-in
    // detected" mails — so a login is never silent. The mail carries the
    // device/IP details and a single-use panic link (sign out everywhere +
    // password reset) for the "this wasn't me" case. Fire-and-forget: a
    // mail outage must never fail the sign-in itself.
    void (async () => {
      try {
        const panicToken = await issuePanicToken(user._id.toString());
        const panicUrl = panicToken
          ? `${process.env.FRONTEND_URL || "http://localhost:5174"}/api/auth/panic/${panicToken}`
          : null;
        await sendSigninDetectedEmail(user.email, {
          device,
          ipAddress,
          when: new Date().toUTCString(),
          provider,
          panicUrl,
        });
      } catch (error) {
        console.warn(`[auth] Failed to send sign-in-detected email: ${error.message}`);
      }
    })();

    setAuthCookies(res, accessToken, refreshToken);

    // Raw session IDs and exact IPs never leave the server; the client only
    // ever sees the derived displayId and a masked network prefix.
    return { handled: false, sessionId, session, risk, accessToken, displayId: toDisplayId(sessionId) };
  } finally {
    await releaseRedisLock(lockKey, lockToken);
  }
};

/* ============================================================
   PANIC LINK ("sign out everywhere + reset password")
   The "we detected a sign-in" email carries a single-use link the
   account owner can press when the sign-in was NOT them. One click:
   every session on the account is revoked and a password-reset email
   follows, so a stolen credential is worthless within seconds. Same
   token pattern as password reset: the URL carries the raw token, the
   server stores only its sha256 hash in Redis, and the link dies after
   one use or 30 minutes — whichever comes first.
   ============================================================ */
const PANIC_TOKEN_TTL_SECONDS = 30 * 60;

const panicTokenKey = (userId) => `panic:token:${userId}`;

const issuePanicToken = async (userId) => {
  if (!redisClient?.isOpen) return null;
  const rawToken = crypto.randomBytes(32).toString("hex");
  await redisClient.setEx(
    panicTokenKey(userId),
    PANIC_TOKEN_TTL_SECONDS,
    hashToken(rawToken),
  );
  return rawToken;
};

const consumePanicToken = async (userId, rawToken) => {
  if (!redisClient?.isOpen || typeof rawToken !== "string" || rawToken.length < 32) {
    return false;
  }
  // Compare first, delete only on match — a wrong guess must not destroy
  // the stored token (GETDEL here would burn the real link on any
  // attacker's random probe). The delete-on-match is still atomic enough:
  // the value read is the one compared, and only the holder of the raw
  // token can produce a matching hash.
  const stored = await redisClient.get(panicTokenKey(userId));
  if (stored !== hashToken(rawToken)) {
    return false;
  }
  await redisClient.del(panicTokenKey(userId));
  return true;
};

/* ============================================================
   REGISTER
   ============================================================ */
export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: "Name, email, and password are required" });
    }

    const parsed = registerSchema.safeParse({ name, email, password });
    if (!parsed.success) {
      const field = parsed.error.issues[0]?.path?.[0];
      return res.status(400).json({
        success: false,
        error: "INVALID_INPUT",
        message: REGISTER_FIELD_ERRORS[field] || "Invalid registration details",
      });
    }

    const { name: cleanName, email: normalizedEmail, password: cleanPassword } = parsed.data;

    // +passwordHash because the schema hides it by default (select: false)
    // and the duplicate-detection compare below needs it.
    const existingUser = await User.findOne({ email: normalizedEmail }).select("+passwordHash");

    if (existingUser) {
      if (existingUser.isVerified) {
        return res.status(409).json({ success: false, message: "An account with this email already exists" });
      }

      // An earlier attempt got as far as creating the account but never
      // finished verification. Two very different situations hide here:
      //
      //   1. The user is CORRECTING their details (new name and/or password)
      //      and retrying — re-registering over that husk is the user fixing
      //      themselves, not a collision. Update the record and send a fresh
      //      code (201).
      //
      //   2. The EXACT same details were submitted again — an accidental
      //      double-submit, or a resend attempt through the wrong door.
      //      Nothing changed, so this is a duplicate: answer 409 and point
      //      at the OTP resend flow instead of minting another code.
      const passwordUnchanged = existingUser.passwordHash
        ? await bcrypt.compare(cleanPassword, existingUser.passwordHash)
        : false;

      if (existingUser.name === cleanName && passwordUnchanged) {
        return res.status(409).json({
          success: false,
          error: "REGISTRATION_PENDING",
          message:
            "This email already has a registration awaiting verification. Check your inbox, or request a new code from the sign-in page.",
        });
      }

      existingUser.name = cleanName;
      existingUser.passwordHash = await bcrypt.hash(cleanPassword, BCRYPT_ROUNDS);
      await existingUser.save();
      const otp = await issueOtp({ user: existingUser, purpose: "registration", req });
      return res.status(201).json({
        success: true,
        requiresVerification: true,
        ...(otp.error
          ? {
              otpError: otp.error,
              message: "Account created. Request a verification code to continue.",
            }
          : {
              message: "Account created. We sent a verification code to your email.",
              expiresInSeconds: otp.expiresInSeconds,
              resendCooldownSeconds: otp.resendCooldownSeconds,
              // Mirrors the login/step-up challenge responses: when mail
              // delivery is console-only (dev) or the provider rejected the
              // send, say so — and hand over the dev code so the flow stays
              // completable without a mailbox.
              ...(otp.deliveryWarning ? { deliveryWarning: otp.deliveryWarning } : {}),
              ...(otp.devCode ? { devCode: otp.devCode } : {}),
            }),
        user: { id: existingUser._id, name: existingUser.name, email: existingUser.email, createdAt: existingUser.createdAt },
      });
    }

    const passwordHash = await bcrypt.hash(cleanPassword, BCRYPT_ROUNDS);
    // Starts UNVERIFIED — the registration OTP email confirms ownership.
    let user;
    try {
      user = await User.create({
        name: cleanName,
        email: normalizedEmail,
        passwordHash,
        isVerified: false,
      });

      // Send the first verification code (rate-limited by the OTP cooldown).
      const otp = await issueOtp({ user, purpose: "registration", req });
      if (!otp.error) {
        return res.status(201).json({
          success: true,
          requiresVerification: true,
          message: "Account created. We sent a verification code to your email.",
          user: { id: user._id, name: user.name, email: user.email, createdAt: user.createdAt },
          expiresInSeconds: otp.expiresInSeconds,
          resendCooldownSeconds: otp.resendCooldownSeconds,
          // Dev-only console-mail code / provider-rejection warning — same
          // policy as the login and step-up challenges.
          ...(otp.deliveryWarning ? { deliveryWarning: otp.deliveryWarning } : {}),
          ...(otp.devCode ? { devCode: otp.devCode } : {}),
        });
      }
      if (otp.error === "COOLDOWN") {
        // Code throttled — the account is fine; the client can request a
        // resend once the cooldown passes.
        return res.status(201).json({
          success: true,
          requiresVerification: true,
          otpError: otp.error,
          message: "Account created. Request a verification code to continue.",
          user: { id: user._id, name: user.name, email: user.email, createdAt: user.createdAt },
        });
      }
      throw new Error(`OTP issue failed: ${otp.error}`);
    } catch (createOrOtpError) {
      // Lost the race: another registration with this email committed
      // between our findOne and the create. The unique index is the real
      // guarantee — this just turns the collision into an honest 409
      // instead of a misleading "email delivery failed".
      if (createOrOtpError?.code === 11000) {
        return res.status(409).json({
          success: false,
          error: "EMAIL_ALREADY_EXISTS",
          message: "An account with this email already exists",
        });
      }
      // The account exists but the verification email could not be delivered
      // (provider outage, invalid recipient). An unusable husk would trap the
      // email behind "already exists" forever — roll the record back and say
      // so plainly.
      if (user) {
        await User.findByIdAndDelete(user._id).catch(() => {});
      }
      console.error("Error registering user (email delivery failed):", createOrOtpError.message);
      return res.status(502).json({
        success: false,
        error: "VERIFICATION_EMAIL_FAILED",
        message: "Account created, but we couldn't deliver your verification email. Please try again in a moment.",
      });
    }
  } catch (error) {
    console.error("Error registering user:", error);
    return res.status(500).json({ success: false, message: "An error occurred while registering the user" });
  }
};

/* ============================================================
   INPUT RULES (public)
   The register/login/profile forms size their inputs and hints from
   this, so every length limit lives in ONE place (.env) and drives
   both the client-side constraints and the server-side validation.
   ============================================================ */
export const getInputRules = (req, res) => {
  return res.status(200).json({
    success: true,
    nameMinLength: NAME_MIN_LENGTH,
    nameMaxLength: NAME_MAX_LENGTH,
    passwordMinLength: PASSWORD_MIN_LENGTH,
    passwordMaxLength: PASSWORD_MAX_LENGTH,
    otpCodeLength: OTP_CODE_LENGTH,
    maxWindows: MAX_APP_WINDOWS,
  });
};

/* ============================================================
   PASSWORD LOGIN (Concurrency & Rate Limit Hardened)
   ============================================================ */
export const login = async (req, res) => {
  try {
    const { email, password, otpChannel } = req.body;

    // Where the login code should go when a second factor is owed. Anything
    // other than "sms" means email — the default and the only option for
    // accounts without a verified phone.
    const codeChannel = otpChannel === "sms" ? "sms" : "email";

    if (!email || !password) {
      return res.status(400).json({ success: false, message: "Email and password are required" });
    }
    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({ success: false, error: "INVALID_INPUT", message: "Invalid input format" });
    }

    // Zod validation: rejects malformed emails before any database or bcrypt
    // work happens (shape errors are already caught above).
    const parsedLogin = loginSchema.safeParse({ email, password });
    if (!parsedLogin.success) {
      await recordFailedLogin(req);
      logAuditEvent({ event: AUDIT_EVENTS.LOGIN_FAILED, req, metadata: { reason: "invalid_credentials" } });
      const failedField = parsedLogin.error.issues[0]?.path?.[0];
      return res.status(401).json({
        success: false,
        error: "INVALID_INPUT",
        message:
          failedField === "email"
            ? "Enter a valid email address"
            : "Enter your password to sign in",
      });
    }

    if (password.length > MAX_PASSWORD_LENGTH) {
      // Fail fast without running bcrypt on oversized input
      await recordFailedLogin(req);
      logAuditEvent({ event: AUDIT_EVENTS.LOGIN_FAILED, req, metadata: { reason: "invalid_credentials" } });
      return res.status(401).json({ success: false, error: "INVALID_CREDENTIALS", message: "Wrong password entered." });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail }).select("+passwordHash");

    if (!user || !user.passwordHash) {
      await bcrypt.compare(password, await getTimingEqualizerHash());
      await recordFailedLogin(req);
      logAuditEvent({ event: AUDIT_EVENTS.LOGIN_FAILED, req, metadata: { reason: "invalid_credentials" } });
      return res.status(401).json({
        success: false,
        error: "ACCOUNT_NOT_FOUND",
        message: "No account found with this email. Create an account to continue.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      const failures = await recordFailedLogin(req);
      logAuditEvent({ event: AUDIT_EVENTS.LOGIN_FAILED, userId: user._id, req, metadata: { reason: "invalid_credentials" } });
      // Counting down to the account lockout helps honest users correct a
      // typo without burning the whole window. The counter itself still
      // lives server-side in Redis, so it can't be forged from the client.
      const attemptsLeft = Math.max(0, getAccountMaxFailures() - failures.accountFailures);
      return res.status(401).json({
        success: false,
        error: "INVALID_CREDENTIALS",
        message: attemptsLeft > 0
          ? `Wrong password entered. ${attemptsLeft} attempt${attemptsLeft === 1 ? "" : "s"} left before your account is temporarily locked.`
          : "Wrong password entered. Your account is temporarily locked — try again in a few minutes.",
        attemptsLeft,
      });
    }

    // Unverified accounts (registered but never confirmed by OTP) must verify
    // before any session is issued. Google-linked accounts are pre-verified.
    if (!user.isVerified) {
      const otp = await issueOtp({ user, purpose: "registration", req });
      return res.status(403).json({
        success: false,
        error: "EMAIL_NOT_VERIFIED",
        message: "Verify your email to sign in. We've sent you a new code.",
        email: user.email,
        ...(otp.error ? { otpError: otp.error, retryAfterSeconds: otp.retryAfterSeconds } : {}),
        // Console-mail code / provider-rejection warning (dev-only code echo).
        ...(otp.deliveryWarning ? { deliveryWarning: otp.deliveryWarning } : {}),
        ...(otp.devCode ? { devCode: otp.devCode } : {}),
      });
    }

    // Trusted device: a previously confirmed "remember this device" cookie
    // skips the risk-based OTP challenge on this browser.
    const trusted = verifyTrustedDeviceToken(req.cookies?.[trustedDeviceCookieName()]);
    const isTrustedDevice = Boolean(trusted && trusted.userId === user._id.toString());

    const failedAttempts = await getFailedLoginAttempts(req);
    const result = await provisionUserSession({
      user,
      req,
      res,
      failedAttempts,
      // When risk lands in the step-up band, provisionUserSession delegates
      // back here instead of issuing the session.
      onStepUp: async ({ risk, reason }) => {
        // Admin sign-in is SEQUENTIAL: the emailed code comes first, and only
        // once it's confirmed is the text sent (texts cost money — never send
        // one before the mailbox is proven). Without a verified phone the
        // email code alone stands, but say so, so the admin knows to add a
        // number.
        const hasVerifiedPhone = Boolean(user.phoneNumber && user.phoneVerified);
        const adminSmsDue =
          reason === "admin_mfa" && ADMIN_LOGIN_REQUIRES_SMS && hasVerifiedPhone;
        const adminSmsMissing =
          reason === "admin_mfa" && ADMIN_LOGIN_REQUIRES_SMS && !adminSmsDue;

        // Channel choice: a regular user with a verified phone may take the
        // login code by TEXT instead of email (and switch mid-challenge) —
        // the recovery path for a mailbox they can no longer reach. Admins
        // under the dual challenge always start with the emailed code, so
        // for them there is nothing to choose.
        const channelChoice = hasVerifiedPhone && !adminSmsDue;
        const smsChannel = channelChoice && codeChannel === "sms";

        // The single login code goes out on the chosen channel. A texted
        // login code uses the login_sms purpose (NOT "login"), so the two
        // channels keep separate resend cooldowns — switching email -> text
        // is instant instead of tripping the other channel's cooldown.
        const otp = smsChannel
          ? await issueOtp({ user, purpose: "login_sms", req, channel: "sms" })
          : await issueOtp({ user, purpose: "login", req });
        if (otp.error) {
          res.status(otp.error === "COOLDOWN" ? 429 : 503).json({
            success: false,
            error: otp.error,
            message:
              otp.error === "COOLDOWN"
                ? "A code was recently sent. Please wait before requesting another."
                : "Verification is temporarily unavailable. Try again shortly.",
            retryAfterSeconds: otp.retryAfterSeconds,
          });
          return;
        }

        let message;
        if (reason === "admin_mfa") {
          message = adminSmsDue
            ? "Admin sign-in starts with the code we emailed you. Once it's confirmed, we'll text a second code to your phone."
            : "Admin accounts always sign in with a verification code. Enter the code we emailed you to continue.";
        } else if (smsChannel) {
          message = `We texted a code to ${maskPhoneNumber(user.phoneNumber)}. Enter it to continue.`;
        } else {
          message = "We detected unusual activity on this login. Enter the code we emailed you to continue.";
        }
        if (adminSmsMissing) {
          // Not a hard failure (the admin must still be able to get in), but
          // the second factor is silently missing until a phone is added.
          message += " Tip: add a phone number in your profile to also require a texted code at sign-in.";
        }

        res.status(200).json({
          success: false,
          requireOtp: true,
          message,
          email: user.email,
          risk: { score: risk.score, level: risk.level },
          // Which channel the single code went out on — the verify step
          // needs the same value to check the right OTP record.
          otpChannel: smsChannel ? "sms" : "email",
          // Present when the code could ALSO have been texted (verified phone
          // on file, no admin dual challenge): lets the login screen offer
          // "send to +••••1234 instead". Masked — the full number never
          // leaves the API.
          ...(channelChoice
            ? { phoneChoice: { maskedPhone: maskPhoneNumber(user.phoneNumber) } }
            : {}),
          expiresInSeconds: otp.expiresInSeconds,
          resendCooldownSeconds: otp.resendCooldownSeconds,
          // The texted half of the admin challenge comes LATER (staged: true
          // means "expected after the emailed code is confirmed" — no text
          // has gone out yet). missingPhone=true means the admin has no
          // verified number yet (email-only sign-in).
          ...(adminSmsDue
            ? { smsOtp: { required: true, staged: true } }
            : { smsOtp: { required: false, ...(adminSmsMissing ? { missingPhone: true } : {}) } }),
          // Mirrors step-up: surface provider rejections (and the dev-only
          // console-mail code) so the UI can say the email never left.
          ...(otp.deliveryWarning ? { deliveryWarning: otp.deliveryWarning } : {}),
          ...(otp.devCode ? { devCode: otp.devCode } : {}),
        });
      },
      isTrustedDevice,
    });
    if (result.handled) return;

    return res.status(200).json({
      success: true,
      message: "Login successful",
      // role travels with the sign-in so the UI can render the admin nav
      // immediately — no refresh needed to learn who just signed in.
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
      session: { id: result.displayId, device: result.session.device },
    });
  } catch (error) {
    console.error("Error logging in:", error);
    return res.status(500).json({ success: false, message: "An error occurred while logging in" });
  }
};

/* ============================================================
   GOOGLE OAUTH — START (State Hardened)
   ============================================================ */
export const beginGoogleAuthentication = (req, res, next) => {
  const state = crypto.randomBytes(32).toString("hex");
  const baseOptions = getBaseCookieOptions();

  res.cookie(oauthStateCookieName(), state, {
    ...baseOptions,
    // SameSite must be Lax, NOT the base policy's Strict: the OAuth callback
    // is a cross-site redirect (accounts.google.com → our domain), and
    // browsers withhold Strict cookies on cross-site navigations — the
    // callback would always arrive state-less ("OAuth state parameter
    // missing"). Lax still blocks the cookie on cross-site POSTs, and the
    // state nonce itself (random 32 bytes, 10-minute TTL) is what actually
    // defeats CSRF here.
    sameSite: "lax",
    // OAUTH_STATE_TTL: how long the CSRF state cookie is valid
    // ("10m" default — just enough to finish the Google round-trip).
    maxAge: durationFromEnv("OAUTH_STATE_TTL", 10 * 60) * 1000,
  });

  return passport.authenticate("google", {
    scope: ["openid", "profile", "email"],
    session: false,
    state,
  })(req, res, next);
};

/* ============================================================
   GOOGLE OAUTH — CALLBACK (State Validation & Concurrency Hardened)
   ============================================================ */
export const completeGoogleAuthentication = (req, res, next) => {
  const savedState = req.cookies?.[oauthStateCookieName()];
  const incomingState = req.query?.state;
  const baseOptions = getBaseCookieOptions();

  res.clearCookie(oauthStateCookieName(), {
    path: baseOptions.path,
    httpOnly: baseOptions.httpOnly,
    secure: baseOptions.secure,
    sameSite: baseOptions.sameSite,
  });

  if (!savedState || !incomingState) {
    logAuditEvent({ event: AUDIT_EVENTS.LOGIN_FAILED, req, metadata: { reason: "oauth_state_missing", provider: "google" } });
    return res.status(400).json({ success: false, error: "INVALID_OAUTH_STATE", message: "OAuth state parameter missing" });
  }

  const savedBuffer = Buffer.from(savedState, "utf-8");
  const incomingBuffer = Buffer.from(incomingState, "utf-8");

  if (savedBuffer.length !== incomingBuffer.length || !crypto.timingSafeEqual(savedBuffer, incomingBuffer)) {
    logAuditEvent({ event: AUDIT_EVENTS.LOGIN_FAILED, req, metadata: { reason: "oauth_state_mismatch", provider: "google" } });
    return res.status(400).json({ success: false, error: "INVALID_OAUTH_STATE", message: "OAuth state mismatch detected" });
  }

  return passport.authenticate("google", { session: false }, async (error, user) => {
    if (error || !user) {
      console.error("Google OAuth authentication error:", error);
      logAuditEvent({ event: AUDIT_EVENTS.LOGIN_FAILED, req, metadata: { reason: "google_oauth_failed", provider: "google" } });
      return res.status(401).json({ success: false, message: "Google authentication failed" });
    }

    try {
      // Admins cannot sign in through Google: the always-on email-OTP rule
      // for admin accounts can't be applied mid-OAuth-handshake, and an
      // OAuth path around it would gut the rule entirely.
      if (user.role === "admin") {
        logAuditEvent({
          event: AUDIT_EVENTS.LOGIN_FAILED,
          userId: user._id,
          req,
          metadata: { reason: "admin_oauth_blocked", provider: "google" },
        });
        const frontendUrl = process.env.FRONTEND_URL || "http://localhost:5174";
        return res.redirect(`${frontendUrl}/login?error=admin_oauth_blocked`);
      }

      const result = await provisionUserSession({ user, req, res, provider: "google" });
      if (result.handled) return;

      // Browser-facing flow: send the user back to the frontend, which
      // completes the handshake by probing /api/users/me with the cookies
      // set below. (API clients still get the JSON body via the query params.)
      const frontendUrl = process.env.FRONTEND_URL || "http://localhost:5174";
      return res.redirect(`${frontendUrl}/oauth/success`);
    } catch (sessionError) {
      console.error("Error during Google session creation:", sessionError);
      const frontendUrl = process.env.FRONTEND_URL || "http://localhost:5174";
      return res.redirect(`${frontendUrl}/login?error=oauth_failed`);
    }
  })(req, res, next);
};

/* ============================================================
   REFRESH (Concurrency Hardened)
   ============================================================ */
export const refresh = async (req, res, next) => {
  try {
    const cookieNames = getCookieNames();
    const refreshToken =
      req.cookies?.[cookieNames.refresh] ||
      req.cookies?.refresh_token ||
      req.cookies?.refreshToken ||
      req.body?.refreshToken;

    if (!refreshToken || typeof refreshToken !== "string") {
      clearAuthCookies(res);
      return res.status(401).json({
        success: false,
        error: "REFRESH_TOKEN_MISSING",
        message: "Refresh token is missing",
      });
    }

    let decoded;
    try {
      decoded = verifyRefreshToken(refreshToken);
    } catch {
      clearAuthCookies(res);
      return res.status(401).json({
        success: false,
        error: "INVALID_REFRESH_TOKEN",
        message: "Invalid or expired refresh token",
      });
    }

    const userId = String(decoded.sub || decoded.id || "");
    const sessionId = String(decoded.sid || decoded.sessionId || "");

    if (!userId || !sessionId) {
      clearAuthCookies(res);
      return res.status(401).json({
        success: false,
        error: "INVALID_TOKEN_STRUCTURE",
        message: "Invalid token payload structure",
      });
    }

    const lockKey = sessionRefreshLockKey(sessionId);
    const lockToken = await acquireRedisLock(lockKey, { ttlMs: 5000, waitMs: 0 });

    if (!lockToken) {
      clearAuthCookies(res);
      return res.status(409).json({
        success: false,
        error: "REFRESH_IN_PROGRESS",
        message: "Another refresh request is being processed.",
      });
    }

    try {
      const hashedIncomingToken = hashToken(refreshToken);
      const redisKey = redisSessionKey(sessionId);

      // 1. Fetch user to ensure account existence and pass to token generator
      const user = await User.findById(userId);
      if (!user) {
        clearAuthCookies(res);
        return res.status(404).json({
          success: false,
          error: "USER_NOT_FOUND",
          message: "User account no longer exists",
        });
      }

      // 2. Generate new rotated credentials
      const newAccessToken = generateAccessToken(user, sessionId);
      const newRefreshToken = generateRefreshToken(user, sessionId);
      const newRefreshTokenHash = hashToken(newRefreshToken);

// 3. Attempt atomic rotation in MongoDB. The lastUsedAt constraint is the
// idle timeout: a session untouched for SESSION_IDLE_TIMEOUT_HOURS fails
// here even with a valid, matching refresh token.
const idleCutoff = sessionIdleCutoff();
const sessionQuery = {
  userId,
  $or: [{ sessionId }],
  revokedAt: null,
  refreshTokenHash: hashedIncomingToken,
  ...(idleCutoff ? { lastUsedAt: { $gt: idleCutoff } } : {}),
};

if (mongoose.isValidObjectId(sessionId)) {
  sessionQuery.$or.push({ _id: sessionId });
}

const updatedSession = await Session.findOneAndUpdate(
  sessionQuery,
  {
    $set: {
      refreshTokenHash: newRefreshTokenHash,
      lastUsedAt: new Date(),
    },
  },
  { returnDocument: "after" }
);

// 4. Handle Token Replay Detection (and idle timeout)
if (!updatedSession) {
  const existingSessionQuery = {
    $or: [{ sessionId }],
  };

  if (mongoose.isValidObjectId(sessionId)) {
    existingSessionQuery.$or.push({ _id: sessionId });
  }

  const existingSession = await Session.findOne(existingSessionQuery).select(
    "+refreshTokenHash revokedAt lastUsedAt expiresAt"
  );

  if (!existingSession || existingSession.revokedAt) {
    clearAuthCookies(res);

    return res.status(401).json({
      success: false,
      error: "SESSION_INACTIVE",
      message: "Session is no longer active",
    });
  }

  // IDLE TIMEOUT: the token is valid and its hash matches — the rotation
  // only failed because the session sat unused past the idle window.
  // Revoke it for good measure so it can't linger as "active".
  if (existingSession.refreshTokenHash === hashedIncomingToken) {
    existingSession.revokedAt = new Date();
    await existingSession.save();
    await markSessionRevokedInRedis(sessionId);

    logAuditEvent({
      event: AUDIT_EVENTS.SESSION_REVOKED,
      userId,
      sessionId,
      req,
      metadata: { reason: "idle_timeout" },
    });

    clearAuthCookies(res);

    return res.status(401).json({
      success: false,
      error: "SESSION_IDLE_TIMEOUT",
      message: "You were signed out after a period of inactivity. Please sign in again.",
    });
  }

  // TOKEN REPLAY DETECTED:
  // Session is active, but refresh-token hash did not match.
  existingSession.revokedAt = new Date();
  await existingSession.save();

  // Tombstone (not DEL) so a concurrent cache fill can't resurrect the
  // session — see markSessionRevokedInRedis.
  await markSessionRevokedInRedis(sessionId);

  logAuditEvent({
    event: AUDIT_EVENTS.TOKEN_REPLAY_DETECTED,
    userId,
    sessionId,
    req,
    metadata: { reason: "refresh_token_reuse" },
  });

  clearAuthCookies(res);

  return res.status(401).json({
    success: false,
    error: "TOKEN_REPLAY_DETECTED",
    message: "Refresh token replay detected. Session revoked.",
  });
}


      // 5. Cache updated session state in Redis. NX is load-bearing: a
      // concurrent revocation's tombstone (unconditional SET) must never be
      // overwritten by this refresh's cache write.
      if (redisClient?.isOpen) {
        await redisClient.set(
          redisKey,
          JSON.stringify({
            userId: String(user._id),
            sessionId,
            refreshTokenHash: newRefreshTokenHash,
          }),
          { EX: REFRESH_SESSION_TTL_SECONDS, NX: true },
        );
      }

      logAuditEvent({ event: AUDIT_EVENTS.TOKEN_REFRESHED, userId, sessionId, req });
      setAuthCookies(res, newAccessToken, newRefreshToken);

      // Tokens are delivered exclusively via HttpOnly cookies — never in the body.
      return res.status(200).json({
        success: true,
        message: "Token refreshed successfully",
        rotated: true,
      });
    } finally {
      await releaseRedisLock(lockKey, lockToken);
    }
  } catch (error) {
    next(error);
  }
};
/* ============================================================
   LOGOUT
   ============================================================ */
export const logout = async (req, res) => {
  try {
    const cookieNames = getCookieNames();
    const refreshToken =
      req.cookies?.[cookieNames.refresh] ||
      req.cookies?.refresh_token ||
      req.cookies?.refreshToken ||
      req.body?.refreshToken;

    if (refreshToken) {
      try {
        const decoded = verifyRefreshToken(refreshToken);
        const userId = decoded.sub || decoded.id;
        const sessionId = decoded.sid || decoded.sessionId;

        if (sessionId && userId) {
          // Scoped by userId so a session can only be revoked by its owner.
          // No distributed lock needed here: revocation is idempotent.
          await Session.findOneAndUpdate({ sessionId, userId }, { revokedAt: new Date() });

          // Tombstone (not DEL) so a concurrent cache fill can't resurrect
          // the session — see markSessionRevokedInRedis.
          await markSessionRevokedInRedis(sessionId);

          logAuditEvent({ event: AUDIT_EVENTS.LOGOUT, userId, sessionId, req });
          logAuditEvent({ event: AUDIT_EVENTS.SESSION_REVOKED, userId, sessionId, req });
        }
      } catch (err) {
        // Token was invalid or expired; proceed to clear cookies
      }
    }

    clearAuthCookies(res);
    return res.status(200).json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    console.error("Error during logout:", error);
    return res.status(500).json({ success: false, message: "An error occurred during logout" });
  }
};

/* ============================================================
   FORGOT PASSWORD — issue a one-time reset token
   Always responds 200 regardless of whether the email exists,
   so the endpoint cannot be used to enumerate accounts.
   ============================================================ */
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const parsed = z.string().trim().toLowerCase().pipe(z.email()).safeParse(email);

    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: "INVALID_INPUT",
        message: "A valid email address is required",
      });
    }

    const user = await User.findOne({ email: parsed.data });

    if (!user) {
      // Same bcrypt work as the success path so response timing doesn't
      // reveal which emails exist (the status code does — explicit
      // "no account found" is the product decision here).
      await getTimingEqualizerHash();
      return res.status(404).json({
        success: false,
        error: "ACCOUNT_NOT_FOUND",
        message: "No account found with this email address",
      });
    }

    // Resend cooldown: one reset email per address, window from env
    // (PASSWORD_RESET_RESEND_COOLDOWN, default "2m").
    if (redisClient?.isOpen) {
      const cooldownSeconds = durationFromEnv(
        "PASSWORD_RESET_RESEND_COOLDOWN",
        120,
        { legacyName: "PASSWORD_RESET_RESEND_COOLDOWN_SECONDS" },
      );
      const cooldownKey = `pwreset:cooldown:${user._id}`;
      const remaining = await redisClient.ttl(cooldownKey);
      if (remaining > 0) {
        return res.status(429).json({
          success: false,
          error: "COOLDOWN",
          message: "A reset link was recently sent. Please wait before requesting another.",
          retryAfterSeconds: remaining,
        });
      }
      await redisClient.setEx(cooldownKey, cooldownSeconds, "1");
    }

    // 32 random bytes, hex-encoded. Only the sha256 hash is stored.
    const rawToken = crypto.randomBytes(32).toString("hex");
    const RESET_TTL_MS = 15 * 60 * 1000; // 15 minutes

    user.passwordResetTokenHash = hashToken(rawToken);
    user.passwordResetExpiresAt = new Date(Date.now() + RESET_TTL_MS);
    await user.save();

    const resetUrl = buildResetUrl(rawToken);
    await sendPasswordResetEmail(user.email, resetUrl);

    logAuditEvent({
      event: AUDIT_EVENTS.PASSWORD_RESET_REQUESTED,
      userId: user._id,
      req,
      metadata: { channel: process.env.SMTP_URL ? "email" : "console" },
    });

    return res.status(200).json({
      success: true,
      message: "A reset link has been sent to your email address.",
      // Dev convenience only — never enabled in production.
      ...(shouldExposeResetLink() ? { devResetUrl: resetUrl } : {}),
    });
  } catch (error) {
    console.error("Error during forgot password:", error);
    return res.status(500).json({ success: false, message: "An error occurred while requesting the reset" });
  }
};

/* ============================================================
   RESET PASSWORD — consume the one-time token (two steps)
   Step 1 (no OTP in body): validate token + new password, then email
   an OTP to the account owner. The password is NOT changed yet.
   Step 2 (OTP in body): re-validate the token and confirm the OTP,
   then set the new password, revoke EVERY session (full forced
   sign-out), and clear the token.
   ============================================================ */
export const resetPassword = async (req, res) => {
  try {
    const { token, newPassword, code } = req.body;

    const tokenParsed = z.string().trim().min(32).max(128).safeParse(token);
    const passwordParsed = z.string().min(PASSWORD_MIN_LENGTH).max(MAX_PASSWORD_LENGTH).safeParse(newPassword);

    if (!tokenParsed.success || !passwordParsed.success) {
      return res.status(400).json({
        success: false,
        error: "INVALID_INPUT",
        message: `A valid reset token and a password of ${PASSWORD_MIN_LENGTH}–${PASSWORD_MAX_LENGTH} characters are required`,
      });
    }

    const user = await User.findOne({
      passwordResetTokenHash: hashToken(tokenParsed.data),
      passwordResetExpiresAt: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        error: "INVALID_OR_EXPIRED_TOKEN",
        message: "This reset link is invalid or has expired. Please request a new one.",
      });
    }

    // Step 1: email a confirmation code before anything is changed.
    if (!code) {
      const otp = await issueOtp({ user, purpose: "password_reset", req });
      if (otp.error) {
        return res.status(otp.error === "COOLDOWN" ? 429 : 503).json({
          success: false,
          error: otp.error,
          message:
            otp.error === "COOLDOWN"
              ? "A confirmation code was recently sent. Please wait before requesting another."
              : "Verification is temporarily unavailable. Try again shortly.",
          ...(otp.retryAfterSeconds ? { retryAfterSeconds: otp.retryAfterSeconds } : {}),
        });
      }

      // A verified phone makes the reset two-channel: the emailed code AND a
      // texted code must both be presented. A stolen mailbox alone (the classic
      // reset-link takeover) can no longer change the password — the attacker
      // would also need the SIM in the user's pocket. Accounts without a
      // verified phone stay email-only.
      const smsRequired = Boolean(user.phoneNumber && user.phoneVerified);
      let smsOtp = null;
      if (smsRequired) {
        smsOtp = await issueOtp({ user, purpose: "password_reset_sms", req, channel: "sms" });
        // COOLDOWN means a texted code from a previous attempt is still live —
        // fine, the user can use that one. Anything else is a delivery outage.
        if (smsOtp.error && smsOtp.error !== OtpError.COOLDOWN) {
          return res.status(503).json({
            success: false,
            error: smsOtp.error,
            message: "We couldn't text your confirmation code. Try again shortly.",
          });
        }
      }

      return res.status(200).json({
        success: true,
        requireOtp: true,
        ...(smsRequired
          ? {
              smsRequired: true,
              smsPhone: maskPhoneNumber(user.phoneNumber),
              message: `Almost there — enter the code we emailed you and the code we texted to ${maskPhoneNumber(user.phoneNumber)} to finish the reset.`,
            }
          : {
              message: "Almost there — enter the confirmation code we emailed you to finish the reset.",
            }),
        expiresInSeconds: otp.expiresInSeconds,
        resendCooldownSeconds: otp.resendCooldownSeconds,
        // Console-mail code / provider-rejection warning (dev-only code echo).
        ...(otp.deliveryWarning ? { deliveryWarning: otp.deliveryWarning } : {}),
        ...(otp.devCode ? { devCode: otp.devCode } : {}),
        ...(smsOtp?.devCode ? { smsDevCode: smsOtp.devCode } : {}),
      });
    }

    // Step 2: every required code must pass before the password changes.
    // A verified phone makes the reset two-channel: the emailed code AND a
    // texted code — the emailed one alone must never complete a reset (a
    // stolen mailbox is the classic reset-link takeover). Codes are single-
    // use, so each is PEEKED first and only consumed once both matched: a
    // typo in one field must not burn the code from the other.
    const smsRequired = Boolean(user.phoneNumber && user.phoneVerified);
    const { smsCode } = req.body;

    if (smsRequired && !smsCode) {
      return res.status(400).json({
        success: false,
        error: "SMS_CODE_REQUIRED",
        message: `Enter the code we texted to ${maskPhoneNumber(user.phoneNumber)} as well — both codes are required.`,
      });
    }

    const emailPeek = await verifyOtp({ user, purpose: "password_reset", code, consume: false });
    const smsPeek = smsRequired
      ? await verifyOtp({ user, purpose: "password_reset_sms", code: smsCode, consume: false })
      : { valid: true };

    if (!emailPeek.valid || !smsPeek.valid) {
      // Re-verify the failing channel for real — the peek deliberately
      // doesn't count the wrong attempt; this call is what burns it.
      const failing = !emailPeek.valid
        ? { purpose: "password_reset", code, texted: false }
        : { purpose: "password_reset_sms", code: smsCode, texted: true };
      const result = await verifyOtp({ user, purpose: failing.purpose, code: failing.code });
      logAuditEvent({
        event: AUDIT_EVENTS.OTP_FAILED,
        userId: user._id,
        req,
        metadata: { purpose: failing.purpose, reason: result.error },
      });
      const statusByError = { INVALID: 401, EXPIRED: 400, LOCKED: 429 };
      return res.status(statusByError[result.error] || 400).json({
        success: false,
        error: result.error,
        message:
          result.error === "INVALID"
            ? `That ${failing.texted ? "texted " : ""}code is incorrect.`
            : result.error === "LOCKED"
              ? "Too many incorrect attempts. Request a new code."
              : `That ${failing.texted ? "texted " : ""}code has expired. Request a new one.`,
        ...(result.attemptsLeft !== undefined ? { attemptsLeft: result.attemptsLeft } : {}),
      });
    }

    // Both matched — now consume them (strictly one use).
    await verifyOtp({ user, purpose: "password_reset", code });
    if (smsRequired) {
      await verifyOtp({ user, purpose: "password_reset_sms", code: smsCode });
    }

    const lockKey = userSessionLockKey(user._id.toString());
    const lockToken = await acquireRedisLock(lockKey);

    if (!lockToken) {
      return res.status(409).json({
        success: false,
        error: "SESSION_OPERATION_BUSY",
        message: "Another session operation is currently being processed. Please try again.",
      });
    }

    try {
      user.passwordHash = await bcrypt.hash(passwordParsed.data, BCRYPT_ROUNDS);
      // Single-use: consume the token immediately.
      user.passwordResetTokenHash = null;
      user.passwordResetExpiresAt = null;
      await user.save();

      // Force sign-out everywhere — a reset usually means the account was
      // compromised, so no existing session can be trusted.
      const sessions = await Session.find({ userId: user._id, revokedAt: null })
        .select("sessionId")
        .lean();
      const sessionIds = sessions.map((s) => s.sessionId);

      if (sessionIds.length > 0) {
        await Session.updateMany(
          { userId: user._id, revokedAt: null },
          { $set: { revokedAt: new Date() } },
        );

        // Tombstones, not DELs — see markSessionRevokedInRedis.
        await markSessionRevokedInRedis(sessionIds);
      }

      logAuditEvent({
        event: AUDIT_EVENTS.PASSWORD_RESET,
        userId: user._id,
        req,
        metadata: { revokedSessions: sessionIds.length },
      });

      return res.status(200).json({
        success: true,
        message: "Password reset successfully. Please sign in with your new password.",
      });
    } finally {
      await releaseRedisLock(lockKey, lockToken);
    }
  } catch (error) {
    console.error("Error during reset password:", error);
    return res.status(500).json({ success: false, message: "An error occurred while resetting the password" });
  }
};
/* ============================================================
   PANIC LINK REDIRECT — the "wasn't you? click here" endpoint
   The email link lands here. One atomic token consumption guards
   the whole action: revoke every session, then immediately mail a
   password-reset link (the mailbox was just proven reachable, so
   the reset cooldown is bypassed). No authentication required —
   the 64-hex token IS the credential, exactly like password reset.
   ============================================================ */
export const panicSignOut = async (req, res) => {
  try {
    // Login attempts must stay rate-limited even here: the token check is
    // cheap and someone could hammer the endpoint to find live tokens.
    const rawToken = typeof req.params?.token === "string" ? req.params.token : "";

    // Find which user the token belongs to without leaking which users
    // exist: scan the panic keys in Redis (bounded — one key per user with
    // an active link, TTL 30 min).
    let matched = null;
    if (redisClient?.isOpen && /^[0-9a-f]{64}$/.test(rawToken)) {
      const keys = await redisClient.keys("panic:token:*");
      for (const key of keys) {
        const userId = key.slice("panic:token:".length);
        // Consume atomically only when it actually matches.
        if (await consumePanicToken(userId, rawToken)) {
          matched = userId;
          break;
        }
      }
    }

    if (!matched) {
      // Expired, already used, or tampered. Same screen either way — the
      // link says nothing about which account was targeted.
      return res.redirect(`${process.env.FRONTEND_URL || "http://localhost:5174"}/panic?status=invalid`);
    }

    const userId = matched;

    // Revoke every live session under the user lock (same lock the rest of
    // the session code uses, so a concurrent login can't slip through).
    const lockKey = userSessionLockKey(userId);
    const lockToken = await acquireRedisLock(lockKey);
    if (!lockToken) {
      return res.redirect(`${process.env.FRONTEND_URL || "http://localhost:5174"}/panic?status=busy`);
    }

    try {
      const sessions = await Session.find({ userId, revokedAt: null }).select("sessionId");
      const sessionIds = sessions.map((s) => s.sessionId);
      if (sessionIds.length > 0) {
        await Session.updateMany(
          { userId, revokedAt: null },
          { $set: { revokedAt: new Date() } },
        );
        await markSessionRevokedInRedis(sessionIds);
      }

      logAuditEvent({
        event: AUDIT_EVENTS.LOGOUT_ALL,
        userId,
        req,
        metadata: { reason: "panic_link", revokedCount: sessionIds.length },
      });

      // Follow up with a password-reset email so the owner can lock the
      // attacker out for good. The mailbox was just proven reachable by
      // clicking the emailed link, so the normal reset cooldown is
      // bypassed (its key is cleared first).
      const user = await User.findById(userId).select("email passwordResetTokenHash passwordResetExpiresAt");
      if (user) {
        const rawResetToken = crypto.randomBytes(32).toString("hex");
        user.passwordResetTokenHash = hashToken(rawResetToken);
        user.passwordResetExpiresAt = new Date(Date.now() + 15 * 60 * 1000);
        await user.save();
        await redisClient.del(`pwreset:cooldown:${userId}`).catch(() => {});
        await sendPasswordResetEmail(user.email, buildResetUrl(rawResetToken)).catch((error) => {
          console.warn(`[auth] Panic-link reset email failed: ${error.message}`);
        });
      }

      return res.redirect(`${process.env.FRONTEND_URL || "http://localhost:5174"}/panic?status=done`);
    } finally {
      await releaseRedisLock(lockKey, lockToken);
    }
  } catch (error) {
    console.error("Error during panic sign-out:", error);
    return res.redirect(`${process.env.FRONTEND_URL || "http://localhost:5174"}/panic?status=error`);
    }
};
