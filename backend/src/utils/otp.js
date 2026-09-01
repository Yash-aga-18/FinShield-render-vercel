// src/utils/otp.js

/*
 * One-time-passcode service.
 *
 * Codes are OTP_CODE_LENGTH digits (default 6, from .env), stored ONLY as
 * sha256 hashes with:
 *   - a 10-minute expiry (users were regularly outrunning the old 5 minutes
 *     while waiting for a delayed email — an expired-code error for a code
 *     they were only just typing)
 *   - a maximum of 5 wrong attempts before the code is voided
 *   - a 45-second resend cooldown per (user, purpose)
 *
 * Purposes: "registration" | "login" | "login_sms" | "step_up"
 *           | "password_reset" | "phone_verify" | "phone_add"
 *           | "phone_remove" | "email_verify" | "update_sms".
 * Delivery channel: "email" (utils/mailer.js) or "sms" (utils/sms.js).
 */

import crypto from "crypto";
import { redisClient } from "../config/redis.js";
import { logAuditEvent, AUDIT_EVENTS } from "./auditLog.js";
import { sendOtpEmail } from "./mailer.js";
import { sendSmsOtp } from "./sms.js";
import { durationFromEnv, numberFromEnv } from "./env.js";

// All tunables come from the environment so ops can adjust without a deploy.
// Duration values accept "300" (seconds), "30s", "15m", "8h", "7d".
const OTP_TTL_SECONDS = durationFromEnv(
  "OTP_TTL", // how long an issued code stays valid
  10 * 60,
  { legacyName: "OTP_TTL_SECONDS" },
);
// Human phrasing for emails/texts ("It expires in 10 minutes") — derived, so
// the wording always matches the actual TTL.
const OTP_EXPIRY_MINUTES = Math.max(1, Math.round(OTP_TTL_SECONDS / 60));
export { OTP_TTL_SECONDS };
const OTP_MAX_ATTEMPTS = numberFromEnv("OTP_MAX_ATTEMPTS", 5); // wrong entries before a code is voided
const RESEND_COOLDOWN_SECONDS = durationFromEnv(
  "OTP_RESEND_COOLDOWN", // wait before the same user/purpose can be re-sent
  45,
  { legacyName: "OTP_RESEND_COOLDOWN_SECONDS" },
);
// Code length in digits (4–10). The frontend sizes its OTP inputs from the
// public input-rules endpoint so both sides always agree.
const OTP_CODE_LENGTH = numberFromEnv("OTP_CODE_LENGTH", 6, { minimum: 4, maximum: 10 });
export { OTP_CODE_LENGTH };

// Admin sign-in can demand BOTH an emailed and a texted code. Toggleable
// because a team with no SMS provider yet should still be able to sign in.
const ADMIN_LOGIN_REQUIRES_SMS = process.env.ADMIN_LOGIN_REQUIRES_SMS !== "false";
export { ADMIN_LOGIN_REQUIRES_SMS };

const otpKey = (userId, purpose) => `otp:${purpose}:${userId}`;
const cooldownKey = (userId, purpose) => `otp:cooldown:${purpose}:${userId}`;

export const OtpError = Object.freeze({
  COOLDOWN: "COOLDOWN",
  INVALID: "INVALID",
  EXPIRED: "EXPIRED",
  LOCKED: "LOCKED",
  DELIVERY_FAILED: "DELIVERY_FAILED",
});

/* ============================================================
   Issue
   ============================================================ */

export async function issueOtp({ user, purpose, req, actionLabel = "", channel = "email", phone = null, email = null }) {
  // Cooldown: block spamming the resend button (and any scripted abuse).
  // The slot is claimed ATOMICALLY with SET NX EX — a plain "check TTL, then
  // set" let two concurrent sends (a double-mounted dialog, a double click)
  // both pass the check before either set the key, issuing two different
  // codes ~100ms apart. The second silently overwrote the first, so the code
  // the user was already reading always failed verification. With NX there
  // is exactly one winner per cooldown window.
  if (redisClient?.isOpen) {
    const claimed = await redisClient.set(
      cooldownKey(user._id.toString(), purpose),
      "1",
      { NX: true, EX: Math.max(1, Math.ceil(RESEND_COOLDOWN_SECONDS)) },
    );
    if (claimed !== "OK") {
      const remaining = await redisClient.ttl(cooldownKey(user._id.toString(), purpose));
      return { error: OtpError.COOLDOWN, retryAfterSeconds: Math.max(remaining, 1) };
    }
  }

  const code = crypto.randomInt(0, 10 ** OTP_CODE_LENGTH).toString().padStart(OTP_CODE_LENGTH, "0");
  const record = {
    hash: crypto.createHash("sha256").update(`${user._id}:${purpose}:${code}`).digest("hex"),
    attempts: 0,
    expiresAt: Date.now() + OTP_TTL_SECONDS * 1000,
  };

  if (redisClient?.isOpen) {
    await redisClient.setEx(otpKey(user._id.toString(), purpose), Math.ceil(OTP_TTL_SECONDS), JSON.stringify(record));
    // Cooldown key was already claimed atomically at the top of issueOtp.
    // Test-only introspection: lets the suite read the code it would
    // otherwise only see in an email. Never active outside NODE_ENV=test.
    if (process.env.NODE_ENV === "test") {
      await redisClient.setEx(
        `otp:code:${purpose}:${user._id}`,
        Math.ceil(OTP_TTL_SECONDS),
        code,
      );
    }
  } else {
    // No Redis: auth flows are already fail-closed elsewhere, so refuse too.
    return { error: "OTP_PROTECTION_UNAVAILABLE" };
  }

  // Delivery: email by default; channel "sms" texts the code instead.
  // `phone` lets a caller target a number that is not on the user record yet
  // (verifying a NEW phone before saving it); `email` does the same for an
  // address that is not the account email yet (verifying a NEW email before
  // making it the account email).
  let delivery;
  try {
    if (channel === "sms") {
      const target = phone || user.phoneNumber;
      if (!target) {
        return { error: "SMS_TARGET_MISSING" };
      }
      delivery = await sendSmsOtp(target, code, purpose, actionLabel, OTP_EXPIRY_MINUTES);
    } else {
      delivery = await sendOtpEmail(email || user.email, code, purpose, actionLabel, OTP_EXPIRY_MINUTES);
    }
  } catch (error) {
    // Provider outage (gateway unreachable, mailer rejection, …). The code
    // and its resend cooldown were stored BEFORE delivery — roll both back
    // so the caller can retry immediately instead of waiting out a cooldown
    // for a code that never arrived. Controllers map this to a clean 503
    // ("delivery temporarily unavailable"), not a raw 500.
    if (redisClient?.isOpen) {
      await redisClient.del(
        otpKey(user._id.toString(), purpose),
        cooldownKey(user._id.toString(), purpose),
      );
    }
    console.error(`[otp] ${channel} delivery failed (${purpose}): ${error.message}`);
    return { error: OtpError.DELIVERY_FAILED };
  }

  logAuditEvent({
    event: AUDIT_EVENTS.OTP_SENT,
    userId: user._id,
    req,
    metadata: { purpose, channel: delivery.channel },
  });

  return {
    expiresInSeconds: OTP_TTL_SECONDS,
    resendCooldownSeconds: RESEND_COOLDOWN_SECONDS,
    // Set when the provider rejected the send (dev falls back to console) so
    // the UI can say the email never left, instead of the user waiting on a
    // code that will never arrive.
    ...(delivery.warning ? { deliveryWarning: delivery.warning } : {}),
    // Dev-only escape hatch (mirrors DEV_EXPOSE_RESET_LINK in mailer.js):
    // when delivery is console-only, surface the code in the response so the
    // flow stays testable without watching the server terminal. Applies to
    // both email and SMS codes. Never active in production.
    ...(process.env.DEV_EXPOSE_RESET_LINK === "true" && process.env.NODE_ENV !== "production"
      ? { devCode: code }
      : {}),
  };
}

/* ============================================================
   Verify
   ============================================================ */

export async function verifyOtp({ user, purpose, code, consume = true }) {
  if (!redisClient?.isOpen) {
    return { error: "OTP_PROTECTION_UNAVAILABLE" };
  }

  const raw = await redisClient.get(otpKey(user._id.toString(), purpose));

  if (!raw) {
    return { error: OtpError.EXPIRED };
  }

  const record = JSON.parse(raw);

  if (Date.now() > record.expiresAt) {
    await redisClient.del(otpKey(user._id.toString(), purpose));
    return { error: OtpError.EXPIRED };
  }

  if (record.attempts >= OTP_MAX_ATTEMPTS) {
    await redisClient.del(otpKey(user._id.toString(), purpose));
    return { error: OtpError.LOCKED };
  }

  const candidate = crypto
    .createHash("sha256")
    .update(`${user._id}:${purpose}:${code}`)
    .digest("hex");

  if (candidate !== record.hash) {
    // consume:false = a peek for dual-code verification (admin login checks an
    // emailed AND a texted code): a wrong guess here must not burn an attempt
    // yet — the caller re-runs the full verify on the failing channel only,
    // so one typo costs one attempt, not one per channel.
    if (!consume) {
      return { error: OtpError.INVALID, attemptsLeft: OTP_MAX_ATTEMPTS - record.attempts };
    }
    record.attempts += 1;
    const remaining = await redisClient.ttl(otpKey(user._id.toString(), purpose));
    await redisClient.setEx(
      otpKey(user._id.toString(), purpose),
      Math.max(remaining, 1),
      JSON.stringify(record),
    );
    return { error: OtpError.INVALID, attemptsLeft: OTP_MAX_ATTEMPTS - record.attempts };
  }

  // Success consumes the code: strictly one use. consume:false is a peek —
  // dual-code verification only consumes once BOTH channels matched, so a
  // correct emailed code survives a typo in the texted one.
  if (consume) {
    await redisClient.del(otpKey(user._id.toString(), purpose));
    if (process.env.NODE_ENV === "test") {
      await redisClient.del(`otp:code:${purpose}:${user._id}`);
    }
  }
  return { valid: true };
}

/* Test-only helper: the most recently issued code for a user/purpose. */
export async function getLatestOtpCode(userId, purpose) {
  if (process.env.NODE_ENV !== "test" || !redisClient?.isOpen) return null;
  return redisClient.get(`otp:code:${purpose}:${userId}`);
}

/* Whether an unexpired code is outstanding for this user/purpose. Used by the
   login verify step to know if the challenge included a texted code (admins
   get BOTH an emailed and an SMS code; the SMS one is only demanded when it
   was actually issued — e.g. the admin had no verified phone at challenge
   time). */
export async function hasPendingOtp(userId, purpose) {
  if (!redisClient?.isOpen) return false;
  const raw = await redisClient.get(otpKey(String(userId), purpose));
  if (!raw) return false;
  try {
    return Date.now() <= JSON.parse(raw).expiresAt;
  } catch {
    return false;
  }
}

/* ============================================================
   Trusted devices ("remember this device")
   TRUSTED_DEVICE_TTL: how long a "remember this device" cookie keeps
   skipping risk-based login challenges ("30d" by default).
   ============================================================ */

const TRUSTED_DEVICE_TTL_SECONDS = durationFromEnv(
  "TRUSTED_DEVICE_TTL",
  30 * 24 * 60 * 60,
  { legacyName: "TRUSTED_DEVICE_TTL_SECONDS" },
);

const trustedDeviceSecret = () => process.env.TRUSTED_DEVICE_SECRET || process.env.JWT_REFRESH_SECRET;

export const trustedDeviceCookieName = () =>
  process.env.NODE_ENV === "production" ? "__Host-trusted_device" : "trusted_device";

export function issueTrustedDeviceToken(userId) {
  const nonce = crypto.randomBytes(16).toString("hex");
  const signature = crypto
    .createHmac("sha256", trustedDeviceSecret())
    .update(`${userId}:${nonce}`)
    .digest("hex");
  return `${userId}.${nonce}.${signature}`;
}

export function verifyTrustedDeviceToken(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [userId, nonce, signature] = parts;
  const expected = crypto
    .createHmac("sha256", trustedDeviceSecret())
    .update(`${userId}:${nonce}`)
    .digest("hex");

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  return { userId };
}

export { TRUSTED_DEVICE_TTL_SECONDS };

/* ============================================================
   Step-up session ("recently re-authenticated")
   STEP_UP_TTL is the "sudo mode" window — confirm once with an emailed
   code, then act freely for that long ("5m" default, like GitHub/Google).
   Lower it to demand a fresh OTP per sensitive action.
   ============================================================ */

const STEP_UP_TTL_SECONDS = durationFromEnv(
  "STEP_UP_TTL",
  5 * 60,
  { legacyName: "STEP_UP_TTL_SECONDS" },
);

export function stepUpCookieName() {
  return process.env.NODE_ENV === "production" ? "__Host-step_up" : "step_up";
}

export function issueStepUpToken(userId) {
  const expiresAt = Date.now() + STEP_UP_TTL_SECONDS * 1000;
  const payload = `${userId}:${expiresAt}`;
  const signature = crypto
    .createHmac("sha256", trustedDeviceSecret())
    .update(`stepup:${payload}`)
    .digest("hex");
  return { token: `${payload}:${signature}`, expiresInSeconds: STEP_UP_TTL_SECONDS };
}

export function verifyStepUpToken(token, userId) {
  if (typeof token !== "string") return false;
  const parts = token.split(":");
  if (parts.length !== 3) return false;

  const [tokenUserId, expiresAt, signature] = parts;
  if (tokenUserId !== String(userId)) return false;
  if (Date.now() > Number(expiresAt)) return false;

  const expected = crypto
    .createHmac("sha256", trustedDeviceSecret())
    .update(`stepup:${tokenUserId}:${expiresAt}`)
    .digest("hex");

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
