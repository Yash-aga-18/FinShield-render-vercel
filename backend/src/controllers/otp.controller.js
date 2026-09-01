// src/controllers/otp.controller.js

import User from "../models/user.model.js";
import { logAuditEvent, AUDIT_EVENTS } from "../utils/auditLog.js";
import { getBaseCookieOptions } from "../utils/cookies.js";
import {
  issueOtp,
  verifyOtp,
  hasPendingOtp,
  OtpError,
  issueTrustedDeviceToken,
  verifyTrustedDeviceToken,
  trustedDeviceCookieName,
  TRUSTED_DEVICE_TTL_SECONDS,
  issueStepUpToken,
  stepUpCookieName,
  ADMIN_LOGIN_REQUIRES_SMS,
} from "../utils/otp.js";
import { provisionUserSession } from "./auth.controller.js";
import { maskPhoneNumber } from "../utils/security.js";

/* ============================================================
   COMMON
   ============================================================ */

const otpFailureResponse = (res, error, extra = {}) => {
  const map = {
    [OtpError.COOLDOWN]: { status: 429, message: "Please wait before requesting another code." },
    [OtpError.INVALID]: { status: 401, message: "That code is incorrect." },
    [OtpError.EXPIRED]: { status: 400, message: "That code has expired. Request a new one." },
    [OtpError.LOCKED]: {
      status: 429,
      message: "Too many incorrect attempts. Request a new code.",
    },
    [OtpError.DELIVERY_FAILED]: {
      status: 503,
      message: "We couldn't send the code right now. Please try again shortly.",
    },
  };
  const entry = map[error] ?? { status: 500, message: "Verification is temporarily unavailable." };
  return res.status(entry.status).json({ success: false, error, message: entry.message, ...extra });
};

/* ============================================================
   REGISTRATION OTP
   New accounts start unverified and must confirm email ownership
   before they can sign in.
   ============================================================ */

export const resendRegistrationOtp = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: String(email || "").toLowerCase().trim() });

    if (!user || user.isVerified) {
      // Never reveal whether the email exists.
      return res.status(200).json({
        success: true,
        message: "If that account needs verification, a new code is on its way.",
      });
    }

    const result = await issueOtp({ user, purpose: "registration", req });
    if (result.error) return otpFailureResponse(res, result.error, result);

    return res.status(200).json({
      success: true,
      message: "A new verification code has been sent.",
      expiresInSeconds: result.expiresInSeconds,
      resendCooldownSeconds: result.resendCooldownSeconds,
      // Console-mail code / provider-rejection warning (dev-only code echo) —
      // same policy as the login and step-up challenge responses.
      ...(result.deliveryWarning ? { deliveryWarning: result.deliveryWarning } : {}),
      ...(result.devCode ? { devCode: result.devCode } : {}),
    });
  } catch (error) {
    console.error("Error resending registration OTP:", error);
    return res.status(500).json({ success: false, message: "An error occurred while sending the code" });
  }
};

export const verifyRegistrationOtp = async (req, res) => {
  try {
    const { email, code } = req.body;

    const user = await User.findOne({ email: String(email || "").toLowerCase().trim() });

    if (!user || user.isVerified) {
      return res.status(400).json({
        success: false,
        error: "INVALID_REQUEST",
        message: "Nothing to verify for this account.",
      });
    }

    const result = await verifyOtp({ user, purpose: "registration", code });
    if (!result.valid) {
      logAuditEvent({
        event: AUDIT_EVENTS.OTP_FAILED,
        userId: user._id,
        req,
        metadata: { purpose: "registration", reason: result.error },
      });
      return otpFailureResponse(res, result.error, result);
    }

    user.isVerified = true;
    await user.save();

    logAuditEvent({
      event: AUDIT_EVENTS.OTP_VERIFIED,
      userId: user._id,
      req,
      metadata: { purpose: "registration" },
    });

    // Auto sign-in after verification — one smooth flow.
    const provisioned = await provisionUserSession({ user, req, res, provider: "registration" });
    if (provisioned.handled) return;

    return res.status(200).json({
      success: true,
      message: "Email verified. Welcome to FinShield!",
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
      session: { id: provisioned.displayId, device: provisioned.session.device },
    });
  } catch (error) {
    console.error("Error verifying registration OTP:", error);
    return res.status(500).json({ success: false, message: "An error occurred during verification" });
  }
};

/* ============================================================
   LOGIN OTP (risk-based second factor)
   provisionUserSession already refuses high-risk logins; for
   MEDIUM-risk logins the risk engine sets requireOtp and this
   endpoint finishes the sign-in.

   Admin sign-in is SEQUENTIAL, one code per screen: the emailed
   code is verified first; only then is the text sent, and the
   texted code finishes the sign-in. Nothing is ever texted
   before the mailbox is confirmed.
   ============================================================ */

export const verifyLoginOtp = async (req, res) => {
  try {
    const { email, code, smsCode, rememberDevice, otpChannel } = req.body;

    const user = await User.findOne({ email: String(email || "").toLowerCase().trim() });

    if (!user) {
      return res.status(401).json({ success: false, message: "Invalid email or code" });
    }

    // Admin dual challenge: an admin with a verified phone confirms the
    // emailed code first, then the texted one. "Issued" is read from the
    // outstanding OTP record itself, so an admin whose challenge predated
    // their phone (or whose SMS code simply expired) isn't locked out of the
    // email-only path.
    const dualChallenge =
      user.role === "admin" &&
      ADMIN_LOGIN_REQUIRES_SMS &&
      Boolean(user.phoneNumber && user.phoneVerified) &&
      (await hasPendingOtp(user._id, "login_sms"));

    // A regular user who ASKED for the code by text: that record lives under
    // the login_sms purpose (separate cooldown from the emailed one). The
    // pending-record check keeps this honest — no record, no SMS login, the
    // plain email purpose is checked instead.
    const smsChannelLogin =
      !dualChallenge &&
      otpChannel === "sms" &&
      Boolean(user.phoneNumber && user.phoneVerified) &&
      (await hasPendingOtp(user._id, "login_sms"));
    const loginPurpose = smsChannelLogin ? "login_sms" : "login";

    /* ---- Texted half (admin, stage 2): finish the sign-in ---- */
    if (dualChallenge && smsCode && !smsChannelLogin) {
      const result = await verifyOtp({ user, purpose: "login_sms", code: smsCode });
      if (!result.valid) {
        logAuditEvent({
          event: AUDIT_EVENTS.OTP_FAILED,
          userId: user._id,
          req,
          metadata: { purpose: "login_sms", reason: result.error },
        });
        return otpFailureResponse(res, result.error, result);
      }

      logAuditEvent({
        event: AUDIT_EVENTS.OTP_VERIFIED,
        userId: user._id,
        req,
        metadata: { purpose: "login_sms" },
      });
      return provisionSession(user, req, res, rememberDevice);
    }

    /* ---- Emailed half: verify, then either text the second code or finish ---- */
    const result = await verifyOtp({ user, purpose: loginPurpose, code });
    if (!result.valid) {
      logAuditEvent({
        event: AUDIT_EVENTS.OTP_FAILED,
        userId: user._id,
        req,
        metadata: { purpose: loginPurpose, reason: result.error },
      });
      return otpFailureResponse(res, result.error, result);
    }

    logAuditEvent({
      event: AUDIT_EVENTS.OTP_VERIFIED,
      userId: user._id,
      req,
      metadata: { purpose: loginPurpose },
    });

    // Admin with a verified phone: the email half is confirmed — NOW the
    // text goes out. No session until the texted code passes too.
    if (
      user.role === "admin" &&
      ADMIN_LOGIN_REQUIRES_SMS &&
      !smsChannelLogin &&
      Boolean(user.phoneNumber && user.phoneVerified)
    ) {
      const smsOtp = await issueOtp({ user, purpose: "login_sms", req, channel: "sms" });
      if (smsOtp.error === OtpError.COOLDOWN) {
        // A text went out moments ago (e.g. the user retried the email step)
        // — that code is still valid, so this is a soft landing, not an error.
        return res.status(200).json({
          success: true,
          requireOtp: true,
          stage: "sms",
          message: "Email confirmed. A text was recently sent — that code is still valid.",
          smsOtp: { required: true, maskedPhone: maskPhoneNumber(user.phoneNumber) },
          ...(smsOtp.retryAfterSeconds ? { retryAfterSeconds: smsOtp.retryAfterSeconds } : {}),
        });
      }
      if (smsOtp.error) {
        return otpFailureResponse(res, smsOtp.error, smsOtp);
      }
      return res.status(200).json({
        success: true,
        requireOtp: true,
        stage: "sms",
        message: `Email confirmed. We texted a code to ${maskPhoneNumber(user.phoneNumber)}. Enter it to finish signing in.`,
        smsOtp: {
          required: true,
          maskedPhone: maskPhoneNumber(user.phoneNumber),
          expiresInSeconds: smsOtp.expiresInSeconds,
          resendCooldownSeconds: smsOtp.resendCooldownSeconds,
          ...(smsOtp.deliveryWarning ? { deliveryWarning: smsOtp.deliveryWarning } : {}),
          ...(smsOtp.devCode ? { devCode: smsOtp.devCode } : {}),
        },
      });
    }

    return provisionSession(user, req, res, rememberDevice);
  } catch (error) {
    console.error("Error verifying login OTP:", error);
    return res.status(500).json({ success: false, message: "An error occurred during verification" });
  }
};

/* Shared tail of verifyLoginOtp: trusted-device cookie (optional) + session. */
async function provisionSession(user, req, res, rememberDevice) {
  if (rememberDevice) {
    const base = getBaseCookieOptions();
    res.cookie(trustedDeviceCookieName(), issueTrustedDeviceToken(user._id.toString()), {
      ...base,
      httpOnly: true,
      maxAge: TRUSTED_DEVICE_TTL_SECONDS * 1000,
    });
    logAuditEvent({
      event: AUDIT_EVENTS.DEVICE_TRUSTED,
      userId: user._id,
      req,
      metadata: { durationDays: Math.round(TRUSTED_DEVICE_TTL_SECONDS / 86400) },
    });
  }

  const provisioned = await provisionUserSession({ user, req, res, provider: "login_otp" });
  if (provisioned.handled) return;

  return res.status(200).json({
    success: true,
    message: "Signed in successfully.",
    // role included so the admin nav renders without a page refresh.
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
    session: { id: provisioned.displayId, device: provisioned.session.device },
  });
}

/* Re-send the login code for whichever stage the user is on. The client says
   which channel it is looking at — both destinations are OTP-protected
   either way, so the hint can't unlock anything on its own. */
export const resendLoginOtp = async (req, res) => {
  try {
    const { email, channel } = req.body;
    const user = await User.findOne({ email: String(email || "").toLowerCase().trim() });

    if (!user) {
      // Never reveal whether the email exists.
      return res.status(200).json({ success: true, message: "If that account needs a code, a new one is on its way." });
    }

    const result =
      channel === "sms"
        ? await issueOtp({ user, purpose: "login_sms", req, channel: "sms" })
        : await issueOtp({ user, purpose: "login", req });
    if (result.error) return otpFailureResponse(res, result.error, result);

    return res.status(200).json({
      success: true,
      message:
        channel === "sms"
          ? `We texted a new code to ${maskPhoneNumber(user.phoneNumber)}.`
          : "We emailed a new code.",
      expiresInSeconds: result.expiresInSeconds,
      resendCooldownSeconds: result.resendCooldownSeconds,
      ...(result.deliveryWarning ? { deliveryWarning: result.deliveryWarning } : {}),
      ...(result.devCode ? { devCode: result.devCode } : {}),
    });
  } catch (error) {
    console.error("Error resending login OTP:", error);
    return res.status(500).json({ success: false, message: "An error occurred while sending the code" });
  }
};

/* ============================================================
   STEP-UP OTP
   Dangerous actions (delete account, revoke-all, admin ops)
   require a fresh OTP unless the device is trusted or a
   step-up token from the last 5 minutes is present.
   ============================================================ */

// Cookie helpers shared with the step-up middleware.
export const hasTrustedDevice = (req, userId) => {
  const token = req.cookies?.[trustedDeviceCookieName()];
  const parsed = verifyTrustedDeviceToken(token);
  return Boolean(parsed && parsed.userId === String(userId));
};

export const sendStepUpOtp = async (req, res) => {
  try {
    const user = req.user;
    // The client says what the pending sensitive action is (e.g. "delete user
    // x@y.com") so the emailed code names the exact action, not a generic
    // "sensitive action". Caller-supplied: normalize and cap before it goes
    // anywhere near an email body.
    const rawAction = req.body?.action;
    const actionLabel =
      typeof rawAction === "string" ? rawAction.replace(/[\r\n\t]+/g, " ").trim().slice(0, 200) : "";

    const result = await issueOtp({ user, purpose: "step_up", req, actionLabel });
    if (result.error) return otpFailureResponse(res, result.error, result);

    logAuditEvent({
      event: AUDIT_EVENTS.STEP_UP_REQUIRED,
      userId: user._id,
      req,
      metadata: {},
    });

    return res.status(200).json({
      success: true,
      message: "A confirmation code has been sent to your email.",
      expiresInSeconds: result.expiresInSeconds,
      resendCooldownSeconds: result.resendCooldownSeconds,
      // Dev-only (DEV_EXPOSE_RESET_LINK=true, non-production): the emailed
      // code, so step-up is testable when mail delivery is console-only.
      ...(result.devCode ? { devCode: result.devCode } : {}),
      // Provider rejected the send (e.g. Brevo blocking an unrecognized IP):
      // tell the user the email never left instead of letting them wait.
      ...(result.deliveryWarning ? { deliveryWarning: result.deliveryWarning } : {}),
    });
  } catch (error) {
    console.error("Error sending step-up OTP:", error);
    return res.status(500).json({ success: false, message: "An error occurred while sending the code" });
  }
};

export const verifyStepUpOtp = async (req, res) => {
  try {
    const { code } = req.body;
    const result = await verifyOtp({ user: req.user, purpose: "step_up", code });

    if (!result.valid) {
      logAuditEvent({
        event: AUDIT_EVENTS.OTP_FAILED,
        userId: req.user._id,
        req,
        metadata: { purpose: "step_up", reason: result.error },
      });
      return otpFailureResponse(res, result.error, result);
    }

    logAuditEvent({
      event: AUDIT_EVENTS.STEP_UP_PASSED,
      userId: req.user._id,
      req,
      metadata: {},
    });

    const { token, expiresInSeconds } = issueStepUpToken(req.user._id.toString());
    const base = getBaseCookieOptions();
    res.cookie(stepUpCookieName(), token, {
      ...base,
      httpOnly: true,
      maxAge: expiresInSeconds * 1000,
    });

    return res.status(200).json({
      success: true,
      message: "Confirmed. You can proceed with the sensitive action.",
      validForSeconds: expiresInSeconds,
    });
  } catch (error) {
    console.error("Error verifying step-up OTP:", error);
    return res.status(500).json({ success: false, message: "An error occurred during verification" });
  }
};
