// src/middleware/stepUp.middleware.js

/*
 * Step-up authentication guard for dangerous actions.
 *
 * A request passes when ANY of:
 *   1. The browser presents a valid trusted-device cookie (the user ticked
 *      "remember this device" during a recent OTP verification, 30 days).
 *   2. A step-up cookie from the last 5 minutes is present (the user just
 *      confirmed an OTP for another sensitive action).
 *
 * Otherwise the endpoint replies 401 STEP_UP_REQUIRED and the frontend
 * shows the OTP challenge modal, which calls /api/auth/step-up/* and
 * retries the original request.
 */

import { verifyStepUpToken, stepUpCookieName } from "../utils/otp.js";
import { hasTrustedDevice } from "../controllers/otp.controller.js";

export const requireStepUp = (req, res, next) => {
  const userId = String(req.user?._id || req.user?.id || "");

  if (!userId) {
    // authMiddleware must run first; guard against misconfigured routes.
    return res.status(401).json({ success: false, message: "Authentication required" });
  }

  const stepUpCookie = req.cookies?.[stepUpCookieName()];
  if (verifyStepUpToken(stepUpCookie, userId)) {
    return next();
  }

  if (hasTrustedDevice(req, userId)) {
    return next();
  }

  return res.status(401).json({
    success: false,
    error: "STEP_UP_REQUIRED",
    message: "This action requires confirmation. Check your email for a verification code.",
  });
};

/*
 * Strict variant for irreversible actions (account deletion): the
 * trusted-device cookie does NOT satisfy it. A 30-day "remember this device"
 * tick must not become a 30-day license to erase the account with no code —
 * only a code confirmed within the current sudo window (default 5 minutes)
 * passes.
 */
export const requireStepUpStrict = (req, res, next) => {
  const userId = String(req.user?._id || req.user?.id || "");

  if (!userId) {
    return res.status(401).json({ success: false, message: "Authentication required" });
  }

  const stepUpCookie = req.cookies?.[stepUpCookieName()];
  if (verifyStepUpToken(stepUpCookie, userId)) {
    return next();
  }

  return res.status(401).json({
    success: false,
    error: "STEP_UP_REQUIRED",
    message: "This action requires confirmation. Check your email for a verification code.",
  });
};

export default requireStepUp;
