// src/routes/auth.routes.js

import express from "express";
import {
  beginGoogleAuthentication,
  completeGoogleAuthentication,
  forgotPassword,
  getInputRules,
  login,
  logout,
  panicSignOut,
  refresh,
  register,
  resetPassword,
} from "../controllers/auth.controller.js";
import {
  resendLoginOtp,
  resendRegistrationOtp,
  sendStepUpOtp,
  verifyLoginOtp,
  verifyRegistrationOtp,
  verifyStepUpOtp,
} from "../controllers/otp.controller.js";
import { issueCsrfToken } from "../middleware/csrf.middleware.js";
import { loginRateLimiter } from "../middleware/rateLimiter.middleware.js";
import authMiddleware from "../middleware/auth.middleware.js";

const authRouter = express.Router();

/* ============================================================
   PUBLIC / UNPROTECTED BOOTSTRAP ENDPOINTS
   ============================================================ */
// GET /api/auth/csrf-token (Issues CSRF cookie + JSON token)
authRouter.get("/csrf-token", issueCsrfToken);

// GET /api/auth/input-rules (length policy for the register/profile forms:
// name, password and OTP code lengths all come from the backend's .env)
authRouter.get("/input-rules", getInputRules);

authRouter.post("/register", loginRateLimiter, register);
authRouter.post("/login", loginRateLimiter, login);

// Password recovery (rate-limited to block reset-link flooding)
authRouter.post("/forgot-password", loginRateLimiter, forgotPassword);
authRouter.post("/reset-password", loginRateLimiter, resetPassword);

// Email OTP: registration verification + risk-based login second factor
authRouter.post("/otp/registration/resend", loginRateLimiter, resendRegistrationOtp);
authRouter.post("/otp/registration/verify", loginRateLimiter, verifyRegistrationOtp);
authRouter.post("/otp/login/resend", loginRateLimiter, resendLoginOtp);
authRouter.post("/otp/login/verify", loginRateLimiter, verifyLoginOtp);

// Step-up authentication for sensitive actions (authenticated callers only)
authRouter.post("/step-up/send", authMiddleware, loginRateLimiter, sendStepUpOtp);
authRouter.post("/step-up/verify", authMiddleware, loginRateLimiter, verifyStepUpOtp);

// OAuth routes (GET requests, exempted by SAFE_METHODS)
authRouter.get("/google", beginGoogleAuthentication);
authRouter.get("/google/callback", completeGoogleAuthentication);

/* ============================================================
   AUTHENTICATED STATE-CHANGING ENDPOINTS (CSRF Protected via server.js)
   ============================================================ */
authRouter.post("/refresh", refresh);
authRouter.post("/logout", logout);

// GET /api/auth/panic/:token — the single-use "wasn't you?" link from the
// sign-in-detected email. Revokes every session on the account and mails a
// password-reset link; no authentication (the token IS the credential, like
// password reset). Redirects to the /panic result page either way.
authRouter.get("/panic/:token", panicSignOut);

export default authRouter;