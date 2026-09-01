// src/routes/user.routes.js

import express from "express";

import {
  changePassword,
  deleteUserProfile,
  getAllUsers,
  getUserActivity,
  getUserById,
  getUserProfile,
  removePhoneNumber,
  setEmailAddress,
  setPhoneNumber,
  updateUserProfile,
} from "../controllers/user.controller.js";

import authMiddleware, { requireAdmin } from "../middleware/auth.middleware.js";
import requireStepUp, { requireStepUpStrict } from "../middleware/stepUp.middleware.js";

const userRouter = express.Router();

// ============================================================
// AUTHENTICATED SELF-PROFILE ROUTES
// ============================================================

userRouter.get("/me", authMiddleware, getUserProfile);

userRouter.put("/me", authMiddleware, updateUserProfile);

// Changing the password re-anchors the credential. The strict step-up check
// lives INSIDE the controller (not this middleware) so the current/new
// password validation runs FIRST — no emailed or texted code is ever sent
// for a request that would fail on the passwords alone. Admins with a
// verified phone additionally confirm by text, sequential, email first.
userRouter.put("/me/password", authMiddleware, changePassword);

// Adding/changing/removing a phone number is a security setting (it becomes
// an authentication factor for admins), so a fresh confirmation is required.
userRouter.post("/me/phone", authMiddleware, requireStepUp, setPhoneNumber);

userRouter.delete("/me/phone", authMiddleware, requireStepUpStrict, removePhoneNumber);

// Changing the account email re-anchors identity: strict step-up (a fresh
// emailed code, the trusted-device cookie does NOT pass) plus, in step 2, the
// code that was mailed to the NEW address itself.
userRouter.post("/me/email", authMiddleware, requireStepUpStrict, setEmailAddress);

// Account deletion is irreversible and can never be satisfied by the
// trusted-device cookie — a fresh emailed code (or one confirmed within the
// current 5-minute step-up window) is always required.
userRouter.delete("/me", authMiddleware, requireStepUpStrict, deleteUserProfile);

// ============================================================
// OTHER USER ROUTES (admin-only: prevent user enumeration / IDOR)
// ============================================================

userRouter.get("/", authMiddleware, requireAdmin, getAllUsers);

userRouter.get("/:id", authMiddleware, requireAdmin, getUserById);

// Basic per-user activity log for the admin panel (created, last login,
// recent audit events). Read-only.
userRouter.get("/:id/activity", authMiddleware, requireAdmin, getUserActivity);

export default userRouter;
