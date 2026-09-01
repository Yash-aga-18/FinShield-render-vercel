// src/routes/admin.routes.js

import express from "express";
import authMiddleware, { requireAdmin } from "../middleware/auth.middleware.js";
import requireStepUp from "../middleware/stepUp.middleware.js";
import {
  adminChangeUserRole,
  adminDeleteUser,
  adminRevokeSession,
  adminRevokeUserSessions,
  getAllActiveSessions,
  verifyAuditIntegrity,
} from "../controllers/admin.controller.js";

const adminRouter = express.Router();

// Every admin route requires authentication AND the admin role.
adminRouter.use(authMiddleware, requireAdmin);

/* ============================================================
   ADMIN PANEL ENDPOINTS
   Read endpoints are open to any admin; destructive endpoints
   additionally require step-up (fresh OTP or trusted device).
   ============================================================ */
// GET /api/admin/sessions — list active sessions across all users
adminRouter.get("/sessions", getAllActiveSessions);

// GET /api/admin/audit/integrity — recompute the audit hash chain and
// report whether the trail is still intact (read-only; nobody can repair
// a broken chain from the panel).
adminRouter.get("/audit/integrity", verifyAuditIntegrity);

// DELETE /api/admin/sessions/:sessionId — revoke any user's session
adminRouter.delete("/sessions/:sessionId", requireStepUp, adminRevokeSession);

// POST /api/admin/users/:userId/revoke-sessions — revoke all of a user's sessions
adminRouter.post("/users/:userId/revoke-sessions", requireStepUp, adminRevokeUserSessions);

// PATCH /api/admin/users/:userId/role — promote to admin / demote to user.
// Step-up on BOTH directions: promotion grants panel power, demotion strips
// it — either way the account's authority changes hands.
adminRouter.patch("/users/:userId/role", requireStepUp, adminChangeUserRole);

// DELETE /api/admin/users/:userId — delete a user and their sessions
adminRouter.delete("/users/:userId", requireStepUp, adminDeleteUser);

export default adminRouter;
