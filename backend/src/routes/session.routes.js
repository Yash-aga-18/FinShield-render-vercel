// src/routes/session.routes.js

import express from "express";
import { getActiveSessions, getSessionHistory, revokeAllSessions, revokeSession } from "../controllers/session.controller.js";
import authMiddleware from "../middleware/auth.middleware.js";
import requireStepUp from "../middleware/stepUp.middleware.js";

const sessionRouter = express.Router();

sessionRouter.use(authMiddleware); // Ensure all session routes are protected by authentication middleware

sessionRouter.get("/active", getActiveSessions);
sessionRouter.get("/history", getSessionHistory);
sessionRouter.delete("/:sessionId", revokeSession); // Standard RESTful path
// Signing out EVERYWHERE is high-impact: step-up (fresh OTP or trusted device) required.
sessionRouter.post("/revoke-all", requireStepUp, revokeAllSessions); // Optional: Revoke current session if no sessionId is provided

export default sessionRouter;