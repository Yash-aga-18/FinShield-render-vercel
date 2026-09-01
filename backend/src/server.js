// server.js

import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "url";

import csrfProtection from "./middleware/csrf.middleware.js";
import passport, { configurePassport } from "./config/passport.js";
import mongoose from "mongoose";
import connectDB from "./config/database.js";
import connectRedis, { redisClient } from "./config/redis.js";

import authRouter from "./routes/auth.routes.js";
import userRouter from "./routes/user.routes.js";
import sessionRouter from "./routes/session.routes.js";
import adminRouter from "./routes/admin.routes.js";
import { notFoundHandler, errorHandler } from "./middleware/error.middleware.js";
import { flushAuditLogs } from "./utils/auditLog.js";
import { ensureDefaultAdmin } from "./utils/ensureDefaultAdmin.js";

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Trust proxy configuration: set TRUST_PROXY to a hop count ("1", "2"…), a
// comma-separated IP/CIDR allow-list of known proxies, "loopback", or "true"
// (alias for 1). Express then safely derives req.ip from X-Forwarded-For;
// without it, spoofed XFF headers are ignored.
//
// NOTE the string/number trap: Express reads a NUMBER as a hop count but a
// STRING as an IP/CIDR allow-list — the literal string "2" trusts nothing
// (no address matches an allow-list of "2"), leaving req.ip as the socket
// address. Numeric strings must therefore be converted to numbers here.
//
// For this deployment the recommended value is a subnet list covering every
// proxy on the chain (Render's forwarder is loopback, Render's balancers are
// 10/8, Render fronts via Cloudflare, and Vercel/Netlify egress through AWS
// + CGNAT ranges), because the Vercel, Netlify, and direct paths have
// DIFFERENT hop counts and client-supplied XFF entries survive the whole
// chain — trusting by subnet stops the walk exactly at the real client and
// drops spoofed entries; a hop count can do only one of the two.
if (process.env.TRUST_PROXY) {
  const raw = String(process.env.TRUST_PROXY).trim();
  const asNumber = raw === "" ? NaN : Number(raw);
  app.set(
    "trust proxy",
    raw === "true" ? 1 : Number.isFinite(asNumber) ? asNumber : raw,
  );
}

// Initialize passport configuration
configurePassport();

app.use(helmet());

// Hardened CORS policy
const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map((origin) => origin.trim())
  : ["http://localhost:5174", "http://localhost:3000"];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        // Disallow without throwing: the request simply gets no CORS headers,
        // which the browser blocks (avoids turning CORS violations into 500s).
        callback(null, false);
      }
    },
    credentials: true,
  })
);

app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());

// Apply CSRF middleware globally
app.use(csrfProtection);
app.use(passport.initialize());


app.get("/", (req, res) => {
  res.status(200).json({
    status: "ok",
    service: "Hello, server is running",
  });
});
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    service: "finshield-api",
  });
});

// TEMPORARY diagnostic for the TRUST_PROXY / X-Forwarded-For investigation:
// shows exactly what Express resolves as the client IP and the proxy headers
// it saw, so we can pick the right hop count for the Vercel→Render chain.
// Remove once the session IP displays correctly.
app.get("/api/diag/ip", (req, res) => {
  res.status(200).json({
    ip: req.ip,
    ips: req.ips,
    socket: req.socket?.remoteAddress ?? null,
    xff: req.headers["x-forwarded-for"] ?? null,
    realIp: req.headers["x-real-ip"] ?? null,
    vercelXff: req.headers["x-vercel-forwarded-for"] ?? null,
    trustProxySetting: app.get("trust proxy") ?? false,
  });
});

app.use("/api/auth", authRouter);
app.use("/api/users", userRouter);
app.use("/api/sessions", sessionRouter);
app.use("/api/admin", adminRouter);

app.use(notFoundHandler);   // 404 handler to catch unhandled routes
app.use(errorHandler);    // Global error handler 


export default app;

// Async startup routine
const startServer = async () => {
  try {
    await connectDB();
    await connectRedis();
    await ensureDefaultAdmin();

    const server = app.listen(PORT, () => {
      console.log(`Server running at http://localhost:${PORT}`);
    });

    // Graceful shutdown: stop accepting connections, drain fire-and-forget
    // audit writes, then close Redis and MongoDB before exiting.
    const shutdown = async (signal) => {
      console.log(`${signal} received. Shutting down gracefully...`);
      try {
        await new Promise((resolve) => server.close(resolve));
        await flushAuditLogs(); // drain pending audit writes before exiting
        if (redisClient?.isOpen) {
          await redisClient.quit();
        }
        await mongoose.connection.close();
        process.exit(0);
      } catch (error) {
        console.error("Error during shutdown:", error);
        process.exit(1);
      }
    };

    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
};

const isMainModule = process.argv[1] === fileURLToPath(import.meta.url);

if (isMainModule) { 
  startServer();
}
