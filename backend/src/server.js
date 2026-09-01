// server.js

// import dotenv from "dotenv";
// dotenv.config();

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

// Trust proxy configuration: set TRUST_PROXY=1 (hop count), "loopback", or an
// IP/CIDR list when deployed behind a reverse proxy. Express then safely
// derives req.ip from X-Forwarded-For; without it, spoofed XFF headers are ignored.
if (process.env.TRUST_PROXY) {
  app.set("trust proxy", process.env.TRUST_PROXY === "true" ? 1 : process.env.TRUST_PROXY);
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
