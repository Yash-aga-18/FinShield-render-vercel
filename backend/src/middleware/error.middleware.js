// src/middleware/error.middleware.js

import { logAuditEvent, AUDIT_EVENTS } from "../utils/auditLog.js";

const isProduction = process.env.NODE_ENV === "production";

/**
 * Handles requests targeting non-existent API routes (404)
 */
export const notFoundHandler = (req, res, next) => {
  return res.status(404).json({
    success: false,
    error: "ROUTE_NOT_FOUND",
    message: `Cannot ${req.method} ${req.originalUrl}`,
  });
};

/**
 * Global Error Handling Middleware
 */
export const errorHandler = (err, req, res, next) => {
  let statusCode = err.statusCode || err.status || 500;
  let errorCode = err.code || "INTERNAL_SERVER_ERROR";
  let message = err.message || "An unexpected error occurred.";

  // 1. Intercept Body Parser Syntax Errors (Malformed JSON payloads)
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    statusCode = 400;
    errorCode = "INVALID_JSON_PAYLOAD";
    message = "Malformed JSON payload provided in request body.";
  }

  // 2. Intercept Mongoose Invalid ObjectId Cast Errors
  else if (err.name === "CastError") {
    statusCode = 400;
    errorCode = "INVALID_RESOURCE_ID";
    message = `Invalid format for field: ${err.path}`;
  }

  // 3. Intercept Mongoose Duplicate Key Errors (MongoDB code 11000)
  else if (err.code === 11000) {
    statusCode = 409;
    errorCode = "DUPLICATE_RESOURCE";
    const field = Object.keys(err.keyValue || {})[0] || "field";
    message = `An account or record with that ${field} already exists.`;
  }

  // 4. Intercept Mongoose Schema Validation Errors
  else if (err.name === "ValidationError") {
    statusCode = 400;
    errorCode = "VALIDATION_ERROR";
    message = Object.values(err.errors)
      .map((e) => e.message)
      .join(", ");
  }

  // 5. Intercept JWT Verification Errors
  else if (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError") {
    statusCode = 401;
    errorCode = "UNAUTHORIZED";
    message = "Authentication token is invalid or expired.";
  }

  // Server-side audit logging for high-severity 500 errors
  if (statusCode >= 500) {
    console.error(`[SERVER_ERROR] ${req.method} ${req.originalUrl}:`, err);

    logAuditEvent({
      event: AUDIT_EVENTS.SYSTEM_ERROR,
      userId: req.user?.id || null,
      sessionId: req.user?.sessionId || null,
      req,
      metadata: {
        reason: "unhandled_exception",
        errorName: err.name,
      },
    });
  }

  // Mask generic 500 errors in production to prevent information leakage
  const responseMessage =
    statusCode === 500 && isProduction
      ? "An internal server error occurred. Please try again later."
      : message;

  return res.status(statusCode).json({
    success: false,
    error: errorCode,
    message: responseMessage,
    ...(isProduction ? {} : { stack: err.stack }),
  });
};