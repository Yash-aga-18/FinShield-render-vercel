// src/utils/jwt.js

import crypto from "crypto";
import jwt from "jsonwebtoken";

/**
 * Validates environment variables and returns standardized JWT configuration
 */
export const getConfig = () => {
  const {
    JWT_ACCESS_SECRET,
    JWT_REFRESH_SECRET,
    JWT_ACCESS_EXPIRES_IN = "15m",
    JWT_REFRESH_EXPIRES_IN = "7d",
    JWT_ISSUER = "finshield-api",
    JWT_AUDIENCE = "finshield-client",
  } = process.env;

  if (!JWT_ACCESS_SECRET || !JWT_REFRESH_SECRET) {
    throw new Error(
      "JWT_ACCESS_SECRET or JWT_REFRESH_SECRET is missing in environment variables"
    );
  }

  return {
    access: {
      secret: JWT_ACCESS_SECRET,
      expiresIn: JWT_ACCESS_EXPIRES_IN,
    },
    refresh: {
      secret: JWT_REFRESH_SECRET,
      expiresIn: JWT_REFRESH_EXPIRES_IN,
    },
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  };
};

/**
 * Generates a short-lived Access Token linked to user ID and session ID
 */
export const generateAccessToken = (user, sessionId) => {
  const config = getConfig();

  return jwt.sign(
    {
      sub: user._id.toString(),
      email: user.email,
      role: user.role === "admin" ? "admin" : "user",
      sid: sessionId,
      type: "access",
    },
    config.access.secret,
    {
      algorithm: "HS256",
      expiresIn: config.access.expiresIn,
      issuer: config.issuer,
      audience: config.audience,
    }
  );
};

/**
 * Generates a long-lived Refresh Token linked to user ID and session ID
 */
export const generateRefreshToken = (userOrId, sessionId) => {
  const config = getConfig();

  const userId =
    typeof userOrId === "object" && userOrId !== null
      ? String(userOrId._id || userOrId.id)
      : String(userOrId);

  if (!userId || userId === "undefined") {
    throw new Error("Cannot generate refresh token: Invalid user identifier");
  }

  return jwt.sign(
    {
      sub: userId,
      sid: String(sessionId),
      type: "refresh",
      jti: crypto.randomUUID(),
    },
    config.refresh.secret,
    {
      algorithm: "HS256",
      expiresIn: config.refresh.expiresIn,
      issuer: config.issuer,
      audience: config.audience,
    }
  );
};



/**
 * Verifies and decodes an incoming Access Token
 */
export const verifyAccessToken = (token) => {
  const config = getConfig();
  const decoded = jwt.verify(token, config.access.secret, {
    algorithms: ["HS256"],
    issuer: config.issuer,
    audience: config.audience,
  });

  if (decoded.type !== "access") {
    throw new Error("Invalid token type: expected access token");
  }

  return decoded;
};

/**
 * Verifies and decodes an incoming Refresh Token
 */
export const verifyRefreshToken = (token) => {
  const config = getConfig();
  const decoded = jwt.verify(token, config.refresh.secret, {
    algorithms: ["HS256"],
    issuer: config.issuer,
    audience: config.audience,
  });

  if (decoded.type !== "refresh") {
    throw new Error("Invalid token type: expected refresh token");
  }

  return decoded;
};