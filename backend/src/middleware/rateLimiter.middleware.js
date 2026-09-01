// src/middleware/rateLimiter.middleware.js

import { redisClient } from "../config/redis.js";
import { getClientIp } from "../utils/ip.js";
import { logAuditEvent, AUDIT_EVENTS } from "../utils/auditLog.js";
import { durationFromEnv, numberFromEnv } from "../utils/env.js";

// Login brute-force limits. Durations accept "300" (seconds), "15m", "8h"…
// Legacy *_SECONDS names still work (bare value = seconds).
// LOGIN_MAX_ATTEMPT_LIMIT / LOGIN_ATTEMPT_WINDOW_SECONDS are the very first
// release's names — still honoured for backwards compatibility.
const legacyAccountMaxFailures = Number(process.env.LOGIN_MAX_ATTEMPT_LIMIT);
const legacyAccountWindowSeconds = Number(process.env.LOGIN_ATTEMPT_WINDOW_SECONDS);

const CONFIG = {
  // Failed attempts allowed from one IP before it is blocked.
  ipMaxAttempts: numberFromEnv("LOGIN_IP_MAX_ATTEMPTS", 20),
  // Window those IP failures are counted in.
  ipWindowSeconds: durationFromEnv("LOGIN_IP_WINDOW", 900, { legacyName: "LOGIN_IP_WINDOW_SECONDS" }),
  // Failed password attempts allowed for one account before lockout.
  accountMaxFailures: numberFromEnv(
    "LOGIN_ACCOUNT_MAX_FAILURES",
    Number.isFinite(legacyAccountMaxFailures) && legacyAccountMaxFailures > 0
      ? Math.floor(legacyAccountMaxFailures)
      : 5,
  ),
  // Window the account failures are counted in.
  accountWindowSeconds: durationFromEnv(
    "LOGIN_ACCOUNT_WINDOW",
    Number.isFinite(legacyAccountWindowSeconds) && legacyAccountWindowSeconds > 0
      ? legacyAccountWindowSeconds
      : 900,
    { legacyName: "LOGIN_ACCOUNT_WINDOW_SECONDS" },
  ),
  // How long the account stays locked once the failure cap is hit.
  blockSeconds: durationFromEnv("LOGIN_BLOCK", 900, { legacyName: "LOGIN_BLOCK_SECONDS" }),
  // Total login requests (success or failure) allowed from one IP.
  globalIpMaxRequests: numberFromEnv("LOGIN_GLOBAL_IP_MAX_REQUESTS", 60),
  // Window for that global IP throughput cap.
  globalIpWindowSeconds: durationFromEnv("LOGIN_GLOBAL_IP_WINDOW", 60, { legacyName: "LOGIN_GLOBAL_IP_WINDOW_SECONDS" }),
};

const normalizeEmail = (email) => {
  if (typeof email !== "string") {
    return "";
  }
  return email.trim().toLowerCase();
};

const getKeys = (email, ip) => {
  const encodedEmail = encodeURIComponent(email);
  const encodedIp = encodeURIComponent(ip);

  return {
    ipAttempts: `ratelimit:login:ip:${encodedIp}`,
    accountFailures: `ratelimit:login:account:${encodedEmail}`,
    accountBlock: `ratelimit:login:block:${encodedEmail}`,
    globalIp: `ratelimit:login:global-ip:${encodedIp}`,
  };
};

// Atomic INCR+EXPIRE via Lua: guarantees the counter always receives its TTL
// even if requests race or the process dies between the two operations.
const INCR_WITH_TTL_SCRIPT = `
  local count = redis.call("INCR", KEYS[1])
  if count == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
  end
  return count
`;

const incrementWithExpiry = async (key, expirySeconds) => {
  if (!redisClient?.isOpen) return 1;
  return redisClient.eval(INCR_WITH_TTL_SCRIPT, {
    keys: [key],
    arguments: [String(expirySeconds)],
  });
};

const safePositiveInteger = (value) => {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    return 0;
  }
  return parsed;
};

const setRateLimitHeaders = (res, limit, remaining, retryAfter) => {
  res.setHeader("X-RateLimit-Limit", String(limit));
  res.setHeader("X-RateLimit-Remaining", String(Math.max(0, remaining)));
  if (retryAfter > 0) {
    res.setHeader("Retry-After", String(retryAfter));
  }
};

/**
 * Login Rate Limiter Middleware
 * Multi-layer security defense enforcing IP caps, account lockouts, and endpoint rate limits.
 */
export const loginRateLimiter = async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const ip = getClientIp(req) || "127.0.0.1";
    const keys = getKeys(email, ip);

    req.loginRateLimit = { email, ip, keys };

    // Fail closed: without Redis, brute-force and lockout protections cannot
    // be enforced, so authentication attempts are rejected rather than allowed.
    if (!redisClient?.isOpen) {
      return res.status(503).json({
        success: false,
        error: "AUTH_PROTECTION_UNAVAILABLE",
        message: "Authentication protection service is temporarily unavailable.",
      });
    }

    const globalIpRequests = await incrementWithExpiry(keys.globalIp, CONFIG.globalIpWindowSeconds);

    const [accountBlockTtl, ipAttempts, accountFailures] = await Promise.all([
      email ? redisClient.ttl(keys.accountBlock) : -2,
      redisClient.get(keys.ipAttempts),
      email ? redisClient.get(keys.accountFailures) : null,
    ]);

    // 1. Check Explicit Account Block
    if (email && accountBlockTtl > 0) {
      setRateLimitHeaders(res, CONFIG.accountMaxFailures, 0, accountBlockTtl);

      logAuditEvent({
        event: AUDIT_EVENTS.RATE_LIMIT_TRIGGERED,
        req,
        metadata: { reason: "account_blocked", ttl: accountBlockTtl },
      });

      return res.status(429).json({
        success: false,
        error: "LOGIN_TEMPORARILY_BLOCKED",
        message: "Too many failed login attempts. Try again later.",
        retryAfterSeconds: accountBlockTtl,
      });
    }

    // 2. Check Global IP Throughput Limit
    if (globalIpRequests > CONFIG.globalIpMaxRequests) {
      setRateLimitHeaders(res, CONFIG.globalIpMaxRequests, 0, CONFIG.globalIpWindowSeconds);

      logAuditEvent({
        event: AUDIT_EVENTS.RATE_LIMIT_TRIGGERED,
        req,
        metadata: { reason: "global_ip_limit" },
      });

      return res.status(429).json({
        success: false,
        error: "RATE_LIMIT_EXCEEDED",
        message: "Too many login requests from this IP.",
        retryAfterSeconds: CONFIG.globalIpWindowSeconds,
      });
    }

    // 3. Check Per-IP Login Failure Cap
    const currentIpCount = safePositiveInteger(ipAttempts);
    if (currentIpCount >= CONFIG.ipMaxAttempts) {
      setRateLimitHeaders(res, CONFIG.ipMaxAttempts, 0, CONFIG.ipWindowSeconds);

      logAuditEvent({
        event: AUDIT_EVENTS.RATE_LIMIT_TRIGGERED,
        req,
        metadata: { reason: "ip_attempt_limit" },
      });

      return res.status(429).json({
        success: false,
        error: "RATE_LIMIT_EXCEEDED",
        message: "Too many login attempts from this IP address.",
        retryAfterSeconds: CONFIG.ipWindowSeconds,
      });
    }

    // 4. Check Per-Account Failure Cap
    const currentAccountFailures = safePositiveInteger(accountFailures);
    if (email && currentAccountFailures >= CONFIG.accountMaxFailures) {
      setRateLimitHeaders(res, CONFIG.accountMaxFailures, 0, CONFIG.accountWindowSeconds);

      logAuditEvent({
        event: AUDIT_EVENTS.RATE_LIMIT_TRIGGERED,
        req,
        metadata: { reason: "login_attempt_limit" },
      });

      return res.status(429).json({
        success: false,
        error: "LOGIN_TEMPORARILY_BLOCKED",
        message: `Too many failed login attempts. Try again in ${Math.ceil(CONFIG.accountWindowSeconds / 60)} minutes.`,
        retryAfterSeconds: CONFIG.accountWindowSeconds,
      });
    }

    setRateLimitHeaders(res, CONFIG.accountMaxFailures, CONFIG.accountMaxFailures - currentAccountFailures, 0);
    return next();
  } catch (error) {
    console.error("Login rate limiter error:", error);

    return res.status(503).json({
      success: false,
      error: "AUTH_PROTECTION_UNAVAILABLE",
      message: "Authentication protection service is temporarily unavailable.",
    });
  }
};

/**
 * Increments failed attempt counters in Redis after authentication failure.
 */
export const getAccountMaxFailures = () => CONFIG.accountMaxFailures;

export const recordFailedLogin = async (req) => {
  const context = req.loginRateLimit;
  if (!context || !redisClient?.isOpen) {
    return { ipAttempts: 0, accountFailures: 0 };
  }

  const { email, keys } = context;

  const [ipAttempts, accountFailures] = await Promise.all([
    incrementWithExpiry(keys.ipAttempts, CONFIG.ipWindowSeconds),
    email
      ? incrementWithExpiry(keys.accountFailures, CONFIG.accountWindowSeconds)
      : Promise.resolve(0),
  ]);

  if (email && accountFailures >= CONFIG.accountMaxFailures) {
    await redisClient.setEx(keys.accountBlock, CONFIG.blockSeconds, "1");
  }

  return { ipAttempts, accountFailures };
};

/**
 * Clears failed attempt keys and locks in Redis upon successful login.
 */
export const clearLoginAttempts = async (req) => {
  const context = req.loginRateLimit;
  if (!redisClient?.isOpen) {
    return;
  }

  const keysToDelete = [];
  if (context?.email) {
    keysToDelete.push(context.keys.accountFailures, context.keys.accountBlock);
  }

  if (keysToDelete.length > 0) {
    await redisClient.del(keysToDelete);
  }
};

export const clearFailedLoginAttempts = clearLoginAttempts;

/**
 * Reads active failed login count for risk engine telemetry.
 */
export const getFailedLoginAttempts = async (req) => {
  const context = req.loginRateLimit;
  if (!context?.email || !redisClient?.isOpen) {
    return 0;
  }

  try {
    const value = await redisClient.get(context.keys.accountFailures);
    return safePositiveInteger(value);
  } catch (error) {
    console.error("[RateLimiter] Failed to read attempt counter:", error.message);
    return 0;
  }
};