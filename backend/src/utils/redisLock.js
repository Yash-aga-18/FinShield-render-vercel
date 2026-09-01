// src/utils/redisLock.js

import crypto from "crypto";
import { redisClient } from "../config/redis.js";
import { durationFromEnvMs } from "./env.js";

// Distributed-lock timings. Values accept "500ms", "5s", bare = milliseconds
// (legacy REDIS_LOCK_*_MS behaviour).
const LOCK_TTL_MS = durationFromEnvMs("REDIS_LOCK_TTL", 5000, { legacyName: "REDIS_LOCK_TTL_MS", legacyUnit: "ms" }); // how long a lock lives before self-expiring
const LOCK_WAIT_MS = durationFromEnvMs("REDIS_LOCK_WAIT", 2000, { legacyName: "REDIS_LOCK_WAIT_MS", legacyUnit: "ms" }); // how long callers wait to acquire it
const LOCK_RETRY_MS = durationFromEnvMs("REDIS_LOCK_RETRY", 50, { legacyName: "REDIS_LOCK_RETRY_MS", legacyUnit: "ms" }); // poll interval while waiting

// Lua script ensures atomic token validation before deletion
const RELEASE_LOCK_SCRIPT = `
  if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
  else
    return 0
  end
`;

/**
 * Acquires a distributed Redis lock with spin-wait polling.
 * Returns a unique ownership token string on success, or null if lock acquisition timed out.
 */
export const acquireRedisLock = async (
  key,
  {
    ttlMs = LOCK_TTL_MS,
    waitMs = LOCK_WAIT_MS,
    retryMs = LOCK_RETRY_MS,
  } = {}
) => {
  // If Redis is offline, issue a single-use fallback token only if waitMs === 0 (fail-fast),
  // otherwise fallback token is scoped safely per request context.
  if (!redisClient?.isOpen) {
    return `FALLBACK_LOCK_TOKEN_${crypto.randomUUID()}`;
  }

  const token = crypto.randomUUID();
  const deadline = Date.now() + waitMs;

  try {
    while (Date.now() <= deadline) {
      const result = await redisClient.set(key, token, {
        NX: true,
        PX: ttlMs,
      });

      if (result === "OK") {
        return token;
      }

      // Fast exit if waitMs is 0 (immediate non-blocking attempt)
      if (waitMs === 0) {
        break;
      }

      await new Promise((resolve) => setTimeout(resolve, retryMs));
    }
  } catch (error) {
    if (process.env.NODE_ENV !== "test") {
      console.error("Redis lock acquisition error:", error.message);
    }
    return `FALLBACK_LOCK_TOKEN_${crypto.randomUUID()}`;
  }

  return null;
};

/**
 * Releases the Redis lock safely using Lua scripting.
 */
export const releaseRedisLock = async (key, token) => {
  if (!token || typeof token !== "string" || token.startsWith("FALLBACK_LOCK_TOKEN") || !redisClient?.isOpen) {
    return;
  }

  try {
    await redisClient.eval(RELEASE_LOCK_SCRIPT, {
      keys: [key],
      arguments: [token],
    });
  } catch (error) {
    if (process.env.NODE_ENV !== "test") {
      console.error("Redis lock release failed:", error.message);
    }
  }
};