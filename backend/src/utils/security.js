// src/utils/security.js

import { createHash, createHmac, timingSafeEqual } from "crypto";
import { redisClient } from "../config/redis.js";
import { durationFromEnv, numberFromEnv } from "./env.js";

/**
 * Derives the HMAC key for session display IDs from the JWT secret, so
 * displayIds are bound to this server and cannot be forged or inverted
 * without the secret.
 */
const displayIdKey = () =>
  createHmac("sha256", process.env.JWT_ACCESS_SECRET || "finshield-insecure-dev-secret")
    .update("finshield-session-display-id")
    .digest();

/**
 * Converts a raw internal session ID into a safe public identifier.
 * The mapping is one-way from the client's perspective: revocation works
 * by re-deriving the HMAC server-side, but the real session ID (which
 * appears inside tokens and cache keys) never leaves the server.
 */
export const toDisplayId = (sessionId) =>
  createHmac("sha256", displayIdKey()).update(String(sessionId)).digest("hex");

/**
 * Masks an IP address for API responses: keeps network-level context
 * (IPv4 /24, IPv6 /64 prefix) while hiding the exact client address.
 */
export const maskIpAddress = (ipAddress) => {
  if (typeof ipAddress !== "string" || ipAddress.length === 0) {
    return null;
  }

  // Outside production (local dev / tests) every request arrives from
  // 127.0.0.1, which masks to a useless "127.0.0.x". Show the real address.
  if (process.env.NODE_ENV !== "production") {
    return ipAddress;
  }

  // IPv4: keep first three octets, mask the last (192.0.2.10 -> 192.0.2.x)
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ipAddress)) {
    return `${ipAddress.split(".").slice(0, 3).join(".")}.x`;
  }

  // IPv6: keep first two groups, mask the rest
  if (ipAddress.includes(":")) {
    const groups = ipAddress.split(":").filter(Boolean);
    return groups.length >= 2 ? `${groups.slice(0, 2).join(":")}::x` : "x::x";
  }

  return "hidden";
};

/**
 * Masks a phone number for display: everything except the last 4 digits
 * becomes bullets (a leading "+" is kept), e.g. +15550001111 -> +•••••••1111.
 * Unlike IP masking this runs in EVERY environment — a phone number is PII
 * that no API response, log, or error message should carry in full.
 */
export const maskPhoneNumber = (phone) => {
  if (typeof phone !== "string" || phone.length < 5) {
    return phone ?? null;
  }
  const keepPlus = phone.startsWith("+");
  const bullets = "•".repeat(phone.length - 4 - (keepPlus ? 1 : 0));
  return `${keepPlus ? "+" : ""}${bullets}${phone.slice(-4)}`;
};

/**
 * Hashes an incoming token using SHA-256.
 */
export const hashToken = (token) => {
  return createHash("sha256").update(token).digest("hex");
};

/**
 * Session idle timeout: a session untouched for this long is dead, even if
 * its refresh token is still cryptographically valid and unexpired. Closes
 * the "closed the laptop, came back next week, still signed in" gap —
 * enforced on refresh and on the MongoDB auth fallback.
 *
 * SESSION_IDLE_TIMEOUT accepts "300" (seconds), "30s", "15m", "8h", "7d".
 * The legacy SESSION_IDLE_TIMEOUT_HOURS (bare value = hours) still works.
 * 0 disables the idle timeout (not recommended).
 */
export const SESSION_IDLE_TIMEOUT_SECONDS = durationFromEnv(
  "SESSION_IDLE_TIMEOUT",
  8 * 3600,
  { legacyName: "SESSION_IDLE_TIMEOUT_HOURS", legacyUnit: "h", allowZero: true },
);

export const sessionIdleCutoff = () =>
  SESSION_IDLE_TIMEOUT_SECONDS === 0
    ? null // disabled: no lastUsedAt constraint on queries
    : new Date(Date.now() - SESSION_IDLE_TIMEOUT_SECONDS * 1000);

/**
 * Timing-safe string comparator to prevent side-channel timing attacks.
 */
export const hashesMatch = (storedHash, candidateHash) => {
  if (typeof storedHash !== "string" || typeof candidateHash !== "string") {
    return false;
  }

  const stored = Buffer.from(storedHash, "utf8");
  const candidate = Buffer.from(candidateHash, "utf8");

  return (
    stored.length === candidate.length && timingSafeEqual(stored, candidate)
  );
};

/**
 * Compares incoming login context against the user's recent sessions.
 * RISK_ANOMALY_LOOKBACK = how many past sessions are considered "known"
 * when deciding whether this login is from a new device / new IP.
 */
export const detectLoginAnomalies = async ({
  userId,
  ipAddress,
  device,
  Session,
}) => {
  const previousSessions = await Session.find({ userId })
    .select("ipAddress userAgent device createdAt")
    .sort({ createdAt: -1 })
    .limit(numberFromEnv("RISK_ANOMALY_LOOKBACK", 20))
    .lean();

  if (previousSessions.length === 0) {
    return {
      newDevice: false,
      newIp: false,
    };
  }

  const knownIps = new Set(
    previousSessions
      .map((session) => session.ipAddress)
      .filter(Boolean)
  );

  const knownDevices = new Set(
    previousSessions
      .map((session) => session.device)
      .filter(Boolean)
  );

  return {
    newDevice: Boolean(device) && !knownDevices.has(device),
    newIp: Boolean(ipAddress) && !knownIps.has(ipAddress),
  };
};

/**
 * Generates standardized lock keys for concurrency management.
 */
export const userSessionLockKey = (userId) => `lock:user-sessions:${userId}`;
export const sessionRefreshLockKey = (sessionId) => `lock:session-refresh:${sessionId}`;

/**
 * Standardized Redis cache key for session state (shared by auth middleware,
 * auth controller, and session controller so the format can never diverge).
 */
export const redisSessionKey = (sessionId) => `session:${sessionId}`;

/**
 * Writes a REVOKED tombstone over a session's Redis cache entry instead of
 * deleting it. DEL alone has a race: auth middleware re-populates the cache
 * from MongoDB on a miss, so a cache fill that raced the DEL would
 * resurrect the session until TTL — a scripted client that keeps polling
 * wins that race indefinitely and stays "active" no matter how often an
 * admin revokes. The tombstone is written with an unconditional SET (so it
 * always beats an in-flight fill) and every cache fill uses SET ... NX (so
 * it can never overwrite a tombstone). auth middleware recognizes the
 * { revoked: true } payload and rejects immediately; even if the tombstone
 * has already expired, the MongoDB fallback still sees revokedAt set, so
 * revocation always wins. The short TTL bounds how long dead keys occupy
 * memory.
 *
 * Accepts one session ID or an array of them. Best-effort: Redis being
 * unavailable must never fail the revocation itself — MongoDB is the
 * source of truth.
 */
export const markSessionRevokedInRedis = async (sessionIds) => {
  if (!redisClient?.isOpen) return;

  const ids = Array.isArray(sessionIds) ? sessionIds : [sessionIds];
  if (ids.length === 0) return;

  // How long a revocation tombstone outlives in Redis before expiring.
  // SESSION_REVOKED_TOMBSTONE_TTL accepts "300", "30s", "5m", … (seconds).
  const REVOKED_TOMBSTONE_TTL_SECONDS = durationFromEnv(
    "SESSION_REVOKED_TOMBSTONE_TTL",
    5 * 60,
  );

  await Promise.all(
    ids.map((sessionId) =>
      redisClient.setEx(
        redisSessionKey(sessionId),
        REVOKED_TOMBSTONE_TTL_SECONDS,
        JSON.stringify({ revoked: true }),
      ),
    ),
  );
};