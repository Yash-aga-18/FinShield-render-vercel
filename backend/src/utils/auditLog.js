// src/utils/auditLog.js

import { createHash } from "node:crypto";
import AuditLog from "../models/auditLog.model.js";
import { AUDIT_EVENTS, EVENT_SEVERITY } from "./auditEvents.js";
import { getClientIp } from "./ip.js";
import { redisClient } from "../config/redis.js";

export { AUDIT_EVENTS };

const safeString = (value, maxLength = 500) => {
  if (typeof value !== "string") {
    return null;
  }
  return value.length > maxLength ? value.slice(0, maxLength) : value;
};

/**
 * Enforces strict allow-list on metadata.
 * Explicitly rejects sensitive keys like passwords, tokens, hashes, and body objects.
 */
const sanitizeMetadata = (metadata) => {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return {};
  }

  const allowedFields = [
    "reason",
    "device",
    "previousDevice",
    "riskScore",
    "riskLevel",
    "riskAction",
    "attemptCount",
    "revokedCount",
    "route",
    "method",
    "provider",
    "errorName",
    "path",
    // OTP bookkeeping: which flow a code belonged to (registration, login,
    // step_up, password_reset) and how it was delivered.
    "purpose",
    "channel",
    // Short human-readable summary of a profile change, e.g.
    // 'name: "Jane" → "Jane Doe"'. Never contains secrets.
    "changes",
  ];

  const result = {};

  for (const field of allowedFields) {
    const value = metadata[field];

    if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean"
    ) {
      result[field] =
        typeof value === "string" ? safeString(value) : value;
    }
  }

  return result;
};

const getRequestContext = (req) => {
  if (!req) {
    return {
      ipAddress: null,
      userAgent: null,
      method: null,
      path: null,
    };
  }

  const rawIp = getClientIp(req);

  return {
    ipAddress: rawIp ? safeString(rawIp, 100) : null,
    userAgent:
      typeof req.get === "function"
        ? safeString(req.get("user-agent"), 1000)
        : null,
    method: typeof req.method === "string" ? req.method : null,
    path:
      typeof req.originalUrl === "string"
        ? safeString(req.originalUrl.split("?")[0], 1000)
        : null,
  };
};

/* ============================================================
   TAMPER-EVIDENT HASH CHAIN
   Every entry links to the previous one: hash = sha256 of the
   previous hash + a canonical serialization of the entry. The
   mongoose guards on the model stop the app from editing history,
   but they cannot stop someone writing to MongoDB directly — the
   chain can. verifyAuditChain() recomputes every link, so an
   edited field (hash mismatch), a deleted middle entry (broken
   link) or a stripped hash all surface. The newest hash is also
   anchored in Redis, so even deleting the trailing entries is
   noticed: the database alone cannot prove records that no longer
   exist were ever there, but the anchor can.
   ============================================================ */
const CHAIN_HEAD_KEY = "audit:chain:head";
const GENESIS_HASH = "0".repeat(64);

// Fixed field order → identical content always hashes identically, whatever
// the key order of the metadata object was when it went in.
const entryPayload = (doc) => [
  "v1",
  doc.prevHash ?? "",
  doc.userId ? String(doc.userId) : "",
  doc.sessionId ?? "",
  doc.event ?? "",
  doc.severity ?? "",
  doc.ipAddress ?? "",
  doc.userAgent ?? "",
  doc.method ?? "",
  doc.path ?? "",
  JSON.stringify(doc.metadata ?? {}),
].join("|");

const computeEntryHash = (doc) =>
  createHash("sha256").update(entryPayload(doc)).digest("hex");

// undefined = not loaded yet, null/64-hex = the newest persisted hash.
// Loaded lazily on the first flush so nothing needs to warm it at boot.
let chainHead = undefined;

/* Test hook: the suite wipes MongoDB between tests, so the in-memory head
   must be forgotten with it (it would otherwise point at deleted entries). */
export const resetAuditChain = () => {
  chainHead = undefined;
};

/* Walks the whole trail and recomputes every link. Entries written before
   the chain existed (no hash) are counted as legacy and skipped — an
   unhashed entry appearing AFTER the chain started is not legacy, it is
   an entry that lost its hash or was inserted outside the logger. */
export const verifyAuditChain = async () => {
  let expected = GENESIS_HASH;
  let checked = 0;
  let legacy = 0;

  const cursor = AuditLog.find({}).sort({ _id: 1 }).lean().cursor();
  for await (const doc of cursor) {
    if (!doc.hash) {
      if (checked > 0) {
        return {
          valid: false,
          reason: "entry_unhashed",
          detail: "an entry lost its hash or was inserted outside the audit logger",
          entryId: String(doc._id),
          event: doc.event,
          checked,
          legacy,
        };
      }
      legacy += 1;
      continue;
    }

    if ((doc.prevHash ?? null) !== expected) {
      return {
        valid: false,
        reason: "chain_broken",
        detail: "an entry is missing or was reordered",
        entryId: String(doc._id),
        event: doc.event,
        checked,
        legacy,
      };
    }

    if (doc.hash !== computeEntryHash(doc)) {
      return {
        valid: false,
        reason: "entry_modified",
        detail: "recorded content no longer matches its hash",
        entryId: String(doc._id),
        event: doc.event,
        checked,
        legacy,
      };
    }

    expected = doc.hash;
    checked += 1;
  }

  // Anchor check: the Redis copy of the newest hash survives trailing
  // deletions in MongoDB. A missing anchor (Redis restarted/flushed) is not
  // tampering — there is simply nothing to compare against.
  let anchor = "unavailable";
  if (redisClient?.isOpen) {
    try {
      const head = await redisClient.get(CHAIN_HEAD_KEY);
      if (head) {
        anchor = head === expected ? "matched" : "mismatch";
        if (anchor === "mismatch") {
          return {
            valid: false,
            reason: "entries_missing",
            detail: "the newest chain link in Redis does not match the database — trailing entries were deleted",
            checked,
            legacy,
          };
        }
      }
    } catch {
      /* the anchor is best-effort */
    }
  }

  return { valid: true, checked, legacy, anchor, lastHash: expected };
};

/* ============================================================
   BOUNDED WRITE QUEUE (backpressure control)
   Audit events are buffered and flushed to MongoDB in batches
   (insertMany) instead of one unbounded fire-and-forget insert
   per event. Under a login burst this caps concurrent inserts,
   and if the queue ever exceeds MAX_QUEUE_SIZE the oldest events
   are dropped (with a warning) rather than exhausting memory.
   ============================================================ */
const FLUSH_INTERVAL_MS = 100;
const FLUSH_BATCH_SIZE = 25;
const MAX_QUEUE_SIZE = 1000;
const pendingEvents = [];
let flushTimer = null;

// Batches are serialized through a promise chain: each batch is hashed and
// inserted in queue order, so the database's _id order always matches the
// chain order the hashes were computed in.
let flushChain = Promise.resolve();

const flushBatch = async () => {
  if (pendingEvents.length === 0) return;

  const batch = pendingEvents.splice(0, FLUSH_BATCH_SIZE);

  try {
    // First flush of this process: pick up where the persisted chain ended.
    if (chainHead === undefined) {
      const latest = await AuditLog.findOne({}, { hash: 1 }).sort({ _id: -1 });
      chainHead = latest?.hash || GENESIS_HASH;
    }

    for (const doc of batch) {
      doc.prevHash = chainHead;
      doc.hash = computeEntryHash(doc);
      chainHead = doc.hash;
    }

    const docs = await AuditLog.insertMany(batch, { ordered: false });

    // Anchor the newest hash (best-effort — a Redis outage must never
    // fail the audit write itself).
    if (redisClient?.isOpen) {
      await redisClient.set(CHAIN_HEAD_KEY, chainHead).catch(() => {});
    }

    if (process.env.NODE_ENV !== "production") {
      for (const doc of docs) {
        console.log(`[FinShield Audit] Event recorded: ${doc.event} (ID: ${doc._id})`);
      }
    }
  } catch (error) {
    console.error(`[FinShield Audit] Batch write failed (${batch.length} events lost):`, error.message);
    // The in-memory head can't be trusted after a failed insert — reload
    // it from whatever actually persisted on the next flush.
    chainHead = undefined;
  }

  // Keep draining while the queue is non-empty (e.g. after a burst).
  if (pendingEvents.length > 0) {
    scheduleFlush();
  }
};

const flushAuditQueue = () => {
  flushChain = flushChain.then(() => flushBatch());
  return flushChain;
};

const scheduleFlush = () => {
  if (!flushTimer) {
    flushTimer = setTimeout(() => {
      flushTimer = null;
      void flushAuditQueue();
    }, FLUSH_INTERVAL_MS);

    // Do not keep the process alive purely for pending audit writes;
    // graceful shutdown flushes explicitly.
    flushTimer.unref?.();
  }
};

/**
 * Drains the pending audit queue. Called on graceful shutdown and available
 * to callers that need to guarantee audit durability.
 */
export const flushAuditLogs = async () => {
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
  // Drain every batch synchronously in order.
  while (pendingEvents.length > 0) {
    await flushAuditQueue();
  }
};

/**
 * NON-BLOCKING, FAIL-SAFE AUDIT LOGGER
 * Enqueues events into the bounded write queue; response latency is
 * never affected by MongoDB availability.
 */
export const logAuditEvent = ({
  event,
  userId = null,
  sessionId = null,
  req = null,
  metadata = {},
}) => {
  try {
    const severity = EVENT_SEVERITY[event] || "INFO";

    if (!EVENT_SEVERITY[event]) {
      console.warn(`[FinShield Audit] Unmapped audit event '${event}', defaulting to INFO severity.`);
    }

    const requestContext = getRequestContext(req);

    const document = {
      userId: userId ? String(userId) : null,
      sessionId:
        typeof sessionId === "string" ? safeString(sessionId, 200) : null,
      event,
      severity,
      ipAddress: requestContext.ipAddress,
      userAgent: requestContext.userAgent,
      method: requestContext.method,
      path: requestContext.path,
      metadata: sanitizeMetadata(metadata),
    };

    // Enqueue into the bounded write queue (flushed in batches).
    if (pendingEvents.length >= MAX_QUEUE_SIZE) {
      pendingEvents.shift(); // backpressure: drop oldest, keep newest
      console.warn("[FinShield Audit] Queue full — oldest event dropped.");
    }
    pendingEvents.push(document);
    scheduleFlush();
  } catch (error) {
    console.error("[FinShield Audit] Logger execution error:", error.message);
  }
};