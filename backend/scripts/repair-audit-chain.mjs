// Audit chain repair — maintenance tool for a FORKED chain.
// When two app instances overlapped during a deploy (before the
// cross-process flush lock existed), the instance with the stale in-memory
// chain head appended an entry that skipped the other's entries. Every
// entry's own hash is still valid; only the links are wrong, so the fix is
// to re-walk the trail in _id order and recompute the affected links.
//
// This is deliberately a CLI tool, never a panel action: repairing the
// audit trail must be a conscious, logged administrative decision.
//
// Usage:
//   MONGODB_URI="..." [REDIS_URL="..."] node scripts/repair-audit-chain.mjs          # dry run
//   MONGODB_URI="..." [REDIS_URL="..."] node scripts/repair-audit-chain.mjs --apply   # write
//
// What it does on --apply:
//   1. Fixes prevHash/hash of every mislinked entry (content is untouched).
//   2. Appends an AUDIT_CHAIN_REPAIRED marker entry, properly chained.
//   3. Re-anchors the newest hash in Redis (best-effort).

import mongoose from "mongoose";
import { createHash } from "node:crypto";

const APPLY = process.argv.includes("--apply");
if (!process.env.MONGODB_URI) {
  console.error('usage: MONGODB_URI="..." [REDIS_URL="..."] node scripts/repair-audit-chain.mjs [--apply]');
  process.exit(1);
}

const GENESIS_HASH = "0".repeat(64);

// Must mirror entryPayload() in src/utils/auditLog.js exactly.
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

await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 15000 });
const collection = mongoose.connection.collection("auditlogs");

const all = await collection.find({}).sort({ _id: 1 }).toArray();
console.log(`total audit entries: ${all.length}`);

let expected = GENESIS_HASH;
let legacy = 0;
let checked = 0;
const fixes = [];
let marker = null;

for (const doc of all) {
  if (!doc.hash) {
    // Pre-chain legacy entry — the verifier skips these, so do we.
    legacy += 1;
    continue;
  }
  const correctHash = computeEntryHash({ ...doc, prevHash: expected });
  if ((doc.prevHash ?? null) !== expected || doc.hash !== correctHash) {
    fixes.push({
      _id: doc._id,
      event: doc.event,
      createdAt: doc.createdAt,
      oldPrev: (doc.prevHash ?? "").slice(0, 12),
      newPrev: expected.slice(0, 12),
      oldHash: doc.hash.slice(0, 12),
      newHash: correctHash.slice(0, 12),
    });
    if (APPLY) {
      await collection.updateOne(
        { _id: doc._id },
        { $set: { prevHash: expected, hash: correctHash } },
      );
    }
    expected = correctHash;
  } else {
    expected = doc.hash;
  }
  checked += 1;
}

if (fixes.length === 0) {
  console.log("chain is intact — nothing to repair.");
  await mongoose.disconnect();
  process.exit(0);
}

console.log(`\n${fixes.length} entr${fixes.length === 1 ? "y" : "ies"} need relinking:`);
for (const f of fixes) {
  console.log(
    `  ${f._id} ${f.createdAt?.toISOString?.() ?? "?"} ${f.event} ` +
    `prev ${f.oldPrev} → ${f.newPrev}, hash ${f.oldHash} → ${f.newHash}`,
  );
}

if (!APPLY) {
  console.log("\nDRY RUN — nothing was written. Re-run with --apply to repair.");
  await mongoose.disconnect();
  process.exit(0);
}

// The repair itself must be on the record: append a properly chained marker
// so any future verification shows the trail was maintained, not silently
// rewritten.
const now = new Date();
marker = {
  event: "AUDIT_CHAIN_REPAIRED",
  severity: "WARN",
  userId: null,
  sessionId: null,
  ipAddress: null,
  userAgent: "maintenance-script",
  method: null,
  path: null,
  metadata: {
    reason: `audit chain relinked after a fork caused by overlapping writers during a deploy; ${fixes.length} entries rehashed`,
    repairedCount: fixes.length,
    firstRepairedId: String(fixes[0]._id),
  },
  prevHash: expected,
  hash: null, // computed below
  createdAt: now,
  updatedAt: now,
};
marker.hash = computeEntryHash(marker);
await collection.insertOne(marker);
expected = marker.hash;
console.log(`\nrepaired ${fixes.length} links and appended AUDIT_CHAIN_REPAIRED (${marker._id}).`);

// Re-anchor the newest hash. If Redis is unreachable the anchor is simply
// absent until the app's next write — the verifier treats that as neutral.
if (process.env.REDIS_URL) {
  try {
    const { createClient } = await import("redis");
    const redis = createClient({ url: process.env.REDIS_URL });
    await redis.connect();
    await redis.set("audit:chain:head", expected);
    await redis.disconnect();
    console.log("Redis anchor updated.");
  } catch (err) {
    console.warn(`Redis anchor NOT updated (${err.message}) — the app will re-anchor on its next write.`);
  }
}

await mongoose.disconnect();
console.log("done.");
