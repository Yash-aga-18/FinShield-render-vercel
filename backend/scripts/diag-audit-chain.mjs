// Read-only audit chain diagnostics: walks the trail around a reported
// break and shows which link doesn't match. Takes the entry id from the
// dashboard warning. Usage:
//   MONGODB_URI="..." node scripts/diag-audit-chain.mjs <entryId>
// Never writes — diagnosis only.

import mongoose from "mongoose";
import { createHash } from "node:crypto";

const entryId = process.argv[2];
if (!entryId || !process.env.MONGODB_URI) {
  console.error("usage: MONGODB_URI=\"...\" node scripts/diag-audit-chain.mjs <entryId>");
  process.exit(1);
}

const AuditLog = mongoose.model(
  "AuditLog",
  new mongoose.Schema(
    {
      event: String,
      severity: String,
      userId: mongoose.Schema.Types.ObjectId,
      ipAddress: String,
      hash: String,
      prevHash: String,
      metadata: mongoose.Schema.Types.Mixed,
    },
    { strict: false },
  ),
  "auditlogs",
);

// Must mirror entryPayload() in src/utils/auditLog.js exactly (field order
// included) or every recomputed hash will be wrong.
const payload = (doc) =>
  [
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
const hashOf = (doc) => createHash("sha256").update(payload(doc)).digest("hex");

await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 15000 });

const total = await AuditLog.countDocuments({});
console.log(`total audit entries: ${total}`);

// The entry the dashboard named (the one whose prevHash doesn't match).
const reported = await AuditLog.findById(entryId).lean();
if (!reported) {
  console.log("reported entry not found");
} else {
  console.log("\n=== reported entry ===");
  console.log(JSON.stringify(reported, null, 2));
  console.log(`hash recomputes correctly: ${hashOf(reported) === reported.hash}`);

  // Who does it claim to chain to? Find that entry.
  const claimedPrev = await AuditLog.findOne({ hash: reported.prevHash }).lean();
  console.log(`\nprevHash points at: ${
    claimedPrev ? `${claimedPrev._id} (${claimedPrev.event}, ${claimedPrev.createdAt?.toISOString?.() ?? "?"})` : "NO entry with that hash — the predecessor is missing from the database"
  }`);

  // What actually precedes it in _id order?
  const actualPrev = await AuditLog.findOne({ _id: { $lt: reported._id } }).sort({ _id: -1 }).lean();
  if (actualPrev) {
    console.log(`entry before it in the collection: ${actualPrev._id} (${actualPrev.event}, ${actualPrev.createdAt?.toISOString?.() ?? "?"})`);
    console.log(`that entry's hash: ${actualPrev.hash}`);
    console.log(`links to predecessor: ${actualPrev.hash === reported.prevHash}`);
  }
}

// Show the neighbourhood for context.
console.log("\n=== entries around the break (10 before → 5 after) ===");
const around = await AuditLog.find({
  _id: reported
    ? { $lte: reported._id }
    : {},
})
  .sort({ _id: -1 })
  .limit(11)
  .lean();
for (const doc of [...around].reverse()) {
  const ok = hashOf(doc) === doc.hash;
  console.log(
    `${doc._id} ${doc.createdAt?.toISOString?.() ?? "?"} ${doc.event ?? "?"} ` +
    `hashOk=${ok} prev=${doc.prevHash?.slice(0, 12) ?? "-"} hash=${doc.hash?.slice(0, 12) ?? "-"}`,
  );
}

await mongoose.disconnect();
