// auditLog.model.js
// src/models/auditLog.model.js

import mongoose from "mongoose";
import { AUDIT_EVENTS } from "../utils/auditEvents.js";

const AUDIT_SEVERITIES = [
  "INFO",
  "WARN",
  "ERROR",
  "HIGH",
  "CRITICAL",
];

const auditLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
      index: true,
      set: (v) => (mongoose.Types.ObjectId.isValid(v) ? v : null),
    },

    sessionId: {
      type: String,
      default: null,
      index: true,
    },

    event: {
      type: String,
      enum: Object.values(AUDIT_EVENTS),
      required: true,
      index: true,
    },

    severity: {
      type: String,
      enum: AUDIT_SEVERITIES,
      required: true,
      index: true,
    },

    ipAddress: {
      type: String,
      default: null,
    },

    userAgent: {
      type: String,
      default: null,
    },

    method: {
      type: String,
      default: null,
    },

    path: {
      type: String,
      default: null,
    },

    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    // Tamper-evidence: each entry stores the hash of the previous entry and
    // a sha256 over its own content + that link (see utils/auditLog.js).
    // The mongoose guards below block the app itself; the chain is what
    // exposes edits made directly in the database. Entries written before
    // the chain existed simply keep null here and are skipped by the
    // integrity check.
    prevHash: {
      type: String,
      default: null,
    },

    hash: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

/*
 * Audit records are append-only.
 * Application code must never modify or delete an audit record.
 */

// Block document mutation on existing save
auditLogSchema.pre("save", function () {
  if (!this.isNew) {
    throw new Error("Audit logs are immutable");
  }
});

// Block update operations by throwing directly
const blockModification = function () {
  throw new Error("Audit logs are immutable");
};

auditLogSchema.pre("updateOne", blockModification);
auditLogSchema.pre("updateMany", blockModification);
auditLogSchema.pre("findOneAndUpdate", blockModification);
auditLogSchema.pre("findOneAndReplace", blockModification);

// Block delete operations by throwing directly
auditLogSchema.pre("deleteOne", blockModification);
auditLogSchema.pre("deleteMany", blockModification);
auditLogSchema.pre("findOneAndDelete", blockModification);

// Performance & Investigation Indexes
auditLogSchema.index({ userId: 1, createdAt: -1 });
auditLogSchema.index({ event: 1, createdAt: -1 });
auditLogSchema.index({ severity: 1, createdAt: -1 });

const AuditLog = mongoose.model("AuditLog", auditLogSchema);

export default AuditLog;