// session.model.js

import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true, // Speeds up queries searching all active sessions for a specific user
    },

    sessionId: {
      type: String,
      required: true,
      unique: true, // unique already creates the index for fast sessionId lookups
    },

    // HMAC-derived public identifier exposed to clients. Indexed so session
    // revocation by displayId is a single indexed lookup instead of a scan.
    displayId: {
      type: String,
      index: true,
    },

    refreshTokenHash: {
      type: String,
      required: true,
      select: false,
    },

    ipAddress: {
      type: String,
      default: null,
    },

    userAgent: {
      type: String,
      default: null,
    },

    device: {
      type: String,
      default: null,
    },

    lastUsedAt: {
      type: Date,
      default: Date.now,
    },

    // Risk score (0-100) and level computed at the sign-in that created this
    // session — the score that admitted it, after any step-up. Kept on the
    // session so the admin panel can show which devices came in on a shaky
    // login. Null on sessions created before the field existed.
    riskScore: {
      type: Number,
      default: null,
      min: 0,
      max: 100,
    },

    riskLevel: {
      type: String,
      default: null,
    },

    expiresAt: {
      type: Date,
      required: true,
      // index: true     // removed here to avoid the duplicate index warning with the TTL index below
    },

    revokedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

// TTL Index: Automatically removes expired session documents from MongoDB when expiresAt date is reached
sessionSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0 }
);

const Session = mongoose.model("Session", sessionSchema);
export default Session;