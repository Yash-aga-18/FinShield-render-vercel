// user.model.js

import mongoose from "mongoose";
import { NAME_MIN_LENGTH, NAME_MAX_LENGTH } from "../utils/namePolicy.js";

const userSchema = new mongoose.Schema({
    name: {
      type: String,
      required: true,
      trim: true,
      // Same env-driven policy the controllers validate with, so the model
      // can never reject something zod already accepted (or vice versa).
      minlength: NAME_MIN_LENGTH,
      maxlength: NAME_MAX_LENGTH,
    },

    // Phone number in E.164 format (e.g. +919876543210). Optional: only
    // admins need one (their sign-in demands a texted code on top of the
    // emailed one). Sparse so multiple users may have no number at all —
    // and NO default: a stored null would defeat the sparse index (the
    // field must be ABSENT, not null, for the index to skip it).
    phoneNumber: {
      type: String,
      unique: true, // unique already creates the index
      sparse: true,
      trim: true,
    },

    // True only after the number's ownership was proven with a texted code —
    // an unverified number is never trusted as a second factor.
    phoneVerified: {
      type: Boolean,
      default: false,
    },

    email: {
      type: String,
      required: true,
      unique: true, // unique already creates the index
      lowercase: true,
      trim: true,
    },

    passwordHash: {
      type: String,
      // required: true,
      default: null,
      select: false,
    },

    googleId: {
      type: String,
      unique: true, // unique already creates the index
      sparse: true,
    },

    // One-time password-reset token (sha256 of the raw token emailed to the
    // user). Only the hash is stored; the raw token exists solely in the link.
    passwordResetTokenHash: {
      type: String,
      default: null,
    },
    passwordResetExpiresAt: {
      type: Date,
      default: null,
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },

    // Email ownership confirmed via OTP at registration time. Unverified
    // accounts cannot sign in.
    isVerified: {
      type: Boolean,
      default: false,
    },

    // Last successful login (any device) — surfaced in the admin panel's
    // user activity view. Not a security primitive, just an activity signal.
    lastLoginAt: {
      type: Date,
      default: null,
    },
},
{ timestamps: true }

);


const User = mongoose.model("User", userSchema);
export default User;
