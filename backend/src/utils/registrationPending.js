// src/utils/registrationPending.js

import { createHash } from "node:crypto";
import { redisClient } from "../config/redis.js";
import { OTP_TTL_SECONDS } from "./otp.js";

/* Registration writes NOTHING to the users collection until the emailed
   code is confirmed. The submitted details live in Redis — under an
   email-derived key with the same TTL as the code itself — and the account
   is created at verify time. A user who never enters the code therefore
   never existed as far as the database (and the admin panel) is concerned.

   The OTP machinery (issueOtp / verifyOtp) keys everything on a user id, so
   pending registrations use a deterministic pseudo id derived from the
   email: 24 hex chars = a valid ObjectId shape, stable per address, which
   also keeps the resend cooldown per-email across attempts. */

export const pendingSubjectId = (email) =>
  createHash("sha256").update(String(email).toLowerCase().trim()).digest("hex").slice(0, 24);

const pendingKey = (email) => `reg:pending:${pendingSubjectId(email)}`;

/** The pseudo-user handed to issueOtp/verifyOtp for a pending registration:
    _id is the email-derived subject, email is the delivery target. */
export const pendingUser = (email) => ({
  _id: pendingSubjectId(email),
  email: String(email).toLowerCase().trim(),
});

/** Stores the submitted details. Returns false when Redis is down — callers
    must refuse to register then (there would be nowhere to hold the data). */
export async function savePendingRegistration({ name, email, passwordHash }) {
  if (!redisClient?.isOpen) return false;
  await redisClient.setEx(
    pendingKey(email),
    Math.ceil(OTP_TTL_SECONDS),
    JSON.stringify({ name, email: String(email).toLowerCase().trim(), passwordHash }),
  );
  return true;
}

/** The pending details for an email, or null when none is outstanding
    (never registered, verified already, or the code expired). */
export async function getPendingRegistration(email) {
  if (!redisClient?.isOpen) return null;
  const raw = await redisClient.get(pendingKey(email));
  return raw ? JSON.parse(raw) : null;
}

/** Drops the pending payload — called once the account exists for real. */
export async function deletePendingRegistration(email) {
  if (!redisClient?.isOpen) return;
  await redisClient.del(pendingKey(email));
}
