// src/utils/deletionRisk.js

import { getRiskLevel, RISK_THRESHOLDS } from "./risk.js";
import { numberFromEnv } from "./env.js";

/* Risk-adaptive second channel for the admin user deletion.

   Whether a texted code is owed used to be a flat "admin has a verified
   phone" — every single deletion texted, no matter how quiet both parties
   were. The verdict is now derived from the risk of BOTH sides of the
   action, each read from live telemetry rather than trusted from the client:

     adminSessionRisk — the risk score of the session ACTUALLY making the
       request (a stolen cookie acting as the admin counts, not whatever
       their last clean login scored). Falls back to the stored last-login
       score when the session row carries none.

     targetRisk — the highest risk among the target's ACTIVE sessions (the
       liveliest thing the account is doing right now), falling back to
       their stored last-login score.

   The two are SUMMED (capped at the engine's ceiling): either side alone
   can pull the action into the challenge band, and a moderately risky
   admin touching a moderately risky account escalates past what either
   would have triggered alone.

   LOW     → the emailed step-up code (already enforced by route middleware)
             fully proves the admin; the deletion proceeds with no text.
   MEDIUM+ → the phone is the last word: after the emailed code, a texted
             code must also pass before the record goes away.

   DELETE_SMS_RISK_THRESHOLD (default: the engine's MEDIUM band) tunes where
   the text kicks in — 0 restores text-always for phone-holding admins. */

const SMS_THRESHOLD = numberFromEnv("DELETE_SMS_RISK_THRESHOLD", RISK_THRESHOLDS.MEDIUM);

const clampScore = (value) => {
  const score = Number(value);
  if (!Number.isFinite(score) || score < 0) return 0;
  return Math.min(100, Math.round(score));
};

export const DELETE_SMS_RISK_THRESHOLD = SMS_THRESHOLD;

/** Combined deletion-risk verdict for an admin deleting a user. */
export const assessDeletionRisk = ({ adminSessionRisk = 0, targetRisk = 0 } = {}) => {
  const admin = clampScore(adminSessionRisk);
  const target = clampScore(targetRisk);
  const score = Math.min(100, admin + target);
  const level = getRiskLevel(score);

  return {
    score,
    level,
    // MEDIUM band and up owes the texted code; below it the emailed
    // step-up already said everything a text would repeat.
    smsRequired: score >= SMS_THRESHOLD,
    // Human-readable basis — audit metadata only keeps `reason`, so this
    // is the one string that rides into the trail.
    basis: `deletion risk ${score} (${level}): admin session ${admin} + target ${target}`,
  };
};
