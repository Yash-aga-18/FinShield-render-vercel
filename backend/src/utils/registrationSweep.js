// src/utils/registrationSweep.js

import User from "../models/user.model.js";
import { logAuditEvent, AUDIT_EVENTS } from "./auditLog.js";
import { durationFromEnv } from "./env.js";

/* Registration now holds its details in Redis and creates the account only
   when the emailed code is confirmed — an abandoned registration never
   reaches the database. Records with isVerified=false are therefore
   leftovers from the earlier create-then-verify flow; this sweep clears
   them so they can't linger in the users list (or hold the unique email
   index) forever. Anyone purged can simply register again.

   It runs lazily wherever husks would be visible or created: on register
   and on the admin users list. */

const GRACE_SECONDS = durationFromEnv(
  "UNVERIFIED_ACCOUNT_GRACE", // how long an unverified husk is kept before purging
  24 * 60 * 60,
);

export async function purgeExpiredRegistrations(req = null) {
  const cutoff = new Date(Date.now() - GRACE_SECONDS * 1000);
  const result = await User.deleteMany({
    isVerified: false,
    createdAt: { $lt: cutoff },
  }).catch((error) => {
    // The sweep must never fail the request it piggybacks on — a purge
    // failure just means the next call tries again.
    console.error("Registration sweep failed:", error.message);
    return null;
  });

  const purged = result?.deletedCount ?? 0;
  if (purged > 0) {
    // One summary event per sweep; the human-readable count rides in
    // `reason` (the only metadata field the audit allow-list keeps).
    logAuditEvent({
      event: AUDIT_EVENTS.USER_DELETED,
      req,
      metadata: {
        reason: `purged ${purged} unverified account${purged === 1 ? "" : "s"} — registration never completed within ${Math.round(GRACE_SECONDS / 3600)}h`,
      },
    });
  }
  return purged;
}
