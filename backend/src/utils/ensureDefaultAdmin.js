// src/utils/ensureDefaultAdmin.js

import User from "../models/user.model.js";

/*
 * Startup bootstrap: guarantees the account named by DEFAULT_ADMIN_EMAIL
 * always has the admin role, so the "default admin" survives database
 * resets or accidental role changes.
 *
 * Deliberately promote-only: the account must already exist (registered
 * through the normal flow). It never creates accounts or sets passwords —
 * an unknown-credentials admin would be worse than no admin.
 */
export async function ensureDefaultAdmin() {
  const email = String(process.env.DEFAULT_ADMIN_EMAIL || "").toLowerCase().trim();
  if (!email) return;

  const user = await User.findOne({ email }).select("email role isVerified").lean();
  if (!user) {
    console.warn(`[bootstrap] DEFAULT_ADMIN_EMAIL (${email}) has no account yet — nothing promoted.`);
    return;
  }

  if (user.role !== "admin") {
    await User.updateOne({ _id: user._id }, { $set: { role: "admin" } });
    console.log(`[bootstrap] Promoted ${email} to admin (DEFAULT_ADMIN_EMAIL).`);
  }

  if (!user.isVerified) {
    console.warn(`[bootstrap] Default admin ${email} is not email-verified — admin login stays blocked until verified.`);
  }
}
