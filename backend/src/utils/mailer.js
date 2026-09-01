// src/utils/mailer.js

/*
 * Email delivery.
 *
 * Providers, in order of preference (set exactly one in .env):
 *   RESEND_API_KEY   — resend.com, 100 emails/day free, no SMTP hassle.
 *                      HTTP API via fetch, no SDK needed.
 *   BREVO_API_KEY    — brevo.com, 300 emails/day free, same HTTP pattern.
 *
 * With neither set, emails fall back to the server console — the flow stays
 * fully testable in development without any external account.
 *
 * Dev-only escape hatch: DEV_EXPOSE_RESET_LINK=true also returns links/OTPs
 * in API responses so the flows can be exercised without opening the console.
 */

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";

const FROM_ADDRESS = process.env.MAIL_FROM || "FinShield <onboarding@resend.dev>";

const RESEND_ENDPOINT = "https://api.resend.com/emails";
const BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email";

export function buildResetUrl(rawToken) {
  return `${FRONTEND_URL}/reset-password?token=${encodeURIComponent(rawToken)}`;
}

/* ============================================================
   Transport
   ============================================================ */

const sendViaResend = async (subject, html, text) => {
  const res = await fetch(RESEND_ENDPOINT, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ from: FROM_ADDRESS, to: [emailTarget], subject, html, text }),
  });
  if (!res.ok) {
    throw new Error(`Resend delivery failed (${res.status}): ${await res.text()}`);
  }
};

// MAIL_FROM looks like "FinShield <noreply@yourdomain.com>" — Brevo wants
// name and address as separate fields.
const parseFrom = () => {
  const match = FROM_ADDRESS.match(/^(.*?)\s*<(.+)>$/);
  return match ? { name: match[1] || "FinShield", email: match[2] } : { name: "FinShield", email: FROM_ADDRESS };
};

const sendViaBrevo = async (subject, html, text) => {
  const res = await fetch(BREVO_ENDPOINT, {
    method: "POST",
    headers: {
      "api-key": process.env.BREVO_API_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ sender: parseFrom(), to: [{ email: emailTarget }], subject, htmlContent: html, textContent: text }),
  });
  if (!res.ok) {
    throw new Error(`Brevo delivery failed (${res.status}): ${await res.text()}`);
  }
};

// Email templates live here so every provider sends the same content.
const template = (title, bodyLines, footer) => `
  <div style="font-family:Georgia,serif;max-width:480px;margin:0 auto;padding:32px;
              background:#faf7f2;border:1px solid #e3ddd2;color:#1c1a17;">
    <h2 style="margin:0 0 16px;font-size:20px;">${title}</h2>
    ${bodyLines.map((line) => `<p style="margin:0 0 12px;font-size:14px;line-height:1.6;">${line}</p>`).join("")}
    ${footer}
    <p style="margin-top:32px;font-size:11px;color:#8a8378;">
      You received this email because a FinShield account exists for this address.
    </p>
  </div>`;

const otpBlock = (code) => `
  <div style="margin:24px 0;padding:16px;text-align:center;background:#e8efe9;
              border:1px solid #1a4a3a;border-radius:4px;font-size:28px;
              letter-spacing:8px;font-weight:600;color:#1a4a3a;">${code}</div>`;

// Which address the current send() call targets (set by sendEmail).
let emailTarget = null;

// In-memory record of test-mode sends — lets the suite assert "this email
// went out" without touching a real provider. Test environment only.
const testOutbox = [];
export const getTestOutbox = () => testOutbox;
export const clearTestOutbox = () => {
  testOutbox.length = 0;
};

const sendEmail = async (to, subject, html, text) => {
  emailTarget = to;

  // Tests must never talk to a real mail provider (quota burn, network
  // flakiness, and providers reject example.com addresses anyway). The
  // console fallback is deterministic and shows up in test output.
  if (process.env.NODE_ENV === "test") {
    testOutbox.push({ to, subject, text });
    console.log(`[mailer:test] To: ${to} — ${subject}`);
    return { channel: "test" };
  }

  if (process.env.RESEND_API_KEY) {
    try {
      await sendViaResend(subject, html, text);
      // One quiet line so "did it really send?" is answerable from the logs.
      console.log(`[mailer] Sent via Resend to ${to} — "${subject}"`);
      return { channel: "resend" };
    } catch (error) {
      if (process.env.NODE_ENV === "production") throw error;
      // Dev: the provider rejected the send (unverified sender, account not
      // activated yet, …). Fall through to the console so local flows keep
      // working instead of hard-failing every registration.
      console.warn(`[mailer] Resend send failed, falling back to console: ${error.message}`);
      return { channel: "console", warning: error.message };
    }
  }
  if (process.env.BREVO_API_KEY) {
    try {
      await sendViaBrevo(subject, html, text);
      console.log(`[mailer] Sent via Brevo to ${to} — "${subject}"`);
      return { channel: "brevo" };
    } catch (error) {
      if (process.env.NODE_ENV === "production") throw error;
      console.warn(`[mailer] Brevo send failed, falling back to console: ${error.message}`);
      return { channel: "console", warning: error.message };
    }
  }

  // Development fallback — no external account needed.
  console.log("──────────────────────────────────────────────────");
  console.log(`[mailer] To: ${to}`);
  console.log(`[mailer] Subject: ${subject}`);
  console.log(`[mailer] ${text}`);
  console.log("──────────────────────────────────────────────────");
  return { channel: "console" };
};

/* ============================================================
   Message types
   ============================================================ */

export async function sendPasswordResetEmail(email, resetUrl) {
  const link = `<p style="margin:24px 0;"><a href="${resetUrl}" style="background:#1a4a3a;color:#faf7f2;padding:12px 24px;text-decoration:none;border-radius:4px;display:inline-block;">Choose a new password</a></p>`;
  const text = `Password reset requested. Open this link (valid 15 minutes): ${resetUrl}`;
  await sendEmail(
    email,
    "Reset your FinShield password",
    template(
      "Reset your password",
      ["We received a request to reset the password on your FinShield account.", link, "The link expires in 15 minutes and can be used only once."],
      "",
    ),
    text,
  );
}

/* HTML-escape before interpolating caller-supplied text (action labels)
   into the HTML template — never trust what goes into an email body. */
const escapeHtml = (text) =>
  String(text).replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[ch]);

export async function sendOtpEmail(email, code, purpose, actionLabel = "", expiryMinutes = 10) {
  const purposeLine =
    purpose === "registration"
      ? "Enter this code to finish creating your FinShield account."
      : purpose === "login"
        ? "Enter this code to finish signing in. It was requested because we detected unusual activity on this login."
        : purpose === "password_reset"
          ? "Enter this code to confirm your new password. Your password is not changed until this code is confirmed."
          : purpose === "email_verify"
            ? "Enter this code to confirm this address should become your FinShield account email. Nothing changes until this code is confirmed."
            : actionLabel
              ? `Enter this code to ${actionLabel}.`
              : "Enter this code to confirm this sensitive action.";

  const text = `Your FinShield verification code is ${code}. It expires in ${expiryMinutes} minutes. ${purposeLine}`;
  // Return the delivery result (channel/warning) so callers can report
  // provider failures instead of silently assuming the email left.
  return sendEmail(
    email,
    "Your FinShield verification code",
    // actionLabel is caller-supplied: escape it for the HTML template.
    template("Your verification code", [escapeHtml(purposeLine), otpBlock(code), `This code expires in ${expiryMinutes} minutes. If you didn't request it, you can safely ignore this email.`], ""),
    text,
  );
}

/* Confirmation sent to the acting admin after a destructive admin-panel
   action (session revocation, user deletion). Fire-and-forget from the
   controllers — a mail outage must never fail the admin action itself. */
export async function sendAdminActionEmail(to, { action, targetEmail, revokedCount = null, newRole = null }) {
  const actionTitle =
    action === "sessions_revoked"
      ? `Sessions revoked for ${targetEmail}`
      : action === "user_deleted"
        ? `User deleted: ${targetEmail}`
        : action === "role_changed"
          ? `Role changed for ${targetEmail}: now ${newRole}`
          : `Admin action on ${targetEmail}`;

  const detailLine =
    action === "sessions_revoked"
      ? `All ${revokedCount ?? 0} active session(s) for ${targetEmail} were invalidated at ${new Date().toUTCString()}. They will need to sign in again on every device.`
      : action === "user_deleted"
        ? `The account ${targetEmail} and all of its sessions were permanently deleted at ${new Date().toUTCString()}. This cannot be undone.`
        : action === "role_changed"
          ? `The account ${targetEmail} was ${newRole === "admin" ? "promoted to admin" : "demoted to a regular user"} at ${new Date().toUTCString()}.${newRole === "user" ? " All of their sessions were revoked — they must sign in again, and the admin role only takes effect at sign-in." : " The new role takes effect the next time they sign in."}`
          : `An administrative action was taken on ${targetEmail} at ${new Date().toUTCString()}.`;

  const text = `${actionTitle}. ${detailLine}`;
  await sendEmail(
    to,
    `FinShield admin — ${actionTitle}`,
    template(actionTitle, [detailLine], ""),
    text,
  );
}

export function shouldExposeResetLink() {
  // Read at call time (not module load) so tests / runtime toggles work.
  return process.env.DEV_EXPOSE_RESET_LINK === "true";
}

/* Security alert: the account was just signed in to. Sent on EVERY
   successful sign-in (password, Google, or OTP) — like Google's "new
   sign-in" mails, the owner always knows their account was accessed,
   not only when a device is new. Not a second factor and not a block —
   the sign-in already succeeded by the time this is sent; the point is
   speed of detection. The panic link is single-use and short-lived: one
   click signs out every device and starts a password reset, so a stolen
   password (and OTP) is worth minutes to the attacker instead of days.
   Sent fire-and-forget by the login flow; a mail outage must never fail
   the sign-in itself. */
export async function sendSigninDetectedEmail(to, { device, ipAddress, when, provider = null, panicUrl }) {
  const via = provider === "google" ? "Google sign-in" : "email and password";
  const detailRows = [
    ["When", when],
    ["Signed in via", via],
    ["Device", device || "Unknown device"],
    ...(ipAddress ? [["IP address", ipAddress]] : []),
  ]
    .map(
      ([label, value]) =>
        `<tr><td style="padding:6px 12px 6px 0;color:#8a8378;">${label}</td>` +
        `<td style="padding:6px 0;color:#1c1a17;text-align:right;">${escapeHtml(value)}</td></tr>`,
    )
    .join("");

  const sessionsUrl = `${FRONTEND_URL}/sessions`;
  const panicBlock = panicUrl
    ? `<p style="margin:24px 0;padding:16px;background:#fdf3f2;border:1px solid #b3261e;border-radius:4px;">` +
      `If this wasn&rsquo;t you, act now — <a href="${panicUrl}" style="color:#b3261e;font-weight:600;">sign out everywhere and change your password</a>. ` +
      `This link works once and expires in 30 minutes.</p>`
    : "";
  const link = `<p style="margin:24px 0;"><a href="${sessionsUrl}" style="background:#1a4a3a;color:#faf7f2;padding:12px 24px;text-decoration:none;border-radius:4px;display:inline-block;">Review your sessions</a></p>`;

  const text = `Sign-in detected on your FinShield account. ${when} — ${device || "unknown device"}${ipAddress ? `, IP ${ipAddress}` : ""}, via ${via}. If this was you, no action needed. If this wasn't you, open ${panicUrl} to sign out everywhere and change your password (single-use link, valid 30 minutes), or review sessions at ${sessionsUrl}.`;

  await sendEmail(
    to,
    "Sign-in detected on your FinShield account",
    template(
      "Sign-in detected",
      [
        "We noticed a successful sign-in to your FinShield account.",
        `<table style="width:100%;border-collapse:collapse;">${detailRows}</table>`,
        '<strong style="color:#1c1a17;">If this was you</strong> — no action needed; you can ignore this email.',
        panicBlock,
        link,
      ],
      "",
    ),
    text,
  );
}
