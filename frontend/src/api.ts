// API client for the FinShield backend.
// Cookie-based auth (httpOnly access/refresh cookies) + double-submit CSRF:
// the backend issues a non-HttpOnly `csrf_token` cookie; we echo its value
// back in the `x-csrf-token` header on every state-changing request.

export interface User {
  id: string;
  name: string;
  email: string;
  role?: "user" | "admin";
  hasPassword?: boolean;
  /** Phone number, MASKED by the API (last 4 digits only, e.g. "+•••••••1111").
      Present once added and verified via SMS OTP. */
  phoneNumber?: string | null;
  phoneVerified?: boolean;
  createdAt?: string;
  updatedAt?: string;
  /** Active (non-revoked, unexpired) sessions — admin list only. */
  activeSessions?: number;
  /** Last successful login, any device — admin list only. */
  lastLoginAt?: string | null;
  /** Highest risk score among the user's ACTIVE sessions, with its level —
      admin list only. Null when no active session carries a score. */
  riskScore?: number | null;
  riskLevel?: string | null;
}

export interface SessionInfo {
  id: string;
  device: string;
  ipAddress: string;
  createdAt: string;
  lastUsedAt: string;
  expiresAt: string;
  current: boolean;
}

export interface SessionHistoryEntry {
  id: string;
  device: string;
  ipAddress: string;
  createdAt: string;
  lastUsedAt: string;
  endedAt: string;
  reason: "revoked" | "expired";
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/* Single knob for where the backend lives — every request in the app goes
   through this. Empty by default: calls use relative paths and hit the same
   origin that serves the page (the Vite dev proxy forwards /api to Express
   locally; vercel.json rewrites forward it in production). Set VITE_API_URL
   to point elsewhere — but leave it EMPTY for this app: auth cookies are
   SameSite=Strict and the CSRF token is read from a same-origin cookie, so
   the backend must be reached through the frontend's own origin. */
export const API_BASE = (import.meta.env.VITE_API_URL ?? "").replace(/\/+$/, "");

function getCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

/** Bootstraps the CSRF token cookie from the server. `cache: "no-store"` is
    load-bearing: the endpoint's JSON body is constant, so any cached copy
    (browser or CDN) carries no Set-Cookie and would starve the app of the
    token it must read back from document.cookie. */
async function bootstrapCsrfToken(): Promise<void> {
  await fetch(`${API_BASE}/api/auth/csrf-token`, {
    credentials: "include",
    cache: "no-store",
  });
}

/** Drops a stale csrf_token cookie (expired, or signed by a rotated secret)
    so the next bootstrap actually reissues instead of no-op-ing against the
    value the server still considers valid. The cookie is non-HttpOnly by
    design, so this is allowed. */
function clearCsrfCookie(): void {
  document.cookie = "csrf_token=; Max-Age=0; Path=/; SameSite=Strict";
}

async function ensureCsrfToken(): Promise<string | null> {
  let token = getCookie("csrf_token");
  if (!token) {
    await bootstrapCsrfToken();
    token = getCookie("csrf_token");
  }
  return token;
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  retry?: boolean;
}

/** 401 error codes that mean "the access token is dead" — the only failures a
    silent refresh can fix. Every other 401 is the endpoint's own verdict
    (wrong OTP, wrong current password, step-up required) and replaying it
    after a refresh would re-run the check: a mistyped OTP code was being
    submitted TWICE, burning two of the five allowed attempts per typo. */
const TOKEN_LEVEL_401_ERRORS = new Set([
  "UNAUTHORIZED",
  "SESSION_INACTIVE",
  "INVALID_TOKEN_STRUCTURE",
  "MISSING_SESSION_ID",
]);

export async function api<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, retry = true } = options;

  const headers: Record<string, string> = {};
  if (body !== undefined) {
    // CSRF: double-submit the cookie value as a header.
    const csrf = await ensureCsrfToken();
    if (csrf) headers["x-csrf-token"] = csrf;
  }

  const res = await fetch(API_BASE + path, {
    method,
    credentials: "include",
    headers: body !== undefined ? { ...headers, "Content-Type": "application/json" } : headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    /* empty body */
  }

  // Access token expired — try one silent refresh, then replay the request.
  // Only token-level 401s qualify: a step-up challenge (STEP_UP_REQUIRED) or
  // an OTP verdict (INVALID) is not an expired token — refreshing and
  // replaying just repeats the challenge or re-submits the bad code, so those
  // go straight to the caller for the OTP modal / error display to handle.
  const payload = data as { error?: string } | null;

  // Stale/unreadable CSRF cookie: the request was rejected by middleware
  // BEFORE reaching the endpoint, so replaying has no side effects (an OTP
  // attempt was NOT consumed). Clear the cookie, force a fresh bootstrap,
  // and try exactly once more.
  if (
    res.status === 403 &&
    retry &&
    (payload?.error === "CSRF_TOKEN_MISSING" || payload?.error === "CSRF_TOKEN_INVALID")
  ) {
    clearCsrfCookie();
    await bootstrapCsrfToken();
    return api<T>(path, { ...options, retry: false });
  }

  if (
    res.status === 401 &&
    retry &&
    !path.includes("/api/auth/refresh") &&
    TOKEN_LEVEL_401_ERRORS.has(payload?.error ?? "")
  ) {
    const refreshed = await fetch(`${API_BASE}/api/auth/refresh`, {
      method: "POST",
      credentials: "include",
      headers: await (async () => {
        const csrf = await ensureCsrfToken();
        const refreshHeaders: Record<string, string> = {};
        if (csrf) refreshHeaders["x-csrf-token"] = csrf;
        return refreshHeaders;
      })(),
    });
    if (refreshed.ok) return api<T>(path, { ...options, retry: false });
  }

  if (!res.ok) {
    const message =
      (data as { message?: string } | null)?.message ?? `Request failed (${res.status})`;
    const error = new ApiError(res.status, message);
    // Attach the structured payload so callers can branch on error codes
    // (e.g. STEP_UP_REQUIRED, COOLDOWN) without string matching.
    (error as ApiError & { payload?: unknown }).payload = data;
    throw error;
  }
  return data as T;
}

/* ==================== Auth ==================== */

/** Input length policy (NAME_* / PASSWORD_* / OTP_CODE_LENGTH on the backend).
    The forms size their inputs and hints from this so the limits have exactly
    one source of truth. The result is cached after the first successful call
    — every page and dialog can ask without extra requests. */
export interface InputRules {
  success: boolean;
  nameMinLength: number;
  nameMaxLength: number;
  passwordMinLength: number;
  passwordMaxLength: number;
  otpCodeLength: number;
  /** Browser windows/tabs allowed at once (MAX_APP_WINDOWS on the backend).
      0 = the single-window guard is disabled. */
  maxWindows: number;
}

let inputRulesCache: Promise<InputRules> | null = null;

export function getInputRules() {
  if (!inputRulesCache) {
    inputRulesCache = api<InputRules>("/api/auth/input-rules").catch((err) => {
      // Don't cache failures — the next caller should retry.
      inputRulesCache = null;
      throw err;
    });
  }
  return inputRulesCache;
}

/** Common tail of every OTP-issuing response. */
interface OtpDeliveryInfo {
  /** Provider rejected the send (dev/console fallback) — the email never left. */
  deliveryWarning?: string;
  /** Dev-only (DEV_EXPOSE_RESET_LINK=true): the emailed code, echoed when
      mail delivery is console-only. Never present in production. */
  devCode?: string;
}

export function register(name: string, email: string, password: string) {
  return api<
    { success: boolean; message: string; expiresInSeconds?: number; resendCooldownSeconds?: number } &
      OtpDeliveryInfo
  >("/api/auth/register", {
    method: "POST",
    body: { name, email, password },
  });
}

/** The texted half of a challenge (admin sign-in / admin update confirmation).
    required=true means a texted code is expected at this point.
    staged=true (admin sign-in): the text has NOT gone out yet — it is sent
    only after the emailed code is confirmed. missingPhone=true means the
    admin has no verified number yet (email-only sign-in). */
export interface SmsOtpChallenge {
  required: boolean;
  staged?: boolean;
  missingPhone?: boolean;
  maskedPhone?: string;
  expiresInSeconds?: number;
  resendCooldownSeconds?: number;
  deliveryWarning?: string;
  devCode?: string;
}

/** The emailed half of the FIRST-time phone add: proves account ownership
    before the number is linked. */
export interface EmailCodeChallenge {
  required: boolean;
  email?: string;
  expiresInSeconds?: number;
  resendCooldownSeconds?: number;
  deliveryWarning?: string;
  devCode?: string;
}

export interface LoginResult {
  success: boolean;
  /** Present when the password was right but a second factor is required
      (admin sign-in always; risky logins otherwise) — no session is issued
      until the code is verified. */
  requireOtp?: boolean;
  message?: string;
  resendCooldownSeconds?: number;
  /** Provider rejected the send (dev/console fallback) — same semantics as
      the step-up send response. */
  deliveryWarning?: string;
  /** Dev-only (DEV_EXPOSE_RESET_LINK=true): the code, echoed when delivery
      is console-only. Never present in production. */
  devCode?: string;
  /** Which channel the single login code went out on. "sms" only when the
      caller asked for text AND a verified phone is on file. */
  otpChannel?: "email" | "sms";
  /** Present when the code could also have been texted (verified phone on
      file, non-admin): the masked number for a "send by text instead" link. */
  phoneChoice?: { maskedPhone: string };
  /** Admin sign-in: the texted-code challenge alongside the emailed one. */
  smsOtp?: SmsOtpChallenge;
  user?: { id: string; name: string; email: string; role?: "user" | "admin" };
  session?: { id: string; device: string };
}

/** otpChannel "sms" asks for the login code by text (needs a verified phone
    on the account) — the recovery path for an unreachable mailbox. */
export function login(email: string, password: string, otpChannel?: "sms") {
  return api<LoginResult>("/api/auth/login", {
    method: "POST",
    body: otpChannel ? { email, password, otpChannel } : { email, password },
  });
}

export function logout() {
  return api<{ success: boolean }>("/api/auth/logout", { method: "POST", body: {} });
}

/* ==================== Sessions ==================== */

export function getActiveSessions() {
  return api<{
    success: boolean;
    totalSessions: number;
    maxActiveSessions: number;
    sessions: SessionInfo[];
  }>("/api/sessions/active");
}

export function getSessionHistory(page = 1, limit = 20) {
  return api<{
    success: boolean;
    page: number;
    total: number;
    totalPages: number;
    totalHistory: number;
    history: SessionHistoryEntry[];
  }>(`/api/sessions/history?page=${page}&limit=${limit}`);
}

export function revokeSession(sessionId: string) {
  return api<{ success: boolean }>(`/api/sessions/${encodeURIComponent(sessionId)}`, {
    method: "DELETE",
    body: {},
  });
}

export function revokeAllSessions() {
  return api<{ success: boolean }>("/api/sessions/revoke-all", { method: "POST", body: {} });
}

/* ==================== Users ==================== */

// Backend user objects carry `_id`; normalize to `id` for the UI.
function normalizeUser(u: User & { _id?: string }): User {
  return { ...u, id: u.id ?? u._id ?? "" };
}

export async function getProfile() {
  const res = await api<{ success: boolean; user: User & { _id?: string } }>("/api/users/me");
  return { ...res, user: normalizeUser(res.user) };
}

export async function updateProfile(payload: { name?: string; email?: string }) {
  const res = await api<{ success: boolean; user: User & { _id?: string } }>("/api/users/me", {
    method: "PUT",
    body: payload,
  });
  return { ...res, user: normalizeUser(res.user) };
}

export function deleteProfile() {
  return api<{ success: boolean }>("/api/users/me", { method: "DELETE", body: {} });
}

/** Step 1 (no smsCode): validates the passwords and, when a verified phone
    is on file, texts a confirmation code to it (the emailed step-up code is
    demanded server-side before anything happens). Step 2 (with smsCode):
    verifies the text and applies the change. Accounts without a phone apply
    directly in step 1. */
export function changePassword(currentPassword: string, newPassword: string, smsCode?: string) {
  return api<
    {
      success: boolean;
      message: string;
      requireOtp?: boolean;
      /** Where the step-1 code was texted (last 4 digits only). */
      maskedPhone?: string;
      expiresInSeconds?: number;
      resendCooldownSeconds?: number;
    } & OtpDeliveryInfo
  >("/api/users/me/password", {
    method: "PUT",
    body: smsCode ? { currentPassword, newPassword, smsCode } : { currentPassword, newPassword },
  });
}

/* ==================== Phone number (SMS OTP) ==================== */

/** Staged, one code per screen. FIRST number: stage "email" (mailed
    account-ownership code — nothing is texted until it's confirmed with
    emailCode, because texts cost money), then stage "sms" (text to the new
    number). Changing an EXISTING number: for admins stage "admin_sms" comes
    first (text to the CURRENT number, confirmed with adminSmsCode), then
    stage "sms"; regular users go straight to stage "sms". Final step (with
    code): confirms the new number and saves it. Step-up (emailed code) is
    enforced server-side throughout. */
export function setPhoneNumber(
  phoneNumber: string,
  code?: string,
  extra?: { emailCode?: string; adminSmsCode?: string },
) {
  return api<
    {
      success: boolean;
      message: string;
      requireOtp?: boolean;
      /** Which code the UI should ask for next. */
      stage?: "email" | "admin_sms" | "sms";
      expiresInSeconds?: number;
      resendCooldownSeconds?: number;
      user?: { phoneNumber: string; phoneVerified: boolean };
      /** First add, email phase: the mailed account-ownership half. */
      emailChallenge?: EmailCodeChallenge;
      /** Admins changing an existing number: the texted half sent to the
          current number. */
      adminSms?: SmsOtpChallenge;
    } & OtpDeliveryInfo
  >("/api/users/me/phone", {
    method: "POST",
    body: {
      phoneNumber,
      ...(code ? { code } : {}),
      ...(extra?.emailCode ? { emailCode: extra.emailCode } : {}),
      ...(extra?.adminSmsCode ? { adminSmsCode: extra.adminSmsCode } : {}),
    },
  });
}

/** Step 1 (no code): texts a code to the number being removed — removal is
    confirmed on both channels (the strict step-up emailed code is demanded
    server-side too). Step 2 (with code): removes the number. */
export function removePhoneNumber(code?: string) {
  return api<
    {
      success: boolean;
      message: string;
      requireOtp?: boolean;
      /** Where the step-1 code was texted (last 4 digits only). */
      maskedPhone?: string;
      expiresInSeconds?: number;
      resendCooldownSeconds?: number;
    } & OtpDeliveryInfo
  >("/api/users/me/phone", {
    method: "DELETE",
    body: code ? { code } : {},
  });
}

/* ==================== Email change (OTP to the NEW address) ==================== */

/** Step 1 (no code): mails a confirmation code to the NEW address (stage
    "email"). Step 2 (with code): confirms that code — for admins with a
    verified phone this issues the text to the CURRENT number (stage "sms"
    with the adminSms challenge) instead of applying; regular users apply
    here. Final step (with smsCode, admins): the texted code applies the
    change. Strict step-up (a fresh emailed code) is required server-side for
    every step. */
export function setEmailAddress(newEmail: string, code?: string, smsCode?: string) {
  return api<
    {
      success: boolean;
      message: string;
      requireOtp?: boolean;
      /** Which code the UI should ask for next. */
      stage?: "email" | "sms";
      expiresInSeconds?: number;
      resendCooldownSeconds?: number;
      user?: { email: string };
      /** Admins: the texted half sent to the current number. */
      adminSms?: SmsOtpChallenge;
    } & OtpDeliveryInfo
  >("/api/users/me/email", {
    method: "POST",
    body: {
      newEmail,
      ...(code ? { code } : {}),
      ...(smsCode ? { smsCode } : {}),
    },
  });
}

/* ==================== Password recovery ==================== */

export function forgotPassword(email: string) {
  return api<{ success: boolean; message: string; devResetUrl?: string }>(
    "/api/auth/forgot-password",
    { method: "POST", body: { email } },
  );
}

// Step 1 (no code): backend validates the link + password and emails an OTP;
// the response carries requireOtp (plus smsRequired when a verified phone
// makes the reset two-channel). Step 2 (with code): the password changes —
// smsCode alongside the emailed code when the account has a verified phone.
export function resetPassword(token: string, newPassword: string, code?: string, smsCode?: string) {
  return api<{
    success: boolean;
    message: string;
    requireOtp?: boolean;
    smsRequired?: boolean;
    smsPhone?: string;
    expiresInSeconds?: number;
    resendCooldownSeconds?: number;
    smsDevCode?: string;
  } & OtpDeliveryInfo>("/api/auth/reset-password", {
    method: "POST",
    body:
      code !== undefined || smsCode !== undefined
        ? { token, newPassword, ...(code !== undefined && { code }), ...(smsCode !== undefined && { smsCode }) }
        : { token, newPassword },
  });
}

/* ==================== Email OTP ==================== */

export function resendRegistrationOtp(email: string) {
  return api<{
    success: boolean;
    message: string;
    expiresInSeconds?: number;
    resendCooldownSeconds?: number;
  } & OtpDeliveryInfo>("/api/auth/otp/registration/resend", { method: "POST", body: { email } });
}

export function verifyRegistrationOtp(email: string, code: string) {
  return api<{
    success: boolean;
    user: { id: string; name: string; email: string; role?: "user" | "admin" };
  }>("/api/auth/otp/registration/verify", { method: "POST", body: { email, code } });
}

/** Admins with a verified phone confirm sign-in SEQUENTIALLY, one code per
    screen: the emailed `code` first — a valid one returns stage "sms" with a
    fresh texted challenge (no session yet); the texted `smsCode` then
    finishes the sign-in. Regular risky logins verify a single code
    (otpChannel "sms" marks a user who took the single login code by text). */
export function verifyLoginOtp(
  email: string,
  code: string,
  rememberDevice: boolean,
  smsCode?: string,
  otpChannel?: "sms",
) {
  return api<{
    success: boolean;
    /** Set when the emailed half passed but the texted half is still owed. */
    requireOtp?: boolean;
    stage?: "sms";
    message?: string;
    smsOtp?: SmsOtpChallenge;
    user?: { id: string; name: string; email: string; role?: "user" | "admin" };
    session?: { id: string; device: string };
  }>("/api/auth/otp/login/verify", {
    method: "POST",
    body:
      smsCode || otpChannel
        ? { email, code, rememberDevice, ...(smsCode ? { smsCode } : {}), ...(otpChannel ? { otpChannel } : {}) }
        : { email, code, rememberDevice },
  });
}

/** Re-send the login code for the stage the user is on: channel "sms"
    re-texts (admin second half, or a regular user who chose text), anything
    else re-mails. */
export function resendLoginOtp(email: string, channel?: "sms") {
  return api<
    {
      success: boolean;
      message: string;
      expiresInSeconds?: number;
      resendCooldownSeconds?: number;
    } & OtpDeliveryInfo
  >("/api/auth/otp/login/resend", {
    method: "POST",
    body: channel ? { email, channel } : { email },
  });
}

/* ==================== Step-up authentication ==================== */

export function sendStepUpOtp(action?: string) {
  return api<{
    success: boolean;
    message: string;
    resendCooldownSeconds?: number;
    /** Dev-only (DEV_EXPOSE_RESET_LINK=true): the emailed code, shown in the
        modal when mail delivery is console-only. Never present in production. */
    devCode?: string;
    /** Provider rejected the send (e.g. Brevo blocking an unrecognized IP) —
        the email never left; the code only exists in the server console. */
    deliveryWarning?: string;
  }>("/api/auth/step-up/send", { method: "POST", body: action ? { action } : {} });
}

export function verifyStepUpOtp(code: string) {
  return api<{ success: boolean; message: string }>("/api/auth/step-up/verify", {
    method: "POST",
    body: { code },
  });
}

/** Sortable columns of the admin users table. "active" and "risk" sort on
    values the backend computes from each user's active sessions. */
export type AdminUserSort = "registered" | "lastLogin" | "active" | "risk" | "name" | "email";

export async function getAllUsers(
  page = 1,
  limit = 100,
  sort: AdminUserSort = "registered",
  order: "asc" | "desc" = "desc",
  search = "",
) {
  const params = new URLSearchParams({
    page: String(page),
    limit: String(limit),
    sort,
    order,
  });
  if (search.trim()) params.set("search", search.trim());
  const res = await api<{
    success: boolean;
    page: number;
    limit: number;
    sort: AdminUserSort;
    order: "asc" | "desc";
    total: number;
    totalPages: number;
    users: (User & { _id?: string })[];
  }>(`/api/users?${params.toString()}`);
  return { ...res, users: res.users.map(normalizeUser) };
}

/* ==================== Admin ==================== */

export interface AdminSession {
  id: string;
  userId: string;
  userName: string;
  userEmail: string;
  device: string;
  ipAddress: string;
  createdAt: string;
  lastUsedAt: string;
  expiresAt: string;
  /** Risk score (0-100) at the sign-in that created this session. Null on
      sessions created before risk was stored on the session. */
  riskScore: number | null;
  riskLevel: string | null;
}

/** Sortable columns of the admin sessions table. */
export type AdminSessionSort = "lastUsed" | "signedIn" | "risk" | "expires";

export function getAllActiveSessions(
  page = 1,
  limit = 50,
  sort: AdminSessionSort = "lastUsed",
  order: "asc" | "desc" = "desc",
) {
  return api<{
    success: boolean;
    page: number;
    limit: number;
    sort: AdminSessionSort;
    order: "asc" | "desc";
    total: number;
    totalPages: number;
    sessions: AdminSession[];
  }>(`/api/admin/sessions?page=${page}&limit=${limit}&sort=${sort}&order=${order}`);
}

export function adminRevokeSession(sessionId: string) {
  return api<{ success: boolean; message: string }>(
    `/api/admin/sessions/${encodeURIComponent(sessionId)}`,
    { method: "DELETE", body: {} },
  );
}

export function adminRevokeUserSessions(userId: string) {
  return api<{ success: boolean; message: string }>(
    `/api/admin/users/${encodeURIComponent(userId)}/revoke-sessions`,
    { method: "POST", body: {} },
  );
}

export function adminDeleteUser(userId: string) {
  return api<{ success: boolean; message: string }>(
    `/api/admin/users/${encodeURIComponent(userId)}`,
    { method: "DELETE", body: {} },
  );
}

/** Promote to admin or demote to user. Step-up (emailed OTP) is required for
    both directions; demotion also revokes the target's sessions server-side. */
export function adminChangeUserRole(userId: string, role: "admin" | "user") {
  return api<{ success: boolean; message: string; revokedCount?: number }>(
    `/api/admin/users/${encodeURIComponent(userId)}/role`,
    { method: "PATCH", body: { role } },
  );
}

/* ==================== Admin: user activity ==================== */

export interface UserActivityEvent {
  id: string;
  event: string;
  severity: string;
  ipAddress: string | null;
  device: string | null;
  reason: string | null;
  riskLevel: string | null;
  createdAt: string;
}

export interface UserActivity {
  user: {
    id: string;
    name: string;
    email: string;
    role: "user" | "admin";
    isVerified: boolean;
    createdAt: string;
    lastLoginAt: string | null;
    /** Masked phone number, or null when no number is linked. */
    phoneNumber: string | null;
    phoneVerified: boolean;
    /** True when the account signs in with Google (possibly alongside a password). */
    hasGoogle: boolean;
    /** Account-level risk from the most recent sign-in (0/LOW when no history). */
    riskScore: number;
    riskLevel: string;
    activeSessions: number;
    totalSessions: number;
  };
  events: UserActivityEvent[];
}

export function getUserActivity(userId: string) {
  return api<UserActivity>(
    `/api/users/${encodeURIComponent(userId)}/activity?limit=30`,
  );
}

/* ==================== Admin: audit integrity ==================== */

/** Verdict of the audit-trail integrity check: the backend recomputes the
    hash chain over every audit entry and reports the first broken link.
    Admins can read this verdict but can never repair a broken chain. */
export type AuditIntegrity = {
  valid: boolean;
  /** Failure cause when valid is false: entry_modified | chain_broken |
      entries_missing | entry_unhashed. */
  reason?: string;
  /** Human-readable sentence describing the failure. */
  detail?: string;
  entryId?: string;
  event?: string;
  /** How many chained entries were verified. */
  checked: number;
  /** Entries written before the chain existed — always skipped. */
  legacy: number;
  /** Redis anchor of the newest hash; it survives trailing deletions in
      MongoDB. "unavailable" means Redis was flushed/restarted — not
      tampering. */
  anchor: "matched" | "mismatch" | "unavailable";
  lastHash?: string;
};

export function getAuditIntegrity() {
  return api<{ success: boolean; integrity: AuditIntegrity }>("/api/admin/audit/integrity");
}
