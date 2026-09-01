import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../auth";
import {
  changePassword,
  deleteProfile,
  getInputRules,
  removePhoneNumber,
  setEmailAddress,
  setPhoneNumber,
  updateProfile,
  type EmailCodeChallenge,
  type SmsOtpChallenge,
} from "../api";
import { Button, ConfirmDialog, ErrorNote, Field, PageTitle, PasswordField, Stamp } from "../ui";
import { OtpInput, useCountdown, ResendButton } from "../otp";
import { useStepUp } from "../stepUp";

/* Country dial codes for the phone form. India is the only ACTIVE choice for
   now — the picker is frozen on it because the backend only accepts +91
   numbers; the list is here so the dropdown already reads "name (code)". */
const COUNTRIES = [
  { name: "India", code: "+91" },
  { name: "United States", code: "+1" },
  { name: "United Kingdom", code: "+44" },
  { name: "United Arab Emirates", code: "+971" },
  { name: "Singapore", code: "+65" },
  { name: "Australia", code: "+61" },
  { name: "Canada", code: "+1" },
  { name: "Germany", code: "+49" },
  { name: "France", code: "+33" },
  { name: "Japan", code: "+81" },
  { name: "Saudi Arabia", code: "+966" },
  { name: "Qatar", code: "+974" },
];

/* Local display mask for a freshly typed 10-digit Indian mobile: everything
   but the last 4 digits becomes bullets — same rule the API applies to the
   stored number. */
const maskLocalPhone = (digits: string) => `+91 ••••••${digits.slice(-4)}`;

/* Shared popup shell — mirrors the sign-in OTP card: accent overline, serif
   heading, one column of inputs, full-width confirm button, centered
   cancel link. Same size as the sign-in card (max-w-sm). */
function DialogShell({
  overline,
  title,
  onClose,
  busy,
  children,
}: {
  overline: string;
  title: string;
  onClose: () => void;
  busy: boolean;
  children: ReactNode;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink/30 p-4"
      role="dialog"
      aria-modal="true"
      onClick={() => !busy && onClose()}
    >
      <div
        className="w-full max-w-sm rounded-sm border border-rule bg-paper-raised p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <p className="mb-1 text-xs font-semibold tracking-[0.14em] text-accent uppercase">
          {overline}
        </p>
        <h2 className="font-display mb-6 text-2xl font-medium text-ink">{title}</h2>
        {children}
        <p className="mt-6 text-center text-sm text-ink-soft">
          <button type="button" className="link" onClick={() => !busy && onClose()}>
            Cancel
          </button>
        </p>
      </div>
    </div>
  );
}

/* One labelled OTP input with its dev-code / delivery-warning notes. */
function CodeInput({
  label,
  code,
  onChange,
  length,
  disabled,
  onEnter,
  hint,
  devCode,
  warning,
}: {
  label: string;
  code: string;
  onChange: (code: string) => void;
  length: number;
  disabled: boolean;
  onEnter: () => void;
  hint?: ReactNode;
  devCode?: string | null;
  warning?: string | null;
}) {
  return (
    <div className="space-y-1.5">
      <label className="block text-sm font-medium text-ink">{label}</label>
      <OtpInput value={code} onChange={onChange} disabled={disabled} onEnter={onEnter} length={length} />
      {hint && <p className="text-xs leading-relaxed text-ink-faint">{hint}</p>}
      {warning && (
        <p className="rounded-xs border border-red-stamp/40 bg-red-soft px-3 py-2 text-sm text-red-stamp">
          The code could not be sent — the provider rejected the request. Details: {warning}
        </p>
      )}
      {devCode && (
        <p className="rounded-xs border border-amber-stamp/40 bg-amber-stamp/10 px-3 py-2 text-xs text-amber-stamp">
          Dev mode (console delivery): your code is{" "}
          <span className="font-mono font-semibold">{devCode}</span>
        </p>
      )}
    </div>
  );
}

export default function ProfilePage() {
  const { user, refreshUser, logout } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState(user?.name ?? "");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  // Input policy comes from the backend (NAME_* / PASSWORD_* / OTP_CODE_LENGTH
  // in its .env); defaults apply if the call fails.
  const [rules, setRules] = useState({
    nameMin: 2,
    nameMax: 100,
    pwMin: 8,
    pwMax: 128,
    otpLength: 6,
  });

  useEffect(() => {
    getInputRules()
      .then((r) =>
        setRules({
          nameMin: r.nameMinLength ?? 2,
          nameMax: r.nameMaxLength ?? 100,
          pwMin: r.passwordMinLength ?? 8,
          pwMax: r.passwordMaxLength ?? 128,
          otpLength: r.otpCodeLength ?? 6,
        }),
      )
      .catch(() => {});
  }, []);

  // Google-only accounts have no password yet: the form becomes "set password"
  // and the current-password field disappears.
  const hasPassword = user?.hasPassword !== false;

  // Change-password form state
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [pwError, setPwError] = useState("");
  const [pwNotice, setPwNotice] = useState("");
  const [pwBusy, setPwBusy] = useState(false);

  const [confirmDelete, setConfirmDelete] = useState(false);
  const stepUp = useStepUp();

  // Phone / email change flows live in popups (same style as the step-up
  // modal), not as inline forms on the page.
  const [phoneDialogOpen, setPhoneDialogOpen] = useState(false);
  const [emailDialogOpen, setEmailDialogOpen] = useState(false);
  const [removeDialogOpen, setRemoveDialogOpen] = useState(false);
  const [phoneError, setPhoneError] = useState("");
  const [confirmRemovePhone, setConfirmRemovePhone] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setNotice("");
    setBusy(true);
    try {
      await updateProfile({ name });
      await refreshUser();
      setNotice("Profile updated.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Update failed");
    } finally {
      setBusy(false);
    }
  }

  // Password change with a verified phone: the texted-code card that opens
  // after the emailed step-up code was confirmed. Holds the pending
  // passwords (the form fields are cleared only on success) plus what the
  // step-1 response carried.
  const [pwSms, setPwSms] = useState<{
    currentPassword: string;
    newPassword: string;
    maskedPhone?: string;
    devCode?: string | null;
    warning?: string | null;
    cooldown?: number;
  } | null>(null);

  async function onChangePassword(e: FormEvent) {
    e.preventDefault();
    setPwError("");
    setPwNotice("");
    if (newPassword.length < rules.pwMin) {
      setPwError(`New password must be at least ${rules.pwMin} characters.`);
      return;
    }
    if (newPassword.length > rules.pwMax) {
      setPwError(`New password must be at most ${rules.pwMax} characters.`);
      return;
    }
    if (newPassword !== confirmPassword) {
      setPwError("New passwords do not match.");
      return;
    }
    // Same rule the backend enforces — catching it here means no code is
    // ever requested for a doomed request.
    if (hasPassword && newPassword === currentPassword) {
      setPwError("The new password must be different from the current one.");
      return;
    }
    setPwBusy(true);
    try {
      // The backend validates the passwords FIRST — a wrong current password
      // or an unchanged one is rejected before any code is sent. Only then
      // does it answer STEP_UP_REQUIRED, which opens the emailed-code dialog
      // below; admins with a verified phone get a texted code on top, one
      // card per code.
      await stepUp.run(
        async () => {
          const res = await changePassword(hasPassword ? currentPassword : "", newPassword);
          if (res.requireOtp) {
            setPwSms({
              currentPassword: hasPassword ? currentPassword : "",
              newPassword,
              maskedPhone: res.maskedPhone,
              devCode: res.devCode ?? null,
              warning: res.deliveryWarning ?? null,
              cooldown: res.resendCooldownSeconds ?? 45,
            });
          } else {
            setPwNotice(res.message);
            setCurrentPassword("");
            setNewPassword("");
            setConfirmPassword("");
            await refreshUser(); // hasPassword flips to true after setting
          }
        },
        "You're changing your password.",
        "change your password",
      );
    } catch (err) {
      setPwError(err instanceof Error ? err.message : "Password change failed");
    } finally {
      setPwBusy(false);
    }
  }

  async function onDelete() {
    setConfirmDelete(false);
    try {
      // Irreversible: the backend may challenge with an emailed OTP first.
      await stepUp.run(
        async () => {
          await deleteProfile();
          await logout();
          navigate("/login", { replace: true });
        },
        "You're about to permanently delete your account.",
        "permanently delete your account",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
    }
  }

  return (
    <div>
      <PageTitle
        overline="Account"
        title="Your profile"
        aside={user?.role && <Stamp tone="neutral">{user.role}</Stamp>}
      />

      <div className="grid gap-12 lg:grid-cols-2">
        {/* Profile details */}
        <section>
          <h2 className="font-display mb-4 text-lg font-medium text-ink">Details</h2>
          <form onSubmit={onSubmit} className="max-w-md space-y-4">
            <Field
              label="Full name"
              value={name}
              onChange={(e) => setName(e.target.value.replace(/[^\p{L}\s'-]/gu, ""))}
              required
              minLength={rules.nameMin}
              maxLength={rules.nameMax}
              hint={`Between ${rules.nameMin} and ${rules.nameMax} characters — letters, spaces, hyphens and apostrophes only.`}
            />
            <div>
              <Field
                label="Email"
                type="email"
                value={user?.email ?? ""}
                readOnly
                disabled
                className="cursor-not-allowed bg-paper-sunken text-ink-soft"
              />
              <button
                type="button"
                className="link mt-1 text-sm"
                onClick={() => setEmailDialogOpen(true)}
              >
                Change email
              </button>
            </div>
            <ErrorNote>{error}</ErrorNote>
            {notice && !error && (
              <p className="rounded-xs border border-accent/30 bg-accent-soft px-3 py-2 text-sm text-accent">
                {notice}
              </p>
            )}
            <div className="pt-2">
              <Button type="submit" disabled={busy}>
                {busy ? "Saving…" : "Save changes"}
              </Button>
            </div>
          </form>
        </section>

        {/* Change password */}
        <section>
          <h2 className="font-display mb-4 text-lg font-medium text-ink">
            {hasPassword ? "Change password" : "Set a password"}
          </h2>
          <form onSubmit={onChangePassword} className="max-w-md space-y-4">
            {hasPassword ? (
              <PasswordField
                label="Current password"
                autoComplete="current-password"
                required
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
              />
            ) : (
              <p className="rounded-xs border border-rule-strong bg-paper-sunken px-3 py-2 text-sm leading-relaxed text-ink-soft">
                You signed up with Google and don&rsquo;t have a password yet. Set one below to also
                sign in with email + password.
              </p>
            )}
            <PasswordField
              label="New password"
              autoComplete="new-password"
              required
              minLength={rules.pwMin}
              maxLength={rules.pwMax}
              hint={`Between ${rules.pwMin} and ${rules.pwMax} characters.`}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
            <PasswordField
              label="Confirm new password"
              autoComplete="new-password"
              required
              minLength={rules.pwMin}
              maxLength={rules.pwMax}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
            <ErrorNote>{pwError}</ErrorNote>
            {pwNotice && !pwError && (
              <p className="rounded-xs border border-accent/30 bg-accent-soft px-3 py-2 text-sm text-accent">
                {pwNotice}
              </p>
            )}
            <div className="pt-2">
              <Button type="submit" disabled={pwBusy}>
                {pwBusy ? "Updating…" : hasPassword ? "Update password" : "Set password"}
              </Button>
            </div>
          </form>
          <p className="mt-4 max-w-md text-xs leading-relaxed text-ink-faint">
            {hasPassword
              ? "Changing your password signs out every other device. This session stays active."
              : "Setting a password signs out every other device. This session stays active."}
          </p>
          {hasPassword && (
            <p className="mt-1 max-w-md text-xs leading-relaxed text-ink-faint">
              Forgot it?{" "}
              <Link to="/forgot-password" className="link">
                Send a reset link
              </Link>
              .
            </p>
          )}
        </section>

        {/* Phone number (texted codes) */}
        <section>
          <h2 className="font-display mb-4 text-lg font-medium text-ink">Phone number</h2>

          {user?.phoneNumber && user?.phoneVerified ? (
            <p className="mb-4 max-w-md text-sm leading-relaxed text-ink-soft">
              Current number: <strong className="text-ink">{user.phoneNumber}</strong> — login codes
              can arrive here instead of by email.
            </p>
          ) : (
            <p className="mb-4 max-w-md text-sm leading-relaxed text-ink-soft">
              Optional. With a verified number you can take login codes by text instead of email.
            </p>
          )}

          <div className="flex flex-wrap gap-3">
            <Button onClick={() => setPhoneDialogOpen(true)}>
              {user?.phoneNumber ? "Change number" : "Add number"}
            </Button>
            {user?.phoneNumber && (
              <Button variant="danger" onClick={() => setConfirmRemovePhone(true)}>
                Remove number
              </Button>
            )}
          </div>
          <ErrorNote>{phoneError}</ErrorNote>
        </section>
      </div>

      {/* Danger zone */}
      <section className="mt-12 max-w-md border-t border-rule pt-8">
        <h2 className="font-display mb-2 text-lg font-medium text-ink">Danger zone</h2>
        <p className="mb-4 text-sm leading-relaxed text-ink-soft">
          Deleting your account erases your profile and invalidates every active session. This
          action is permanent.
        </p>
        <Button variant="danger" onClick={() => setConfirmDelete(true)}>
          Delete account
        </Button>
      </section>

      <ConfirmDialog
        open={confirmDelete}
        title="Delete account permanently?"
        message="Your profile and every active session will be erased. This cannot be undone. You may be asked to confirm with an emailed code."
        confirmLabel="Delete account"
        onConfirm={onDelete}
        onCancel={() => setConfirmDelete(false)}
      />
      <ConfirmDialog
        open={confirmRemovePhone}
        title="Remove your phone number?"
        message={
          (user?.role === "admin"
            ? "Admin sign-in will stop asking for a texted code until you add a number again. "
            : "Texted verification codes will no longer be sent to you. ") +
          "We'll text a code to the number first, and an emailed code may also be asked for."
        }
        confirmLabel="Continue"
        onConfirm={() => {
          setConfirmRemovePhone(false);
          setRemoveDialogOpen(true);
        }}
        onCancel={() => setConfirmRemovePhone(false)}
      />

      {removeDialogOpen && (
        <PhoneRemoveDialog
          otpLength={rules.otpLength}
          runStepUp={stepUp.run}
          onClose={() => setRemoveDialogOpen(false)}
          onDone={(message) => {
            setRemoveDialogOpen(false);
            setPhoneError("");
            setNotice(message);
            void refreshUser();
          }}
        />
      )}
      {pwSms && (
        <PasswordSmsDialog
          otpLength={rules.otpLength}
          pending={pwSms}
          runStepUp={stepUp.run}
          onClose={() => setPwSms(null)}
          onDone={(message) => {
            setPwSms(null);
            setPwError("");
            setPwNotice(message);
            setCurrentPassword("");
            setNewPassword("");
            setConfirmPassword("");
            void refreshUser();
          }}
        />
      )}
      {phoneDialogOpen && (
        <PhoneChangeDialog
          otpLength={rules.otpLength}
          hasPhone={Boolean(user?.phoneNumber)}
          currentPhone={user?.phoneNumber}
          email={user?.email}
          runStepUp={stepUp.run}
          onClose={() => setPhoneDialogOpen(false)}
          onDone={(message) => {
            setPhoneDialogOpen(false);
            setPhoneError("");
            setNotice(message);
            void refreshUser();
          }}
        />
      )}
      {emailDialogOpen && (
        <EmailChangeDialog
          otpLength={rules.otpLength}
          runStepUp={stepUp.run}
          onClose={() => setEmailDialogOpen(false)}
          onDone={(message) => {
            setEmailDialogOpen(false);
            setNotice(message);
            void refreshUser();
          }}
        />
      )}
      {/* Rendered after the change dialogs so it stacks ON TOP when a step-up
          challenge fires from inside one of them. */}
      {stepUp.dialog}
    </div>
  );
}

/* Phone add/change popup. Stage "number": country (frozen to India) +
   10-digit number. The FIRST number then goes through an EMAIL stage — the
   mailed code must be confirmed before anything is texted (texts cost
   money); only then does the SMS stage appear. Changing an existing number
   skips straight to the SMS stage. Admins confirm that stage with the code
   texted to their current number as well. */
function PhoneChangeDialog({
  otpLength,
  hasPhone,
  currentPhone,
  email,
  runStepUp,
  onClose,
  onDone,
}: {
  otpLength: number;
  hasPhone: boolean;
  currentPhone?: string;
  email?: string;
  runStepUp: (action: () => Promise<void>, context: string, actionLabel?: string) => Promise<void>;
  onClose: () => void;
  onDone: (message: string) => void;
}) {
  const [digits, setDigits] = useState("");
  // number → email (first add only) → admin_sms (admins changing an existing
  // number) → sms. One code per screen.
  const [stage, setStage] = useState<"number" | "email" | "admin_sms" | "sms">("number");
  const [code, setCode] = useState("");
  const [emailCode, setEmailCode] = useState("");
  const [adminCode, setAdminCode] = useState("");
  // First add, email phase: where the mailed code went.
  const [emailInfo, setEmailInfo] = useState<EmailCodeChallenge | null>(null);
  // Admins: the texted half sent to the CURRENT number.
  const [adminSms, setAdminSms] = useState<SmsOtpChallenge | null>(null);
  const [devCode, setDevCode] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [resendBusy, setResendBusy] = useState(false);
  const countdown = useCountdown(0);

  const fullNumber = `+91${digits}`;
  const digitsValid = /^\d{10}$/.test(digits) && /^[6-9]/.test(digits);

  const applyEmailStage = (res: Awaited<ReturnType<typeof setPhoneNumber>>) => {
    setStage("email");
    setEmailInfo(res.emailChallenge ?? null);
    countdown.start(res.emailChallenge?.resendCooldownSeconds ?? 45);
    setDevCode(res.emailChallenge?.devCode ?? null);
    setWarning(res.emailChallenge?.deliveryWarning ?? null);
  };

  const applySmsStage = (res: Awaited<ReturnType<typeof setPhoneNumber>>) => {
    setStage("sms");
    countdown.start(res.resendCooldownSeconds ?? 45);
    setDevCode(res.devCode ?? null);
    setWarning(res.deliveryWarning ?? null);
  };

  // Admins changing an existing number: their current number is texted
  // FIRST; only once that code passes does the new number get its text.
  const applyAdminSmsStage = (res: Awaited<ReturnType<typeof setPhoneNumber>>) => {
    setStage("admin_sms");
    setAdminSms(res.adminSms?.required ? res.adminSms : null);
    countdown.start(res.adminSms?.resendCooldownSeconds ?? 45);
    setDevCode(res.adminSms?.devCode ?? null);
    setWarning(res.adminSms?.deliveryWarning ?? null);
  };

  // Request (or re-request) codes for the typed number. A bare call lands on
  // whatever stage the backend has pending: the emailed code first, or a
  // re-text once the earlier phase is confirmed.
  const requestCode = async (resend = false) => {
    setError("");
    if (resend) setResendBusy(true);
    else setBusy(true);
    try {
      await runStepUp(
        async () => {
          const res = await setPhoneNumber(fullNumber);
          if (res.stage === "email") applyEmailStage(res);
          else if (res.stage === "admin_sms") applyAdminSmsStage(res);
          else applySmsStage(res);
        },
        "You're linking a phone number to your account.",
        "link this phone number",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't send the code");
    } finally {
      setBusy(false);
      setResendBusy(false);
    }
  };

  // Email stage: confirming the mailed code is what triggers the text.
  const confirmEmail = async () => {
    setError("");
    setBusy(true);
    try {
      await runStepUp(
        async () => {
          const res = await setPhoneNumber(fullNumber, undefined, { emailCode });
          applySmsStage(res);
        },
        "You're linking a phone number to your account.",
        "link this phone number",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't verify the code");
    } finally {
      setBusy(false);
    }
  };

  // Admin stage: confirming the CURRENT-number code is what triggers the
  // text to the new number.
  const confirmAdminSms = async () => {
    setError("");
    setBusy(true);
    try {
      await runStepUp(
        async () => {
          const res = await setPhoneNumber(fullNumber, undefined, { adminSmsCode: adminCode });
          applySmsStage(res);
        },
        "You're linking a phone number to your account.",
        "link this phone number",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't verify the code");
    } finally {
      setBusy(false);
    }
  };

  // SMS stage: the texted code to the NEW number saves it.
  const verify = async () => {
    setError("");
    setBusy(true);
    try {
      await runStepUp(
        async () => {
          const res = await setPhoneNumber(fullNumber, code);
          onDone(res.message ?? "Phone number saved.");
        },
        "You're linking a phone number to your account.",
        "link this phone number",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't verify the code");
    } finally {
      setBusy(false);
    }
  };

  const allCodesFilled = code.length === otpLength;

  return (
    <DialogShell
      overline="Phone number"
      title={
        stage === "number"
          ? hasPhone
            ? "Change number"
            : "Add a number"
          : stage === "email"
            ? "Confirm your email"
            : stage === "admin_sms"
              ? "Confirm current number"
              : "Enter your code"
      }
      onClose={onClose}
      busy={busy}
    >
      {stage === "number" && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            // Same rule the backend enforces — the number already on the
            // account is refused before any email or text goes out.
            if (hasPhone && fullNumber === currentPhone) {
              setError("That's already the number on your account — enter a different one.");
              return;
            }
            if (digitsValid) void requestCode();
          }}
          className="space-y-4"
        >
          <p className="text-sm leading-relaxed text-ink-soft">
            {hasPhone
              ? "We'll text a code to the new number to confirm it's yours."
              : "We'll email you a code first — once it's confirmed, we text a code to the number to finish linking it."}
          </p>
          <label className="block">
            <span className="mb-1.5 block text-xs font-semibold tracking-[0.08em] text-ink-soft uppercase">
              Country
            </span>
            <select
              disabled
              value="+91"
              className="w-full cursor-not-allowed rounded-sm border border-rule-strong bg-paper-sunken px-3 py-2 text-sm text-ink-soft outline-none"
            >
              {COUNTRIES.map((c) => (
                <option key={c.name} value={c.code}>
                  {c.name} ({c.code})
                </option>
              ))}
            </select>
            <span className="mt-1 block text-xs text-ink-faint">
              India only for now — more countries coming soon.
            </span>
          </label>
          <Field
            label="Mobile number"
            type="tel"
            inputMode="numeric"
            autoComplete="tel-national"
            required
            placeholder="9876543210"
            value={digits}
            onChange={(e) => setDigits(e.target.value.replace(/\D/g, "").slice(0, 10))}
            hint="10 digits only, starting with 6–9."
          />
          <ErrorNote>{error}</ErrorNote>
          <Button type="submit" disabled={busy || !digitsValid} className="w-full">
            {busy ? "Sending…" : "Send code"}
          </Button>
        </form>
      )}

      {stage === "email" && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void confirmEmail();
          }}
          className="space-y-4"
        >
          <p className="text-sm leading-relaxed text-ink-soft">
            We emailed a {otpLength}-digit code to{" "}
            <strong className="text-ink">{emailInfo?.email ?? email}</strong>. Confirm it to
            continue — nothing is texted until then.
          </p>
          <OtpInput
            value={emailCode}
            onChange={setEmailCode}
            disabled={busy}
            length={otpLength}
            onEnter={() => emailCode.length === otpLength && void confirmEmail()}
          />
          {warning && (
            <p className="rounded-xs border border-red-stamp/40 bg-red-soft px-3 py-2 text-sm text-red-stamp">
              The email could not be sent — the provider rejected the request. Details: {warning}
            </p>
          )}
          {devCode && (
            <p className="rounded-xs border border-amber-stamp/40 bg-amber-stamp/10 px-3 py-2 text-xs text-amber-stamp">
              Dev mode (console mail delivery): your code is{" "}
              <span className="font-mono font-semibold">{devCode}</span>
            </p>
          )}
          <ErrorNote>{error}</ErrorNote>
          <Button
            type="submit"
            disabled={busy || emailCode.length !== otpLength}
            className="w-full"
          >
            {busy ? "Confirming…" : "Confirm email"}
          </Button>
          <div className="text-center">
            <ResendButton countdown={countdown} onResend={() => void requestCode(true)} busy={resendBusy} />
          </div>
        </form>
      )}

      {stage === "admin_sms" && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void confirmAdminSms();
          }}
          className="space-y-4"
        >
          <p className="text-sm leading-relaxed text-ink-soft">
            We texted a {otpLength}-digit code to{" "}
            <strong className="text-ink">{adminSms?.maskedPhone ?? "your current number"}</strong>{" "}
            — the number already on your account. Enter it to continue; the new number gets its
            own code next.
          </p>
          <CodeInput
            label="Current-number code"
            code={adminCode}
            onChange={setAdminCode}
            length={otpLength}
            disabled={busy}
            onEnter={() => adminCode.length === otpLength && void confirmAdminSms()}
            hint={<>Sent to {adminSms?.maskedPhone ?? "your current number"}.</>}
            devCode={devCode}
            warning={warning}
          />
          <ErrorNote>{error}</ErrorNote>
          <Button
            type="submit"
            disabled={busy || adminCode.length !== otpLength}
            className="w-full"
          >
            {busy ? "Verifying…" : "Continue"}
          </Button>
          <div className="text-center">
            <ResendButton countdown={countdown} onResend={() => void requestCode(true)} busy={resendBusy} />
          </div>
        </form>
      )}

      {stage === "sms" && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void verify();
          }}
          className="space-y-4"
        >
          <p className="text-sm leading-relaxed text-ink-soft">
            We texted a {otpLength}-digit code to{" "}
            <strong className="text-ink">{maskLocalPhone(digits)}</strong>. It expires in 10
            minutes.
          </p>
          <CodeInput
            label="Texted code"
            code={code}
            onChange={setCode}
            length={otpLength}
            disabled={busy}
            onEnter={() => allCodesFilled && void verify()}
            hint={<>Sent to {maskLocalPhone(digits)}.</>}
            devCode={devCode}
            warning={warning}
          />
          <ErrorNote>{error}</ErrorNote>
          <Button type="submit" disabled={busy || !allCodesFilled} className="w-full">
            {busy ? "Verifying…" : "Confirm number"}
          </Button>
          <div className="text-center">
            <ResendButton countdown={countdown} onResend={() => void requestCode(true)} busy={resendBusy} />
          </div>
        </form>
      )}
    </DialogShell>
  );
}

/* Email change popup, staged — one code per screen. Stage "email": the new
   address. Stage "code": the code MAILED TO THAT NEW ADDRESS (the full
   address is shown — unlike phone numbers, emails are not masked). For
   admins, confirming it issues the text to the CURRENT number: stage "sms".
   Regular users finish at the "code" stage. */
function EmailChangeDialog({
  otpLength,
  runStepUp,
  onClose,
  onDone,
}: {
  otpLength: number;
  runStepUp: (action: () => Promise<void>, context: string, actionLabel?: string) => Promise<void>;
  onClose: () => void;
  onDone: (message: string) => void;
}) {
  const [newEmail, setNewEmail] = useState("");
  // email → code → sms (admins only).
  const [stage, setStage] = useState<"email" | "code" | "sms">("email");
  const [code, setCode] = useState("");
  const [smsCode, setSmsCode] = useState("");
  // Admins: the texted half sent to the CURRENT number.
  const [adminSms, setAdminSms] = useState<SmsOtpChallenge | null>(null);
  const [devCode, setDevCode] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [resendBusy, setResendBusy] = useState(false);
  const countdown = useCountdown(0);

  const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail.trim());

  const applyCodeStage = (res: Awaited<ReturnType<typeof setEmailAddress>>) => {
    setStage("code");
    countdown.start(res.resendCooldownSeconds ?? 45);
    setDevCode(res.devCode ?? null);
    setWarning(res.deliveryWarning ?? null);
  };

  const applySmsStage = (res: Awaited<ReturnType<typeof setEmailAddress>>) => {
    setStage("sms");
    setAdminSms(res.adminSms?.required ? res.adminSms : null);
    countdown.start(res.adminSms?.resendCooldownSeconds ?? 45);
    setDevCode(res.adminSms?.devCode ?? null);
    setWarning(res.adminSms?.deliveryWarning ?? null);
  };

  // (Re)send. A bare call lands on whatever stage the backend has pending:
  // the emailed code to the new address, or — after that's confirmed — a
  // re-text to the admin's current number.
  const send = async (resend = false) => {
    setError("");
    if (resend) setResendBusy(true);
    else setBusy(true);
    try {
      await runStepUp(
        async () => {
          const res = await setEmailAddress(newEmail.trim().toLowerCase());
          if (res.stage === "sms") applySmsStage(res);
          else applyCodeStage(res);
        },
        "You're changing your account email.",
        "change your account email",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't send the code");
    } finally {
      setBusy(false);
      setResendBusy(false);
    }
  };

  // Confirming the code from the NEW inbox either applies the change
  // (regular users) or issues the admin's current-number text.
  const confirmEmailCode = async () => {
    setError("");
    setBusy(true);
    try {
      await runStepUp(
        async () => {
          const res = await setEmailAddress(newEmail.trim().toLowerCase(), code);
          if (res.stage === "sms") {
            applySmsStage(res);
            return;
          }
          onDone(res.message ?? "Email address updated.");
        },
        "You're changing your account email.",
        "change your account email",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't verify the code");
    } finally {
      setBusy(false);
    }
  };

  // Admin final stage: the texted code applies the change.
  const verifySms = async () => {
    setError("");
    setBusy(true);
    try {
      await runStepUp(
        async () => {
          const res = await setEmailAddress(newEmail.trim().toLowerCase(), undefined, smsCode);
          onDone(res.message ?? "Email address updated.");
        },
        "You're changing your account email.",
        "change your account email",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't verify the code");
    } finally {
      setBusy(false);
    }
  };

  return (
    <DialogShell
      overline="Email"
      title={
        stage === "email" ? "Change email" : stage === "code" ? "Enter your code" : "Confirm current number"
      }
      onClose={onClose}
      busy={busy}
    >
      {stage === "email" && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (emailValid) void send();
          }}
          className="space-y-4"
        >
          <p className="text-sm leading-relaxed text-ink-soft">
            We&rsquo;ll email a confirmation code to the new address. Your current email keeps
            working until the code is confirmed.
          </p>
          <Field
            label="New email address"
            type="email"
            autoComplete="email"
            required
            placeholder="you@example.com"
            value={newEmail}
            onChange={(e) => setNewEmail(e.target.value)}
            hint="The code is sent to THIS address — make sure you can open it."
          />
          <ErrorNote>{error}</ErrorNote>
          <Button type="submit" disabled={busy || !emailValid} className="w-full">
            {busy ? "Sending…" : "Send code"}
          </Button>
        </form>
      )}

      {stage === "code" && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void confirmEmailCode();
          }}
          className="space-y-4"
        >
          <p className="text-sm leading-relaxed text-ink-soft">
            We emailed a {otpLength}-digit code to{" "}
            <strong className="text-ink">{newEmail.trim().toLowerCase()}</strong>. It expires in 10
            minutes — nothing changes on your account until it&rsquo;s confirmed.
          </p>
          <CodeInput
            label="Emailed code"
            code={code}
            onChange={setCode}
            length={otpLength}
            disabled={busy}
            onEnter={() => code.length === otpLength && void confirmEmailCode()}
            hint={<>Sent to the new address — check that inbox.</>}
            devCode={devCode}
            warning={warning}
          />
          <ErrorNote>{error}</ErrorNote>
          <Button
            type="submit"
            disabled={busy || code.length !== otpLength}
            className="w-full"
          >
            {busy ? "Verifying…" : "Confirm new email"}
          </Button>
          <div className="text-center">
            <ResendButton countdown={countdown} onResend={() => void send(true)} busy={resendBusy} />
          </div>
        </form>
      )}

      {stage === "sms" && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void verifySms();
          }}
          className="space-y-4"
        >
          <p className="text-sm leading-relaxed text-ink-soft">
            Email confirmed. We texted a {otpLength}-digit code to{" "}
            <strong className="text-ink">{adminSms?.maskedPhone ?? "your current number"}</strong>{" "}
            — the number already on your account. Enter it to finish the change.
          </p>
          <CodeInput
            label="Current-number code"
            code={smsCode}
            onChange={setSmsCode}
            length={otpLength}
            disabled={busy}
            onEnter={() => smsCode.length === otpLength && void verifySms()}
            hint={<>Sent to {adminSms?.maskedPhone ?? "your current number"}.</>}
            devCode={devCode}
            warning={warning}
          />
          <ErrorNote>{error}</ErrorNote>
          <Button
            type="submit"
            disabled={busy || smsCode.length !== otpLength}
            className="w-full"
          >
            {busy ? "Verifying…" : "Confirm new email"}
          </Button>
          <div className="text-center">
            <ResendButton countdown={countdown} onResend={() => void send(true)} busy={resendBusy} />
          </div>
        </form>
      )}
    </DialogShell>
  );
}

/* Phone removal popup. Dropping the number also drops the SMS channel, so a
   code is texted to the number one last time — together with the emailed
   step-up code (its own dialog, stacked on top of this one), removal is
   confirmed on both channels. The code is requested as soon as the dialog
   opens; the confirm dialog before it is the guard against accidental sends
   (texts cost money). */
function PhoneRemoveDialog({
  otpLength,
  runStepUp,
  onClose,
  onDone,
}: {
  otpLength: number;
  runStepUp: (action: () => Promise<void>, context: string, actionLabel?: string) => Promise<void>;
  onClose: () => void;
  onDone: (message: string) => void;
}) {
  const [code, setCode] = useState("");
  const [maskedPhone, setMaskedPhone] = useState<string | null>(null);
  const [devCode, setDevCode] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [resendBusy, setResendBusy] = useState(false);
  const countdown = useCountdown(0);

  // (Re)request the texted code. A bare DELETE is the backend's step 1.
  const requestCode = async (resend = false) => {
    setError("");
    if (resend) setResendBusy(true);
    else setBusy(true);
    try {
      await runStepUp(
        async () => {
          const res = await removePhoneNumber();
          setMaskedPhone(res.maskedPhone ?? null);
          countdown.start(res.resendCooldownSeconds ?? 45);
          setDevCode(res.devCode ?? null);
          setWarning(res.deliveryWarning ?? null);
        },
        "You're removing your phone number.",
        "remove your phone number",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't send the code");
    } finally {
      setBusy(false);
      setResendBusy(false);
    }
  };

  // Fire once on open — the confirm dialog has already been answered. A ref
  // (not the effect deps) so React StrictMode's dev double-mount can't fire
  // a second request into the 45s resend cooldown.
  const startedRef = useRef(false);
  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    void requestCode();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const verify = async () => {
    setError("");
    setBusy(true);
    try {
      await runStepUp(
        async () => {
          const res = await removePhoneNumber(code);
          onDone(res.message ?? "Phone number removed.");
        },
        "You're removing your phone number.",
        "remove your phone number",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't verify the code");
    } finally {
      setBusy(false);
    }
  };

  return (
    <DialogShell overline="Phone number" title="Enter your code" onClose={onClose} busy={busy}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void verify();
        }}
        className="space-y-4"
      >
        <p className="text-sm leading-relaxed text-ink-soft">
          We texted a {otpLength}-digit code to{" "}
          <strong className="text-ink">{maskedPhone ?? "your number"}</strong> — the one being
          removed. Enter it to finish. It expires in 10 minutes.
        </p>
        <CodeInput
          label="Texted code"
          code={code}
          onChange={setCode}
          length={otpLength}
          disabled={busy}
          onEnter={() => code.length === otpLength && void verify()}
          hint={<>Removing the number is confirmed on both channels — an emailed code may also be asked for.</>}
          devCode={devCode}
          warning={warning}
        />
        <ErrorNote>{error}</ErrorNote>
        <Button type="submit" disabled={busy || code.length !== otpLength} className="w-full">
          {busy ? "Verifying…" : "Remove number"}
        </Button>
        <div className="text-center">
          <ResendButton countdown={countdown} onResend={() => void requestCode(true)} busy={resendBusy} />
        </div>
      </form>
    </DialogShell>
  );
}

/* Password change, texted half. Opens AFTER the emailed step-up code was
   confirmed (its own dialog) — sequential, one code per card. The pending
   passwords ride along in every call; the backend re-validates them before
   each text, so a stale request can never apply an unverified change. */
function PasswordSmsDialog({
  otpLength,
  pending,
  runStepUp,
  onClose,
  onDone,
}: {
  otpLength: number;
  pending: {
    currentPassword: string;
    newPassword: string;
    maskedPhone?: string;
    devCode?: string | null;
    warning?: string | null;
    cooldown?: number;
  };
  runStepUp: (action: () => Promise<void>, context: string, actionLabel?: string) => Promise<void>;
  onClose: () => void;
  onDone: (message: string) => void;
}) {
  const [code, setCode] = useState("");
  const [maskedPhone, setMaskedPhone] = useState(pending.maskedPhone);
  const [devCode, setDevCode] = useState(pending.devCode ?? null);
  const [warning, setWarning] = useState(pending.warning ?? null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [resendBusy, setResendBusy] = useState(false);
  const countdown = useCountdown(pending.cooldown ?? 45);

  // The initial text already went out (the dialog opens on its response), so
  // a resend is the only thing that re-issues a code.
  const resend = async () => {
    setError("");
    setResendBusy(true);
    try {
      await runStepUp(
        async () => {
          const res = await changePassword(pending.currentPassword, pending.newPassword);
          setMaskedPhone(res.maskedPhone);
          countdown.start(res.resendCooldownSeconds ?? 45);
          setDevCode(res.devCode ?? null);
          setWarning(res.deliveryWarning ?? null);
          if (!res.requireOtp) {
            // The phone was removed in the meantime — the change applied
            // without the text.
            onDone(res.message);
          }
        },
        "You're changing your password.",
        "change your password",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't resend the code");
    } finally {
      setResendBusy(false);
    }
  };

  const verify = async () => {
    setError("");
    setBusy(true);
    try {
      await runStepUp(
        async () => {
          const res = await changePassword(pending.currentPassword, pending.newPassword, code);
          onDone(res.message);
        },
        "You're changing your password.",
        "change your password",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't verify the code");
    } finally {
      setBusy(false);
    }
  };

  return (
    <DialogShell overline="Password" title="Enter your code" onClose={onClose} busy={busy}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void verify();
        }}
        className="space-y-4"
      >
        <p className="text-sm leading-relaxed text-ink-soft">
          We texted a {otpLength}-digit code to{" "}
          <strong className="text-ink">{maskedPhone ?? "your number"}</strong> — the final check
          for the password change. It expires in 10 minutes.
        </p>
        <CodeInput
          label="Texted code"
          code={code}
          onChange={setCode}
          length={otpLength}
          disabled={busy}
          onEnter={() => code.length === otpLength && void verify()}
          hint={<>Your emailed code was already confirmed — this is the last step.</>}
          devCode={devCode}
          warning={warning}
        />
        <ErrorNote>{error}</ErrorNote>
        <Button type="submit" disabled={busy || code.length !== otpLength} className="w-full">
          {busy ? "Verifying…" : "Update password"}
        </Button>
        <div className="text-center">
          <ResendButton countdown={countdown} onResend={() => void resend()} busy={resendBusy} />
        </div>
      </form>
    </DialogShell>
  );
}
