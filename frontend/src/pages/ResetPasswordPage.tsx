import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { getInputRules, resetPassword } from "../api";
import { Button, ErrorNote, PasswordField } from "../ui";
import { OtpInput, OtpStep, ResendButton, useCountdown } from "../otp";
import { Brand } from "./LoginPage";

/* Two-step recovery: choose the new password (link is validated, code is
   emailed), then confirm the emailed code — only then does the password
   actually change. Accounts with a verified phone are two-channel: a code is
   emailed AND texted, and both must be entered (a stolen mailbox alone must
   not be enough to take over an account). */

export default function ResetPasswordPage() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const navigate = useNavigate();
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [resendBusy, setResendBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");

  // Password policy comes from the backend env, same as the other forms.
  const [pwRules, setPwRules] = useState({ min: 8, max: 128, otpLength: 6 });

  useEffect(() => {
    getInputRules()
      .then((r) =>
        setPwRules({
          min: r.passwordMinLength ?? 8,
          max: r.passwordMaxLength ?? 128,
          otpLength: r.otpCodeLength ?? 6,
        }),
      )
      .catch(() => {});
  }, []);

  // OTP step state (set once the backend has accepted the link + password).
  const [awaitOtp, setAwaitOtp] = useState(false);
  const [code, setCode] = useState("");
  const [cooldown, setCooldown] = useState(45);
  const [otpError, setOtpError] = useState("");
  // Dev-only console-mail code / provider-rejection warning.
  const [devCode, setDevCode] = useState<string | null>(null);
  const [deliveryWarning, setDeliveryWarning] = useState<string | null>(null);
  // Two-channel reset: the account has a verified phone, so a second code is
  // texted and both must be entered.
  const [smsRequired, setSmsRequired] = useState(false);
  const [smsPhone, setSmsPhone] = useState<string | null>(null);
  const [smsCode, setSmsCode] = useState("");
  const [smsDevCode, setSmsDevCode] = useState<string | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (newPassword.length < pwRules.min) {
      setError(`Password must be at least ${pwRules.min} characters.`);
      return;
    }
    if (newPassword.length > pwRules.max) {
      setError(`Password must be at most ${pwRules.max} characters.`);
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      // Step 1: the backend emails a confirmation code before changing
      // anything (and texts one too when a verified phone is linked).
      const res = await resetPassword(token, newPassword);
      if (res.requireOtp) {
        setAwaitOtp(true);
        setCooldown(res.resendCooldownSeconds ?? 45);
        setCode("");
        setDevCode(res.devCode ?? null);
        setDeliveryWarning(res.deliveryWarning ?? null);
        setSmsRequired(Boolean(res.smsRequired));
        setSmsPhone(res.smsPhone ?? null);
        setSmsCode("");
        setSmsDevCode(res.smsDevCode ?? null);
      } else {
        setDone(true);
        setTimeout(() => navigate("/login", { replace: true }), 2500);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reset failed");
    } finally {
      setBusy(false);
    }
  }

  async function onVerifyOtp(e?: FormEvent) {
    e?.preventDefault();
    setOtpError("");
    setBusy(true);
    try {
      // Step 2: the codes confirm the change; this call mutates the password.
      await resetPassword(token, newPassword, code, smsRequired ? smsCode : undefined);
      setDone(true);
      setTimeout(() => navigate("/login", { replace: true }), 2500);
    } catch (err) {
      setOtpError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setBusy(false);
    }
  }

  async function onResendOtp() {
    setOtpError("");
    setResendBusy(true);
    try {
      // Re-running step 1 re-issues both codes (subject to the cooldown).
      const res = await resetPassword(token, newPassword);
      setCooldown(res.resendCooldownSeconds ?? 45);
      setDevCode(res.devCode ?? null);
      setDeliveryWarning(res.deliveryWarning ?? null);
      setSmsDevCode(res.smsDevCode ?? null);
    } catch (err) {
      setOtpError(err instanceof Error ? err.message : "Couldn't resend the code");
    } finally {
      setResendBusy(false);
    }
  }

  return (
    <main className="relative flex min-h-screen items-center justify-center p-8">
      <div className="w-full max-w-sm">
        <div className="mb-8">
          <Brand />
        </div>
        <p className="mb-1 text-xs font-semibold tracking-[0.14em] text-accent uppercase">
          Account recovery
        </p>
        <h1 className="font-display mb-6 text-3xl font-medium text-ink">Choose a new password</h1>

        {done ? (
          <div className="space-y-4">
            <p className="text-sm leading-relaxed text-ink-soft">
              Your password has been reset and every active session was signed out. Taking you to
              sign in…
            </p>
            <p className="text-sm text-ink-soft">
              <Link to="/login" className="link">
                Go to sign in now
              </Link>
            </p>
          </div>
        ) : !token ? (
          <div className="space-y-4">
            <ErrorNote>This reset link is missing its token. Please request a new one.</ErrorNote>
            <p className="text-sm text-ink-soft">
              <Link to="/forgot-password" className="link">
                Request a new reset link
              </Link>
            </p>
          </div>
        ) : awaitOtp ? (
          smsRequired ? (
            <>
              <p className="mb-1 text-xs font-semibold tracking-[0.14em] text-accent uppercase">
                Final check
              </p>
              <h2 className="font-display mb-6 text-2xl font-medium text-ink">Confirm the change</h2>
              <TwoCodeStep
                error={otpError}
                busy={busy}
                code={code}
                onCodeChange={setCode}
                smsCode={smsCode}
                onSmsCodeChange={setSmsCode}
                smsPhone={smsPhone}
                onSubmit={onVerifyOtp}
                onResend={onResendOtp}
                resendBusy={resendBusy}
                cooldownSeconds={cooldown}
                deliveryWarning={deliveryWarning}
                devCode={devCode}
                smsDevCode={smsDevCode}
                length={pwRules.otpLength}
              />
            </>
          ) : (
            <>
              <p className="mb-1 text-xs font-semibold tracking-[0.14em] text-accent uppercase">
                Final check
              </p>
              <h2 className="font-display mb-6 text-2xl font-medium text-ink">Confirm the change</h2>
              <OtpStep
                email="your email"
                error={otpError}
                busy={busy}
                code={code}
                onCodeChange={setCode}
                onSubmit={onVerifyOtp}
                onResend={onResendOtp}
                resendBusy={resendBusy}
                cooldownSeconds={cooldown}
                deliveryWarning={deliveryWarning}
                devCode={devCode}
                length={pwRules.otpLength}
              />
            </>
          )
        ) : (
          <>
            <p className="mb-6 text-sm leading-relaxed text-ink-soft">
              Setting a new password signs you out everywhere for your security. After you choose
              the new password we&rsquo;ll email you a confirmation code — and text one to your
              phone as well, if a number is linked to your account. The password only changes once
              you enter them.
            </p>
            <form onSubmit={onSubmit} className="space-y-4">
              <PasswordField
                label="New password"
                autoComplete="new-password"
                required
                minLength={pwRules.min}
                maxLength={pwRules.max}
                hint={`Between ${pwRules.min} and ${pwRules.max} characters.`}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
              <PasswordField
                label="Confirm new password"
                autoComplete="new-password"
                required
                minLength={pwRules.min}
                maxLength={pwRules.max}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
              <ErrorNote>{error}</ErrorNote>
              <Button type="submit" disabled={busy} className="w-full">
                {busy ? "Sending code…" : "Continue"}
              </Button>
            </form>
          </>
        )}
      </div>
    </main>
  );
}

/* Two-channel confirmation: one code arrived by email, one by text — both
   are required before anything changes. Mirrors OtpStep's layout so the
   experience feels like the same screen with a second field. */
function TwoCodeStep({
  error,
  busy,
  code,
  onCodeChange,
  smsCode,
  onSmsCodeChange,
  smsPhone,
  onSubmit,
  onResend,
  resendBusy,
  cooldownSeconds,
  deliveryWarning,
  devCode,
  smsDevCode,
  length = 6,
}: {
  error: string;
  busy: boolean;
  code: string;
  onCodeChange: (code: string) => void;
  smsCode: string;
  onSmsCodeChange: (code: string) => void;
  smsPhone: string | null;
  onSubmit: () => void;
  onResend: () => void;
  resendBusy: boolean;
  cooldownSeconds: number;
  deliveryWarning?: string | null;
  devCode?: string | null;
  smsDevCode?: string | null;
  length?: number;
}) {
  const countdown = useCountdown(cooldownSeconds);

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <p className="text-sm leading-relaxed text-ink-soft">
        We emailed a {length}-digit code to your email and texted another to{" "}
        <strong className="text-ink">{smsPhone ?? "your phone"}</strong>. Both are required — they
        expire in 10 minutes.
      </p>
      <div>
        <p className="mb-2 text-xs font-semibold tracking-[0.14em] text-ink-faint uppercase">
          Emailed code
        </p>
        <OtpInput value={code} onChange={onCodeChange} disabled={busy} onEnter={onSubmit} length={length} />
      </div>
      <div>
        <p className="mb-2 text-xs font-semibold tracking-[0.14em] text-ink-faint uppercase">
          Texted code
        </p>
        <OtpInput value={smsCode} onChange={onSmsCodeChange} disabled={busy} onEnter={onSubmit} length={length} />
      </div>
      {deliveryWarning && (
        <p className="rounded-xs border border-red-stamp/40 bg-red-soft px-3 py-2 text-sm text-red-stamp">
          The email could not be sent — the provider rejected the request. The code is from the
          server console only. Details: {deliveryWarning}
        </p>
      )}
      {devCode && (
        <p className="rounded-xs border border-amber-stamp/40 bg-amber-stamp/10 px-3 py-2 text-xs text-amber-stamp">
          Dev mode (console mail delivery): your emailed code is{" "}
          <span className="font-mono font-semibold">{devCode}</span>
        </p>
      )}
      {smsDevCode && (
        <p className="rounded-xs border border-amber-stamp/40 bg-amber-stamp/10 px-3 py-2 text-xs text-amber-stamp">
          Dev mode (console SMS delivery): your texted code is{" "}
          <span className="font-mono font-semibold">{smsDevCode}</span>
        </p>
      )}
      <ErrorNote>{error}</ErrorNote>
      <Button
        type="submit"
        disabled={busy || code.length !== length || smsCode.length !== length}
        className="w-full"
      >
        {busy ? "Verifying…" : "Verify"}
      </Button>
      <div className="text-center">
        <ResendButton countdown={countdown} onResend={onResend} busy={resendBusy} />
      </div>
    </form>
  );
}
