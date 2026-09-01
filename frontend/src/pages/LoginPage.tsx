import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../auth";
import {
  getInputRules,
  resendLoginOtp,
  resendRegistrationOtp,
  verifyLoginOtp,
  verifyRegistrationOtp,
  ApiError,
  type SmsOtpChallenge,
} from "../api";
import { Button, Field, PasswordField } from "../ui";
import { OtpStep } from "../otp";

/* Editorial split layout: brand statement on the paper-sunken left panel,
   the form on the right. Serif masthead, hairline rules. */

/* The Google OAuth redirect_uri is registered for exactly one origin — the
   Vercel deployment — in the Google Cloud Console, and the state cookie must
   land on that same origin or the callback arrives state-less
   ("OAuth state parameter missing" — exactly what signing in from the
   Netlify mirror or the bare backend host produced). So on any other host,
   the button routes the user through the registered origin first; there the
   cookie, the callback and the resulting session all live. In dev the
   Vite proxy already shares the localhost cookie jar, so same-origin is
   correct there. */
const OAUTH_START_ORIGIN = "https://finshield-frontend-xi.vercel.app";

export function GoogleButton({ label }: { label: string }) {  const googleHref = import.meta.env.DEV
    ? "/api/auth/google"
    : window.location.origin === OAUTH_START_ORIGIN
      ? "/api/auth/google"
      : `${OAUTH_START_ORIGIN}/api/auth/google`;
  return (
    <a
      href={googleHref}
      className="inline-flex w-full items-center justify-center gap-3 rounded-sm border border-rule-strong bg-paper-raised px-4 py-2 text-sm font-medium text-ink transition-colors hover:bg-paper-sunken"
    >
      <svg width="17" height="17" viewBox="0 0 48 48" aria-hidden="true">
        <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
        <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
        <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
        <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
      </svg>
      {label}
    </a>
  );
}

export default function LoginPage() {
  const { login, setUser } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  // Structured error code ("ACCOUNT_NOT_FOUND", …) so the form can offer the
  // next step (e.g. a register link) instead of just the message text.
  const [errorKind, setErrorKind] = useState("");
  const [info] = useState(() => {
    const reason = new URLSearchParams(window.location.search).get("reason");
    if (reason === "timeout") {
      return "You were signed out automatically after 15 minutes of inactivity.";
    }
    if (reason === "revoked") {
      return "You revoked your own session, so you've been signed out. Sign in again to continue.";
    }
    return "";
  });
  const [busy, setBusy] = useState(false);

  // Risk-based OTP challenge / unverified-email verification
  const [challenge, setChallenge] = useState(false);
  const [unverified, setUnverified] = useState(false);
  const [riskNote, setRiskNote] = useState("");
  const [code, setCode] = useState("");
  const [rememberDevice, setRememberDevice] = useState(false);
  const [otpError, setOtpError] = useState("");
  const [otpBusy, setOtpBusy] = useState(false);
  const [resendBusy, setResendBusy] = useState(false);
  const [cooldown, setCooldown] = useState(45);
  // Dev-only console-mail code / provider-rejection warning for the challenge.
  const [devCode, setDevCode] = useState<string | null>(null);
  const [deliveryWarning, setDeliveryWarning] = useState<string | null>(null);
  // Admin sign-in: the texted half of the challenge. smsChallenge=true means
  // a texted-code stage EXISTS, but it only shows up AFTER the emailed code
  // is confirmed — one code per screen (texts cost money, so nothing is
  // texted before the mailbox is proven).
  const [smsChallenge, setSmsChallenge] = useState(false);
  // "email" while the emailed code is being confirmed; "sms" once the text
  // has gone out and the texted code finishes the sign-in.
  const [challengeStage, setChallengeStage] = useState<"email" | "sms">("email");
  const [smsCode, setSmsCode] = useState("");
  const [smsDevCode, setSmsDevCode] = useState<string | null>(null);
  const [smsWarning, setSmsWarning] = useState<string | null>(null);
  const [smsMaskedPhone, setSmsMaskedPhone] = useState<string | null>(null);
  // Which channel the single login code arrived on — "email" unless the user
  // asked for text (needs a verified phone on the account).
  const [otpChannel, setOtpChannel] = useState<"email" | "sms">("email");
  // Masked number (last 4 digits) when a text was possible — drives the
  // "send to +••••1234 instead" link.
  const [phoneChoice, setPhoneChoice] = useState<string | null>(null);
  // Code length follows the backend's OTP_CODE_LENGTH env.
  const [otpLength, setOtpLength] = useState(6);

  useEffect(() => {
    getInputRules()
      .then((r) => setOtpLength(r.otpCodeLength ?? 6))
      .catch(() => {});
  }, []);

  // Pull the SMS half of a challenge out of a login response (success or
  // error payload — cooldown races land in the catch branch).
  const applySmsChallenge = (sms?: SmsOtpChallenge) => {
    const required = Boolean(sms?.required);
    setSmsChallenge(required);
    setSmsDevCode(sms?.devCode ?? null);
    setSmsWarning(sms?.deliveryWarning ?? null);
  };

  // Apply every field a challenge response carries: which channel the code
  // went out on, whether a text was possible, timing, and the dev helpers.
  // Channel/phone hints are only touched when present — a resend response
  // doesn't carry them and must not wipe what the login already set.
  const applyOtpChallenge = (payload: {
    message?: string;
    resendCooldownSeconds?: number;
    retryAfterSeconds?: number;
    devCode?: string;
    deliveryWarning?: string;
    smsOtp?: SmsOtpChallenge;
    otpChannel?: "email" | "sms";
    phoneChoice?: { maskedPhone: string };
  }) => {
    setCooldown(payload.resendCooldownSeconds ?? payload.retryAfterSeconds ?? 45);
    setRiskNote(payload.message ?? "");
    setDevCode(payload.devCode ?? null);
    setDeliveryWarning(payload.deliveryWarning ?? null);
    applySmsChallenge(payload.smsOtp);
    if (payload.otpChannel) setOtpChannel(payload.otpChannel);
    if (payload.phoneChoice) setPhoneChoice(payload.phoneChoice.maskedPhone);
  };

  // The emailed half of an admin sign-in passed — the text goes out NOW and
  // the screen moves to the texted-code stage.
  const enterSmsStage = (sms: SmsOtpChallenge, message: string, cooldownSeconds?: number) => {
    setChallengeStage("sms");
    setSmsChallenge(true);
    setSmsDevCode(sms.devCode ?? null);
    setSmsWarning(sms.deliveryWarning ?? null);
    setSmsMaskedPhone(sms.maskedPhone ?? null);
    setRiskNote(message);
    setDevCode(null);
    setDeliveryWarning(null);
    setCode("");
    setCooldown(cooldownSeconds ?? sms.resendCooldownSeconds ?? 45);
  };

  // Surface OAuth failure (redirected back by the backend) as a form error.
  useEffect(() => {
    const oauthError = new URLSearchParams(window.location.search).get("error");
    if (oauthError === "oauth_failed") {
      setError("Google sign-in failed. Please try again.");
    } else if (oauthError === "oauth_state") {
      setError("Your Google sign-in session expired — the page was open too long before you finished. Please try again.");
    } else if (oauthError === "admin_oauth_blocked") {
      setError("Admin accounts sign in with email and password — Google sign-in is disabled for them.");
    }
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setErrorKind("");
    setBusy(true);
    try {
      const res = await login(email, password);
      if (res.requireOtp) {
        // 200 + requireOtp: the password was right but a second factor is
        // owed (every admin sign-in, or a risky login). No session yet.
        setChallenge(true);
        setUnverified(false);
        applyOtpChallenge(res);
        return;
      }
      navigate("/sessions", { replace: true });
    } catch (err) {
      const payload = (
        err as ApiError & {
          payload?: {
            error?: string;
            requireOtp?: boolean;
            message?: string;
            resendCooldownSeconds?: number;
            retryAfterSeconds?: number;
            deliveryWarning?: string;
            devCode?: string;
            smsOtp?: SmsOtpChallenge;
            otpChannel?: "email" | "sms";
            phoneChoice?: { maskedPhone: string };
          };
        }
      ).payload;
      if (payload?.requireOtp) {
        // Defensive: a non-2xx challenge (cooldown races) still lands here.
        setChallenge(true);
        applyOtpChallenge(payload);
      } else if (payload?.error === "EMAIL_NOT_VERIFIED") {
        // Registration was never completed — jump straight to verification.
        setChallenge(true);
        setUnverified(true);
        applyOtpChallenge(payload);
      } else {
        setError(err instanceof Error ? err.message : "Login failed");
        setErrorKind(payload?.error ?? "");
      }
    } finally {
      setBusy(false);
    }
  }

  async function onVerifyOtp(e?: FormEvent) {
    e?.preventDefault();
    setOtpError("");
    setOtpBusy(true);
    try {
      // Unverified accounts finish registration; risky logins pass the
      // second factor. Admin sign-in is staged: the emailed code first, and
      // only once it's confirmed does the texted code finish the sign-in.
      if (unverified) {
        const res = await verifyRegistrationOtp(email, code);
        setUser(res.user);
        navigate("/sessions", { replace: true });
        return;
      }

      if (challengeStage === "sms") {
        // The texted half of an admin sign-in.
        const res = await verifyLoginOtp(email, "", rememberDevice, smsCode);
        if (res.user) {
          setUser(res.user);
          navigate("/sessions", { replace: true });
          return;
        }
        setOtpError(res.message ?? "Verification failed");
        return;
      }

      const res = await verifyLoginOtp(
        email,
        code,
        rememberDevice,
        undefined,
        otpChannel === "sms" ? "sms" : undefined,
      );
      if (res.stage === "sms" && res.smsOtp) {
        // Email confirmed — the text goes out now, one code per screen.
        enterSmsStage(res.smsOtp, res.message ?? "", (res as { retryAfterSeconds?: number }).retryAfterSeconds);
        return;
      }
      if (res.user) {
        setUser(res.user);
        navigate("/sessions", { replace: true });
        return;
      }
      setOtpError(res.message ?? "Verification failed");
    } catch (err) {
      setOtpError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setOtpBusy(false);
    }
  }

  async function onResendOtp() {
    setOtpError("");
    setResendBusy(true);
    try {
      if (unverified) {
        const res = await resendRegistrationOtp(email);
        applyOtpChallenge(res);
      } else if (challengeStage === "sms") {
        // Admin second half — re-text the phone.
        const res = await resendLoginOtp(email, "sms");
        setRiskNote(res.message ?? "");
        setSmsDevCode(res.devCode ?? null);
        setSmsWarning(res.deliveryWarning ?? null);
        setCooldown(res.resendCooldownSeconds ?? 45);
      } else {
        // Re-send on the channel the user is looking at.
        const res = await resendLoginOtp(email, otpChannel === "sms" ? "sms" : undefined);
        applyOtpChallenge(res);
      }
    } catch (err) {
      const payload = (err as ApiError & { payload?: { retryAfterSeconds?: number; message?: string } })
        .payload;
      // "A code was recently sent" — keep the countdown honest instead of
      // resetting it to a fresh 45s.
      if (payload?.retryAfterSeconds) setCooldown(payload.retryAfterSeconds);
      setOtpError(
        payload?.message ?? (err instanceof Error ? err.message : "Couldn't resend the code"),
      );
    } finally {
      setResendBusy(false);
    }
  }

  // Switch the login code between email and text. Both channels have their
  // own OTP record and cooldown, so switching is instant — except switching
  // BACK to an email code sent less than 45s ago, in which case that earlier
  // code is still valid and the user should just use it.
  async function switchOtpChannel() {
    const next = otpChannel === "sms" ? "email" : "sms";
    setOtpError("");
    setCode("");
    setSmsCode("");
    setResendBusy(true);
    try {
      const res = await login(email, password, next === "sms" ? "sms" : undefined);
      if (!res.requireOtp) {
        navigate("/sessions", { replace: true });
        return;
      }
      applyOtpChallenge(res);
    } catch (err) {
      const payload = (
        err as ApiError & {
          payload?: { error?: string; message?: string; retryAfterSeconds?: number };
        }
      ).payload;
      if (payload?.retryAfterSeconds) setCooldown(payload.retryAfterSeconds);
      if (next === "email" && payload?.error === "COOLDOWN") {
        // The emailed code from before the switch is still valid — go back
        // to it instead of leaving the user stranded on a throttled channel.
        setOtpChannel("email");
        setOtpError("Your earlier emailed code is still valid — use the one in your inbox.");
      } else {
        setOtpError(payload?.message ?? (err instanceof Error ? err.message : "Couldn't switch"));
      }
    } finally {
      setResendBusy(false);
    }
  }

  return (
    <div className="grid min-h-screen grid-cols-1 lg:grid-cols-[2fr_3fr]">
      <aside className="relative hidden flex-col justify-between bg-paper-sunken p-10 lg:flex">
        <Brand />
        <div>
          <p className="font-display max-w-sm text-2xl leading-snug text-ink">
            Every login leaves a trace. Know exactly which devices hold the keys to your account —
            and take them back in one click.
          </p>
        </div>
        <p className="text-xs text-ink-faint">
          Protected by rotating sessions, CSRF double-submit, and device risk scoring.
        </p>
      </aside>

      <main className="relative flex items-center justify-center p-8">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <Brand />
          </div>

          {challenge ? (
            <>
              <p className="mb-1 text-xs font-semibold tracking-[0.14em] text-accent uppercase">
                {unverified ? "Verify your email" : "Confirm it's you"}
              </p>
              <h1 className="font-display mb-6 text-3xl font-medium text-ink">
                {unverified
                  ? "Enter your code"
                  : challengeStage === "sms"
                    ? "Enter your code"
                    : "Extra check needed"}
              </h1>
              {riskNote && !otpError && (
                <p className="mb-4 rounded-xs border border-rule-strong bg-paper-sunken px-3 py-2 text-sm text-ink-soft">
                  {riskNote}
                </p>
              )}
              {challengeStage === "sms" && !unverified ? (
                /* Admin second half — the text that went out only after the
                   emailed code was confirmed. One code per screen. */
                <OtpStep
                  email={email}
                  error={otpError}
                  busy={otpBusy}
                  code={smsCode}
                  onCodeChange={setSmsCode}
                  onSubmit={onVerifyOtp}
                  onResend={onResendOtp}
                  resendBusy={resendBusy}
                  cooldownSeconds={cooldown}
                  deliveryWarning={smsWarning}
                  devCode={smsDevCode}
                  length={otpLength}
                  channel="sms"
                  maskedPhone={smsMaskedPhone}
                  footer={
                    <label className="flex cursor-pointer items-start gap-2 pt-2 text-sm text-ink-soft">
                      <input
                        type="checkbox"
                        checked={rememberDevice}
                        onChange={(e) => setRememberDevice(e.target.checked)}
                        className="mt-0.5 accent-[var(--color-accent)]"
                      />
                      Remember this device for 30 days (skips this check here)
                    </label>
                  }
                />
              ) : (
                <OtpStep
                  email={email}
                  error={otpError}
                  busy={otpBusy}
                  code={code}
                  onCodeChange={setCode}
                  onSubmit={onVerifyOtp}
                  onResend={onResendOtp}
                  resendBusy={resendBusy}
                  cooldownSeconds={cooldown}
                  deliveryWarning={deliveryWarning}
                  devCode={devCode}
                  length={otpLength}
                  channel={otpChannel}
                  maskedPhone={phoneChoice}
                  channelSwitch={
                    phoneChoice && !smsChallenge && !unverified ? (
                      <button
                        type="button"
                        className="link text-sm"
                        onClick={switchOtpChannel}
                        disabled={resendBusy}
                      >
                        {otpChannel === "sms"
                          ? "Send to email instead"
                          : `Send to ${phoneChoice} instead`}
                      </button>
                    ) : undefined
                  }
                  footer={
                    !unverified ? (
                      <label className="flex cursor-pointer items-start gap-2 pt-2 text-sm text-ink-soft">
                        <input
                          type="checkbox"
                          checked={rememberDevice}
                          onChange={(e) => setRememberDevice(e.target.checked)}
                          className="mt-0.5 accent-[var(--color-accent)]"
                        />
                        Remember this device for 30 days (skips this check here)
                      </label>
                    ) : undefined
                  }
                />
              )}
              <p className="mt-4 text-center text-sm text-ink-soft">
                <button
                  type="button"
                  className="link"
                  onClick={() => {
                    setChallenge(false);
                    setUnverified(false);
                    setCode("");
                    setSmsCode("");
                    setChallengeStage("email");
                    setSmsChallenge(false);
                    setSmsDevCode(null);
                    setSmsWarning(null);
                    setSmsMaskedPhone(null);
                    setOtpChannel("email");
                    setPhoneChoice(null);
                    setOtpError("");
                    setDevCode(null);
                    setDeliveryWarning(null);
                  }}
                >
                  Back to sign in
                </button>
              </p>
            </>
          ) : (
            <>
              <p className="mb-1 text-xs font-semibold tracking-[0.14em] text-accent uppercase">
                Sign in
              </p>
              <h1 className="font-display mb-6 text-3xl font-medium text-ink">Welcome back</h1>

              <form onSubmit={onSubmit} className="space-y-4">
                <Field
                  label="Email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
                <PasswordField
                  label="Password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                {error && (
                  <div className="rounded-xs border border-red-stamp/40 bg-red-stamp/5 px-3 py-2">
                    <p className="text-sm text-red-stamp">{error}</p>
                    {errorKind === "ACCOUNT_NOT_FOUND" && (
                      <p className="mt-1 text-sm text-ink-soft">
                        New here?{" "}
                        <Link to="/register" className="link text-accent">
                          Create an account
                        </Link>
                      </p>
                    )}
                  </div>
                )}
                {info && !error && (
                  <p className="rounded-xs border border-rule-strong bg-paper-sunken px-3 py-2 text-sm text-ink-soft">
                    {info}
                  </p>
                )}
                <Button type="submit" disabled={busy} className="w-full">
                  {busy ? "Signing in…" : "Sign in"}
                </Button>
              </form>

              <div className="my-6 flex items-center gap-4">
                <span className="h-px flex-1 bg-rule" />
                <span className="text-xs text-ink-faint">or</span>
                <span className="h-px flex-1 bg-rule" />
              </div>
              <GoogleButton label="Continue with Google" />

              <p className="mt-6 text-sm text-ink-soft">
                New here?{" "}
                <Link to="/register" className="link">
                  Create an account
                </Link>
              </p>
              <p className="mt-2 text-sm text-ink-soft">
                <Link to="/forgot-password" className="link">
                  Forgot your password?
                </Link>
              </p>
            </>
          )}
        </div>
      </main>
    </div>
  );
}

export function Brand() {
  return (
    <div className="flex items-center gap-2.5">
      <svg width="26" height="26" viewBox="0 0 26 26" aria-hidden="true">
        <rect x="1" y="1" width="24" height="24" rx="4" fill="none" stroke="var(--color-accent-strong)" strokeWidth="1.5" />
        <path d="M13 6.5v13M9 10.5c0-2 1.8-3.2 4-3.2s4 1.2 4 3.2c0 4.4-8 2.6-8 7 0 2 1.8 3.2 4 3.2s4-1.2 4-3.2" fill="none" stroke="var(--color-accent-strong)" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
      <span className="font-display text-lg font-semibold tracking-tight text-ink">FinShield</span>
    </div>
  );
}
