import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../auth";
import { getInputRules, resendRegistrationOtp, verifyRegistrationOtp } from "../api";
import { Button, ErrorNote, Field, PasswordField } from "../ui";
import { OtpStep } from "../otp";
import { Brand, GoogleButton } from "./LoginPage";

export default function RegisterPage() {
  const { register, setUser } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // Input policy comes from the backend (NAME_* / PASSWORD_* / OTP_CODE_LENGTH
  // in its .env) so the inputs, hints and validation always agree with the
  // server. Falls back to the defaults if the call fails.
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

  // OTP verification state
  const [awaitingOtp, setAwaitingOtp] = useState(false);
  const [code, setCode] = useState("");
  const [otpError, setOtpError] = useState("");
  const [otpBusy, setOtpBusy] = useState(false);
  const [resendBusy, setResendBusy] = useState(false);
  const [cooldown, setCooldown] = useState(45);
  // Dev-only console-mail code / provider-rejection warning.
  const [devCode, setDevCode] = useState<string | null>(null);
  const [deliveryWarning, setDeliveryWarning] = useState<string | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (password.length < rules.pwMin) {
      setError(`Password must be at least ${rules.pwMin} characters.`);
      return;
    }
    if (password.length > rules.pwMax) {
      setError(`Password must be at most ${rules.pwMax} characters.`);
      return;
    }
    setBusy(true);
    try {
      const res = await register(name, email, password);
      // Account created — now verify email ownership with the OTP.
      setAwaitingOtp(true);
      setCooldown(res.resendCooldownSeconds ?? 45);
      setDevCode(res.devCode ?? null);
      setDeliveryWarning(res.deliveryWarning ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setBusy(false);
    }
  }

  async function onVerifyOtp(e?: FormEvent) {
    e?.preventDefault();
    setOtpError("");
    setOtpBusy(true);
    try {
      const res = await verifyRegistrationOtp(email, code);
      setUser(res.user);
      navigate("/sessions", { replace: true });
    } catch (err) {
      setOtpError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setOtpBusy(false);
    }
  }

  async function onResend() {
    setOtpError("");
    setResendBusy(true);
    try {
      const res = await resendRegistrationOtp(email);
      setCooldown(res.resendCooldownSeconds ?? 45);
      setDevCode(res.devCode ?? null);
      setDeliveryWarning(res.deliveryWarning ?? null);
    } catch (err) {
      setOtpError(err instanceof Error ? err.message : "Couldn't resend the code");
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
            One account, every session accounted for. From the moment you sign up, each device you
            use is tracked, scored, and revocable.
          </p>
        </div>
        <p className="text-xs text-ink-faint">
          Your password is hashed with bcrypt. We never store it in plain text.
        </p>
      </aside>

      <main className="relative flex items-center justify-center p-8">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <Brand />
          </div>

          {awaitingOtp ? (
            <>
              <p className="mb-1 text-xs font-semibold tracking-[0.14em] text-accent uppercase">
                Step 2 of 2
              </p>
              <h1 className="font-display mb-6 text-3xl font-medium text-ink">
                Verify your email
              </h1>
              <OtpStep
                email={email}
                error={otpError}
                busy={otpBusy}
                code={code}
                onCodeChange={setCode}
                onSubmit={onVerifyOtp}
                onResend={onResend}
                resendBusy={resendBusy}
                cooldownSeconds={cooldown}
                deliveryWarning={deliveryWarning}
                devCode={devCode}
                length={rules.otpLength}
                footer={
                  <p className="pt-2 text-center text-sm text-ink-soft">
                    Wrong email?{" "}
                    <button
                      type="button"
                      className="link"
                      onClick={() => {
                        setAwaitingOtp(false);
                        setCode("");
                      }}
                    >
                      Start over
                    </button>
                  </p>
                }
              />
            </>
          ) : (
            <>
              <p className="mb-1 text-xs font-semibold tracking-[0.14em] text-accent uppercase">
                Get started
              </p>
              <h1 className="font-display mb-6 text-3xl font-medium text-ink">
                Create your account
              </h1>

              <form onSubmit={onSubmit} className="space-y-4">
                <Field
                  label="Full name"
                  autoComplete="name"
                  required
                  minLength={rules.nameMin}
                  maxLength={rules.nameMax}
                  hint={`Between ${rules.nameMin} and ${rules.nameMax} characters — letters, spaces, hyphens and apostrophes only (no digits, periods or symbols).`}
                  value={name}
                  onChange={(e) => setName(e.target.value.replace(/[^\p{L}\s'-]/gu, ""))}
                />
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
                  autoComplete="new-password"
                  required
                  minLength={rules.pwMin}
                  maxLength={rules.pwMax}
                  hint={`Between ${rules.pwMin} and ${rules.pwMax} characters.`}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <ErrorNote>{error}</ErrorNote>
                <Button type="submit" disabled={busy} className="w-full">
                  {busy ? "Creating account…" : "Create account"}
                </Button>
              </form>

              <div className="my-6 flex items-center gap-4">
                <span className="h-px flex-1 bg-rule" />
                <span className="text-xs text-ink-faint">or</span>
                <span className="h-px flex-1 bg-rule" />
              </div>
              <GoogleButton label="Sign up with Google" />

              <p className="mt-6 text-sm text-ink-soft">
                Already registered?{" "}
                <Link to="/login" className="link">
                  Sign in
                </Link>
              </p>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
