import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { forgotPassword } from "../api";
import { Button, ErrorNote, Field } from "../ui";
import { useCountdown } from "../otp";
import { Brand } from "./LoginPage";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [devLink, setDevLink] = useState("");
  const [error, setError] = useState("");
  const countdown = useCountdown(0);

  async function send() {
    setError("");
    setBusy(true);
    try {
      const res = await forgotPassword(email);
      setSent(true);
      if (res.devResetUrl) setDevLink(res.devResetUrl);
      countdown.start(120);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    await send();
  }

  async function onResend() {
    await send();
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
        <h1 className="font-display mb-6 text-3xl font-medium text-ink">Forgot your password?</h1>

        {sent ? (
          <div className="space-y-4">
            <p className="text-sm leading-relaxed text-ink-soft">
              A reset link is on its way to <strong className="text-ink">{email}</strong>. The link
              expires in 15 minutes.
            </p>
            {devLink && (
              <div className="rounded-xs border border-rule-strong bg-paper-sunken p-3">
                <p className="mb-2 text-xs font-semibold tracking-[0.08em] text-ink-faint uppercase">
                  Dev mode — reset link
                </p>
                <a href={devLink} className="link break-all text-xs">
                  {devLink}
                </a>
              </div>
            )}
            <div className="space-y-3 rounded-xs border border-rule bg-paper-raised p-4">
              <Field
                label="Didn't get it?"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
              <ErrorNote>{error}</ErrorNote>
              <Button
                variant="outline"
                onClick={onResend}
                disabled={busy || countdown.isCoolingDown}
                className="w-full"
              >
                {busy
                  ? "Sending…"
                  : countdown.isCoolingDown
                    ? `Resend in ${countdown.label.replace("Resend available in ", "")}`
                    : "Resend reset link"}
              </Button>
            </div>
            <p className="text-sm text-ink-soft">
              <Link to="/login" className="link">
                Back to sign in
              </Link>
            </p>
          </div>
        ) : (
          <>
            <p className="mb-6 text-sm leading-relaxed text-ink-soft">
              Enter the email you signed up with and we&rsquo;ll send you a link to choose a new
              password.
            </p>
            <form onSubmit={onSubmit} className="space-y-4">
              <Field
                label="Email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
              <ErrorNote>{error}</ErrorNote>
              <Button type="submit" disabled={busy} className="w-full">
                {busy ? "Sending…" : "Send reset link"}
              </Button>
            </form>
            <p className="mt-6 text-sm text-ink-soft">
              <Link to="/login" className="link">
                Back to sign in
              </Link>
            </p>
          </>
        )}
      </div>
    </main>
  );
}
