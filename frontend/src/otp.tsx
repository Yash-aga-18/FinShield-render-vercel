import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Button, ErrorNote } from "./ui";

/* Shared OTP entry card: 6-digit code, resend button with a live countdown.
   Used by registration verification, login step-up, and sensitive-action
   confirmation. */

export function OtpInput({
  value,
  onChange,
  disabled,
  onEnter,
  length = 6,
}: {
  value: string;
  onChange: (code: string) => void;
  disabled?: boolean;
  /** Fired on Enter — wired to submit so the key always confirms, even where
      implicit form submission doesn't apply. */
  onEnter?: () => void;
  /** Code length in digits — follows the backend's OTP_CODE_LENGTH env. */
  length?: number;
}) {
  return (
    <input
      inputMode="numeric"
      autoComplete="one-time-code"
      pattern={`\\d{${length}}`}
      maxLength={length}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value.replace(/\D/g, "").slice(0, length))}
      onKeyDown={(e) => {
        if (e.key === "Enter" && !disabled) {
          e.preventDefault();
          onEnter?.();
        }
      }}
      className="w-full rounded-sm border border-rule-strong bg-paper-raised px-3 py-3 text-center font-mono text-2xl tracking-[0.6em] text-ink
        outline-none transition-colors placeholder:tracking-[0.2em] placeholder:font-sans placeholder:text-sm placeholder:text-ink-faint
        focus:border-accent focus:ring-2 focus:ring-accent/15 disabled:opacity-50"
      placeholder={"0".repeat(length)}
    />
  );
}

export function useCountdown(initialSeconds: number | null) {
  const [secondsLeft, setSecondsLeft] = useState(initialSeconds ?? 0);

  useEffect(() => {
    if (secondsLeft <= 0) return;
    const timer = setInterval(() => {
      setSecondsLeft((s) => (s > 0 ? s - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [secondsLeft > 0]); // eslint-disable-line react-hooks/exhaustive-deps

  // Stable across renders so consumers can safely use it in useCallback or
  // mount-only useEffect deps without re-triggering them every second.
  const start = useCallback((seconds: number) => setSecondsLeft(seconds), []);

  return {
    secondsLeft,
    start,
    isCoolingDown: secondsLeft > 0,
    label:
      secondsLeft > 0
        ? `Resend available in ${Math.floor(secondsLeft / 60)}:${String(secondsLeft % 60).padStart(2, "0")}`
        : "",
  };
}

export function ResendButton({
  countdown,
  onResend,
  busy,
}: {
  countdown: ReturnType<typeof useCountdown>;
  onResend: () => void;
  busy?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onResend}
      disabled={countdown.isCoolingDown || busy}
      className="text-sm text-ink-faint transition-colors enabled:hover:text-accent disabled:cursor-not-allowed"
    >
      {busy ? "Sending…" : countdown.isCoolingDown ? countdown.label : "Resend code"}
    </button>
  );
}

/* Full OTP step used on the registration and login screens. One code per
   screen — admin sign-in stages its two codes across two visits of this
   card (email first, then the text), they are never merged. */
export function OtpStep({
  email,
  error,
  busy,
  code,
  onCodeChange,
  onSubmit,
  onResend,
  resendBusy,
  cooldownSeconds,
  footer,
  deliveryWarning,
  devCode,
  length = 6,
  channel = "email",
  maskedPhone,
  channelSwitch,
}: {
  email: string;
  error: string;
  busy: boolean;
  code: string;
  onCodeChange: (code: string) => void;
  onSubmit: () => void;
  onResend: () => void;
  resendBusy: boolean;
  cooldownSeconds: number;
  footer?: ReactNode;
  /** Provider rejected the send — the message never left (red note). */
  deliveryWarning?: string | null;
  /** Dev-only: console delivery echoes the code in the response. */
  devCode?: string | null;
  /** Code length in digits — follows the backend's OTP_CODE_LENGTH env. */
  length?: number;
  /** Which channel the single code arrived on; "sms" swaps the intro and
      dev-note wording from email to text. */
  channel?: "email" | "sms";
  /** Masked destination (last 4 digits) when the code was texted. */
  maskedPhone?: string | null;
  /** Optional "send to email/phone instead" control, rendered under the intro. */
  channelSwitch?: ReactNode;
}) {
  const countdown = useCountdown(cooldownSeconds);

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <p className="text-sm leading-relaxed text-ink-soft">
        {channel === "sms" ? (
          <>
            We texted a {length}-digit code to{" "}
            <strong className="text-ink">{maskedPhone ?? "your phone"}</strong>. It expires in 10
            minutes.
          </>
        ) : (
          <>
            We sent a {length}-digit code to <strong className="text-ink">{email}</strong>. It
            expires in 10 minutes.
          </>
        )}
      </p>
      {channelSwitch}
      <OtpInput value={code} onChange={onCodeChange} disabled={busy} onEnter={onSubmit} length={length} />
      {deliveryWarning && (
        <p className="rounded-xs border border-red-stamp/40 bg-red-soft px-3 py-2 text-sm text-red-stamp">
          The {channel === "sms" ? "text" : "email"} could not be sent — the provider rejected the
          request. The code below is from the server console only. Details: {deliveryWarning}
        </p>
      )}
      {devCode && (
        <p className="rounded-xs border border-amber-stamp/40 bg-amber-stamp/10 px-3 py-2 text-xs text-amber-stamp">
          Dev mode (console {channel === "sms" ? "SMS" : "mail"} delivery): your code is{" "}
          <span className="font-mono font-semibold">{devCode}</span>
        </p>
      )}
      <ErrorNote>{error}</ErrorNote>
      <Button type="submit" disabled={busy || code.length !== length} className="w-full">
        {busy ? "Verifying…" : "Verify"}
      </Button>
      <div className="text-center">
        <ResendButton countdown={countdown} onResend={onResend} busy={resendBusy} />
      </div>
      {footer}
    </form>
  );
}
