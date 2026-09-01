import { useState } from "react";
import { OtpInput, useCountdown, ResendButton } from "./otp";
import { Button, ErrorNote } from "./ui";

/* Shared second-channel confirmation dialog: the emailed step-up code has
   already been confirmed when this opens; what's left is the code that was
   texted to the account's verified phone. Used for the two-channel flows
   (account deletion, password change) where the phone is the last word.
   The caller supplies the two halves of the two-step API: `send` re-issues
   a text (step 1), `verify` submits the code (step 2). Both run inside the
   caller's stepUp wrapper so the emailed half is always re-challenged if
   its 5-minute window lapsed. */

/** The challenge half of a two-channel response — everything the step-1
    call returns before the action applies. */
export interface SmsChallenge {
  maskedPhone?: string;
  expiresInSeconds?: number;
  resendCooldownSeconds?: number;
  devCode?: string | null;
  deliveryWarning?: string | null;
}

export function SmsConfirmDialog({
  overline,
  title,
  body,
  confirmLabel,
  otpLength,
  initial,
  send,
  verify,
  onClose,
}: {
  /** Accent overline — the area the action belongs to ("Account"). */
  overline: string;
  title: string;
  /** One-line context above the input, e.g. what the code finalizes. */
  body: (maskedPhone: string | null) => string;
  confirmLabel: string;
  otpLength: number;
  /** The step-1 response that opened this dialog. */
  initial: SmsChallenge;
  /** Step 1 (no code): re-issues the text; resolves with the fresh challenge. */
  send: () => Promise<SmsChallenge & { requireOtp?: boolean }>;
  /** Step 2 (with code): applies the action; resolves when done. */
  verify: (code: string) => Promise<void>;
  onClose: () => void;
}) {
  const [code, setCode] = useState("");
  const [maskedPhone, setMaskedPhone] = useState(initial.maskedPhone ?? null);
  const [devCode, setDevCode] = useState(initial.devCode ?? null);
  const [warning, setWarning] = useState(initial.deliveryWarning ?? null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [resendBusy, setResendBusy] = useState(false);
  const [expiresInSeconds, setExpiresInSeconds] = useState(initial.expiresInSeconds ?? 600);
  const countdown = useCountdown(initial.resendCooldownSeconds ?? 45);

  // The code's lifetime, rounded up to whole minutes — the same closing
  // sentence every other OTP dialog uses ("It expires in 10 minutes.").
  const expiresMinutes = Math.max(1, Math.ceil(expiresInSeconds / 60));

  // The initial text already went out (this dialog opens on its response),
  // so a resend is the only thing that re-issues a code.
  const resend = async () => {
    setError("");
    setResendBusy(true);
    try {
      const res = await send();
      setMaskedPhone(res.maskedPhone ?? maskedPhone);
      countdown.start(res.resendCooldownSeconds ?? 45);
      setDevCode(res.devCode ?? null);
      setWarning(res.deliveryWarning ?? null);
      setExpiresInSeconds(res.expiresInSeconds ?? expiresInSeconds);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't resend the code");
    } finally {
      setResendBusy(false);
    }
  };

  const submit = async () => {
    setError("");
    setBusy(true);
    try {
      await verify(code);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setBusy(false);
    }
  };

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
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
          className="space-y-4"
        >
          <p className="text-sm leading-relaxed text-ink-soft">
            {body(maskedPhone)} It expires in {expiresMinutes} minute
            {expiresMinutes === 1 ? "" : "s"}.
          </p>
          <div className="space-y-1.5">
            <label className="block text-sm font-medium text-ink">Texted code</label>
            <OtpInput
              value={code}
              onChange={setCode}
              disabled={busy}
              length={otpLength}
              onEnter={() => code.length === otpLength && void submit()}
            />
            <p className="text-xs leading-relaxed text-ink-faint">
              Your emailed code was already confirmed — this is the last step.
            </p>
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
          <ErrorNote>{error}</ErrorNote>
          <Button type="submit" disabled={busy || code.length !== otpLength} className="w-full">
            {busy ? "Verifying…" : confirmLabel}
          </Button>
          <div className="text-center">
            <ResendButton countdown={countdown} onResend={() => void resend()} busy={resendBusy} />
          </div>
        </form>
        <p className="mt-6 text-center text-sm text-ink-soft">
          <button type="button" className="link" onClick={() => !busy && onClose()}>
            Cancel
          </button>
        </p>
      </div>
    </div>
  );
}
