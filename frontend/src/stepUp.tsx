import { memo, useCallback, useEffect, useState, type ReactNode } from "react";
import { sendStepUpOtp, verifyStepUpOtp, getInputRules, ApiError } from "./api";
import { useAuth } from "./auth";
import { Button } from "./ui";
import { OtpInput, useCountdown } from "./otp";

/* Step-up challenge: wraps a sensitive action. When the backend answers
   STEP_UP_REQUIRED, this modal collects an emailed OTP, verifies it (5-min
   step-up cookie), then transparently retries the original action. */

const isStepUpRequired = (err: unknown) =>
  (err as (ApiError & { payload?: { error?: string } }) | null)?.payload?.error ===
  "STEP_UP_REQUIRED";

const stepUpMessage = (err: unknown, fallback: string) =>
  (err as ApiError & { payload?: { message?: string } })?.payload?.message ??
  (err instanceof Error ? err.message : fallback);

/* The dialog owns its own code/error/countdown state so every keystroke
   re-renders only this modal — never the whole page behind it (the admin
   users table re-rendering per keystroke is what made input feel laggy).
   memoized for the same reason: host-page re-renders (countdown chips,
   table refreshes) must not disturb a focused OTP field. */
const StepUpDialog = memo(function StepUpDialog({
  context,
  emailAction,
  action,
  onClose,
}: {
  context: string;
  /** Short action phrase sent to the backend so the emailed code names the
      exact action (e.g. "delete user x@y.com"), not a generic "sensitive action". */
  emailAction?: string;
  action: () => Promise<void>;
  onClose: () => void;
}) {
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sending, setSending] = useState(false);
  // Dev-only: when the backend runs with console mail delivery it echoes the
  // code in the response; show it so the flow is testable without a mailbox.
  const [devCode, setDevCode] = useState<string | null>(null);
  // Set when the mail provider rejected the send — the email never left.
  const [deliveryWarning, setDeliveryWarning] = useState<string | null>(null);
  // Code length follows the backend's OTP_CODE_LENGTH env (cached request).
  const [otpLength, setOtpLength] = useState(6);
  // The account email — shown in full so the user knows which inbox to check.
  const { user } = useAuth();
  const { start: startCountdown, isCoolingDown, label } = useCountdown(0);

  useEffect(() => {
    getInputRules()
      .then((r) => setOtpLength(r.otpCodeLength ?? 6))
      .catch(() => {});
  }, []);

  const requestCode = useCallback(
    async (initial = false) => {
      setError("");
      setSending(true);
      try {
        const res = await sendStepUpOtp(emailAction);
        startCountdown(res.resendCooldownSeconds ?? 45);
        setDevCode(res.devCode ?? null);
        setDeliveryWarning(res.deliveryWarning ?? null);
      } catch (err) {
        // The automatic send happens on mount. A cooldown there just means a
        // code was issued moments ago (e.g. a re-opened dialog) — the user
        // already has a valid code, so don't flash an error at them.
        const status = err instanceof ApiError ? err.status : 0;
        if (!initial || status !== 429) {
          setError(err instanceof Error ? err.message : "Couldn't send the code");
        }
      } finally {
        setSending(false);
      }
    },
    [startCountdown, emailAction],
  );

  // Request the first code exactly once, when the dialog mounts. (The old
  // version re-sent on every render — an endless stream of requests that
  // made the modal jitter and ate the IP rate-limit budget.)
  useEffect(() => {
    void requestCode(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function onVerify() {
    setError("");
    setBusy(true);
    try {
      await verifyStepUpOtp(code);
      // Step-up cookie is set — the original action now passes the guard.
      await action();
      onClose();
    } catch (err) {
      if (isStepUpRequired(err)) {
        // Code accepted server-side but the retry was still challenged —
        // keep the dialog open so the message is actually visible.
        setError(stepUpMessage(err, "Please verify again."));
      } else {
        setError(stepUpMessage(err, "Verification failed"));
      }
    } finally {
      setBusy(false);
    }
  }

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
        <h2 className="font-display mb-2 text-xl font-medium text-ink">Confirm with a code</h2>
        <p className="mb-4 text-sm leading-relaxed text-ink-soft">
          {context} For your security, we emailed a {otpLength}-digit confirmation code to{" "}
          <strong className="text-ink">{user?.email ?? "your account email"}</strong>. It expires
          in 10 minutes.
        </p>
        {/* A real form so Enter in the OTP field submits, like users expect. */}
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (code.length === otpLength && !busy) void onVerify();
          }}
        >
          <OtpInput
            value={code}
            onChange={setCode}
            disabled={busy}
            length={otpLength}
            onEnter={() => {
              if (code.length === otpLength && !busy) void onVerify();
            }}
          />
          {deliveryWarning && (
            <p className="rounded-xs border border-red-stamp/40 bg-red-soft px-3 py-2 text-sm text-red-stamp">
              The email could not be sent — the mail provider rejected the request. The code below is
              from the server console only. Details: {deliveryWarning}
            </p>
          )}
          {devCode && (
            <p className="rounded-xs border border-amber-stamp/40 bg-amber-stamp/10 px-3 py-2 text-xs text-amber-stamp">
              Dev mode (console mail delivery): your code is{" "}
              <span className="font-mono font-semibold">{devCode}</span>
            </p>
          )}
          {error && (
            <p className="rounded-xs border border-red-stamp/40 bg-red-soft px-3 py-2 text-sm text-red-stamp">
              {error}
            </p>
          )}
          <div className="flex items-center justify-between">
            <button
              type="button"
              onClick={() => void requestCode(false)}
              disabled={isCoolingDown || sending}
              className="text-xs text-ink-faint transition-colors enabled:hover:text-accent disabled:cursor-not-allowed"
            >
              {sending ? "Sending…" : isCoolingDown ? label : "Resend code"}
            </button>
          </div>
          <div className="flex justify-end gap-3">
            <Button variant="outline" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy || code.length !== otpLength}>
              {busy ? "Confirming…" : "Confirm"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
});

export function useStepUp() {
  const [pending, setPending] = useState<null | (() => Promise<void>)>(null);
  const [context, setContext] = useState<string>("");
  const [emailAction, setEmailAction] = useState<string | undefined>(undefined);

  // Kick off a sensitive action; intercept the STEP_UP_REQUIRED error.
  // emailAction (optional) names the action in the emailed OTP, e.g.
  // "delete user x@y.com" instead of a generic "sensitive action".
  const run = useCallback(
    async (action: () => Promise<void>, actionContext: string, actionLabel?: string) => {
      setContext(actionContext);
      setEmailAction(actionLabel);
      try {
        await action();
      } catch (err) {
        if (isStepUpRequired(err)) {
          setPending(() => action);
          return;
        }
        throw err;
      }
    },
    [],
  );

  const close = useCallback(() => setPending(null), []);

  // key={context} resets the dialog's internal state (code, countdown) when a
  // different sensitive action takes over while a dialog is already open.
  const dialog: ReactNode = pending ? (
    <StepUpDialog
      key={context}
      context={context}
      emailAction={emailAction}
      action={pending}
      onClose={close}
    />
  ) : null;

  return { run, dialog };
}
