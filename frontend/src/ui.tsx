import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
} from "react";

/* Shared "Paper & Ink" UI primitives: flat surfaces, hairline rules,
   small radii, one green accent. No shadows, no glass, no gradients. */

export function Button({
  variant = "primary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "outline" | "danger" }) {
  const base =
    "inline-flex items-center justify-center gap-2 rounded-sm px-4 py-2 text-sm font-medium " +
    "transition-colors duration-100 disabled:cursor-not-allowed disabled:opacity-50";
  const styles = {
    primary: "bg-accent text-paper hover:bg-[#123528]",
    outline: "border border-rule-strong text-ink hover:bg-paper-sunken",
    danger: "border border-red-stamp text-red-stamp hover:bg-red-soft",
  }[variant];
  return <button className={`${base} ${styles} ${className}`} {...props} />;
}

export function Field({
  label,
  hint,
  className = "",
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-semibold tracking-[0.08em] text-ink-soft uppercase">
        {label}
      </span>
      <input
        className={`w-full rounded-sm border border-rule-strong bg-paper-raised px-3 py-2 text-sm text-ink
          outline-none transition-colors placeholder:text-ink-faint
          focus:border-accent focus:ring-2 focus:ring-accent/15 ${className}`}
        {...props}
      />
      {hint && <span className="mt-1 block text-xs text-ink-faint">{hint}</span>}
    </label>
  );
}

/* Password input with a show/hide eye toggle. */
export function PasswordField({
  label,
  hint,
  className = "",
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  const [visible, setVisible] = useState(false);
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-semibold tracking-[0.08em] text-ink-soft uppercase">
        {label}
      </span>
      <div className="relative">
        <input
          type={visible ? "text" : "password"}
          className={`w-full rounded-sm border border-rule-strong bg-paper-raised py-2 pr-11 pl-3 text-sm text-ink
            outline-none transition-colors placeholder:text-ink-faint
            focus:border-accent focus:ring-2 focus:ring-accent/15 ${className}`}
          {...props}
        />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? "Hide password" : "Show password"}
          className="absolute inset-y-0 right-0 flex w-10 items-center justify-center text-ink-faint transition-colors hover:text-ink"
        >
          {visible ? (
            /* eye-off icon */
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
              <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
              <path d="M14.12 14.12A3 3 0 1 1 9.88 9.88" />
              <line x1="1" y1="1" x2="23" y2="23" />
            </svg>
          ) : (
            /* eye icon */
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
              <circle cx="12" cy="12" r="3" />
            </svg>
          )}
        </button>
      </div>
      {hint && <span className="mt-1 block text-xs text-ink-faint">{hint}</span>}
    </label>
  );
}

/* Styled confirmation dialog used for destructive actions. */
export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  danger = true,
  busy = false,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink/30 p-4"
      role="dialog"
      aria-modal="true"
      onClick={onCancel}
    >
      <div
        className="w-full max-w-sm rounded-sm border border-rule bg-paper-raised p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="font-display mb-2 text-xl font-medium text-ink">{title}</h2>
        <p className="mb-6 text-sm leading-relaxed text-ink-soft">{message}</p>
        <div className="flex justify-end gap-3">
          <Button variant="outline" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant={danger ? "danger" : "primary"}
            onClick={onConfirm}
            disabled={busy}
          >
            {busy ? "Working…" : confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}

export function Stamp({
  tone = "neutral",
  children,
}: {
  tone?: "neutral" | "good" | "warn" | "bad";
  children: ReactNode;
}) {
  const colors = {
    neutral: "text-ink-soft",
    good: "text-accent",
    warn: "text-amber-stamp",
    bad: "text-red-stamp",
  }[tone];
  return <span className={`stamp ${colors}`}>{children}</span>;
}

export function ErrorNote({ children }: { children: ReactNode }) {
  if (!children) return null;
  return (
    <p className="rounded-xs border border-red-stamp/40 bg-red-soft px-3 py-2 text-sm text-red-stamp">
      {children}
    </p>
  );
}

/* Risk score + level, as shown in the admin tables. Risk levels map to the
   same stamp tones the audit log uses. Sessions (and users) with no stored
   score — sessions created before risk was recorded — show an em dash,
   never a guessed 0. */
export function RiskCell({ score, level }: { score: number | null; level: string | null }) {
  if (score === null || score === undefined) {
    return <span className="text-ink-faint">—</span>;
  }
  const tone =
    level === "CRITICAL" || level === "HIGH" ? "bad" : level === "MEDIUM" ? "warn" : "good";
  return (
    <span className="flex items-center justify-end gap-2">
      <span className="tnum text-ink">{score}</span>
      <Stamp tone={tone}>{level ?? "—"}</Stamp>
    </span>
  );
}

/* Page-size options for tables. 5 is the default everywhere — tables stay
   scannable; bigger pages are one dropdown away. */
export const PAGE_SIZE_OPTIONS = [5, 10, 15, 20, 30, 50];

/* Pagination bar: "x–y of z" summary, prev/next page controls, and (only
   when onPageSizeChange is given) a rows-per-page dropdown. Pass the
   dropdown only where it's genuinely useful — active sessions, a short
   capped list, reads better without one. */
export function Pagination({
  page,
  totalPages,
  totalItems,
  pageSize,
  onPageChange,
  onPageSizeChange,
  label = "rows",
  disabled = false,
}: {
  page: number;
  totalPages: number;
  totalItems: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  /** Omit to render the bar without the rows-per-page dropdown. */
  onPageSizeChange?: (size: number) => void;
  /** What a row is called in the summary — "sessions", "entries", … */
  label?: string;
  disabled?: boolean;
}) {
  if (totalItems === 0) return null;

  const from = (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, totalItems);
  const summary = `${from}–${to} of ${totalItems} ${totalItems === 1 ? label.replace(/s$/, "") : label}`;

  return (
    <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
      <div className="flex items-center gap-4">
        <span className="tnum text-xs text-ink-faint">{summary}</span>
        {onPageSizeChange && (
          <label className="flex items-center gap-2 text-xs text-ink-faint">
            <span>Per page</span>
            <select
              value={pageSize}
              disabled={disabled}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              className="rounded-sm border border-rule-strong bg-paper-raised px-2 py-1 text-xs text-ink outline-none transition-colors focus:border-accent disabled:opacity-50"
            >
              {PAGE_SIZE_OPTIONS.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
        )}
      </div>
      {totalPages > 1 && (
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            className="px-3 py-1.5 text-xs"
            onClick={() => onPageChange(page - 1)}
            disabled={disabled || page <= 1}
          >
            ← Previous
          </Button>
          <span className="tnum text-xs text-ink-soft">
            Page {page} of {totalPages}
          </span>
          <Button
            variant="outline"
            className="px-3 py-1.5 text-xs"
            onClick={() => onPageChange(page + 1)}
            disabled={disabled || page >= totalPages}
          >
            Next →
          </Button>
        </div>
      )}
    </div>
  );
}

/* Success toast: fixed bottom-right, auto-dismisses. Used to confirm
   destructive admin actions ("John (x@y.com) was deleted") — the kind of
   feedback a passive banner on the page can't deliver, because the modal
   closing means "done" only if something says what was done. */
export function useToast() {
  const [message, setMessage] = useState("");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const show = useCallback((text: string) => {
    if (timer.current) clearTimeout(timer.current);
    setMessage(text);
  }, []);

  const dismiss = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    setMessage("");
  }, []);

  useEffect(() => {
    if (!message) return;
    timer.current = setTimeout(() => setMessage(""), 5000);
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [message]);

  const toast: ReactNode = message ? (
    <div
      role="status"
      aria-live="polite"
      className="fixed right-6 bottom-6 z-[60] flex max-w-sm items-start gap-3 rounded-sm border border-accent/40 bg-paper-raised px-4 py-3 text-sm text-ink"
    >
      <span className="mt-0.5 text-accent" aria-hidden>
        ✓
      </span>
      <p className="leading-relaxed">{message}</p>
      <button
        type="button"
        onClick={dismiss}
        aria-label="Dismiss"
        className="ml-1 shrink-0 text-ink-faint transition-colors hover:text-ink"
      >
        ✕
      </button>
    </div>
  ) : null;

  return { show, toast };
}

export function PageTitle({
  overline,
  title,
  aside,
}: {
  overline: string;
  title: string;
  aside?: ReactNode;
}) {
  return (
    <div className="mb-8 flex flex-wrap items-end justify-between gap-4 border-b border-rule pb-5">
      <div>
        <p className="mb-1 text-xs font-semibold tracking-[0.14em] text-accent uppercase">
          {overline}
        </p>
        <h1 className="font-display text-3xl font-medium text-ink">{title}</h1>
      </div>
      {aside && <div className="text-sm text-ink-soft">{aside}</div>}
    </div>
  );
}
