import { useCallback, useEffect, useState } from "react";
import {
  getActiveSessions,
  getSessionHistory,
  revokeAllSessions,
  revokeSession,
  type SessionHistoryEntry,
  type SessionInfo,
} from "../api";
import { Button, ConfirmDialog, ErrorNote, PageTitle, Pagination, Stamp } from "../ui";
import { useStepUp } from "../stepUp";

/* Bank-statement style table: dense rows, hairline rules, monospace
   for device/IP data, outlined stamps for the "current session" marker.
   Both tables page: active sessions client-side (the API returns them all
   and they're capped server-side anyway, so the page size is fixed at 5 —
   no dropdown), history server-side via the history endpoint's page/limit
   params, with its own rows-per-page dropdown. The two page sizes are
   independent state: changing one must never move the other. */

const ACTIVE_PAGE_SIZE = 5;

function formatDateTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [activePage, setActivePage] = useState(1);
  const [history, setHistory] = useState<SessionHistoryEntry[]>([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyTotalPages, setHistoryTotalPages] = useState(1);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyBusy, setHistoryBusy] = useState(false);
  // Rows per page for the HISTORY table only — the active table's size is
  // the fixed constant above.
  const [historyPageSize, setHistoryPageSize] = useState(5);
  const [maxSessions, setMaxSessions] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [revoking, setRevoking] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [revokeTarget, setRevokeTarget] = useState<SessionInfo | null>(null);
  const [confirmRevokeAll, setConfirmRevokeAll] = useState(false);
  const stepUp = useStepUp();

  const loadActive = useCallback(async () => {
    const active = await getActiveSessions();
    setSessions(active.sessions);
    setMaxSessions(active.maxActiveSessions ?? null);
    // Page 1 of a fresh list (or clamp if the list shrank).
    setActivePage(
      (prev) => Math.min(prev, Math.max(1, Math.ceil(active.sessions.length / ACTIVE_PAGE_SIZE))) || 1,
    );
  }, []);

  const loadHistory = useCallback(async (page: number, limit: number) => {
    setHistoryBusy(true);
    try {
      const past = await getSessionHistory(page, limit);
      setHistory(past.history);
      setHistoryTotal(past.total);
      setHistoryTotalPages(past.totalPages || 1);
      setHistoryPage(past.page || page);
    } finally {
      setHistoryBusy(false);
    }
  }, []);

  const load = useCallback(async () => {
    try {
      setError("");
      await Promise.all([loadActive(), loadHistory(1, historyPageSize)]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load sessions");
    } finally {
      setLoading(false);
    }
  }, [loadActive, loadHistory, historyPageSize]);

  useEffect(() => {
    load();
  }, [load]);

  // Changing the history page size restarts the history table at page 1
  // with the new size — the active table is untouched.
  const onHistoryPageSizeChange = (size: number) => {
    setHistoryPageSize(size);
  };

  async function onRevoke(session: SessionInfo) {
    setRevoking(session.id);
    setError("");
    setNotice("");
    try {
      await revokeSession(session.id);
      if (session.current) {
        // Revoking the current session invalidates our own cookies. Sending
        // the user to the login screen with a message beats a silent bounce:
        // they see WHY they suddenly have to sign in again.
        window.location.href = "/login?reason=revoked";
        return;
      }
      setSessions((prev) => prev.filter((s) => s.id !== session.id));
      setNotice(`Session on ${session.device} revoked.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke session");
    } finally {
      setRevoking(null);
    }
  }

  async function onRevokeAll() {
    setConfirmRevokeAll(false);
    setRevoking("all");
    setError("");
    try {
      // Signing out everywhere is high-impact: the backend may challenge with
      // an emailed OTP (step-up) before letting it through.
      await stepUp.run(
        async () => {
          await revokeAllSessions();
          window.location.href = "/login";
        },
        "You're about to sign out on every device.",
        "sign out on all your devices",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke sessions");
    } finally {
      setRevoking(null);
    }
  }

  // Active sessions page client-side: the endpoint returns them all (they're
  // capped server-side by MAX_ACTIVE_SESSIONS anyway).
  const activeTotalPages = Math.max(1, Math.ceil(sessions.length / ACTIVE_PAGE_SIZE));
  const activeSlice = sessions.slice((activePage - 1) * ACTIVE_PAGE_SIZE, activePage * ACTIVE_PAGE_SIZE);

  return (
    <div>
      <PageTitle
        overline="Security"
        title="Active sessions"
        aside={
          <span className="flex items-center gap-3">
            <span className="tnum">
              {maxSessions
                ? `${sessions.length} of ${maxSessions} ${maxSessions === 1 ? "device" : "devices"} used`
                : `${sessions.length} ${sessions.length === 1 ? "session" : "sessions"} active`}
            </span>
            <Button
              variant="outline"
              className="px-3 py-1.5 text-xs"
              onClick={() => void load()}
              disabled={loading}
            >
              {loading ? "Refreshing…" : "↻ Refresh"}
            </Button>
          </span>
        }
      />

      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-xl text-sm leading-relaxed text-ink-soft">
          Each row is a device currently holding valid credentials for your account. Anything you
          don&rsquo;t recognise — revoke it immediately.
        </p>
        <Button variant="danger" onClick={() => setConfirmRevokeAll(true)} disabled={revoking === "all"}>
          {revoking === "all" ? "Revoking all…" : "Revoke all sessions"}
        </Button>
      </div>

      <ErrorNote>{error}</ErrorNote>
      {notice && !error && (
        <p className="mb-4 rounded-xs border border-accent/30 bg-accent-soft px-3 py-2 text-sm text-accent">
          {notice}
        </p>
      )}

      {loading ? (
        <p className="py-16 text-center text-sm text-ink-faint">Loading sessions…</p>
      ) : sessions.length === 0 ? (
        <p className="py-16 text-center text-sm text-ink-faint">No active sessions.</p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-sm border border-rule bg-paper-raised">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b border-rule text-left text-xs font-semibold tracking-[0.08em] text-ink-faint uppercase">
                  <th className="px-4 py-3">Device</th>
                  <th className="px-4 py-3">IP address</th>
                  <th className="px-4 py-3">Signed in</th>
                  <th className="px-4 py-3">Last used</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {activeSlice.map((s) => (
                  <tr
                    key={s.id}
                    className={`border-b border-rule last:border-b-0 ${s.current ? "bg-accent-soft/50" : ""}`}
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[13px] text-ink">{s.device}</span>
                        {s.current && <Stamp tone="good">This device</Stamp>}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-[13px] text-ink-soft">
                      {s.ipAddress || "—"}
                    </td>
                    <td className="tnum px-4 py-3 text-ink-soft">{formatDateTime(s.createdAt)}</td>
                    <td className="tnum px-4 py-3 text-ink-soft">{formatDateTime(s.lastUsedAt)}</td>
                    <td className="px-4 py-3 text-right">
                      <Button
                        variant="outline"
                        className="px-3 py-1.5 text-xs"
                        onClick={() => setRevokeTarget(s)}
                        disabled={revoking === s.id}
                      >
                        {revoking === s.id ? "Revoking…" : "Revoke"}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination
            page={activePage}
            totalPages={activeTotalPages}
            totalItems={sessions.length}
            pageSize={ACTIVE_PAGE_SIZE}
            onPageChange={setActivePage}
            label="sessions"
          />
        </>
      )}

      {!loading && historyTotal > 0 && (
        <section className="mt-10">
          <div className="mb-4 flex items-baseline justify-between gap-3">
            <h2 className="font-display text-xl font-medium text-ink">Session history</h2>
            <span className="tnum text-xs text-ink-faint">read-only</span>
          </div>
          <div className="overflow-x-auto rounded-sm border border-rule bg-paper-raised">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b border-rule text-left text-xs font-semibold tracking-[0.08em] text-ink-faint uppercase">
                  <th className="px-4 py-3">Device</th>
                  <th className="px-4 py-3">IP address</th>
                  <th className="px-4 py-3">Signed in</th>
                  <th className="px-4 py-3">Ended</th>
                  <th className="px-4 py-3 text-right">How</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id} className="border-b border-rule last:border-b-0">
                    <td className="px-4 py-3 font-mono text-[13px] text-ink">{h.device}</td>
                    <td className="px-4 py-3 font-mono text-[13px] text-ink-soft">
                      {h.ipAddress || "—"}
                    </td>
                    <td className="tnum px-4 py-3 text-ink-soft">{formatDateTime(h.createdAt)}</td>
                    <td className="tnum px-4 py-3 text-ink-soft">{formatDateTime(h.endedAt)}</td>
                    <td className="px-4 py-3 text-right">
                      <Stamp tone={h.reason === "revoked" ? "bad" : "neutral"}>
                        {h.reason === "revoked" ? "Signed out" : "Expired"}
                      </Stamp>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {historyBusy && <p className="mt-3 text-center text-xs text-ink-faint">Loading page…</p>}
          <Pagination
            page={historyPage}
            totalPages={historyTotalPages}
            totalItems={historyTotal}
            pageSize={historyPageSize}
            onPageChange={(page) => void loadHistory(page, historyPageSize)}
            onPageSizeChange={onHistoryPageSizeChange}
            label="entries"
            disabled={historyBusy}
          />
          <p className="mt-3 text-xs text-ink-faint">
            Past sessions are kept for your security record and cannot be modified.
          </p>
        </section>
      )}
      <ConfirmDialog
        open={revokeTarget !== null}
        title={revokeTarget?.current ? "Revoke this device?" : "Revoke this session?"}
        message={
          revokeTarget
            ? revokeTarget.current
              ? `This is the session you're using right now (${revokeTarget.device}). Revoking it signs you out immediately — you'll land back on the sign-in screen.`
              : `The device "${revokeTarget.device}" will be signed out immediately. It will need to sign in again to access your account.`
            : ""
        }
        confirmLabel={revokeTarget?.current ? "Revoke and sign out" : "Revoke session"}
        busy={revoking !== null}
        onConfirm={() => {
          if (revokeTarget) void onRevoke(revokeTarget);
          setRevokeTarget(null);
        }}
        onCancel={() => setRevokeTarget(null)}
      />
      <ConfirmDialog
        open={confirmRevokeAll}
        title="Revoke all sessions?"
        message="You will be signed out on every device, including this one. You may be asked to confirm with an emailed code first."
        confirmLabel="Revoke all"
        busy={revoking === "all"}
        onConfirm={onRevokeAll}
        onCancel={() => setConfirmRevokeAll(false)}
      />
      {stepUp.dialog}
    </div>
  );
}
