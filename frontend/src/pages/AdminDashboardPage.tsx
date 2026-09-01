import { useEffect, useMemo, useState } from "react";
import { getAllActiveSessions, getAllUsers, getAuditIntegrity, type AdminSession, type AuditIntegrity } from "../api";
import { ErrorNote, PageTitle, Stamp } from "../ui";

/* Admin dashboard — built entirely from data the existing admin endpoints
   already return (users list + all active sessions), so no backend changes
   were needed. Numbers are computed client-side on load. */

function StatCard({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-sm border border-rule bg-paper-raised p-5">
      <p className="text-xs font-semibold tracking-[0.08em] text-ink-faint uppercase">{label}</p>
      <p className="font-display tnum mt-2 text-3xl font-medium text-ink">{value}</p>
      {hint && <p className="mt-1 text-xs text-ink-faint">{hint}</p>}
    </div>
  );
}

/* Hour-of-day distribution of sign-ins, rendered as plain CSS bars —
   no chart library needed. Built from currently active sessions, which is
   all the existing API exposes; the label says so honestly. */
function SignInChart({ sessions }: { sessions: AdminSession[] }) {
  const buckets = useMemo(() => {
    const counts = new Array(24).fill(0) as number[];
    for (const s of sessions) {
      counts[new Date(s.createdAt).getHours()] += 1;
    }
    return counts;
  }, [sessions]);

  const max = Math.max(1, ...buckets);

  return (
    <div className="rounded-sm border border-rule bg-paper-raised p-5">
      <p className="text-xs font-semibold tracking-[0.08em] text-ink-faint uppercase">
        Sign-in time of day
      </p>
      <div className="mt-4 flex h-32 items-end gap-1">
        {buckets.map((count, hour) => (
          <div key={hour} className="group relative flex-1" title={`${hour}:00 — ${count}`}>
            <div
              className="w-full rounded-t-[2px] bg-accent/70 transition-colors group-hover:bg-accent"
              style={{ height: `${count === 0 ? 2 : Math.max(4, (count / max) * 100)}%` }}
            />
          </div>
        ))}
      </div>
      <div className="mt-2 flex justify-between text-[10px] text-ink-faint tnum">
        <span>00</span>
        <span>06</span>
        <span>12</span>
        <span>18</span>
        <span>23</span>
      </div>
      <p className="mt-3 text-xs text-ink-faint">
        When accounts signed in, grouped by hour. Based on the {sessions.length} currently active
        session{sessions.length === 1 ? "" : "s"} — expired or revoked sessions aren&rsquo;t
        included.
      </p>
    </div>
  );
}

function SessionsByUser({ sessions }: { sessions: AdminSession[] }) {
  const byUser = useMemo(() => {
    const map = new Map<string, { name: string; email: string; count: number; devices: Set<string> }>();
    for (const s of sessions) {
      const entry = map.get(s.userId) ?? {
        name: s.userName,
        email: s.userEmail,
        count: 0,
        devices: new Set<string>(),
      };
      entry.count += 1;
      entry.devices.add(s.device);
      map.set(s.userId, entry);
    }
    return [...map.values()].sort((a, b) => b.count - a.count);
  }, [sessions]);

  return (
    <div className="overflow-x-auto rounded-sm border border-rule bg-paper-raised">
      <table className="w-full min-w-[520px] text-sm">
        <thead>
          <tr className="border-b border-rule text-left text-xs font-semibold tracking-[0.08em] text-ink-faint uppercase">
            <th className="px-4 py-3">User</th>
            <th className="px-4 py-3 text-right">Active sessions</th>
            <th className="px-4 py-3">Devices</th>
          </tr>
        </thead>
        <tbody>
          {byUser.map((u) => (
            <tr key={u.email} className="border-b border-rule last:border-b-0">
              <td className="px-4 py-3">
                <div className="text-ink">{u.name}</div>
                <div className="text-xs text-ink-faint">{u.email}</div>
              </td>
              <td className="tnum px-4 py-3 text-right text-ink">{u.count}</td>
              <td className="px-4 py-3 font-mono text-[13px] text-ink-soft">
                {[...u.devices].join(", ")}
              </td>
            </tr>
          ))}
          {byUser.length === 0 && (
            <tr>
              <td colSpan={3} className="px-4 py-8 text-center text-sm text-ink-faint">
                No active sessions.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

/* Audit-trail integrity: every audit entry is hash-chained to the previous
   one, and the backend recomputes the whole chain on request. "Intact"
   means nobody — not even an admin, not even someone writing to the
   database directly — has edited or deleted history without it showing.
   A broken chain is a verdict, not a problem to fix from here. */
function AuditIntegrityCard() {
  const [integrity, setIntegrity] = useState<AuditIntegrity | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getAuditIntegrity()
      .then((res) => setIntegrity(res.integrity))
      .catch(
        (err) =>
          setError(err instanceof Error ? err.message : "Failed to check the audit trail"),
      );
  }, []);

  if (error) {
    return (
      <div className="rounded-sm border border-rule bg-paper-raised p-5">
        <p className="text-xs font-semibold tracking-[0.08em] text-ink-faint uppercase">
          Audit trail
        </p>
        <p className="mt-2 text-sm text-red-stamp">{error}</p>
      </div>
    );
  }
  if (!integrity) return null;

  const intact = integrity.valid;
  return (
    <div
      className={`rounded-sm border bg-paper-raised p-5 ${
        intact ? "border-rule" : "border-red-stamp/60"
      }`}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <p className="text-xs font-semibold tracking-[0.08em] text-ink-faint uppercase">
          Audit trail
        </p>
        <Stamp tone={intact ? "good" : "bad"}>{intact ? "Intact" : "Tampering detected"}</Stamp>
        {integrity.anchor === "matched" && (
          <span className="text-xs text-ink-faint">anchored</span>
        )}
      </div>
      <p className={`mt-2 text-sm leading-relaxed ${intact ? "text-ink-soft" : "text-red-stamp"}`}>
        {intact
          ? `${integrity.checked} chained ${
              integrity.checked === 1 ? "entry" : "entries"
            } verified — the log is append-only and unedited.`
          : `${integrity.detail ?? "The chain is broken."} (${integrity.event ?? "unknown"} event, id ${
              integrity.entryId ?? "—"
            })`}
      </p>
      {!intact && (
        <p className="mt-1 text-xs text-ink-faint">
          A broken chain cannot be repaired from the panel — investigate the database directly.
        </p>
      )}
    </div>
  );
}

export default function AdminDashboardPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [totalUsers, setTotalUsers] = useState(0);
  const [totalSessions, setTotalSessions] = useState(0);
  const [sessions, setSessions] = useState<AdminSession[]>([]);

  useEffect(() => {
    (async () => {
      try {
        setError("");
        // The chart/by-user tables work on the first page of sessions (the
        // endpoint is hard-capped server-side); the stat card uses `total`
        // so the count stays honest past the cap.
        const [usersRes, sessionsRes] = await Promise.all([
          getAllUsers(),
          getAllActiveSessions(1, 100),
        ]);
        setTotalUsers(usersRes.total);
        setTotalSessions(sessionsRes.total);
        setSessions(sessionsRes.sessions);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load dashboard");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const usersWithSessions = new Set(sessions.map((s) => s.userId)).size;

  return (
    <div>
      <PageTitle
        overline="Admin panel"
        title="Dashboard"
        aside={<span className="tnum text-xs text-ink-faint">Live overview</span>}
      />

      <ErrorNote>{error}</ErrorNote>

      {loading ? (
        <p className="py-16 text-center text-sm text-ink-faint">Loading dashboard…</p>
      ) : (
        <>
          <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
            <StatCard label="Total users" value={String(totalUsers)} hint="All registered accounts" />
            <StatCard
              label="Active sessions"
              value={String(totalSessions)}
              hint="Devices signed in right now"
            />
            <StatCard
              label="Users online"
              value={String(usersWithSessions)}
              hint="Users holding at least one session"
            />
          </div>

          <div className="mb-8">
            <AuditIntegrityCard />
          </div>

          <div className="mb-8">
            <h2 className="font-display mb-4 text-xl font-medium text-ink">
              Active sessions by user
            </h2>
            <SessionsByUser sessions={sessions} />
          </div>

          <SignInChart sessions={sessions} />
        </>
      )}
    </div>
  );
}
