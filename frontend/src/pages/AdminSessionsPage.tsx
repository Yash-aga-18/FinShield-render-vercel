import { useCallback, useEffect, useState } from "react";
import {
  adminRevokeSession,
  getAllActiveSessions,
  type AdminSession,
  type AdminSessionSort,
} from "../api";
import { Button, ConfirmDialog, ErrorNote, PageTitle, Pagination, RefreshButton, RiskCell, Stamp, useToast } from "../ui";
import { useStepUp } from "../stepUp";
import { useAuth } from "../auth";

/* Admin panel — global session view: every active session across every
   users, sortable (last used / signed in / risk / expiry, either
   direction) and paged server-side. Admins can revoke any session. */

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const SORT_OPTIONS: { value: AdminSessionSort; label: string }[] = [
  { value: "lastUsed", label: "Last used" },
  { value: "signedIn", label: "Signed in" },
  { value: "risk", label: "Risk score" },
  { value: "expires", label: "Expires" },
];

export default function AdminSessionsPage() {
  const { user: me } = useAuth();
  const [sessions, setSessions] = useState<AdminSession[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [sort, setSort] = useState<AdminSessionSort>("lastUsed");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [revokeTarget, setRevokeTarget] = useState<AdminSession | null>(null);
  const stepUp = useStepUp();
  const { show: showToast, toast } = useToast();

  const load = useCallback(
    async (opts?: { page?: number; pageSize?: number; sort?: AdminSessionSort; order?: "asc" | "desc" }) => {
      const target = opts ?? {};
      try {
        setError("");
        const res = await getAllActiveSessions(
          target.page ?? page,
          target.pageSize ?? pageSize,
          target.sort ?? sort,
          target.order ?? order,
        );
        setSessions(res.sessions);
        setTotal(res.total);
        setTotalPages(res.totalPages || 1);
        setPage(res.page || (target.page ?? page));
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load sessions");
      } finally {
        setLoading(false);
      }
    },
    [page, pageSize, sort, order],
  );

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pageSize, sort, order]);

  /* Sorting resets to page 1 — page 3 of a "last used" sort is a different
     slice of rows entirely once the sort key changes. */
  const onSortChange = (next: AdminSessionSort) => {
    setSort(next);
    setPage(1);
  };

  const onOrderChange = (next: "asc" | "desc") => {
    setOrder(next);
    setPage(1);
  };

  const onPageChange = (next: number) => {
    setPage(next);
    void load({ page: next });
  };

  const onPageSizeChange = (size: number) => {
    setPageSize(size);
    setPage(1);
  };

  async function onRevoke() {
    const target = revokeTarget;
    if (!target) return;
    setRevokeTarget(null);
    setError("");
    const isOwnSession = me && target.userId === me.id;
    try {
      await stepUp.run(
        async () => {
          await adminRevokeSession(target.id);
          if (isOwnSession) {
            // Our own cookies just died. A toast would vanish with the
            // redirect — send the user to the login screen with the
            // reason spelled out there instead of a silent bounce.
            window.location.href = "/login?reason=revoked";
            return;
          }
          setSessions((prev) => prev.filter((s) => s.id !== target.id));
          showToast(
            `Session revoked: ${target.userName} (${target.userEmail}) signed out from ${target.device}.`,
          );
        },
        isOwnSession
          ? "You're about to revoke YOUR OWN session — this signs you out immediately."
          : `You're about to sign out ${target.userEmail}'s device.`,
        `revoke the session for ${target.userEmail} (${target.device})`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke session");
    }
  }

  const selectClass =
    "rounded-sm border border-rule-strong bg-paper-raised px-2 py-1.5 text-xs text-ink outline-none transition-colors focus:border-accent disabled:opacity-50";

  return (
    <div>
      <PageTitle
        overline="Admin panel"
        title="All active sessions"
        aside={
          <span className="flex items-center gap-3">
            <span className="tnum">
              {total} {total === 1 ? "session" : "sessions"} across all users
            </span>
            <RefreshButton
              loading={loading}
              onClick={async () => {
                await load();
                showToast("Session list refreshed.");
              }}
            />
          </span>
        }
      />

      <p className="mb-6 max-w-xl text-sm leading-relaxed text-ink-soft">
        Every device currently holding valid credentials, across every account, with the risk score
        of the sign-in that created it. Revoking a session signs that device out immediately.
      </p>

      <ErrorNote>{error}</ErrorNote>

      {/* Sort controls — column + direction, applied server-side so the
          order holds across pages. */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-xs text-ink-faint">
          <span>Sort by</span>
          <select value={sort} onChange={(e) => onSortChange(e.target.value as AdminSessionSort)} className={selectClass}>
            {SORT_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2 text-xs text-ink-faint">
          <span>Order</span>
          <select
            value={order}
            onChange={(e) => onOrderChange(e.target.value as "asc" | "desc")}
            className={selectClass}
          >
            <option value="desc">High → low</option>
            <option value="asc">Low → high</option>
          </select>
        </label>
        <span className="text-xs text-ink-faint">
          {sort === "risk" ? "Highest risk first" : "Most recent first"}
          {order === "asc" ? " (reversed)" : ""}
        </span>
      </div>

      {loading ? (
        <p className="py-16 text-center text-sm text-ink-faint">Loading sessions…</p>
      ) : sessions.length === 0 ? (
        <p className="py-16 text-center text-sm text-ink-faint">No active sessions.</p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-sm border border-rule bg-paper-raised">
            <table className="w-full min-w-[900px] text-sm">
              <thead>
                <tr className="border-b border-rule text-left text-xs font-semibold tracking-[0.08em] text-ink-faint uppercase">
                  <th className="px-4 py-3">User</th>
                  <th className="px-4 py-3">Device</th>
                  <th className="px-4 py-3">IP address</th>
                  <th className="px-4 py-3">Signed in</th>
                  <th className="px-4 py-3">Last used</th>
                  <th className="px-4 py-3 text-right">Risk score</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((s) => (
                  <tr key={s.id} className="border-b border-rule last:border-b-0">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-ink">{s.userName}</span>
                        {me && s.userId === me.id && <Stamp tone="good">You</Stamp>}
                      </div>
                      <div className="text-xs text-ink-faint">{s.userEmail}</div>
                    </td>
                    <td className="px-4 py-3 font-mono text-[13px] text-ink">{s.device}</td>
                    <td className="px-4 py-3 font-mono text-[13px] text-ink-soft">{s.ipAddress}</td>
                    <td className="tnum px-4 py-3 text-ink-soft">{formatDateTime(s.createdAt)}</td>
                    <td className="tnum px-4 py-3 text-ink-soft">{formatDateTime(s.lastUsedAt)}</td>
                    <td className="px-4 py-3 text-right">
                      <RiskCell score={s.riskScore} level={s.riskLevel} />
                    </td>
                    <td className="px-4 py-3 text-right">
                      <Button
                        variant="outline"
                        className="px-3 py-1.5 text-xs"
                        onClick={() => setRevokeTarget(s)}
                      >
                        Revoke
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination
            page={page}
            totalPages={totalPages}
            totalItems={total}
            pageSize={pageSize}
            onPageChange={onPageChange}
            onPageSizeChange={onPageSizeChange}
            label="sessions"
          />
        </>
      )}

      <ConfirmDialog
        open={revokeTarget !== null}
        title="Revoke this session?"
        message={
          revokeTarget
            ? me && revokeTarget.userId === me.id
              ? `This is YOUR OWN session on "${revokeTarget.device}". Revoking it signs you out of the admin panel immediately.`
              : `The device "${revokeTarget.device}" signed in as ${revokeTarget.userEmail} will be signed out immediately.`
            : ""
        }
        confirmLabel="Revoke session"
        onConfirm={onRevoke}
        onCancel={() => setRevokeTarget(null)}
      />
      {stepUp.dialog}
      {toast}
    </div>
  );
}
