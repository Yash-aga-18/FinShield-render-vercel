import { useCallback, useEffect, useState } from "react";
import {
  adminChangeUserRole,
  adminDeleteUser,
  adminRevokeUserSessions,
  getAllUsers,
  getUserActivity,
  type AdminUserSort,
  type User,
  type UserActivity,
} from "../api";
import { useAuth } from "../auth";
import {
  Button,
  ConfirmDialog,
  ErrorNote,
  PageTitle,
  Pagination,
  RiskCell,
  Stamp,
  useToast,
} from "../ui";
import { useStepUp } from "../stepUp";
/* Admin panel — user management: list all users with active-session,
   last-login, and risk columns, sortable and searchable, view a per-user
   activity log, revoke sessions, or delete the user. Confirmation dialogs
   guard destructive actions. */

/* Sortable columns of the users table. "Risk" is the user's highest
   active-session risk score — computed server-side, so the order holds
   across pages. */
const SORT_OPTIONS: { value: AdminUserSort; label: string }[] = [
  { value: "registered", label: "Registered" },
  { value: "lastLogin", label: "Last login" },
  { value: "active", label: "Active sessions" },
  { value: "risk", label: "Risk score" },
  { value: "name", label: "Name" },
  { value: "email", label: "Email" },
];

function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function timeAgo(value?: string | null): string {
  if (!value) return "never";
  const ms = Date.now() - new Date(value).getTime();
  const mins = Math.floor(ms / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(value).toLocaleDateString();
}

const severityTone = (severity: string) =>
  severity === "CRITICAL" || severity === "HIGH"
    ? "bad"
    : severity === "ERROR" || severity === "WARN"
      ? "warn"
      : "neutral";

const eventLabel = (event: string): string =>
  event
    .toLowerCase()
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");

/* Side drawer with one user's details: contact info, verification state,
   session counts, and their recent audit events. Opened by clicking the
   user's name (or "Logs") in the table. */
function ActivityDrawer({
  user,
  refreshKey,
  onRevokeRequest,
  onClose,
}: {
  user: User;
  /* Bumped by the parent after a revoke completes so this drawer re-fetches
     even while it stays open behind the step-up modal. */
  refreshKey: number;
  /* Asks the parent to start a revoke — the parent opens the confirmation
     dialog (and owns the step-up flow). Calling the API directly here would
     skip the confirmation AND always fail with STEP_UP_REQUIRED. */
  onRevokeRequest: (user: User) => void;
  onClose: () => void;
}) {
  const [activity, setActivity] = useState<UserActivity | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try {
        setError("");
        setActivity(await getUserActivity(user.id));
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load activity");
      }
    })();
  }, [user.id, refreshKey]);

  function onRevoke() {
    setError("");
    // Never revoke straight from the drawer — the confirm dialog in the
    // parent decides whether it happens at all (and warns when the target
    // is the admin's own account).
    onRevokeRequest(user);
  }

  return (
    <div
      className="fixed inset-0 z-40 flex justify-end bg-ink/30"
      role="dialog"
      aria-modal="true"
      onClick={onClose}
    >
      <div
        className="h-full w-full max-w-lg overflow-y-auto bg-paper-raised p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between">
          <div>
            <p className="text-xs font-semibold tracking-[0.08em] text-ink-faint uppercase">
              User details
            </p>
            <h2 className="font-display mt-1 text-xl font-medium text-ink">{user.name}</h2>
            <p className="text-sm text-ink-soft">{user.email}</p>
          </div>
          <button
            onClick={onClose}
            className="text-sm text-ink-soft transition-colors hover:text-ink"
            aria-label="Close"
          >
            Close
          </button>
        </div>

        <ErrorNote>{error}</ErrorNote>

        {!activity ? (
          <p className="py-12 text-center text-sm text-ink-faint">Loading activity…</p>
        ) : (
          <>
            <div className="mb-6 grid grid-cols-2 gap-3">
              <div className="rounded-sm border border-rule p-3">
                <p className="text-xs text-ink-faint uppercase">Phone number</p>
                <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-ink">
                  {activity.user.phoneNumber ?? (
                    <span className="text-ink-faint">Not added</span>
                  )}
                  {activity.user.phoneNumber && (
                    <Stamp tone={activity.user.phoneVerified ? "good" : "warn"}>
                      {activity.user.phoneVerified ? "Verified" : "Unverified"}
                    </Stamp>
                  )}
                </p>
              </div>
              <div className="rounded-sm border border-rule p-3">
                <p className="text-xs text-ink-faint uppercase">Sign-in method</p>
                <p className="mt-1 text-sm text-ink">
                  {activity.user.hasGoogle ? "Google account" : "Email & password"}
                </p>
              </div>
              <div className="rounded-sm border border-rule p-3">
                <p className="text-xs text-ink-faint uppercase">Email</p>
                <p className="mt-1 text-sm">
                  <Stamp tone={activity.user.isVerified ? "good" : "warn"}>
                    {activity.user.isVerified ? "Verified" : "Not verified"}
                  </Stamp>
                </p>
              </div>
              <div className="rounded-sm border border-rule p-3">
                <p className="text-xs text-ink-faint uppercase">Role</p>
                <p className="mt-1 text-sm text-ink">
                  <Stamp tone={activity.user.role === "admin" ? "warn" : "neutral"}>
                    {activity.user.role}
                  </Stamp>
                </p>
              </div>
              <div className="rounded-sm border border-rule p-3">
                <p className="text-xs text-ink-faint uppercase">Account created</p>
                <p className="mt-1 text-sm text-ink">{formatDateTime(activity.user.createdAt)}</p>
              </div>
              <div className="rounded-sm border border-rule p-3">
                <p className="text-xs text-ink-faint uppercase">Last login</p>
                <p className="mt-1 text-sm text-ink">
                  {formatDateTime(activity.user.lastLoginAt)}
                  <span className="ml-2 text-xs text-ink-faint">
                    ({timeAgo(activity.user.lastLoginAt)})
                  </span>
                </p>
              </div>
              <div className="rounded-sm border border-rule p-3">
                <p className="text-xs text-ink-faint uppercase">Active sessions</p>
                <p className="tnum mt-1 text-sm text-ink">{activity.user.activeSessions}</p>
              </div>
              <div className="rounded-sm border border-rule p-3">
                <p className="text-xs text-ink-faint uppercase">Sessions all-time</p>
                <p className="tnum mt-1 text-sm text-ink">{activity.user.totalSessions}</p>
              </div>
            </div>

            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold tracking-[0.08em] text-ink-faint uppercase">
                Recent events
              </h3>
              {activity.user.activeSessions > 0 && (
                <Button
                  variant="outline"
                  className="px-3 py-1 text-xs"
                  onClick={onRevoke}
                >
                  Revoke sessions
                </Button>
              )}
            </div>

            <ul className="divide-y divide-rule rounded-sm border border-rule">
              {activity.events.map((e) => (
                <li key={e.id} className="flex items-start gap-3 px-3 py-2.5 text-sm">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-ink">{eventLabel(e.event)}</span>
                      <Stamp tone={severityTone(e.severity)}>{e.severity}</Stamp>
                      {e.reason && (
                        <span className="text-xs text-ink-faint">({e.reason.replaceAll("_", " ")})</span>
                      )}
                    </div>
                    <p className="mt-0.5 truncate text-xs text-ink-faint">
                      {[e.device, e.ipAddress].filter(Boolean).join(" · ") || "—"}
                    </p>
                  </div>
                  <span className="tnum shrink-0 text-xs text-ink-faint">
                    {formatDateTime(e.createdAt)}
                  </span>
                </li>
              ))}
              {activity.events.length === 0 && (
                <li className="px-3 py-6 text-center text-sm text-ink-faint">
                  No recorded events for this user.
                </li>
              )}
            </ul>
          </>
        )}
      </div>
    </div>
  );
}

export default function AdminUsersPage() {
  const { user: me } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [sort, setSort] = useState<AdminUserSort>("registered");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  // Typed into the box; debounced into `search` so the server isn't queried
  // on every keystroke.
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<User | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<User | null>(null);
  const [roleTarget, setRoleTarget] = useState<User | null>(null);
  const [activityTarget, setActivityTarget] = useState<User | null>(null);
  const [activityRefresh, setActivityRefresh] = useState(0);
  const stepUp = useStepUp();
  const { show: showToast, toast } = useToast();

  const load = useCallback(
    async (opts?: {
      page?: number;
      pageSize?: number;
      sort?: AdminUserSort;
      order?: "asc" | "desc";
      search?: string;
    }) => {
      const target = opts ?? {};
      try {
        setError("");
        const res = await getAllUsers(
          target.page ?? page,
          target.pageSize ?? pageSize,
          target.sort ?? sort,
          target.order ?? order,
          target.search ?? search,
        );
        setUsers(res.users);
        setTotal(res.total);
        setTotalPages(res.totalPages || 1);
        setPage(res.page || (target.page ?? page));
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load users");
      } finally {
        setLoading(false);
      }
    },
    [page, pageSize, sort, order, search],
  );

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pageSize, sort, order, search]);

  // Debounce the search box: wait for a pause in typing before querying.
  useEffect(() => {
    const timer = setTimeout(() => setSearch(searchInput.trim()), 350);
    return () => clearTimeout(timer);
  }, [searchInput]);

  /* Sorting or searching resets to page 1 — page 3 of a "last login" sort
     is a different slice of rows entirely once the sort key changes. */
  const onSortChange = (next: AdminUserSort) => {
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

  /* Shared revoke path for the confirm dialog and the activity drawer.
     Goes through stepUp.run so the OTP challenge modal is shown when the
     backend demands step-up auth. */
  async function revokeSessionsFor(target: User) {
    setError("");
    const isSelf = target.id === me?.id;
    await stepUp.run(
      async () => {
        await adminRevokeUserSessions(target.id);
        if (isSelf) {
          // Revoking your own account's sessions kills the session this very
          // page is using — leave deliberately, with an explanation on the
          // login screen, instead of silently dropping dead.
          window.location.href = "/login?reason=revoked";
          return;
        }
        showToast(`All sessions revoked for ${target.name} (${target.email}). They'll need to sign in again on every device.`);
        setActivityRefresh((n) => n + 1);
        await load();
      },
      `You're about to sign out ${target.email} everywhere.`,
      `revoke all sessions for ${target.email}`,
    );
  }

  async function onRevokeSessions() {
    const target = revokeTarget;
    if (!target) return;
    setRevokeTarget(null);
    setBusyId(target.id);
    try {
      await revokeSessionsFor(target);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke sessions");
    } finally {
      setBusyId(null);
    }
  }

  /* Promote/demote. Both directions change who holds panel power, so both go
     through the step-up OTP challenge; the emailed code names the exact
     action ("promote x@y.com to admin"). */
  async function onToggleRole() {
    const target = roleTarget;
    if (!target) return;
    setRoleTarget(null);
    setBusyId(target.id);
    setError("");
    const newRole = target.role === "admin" ? "user" : "admin";
    try {
      await stepUp.run(
        async () => {
          const res = await adminChangeUserRole(target.id, newRole);
          showToast(res.message);
          await load();
        },
        newRole === "admin"
          ? `You're about to give ${target.email} full admin access.`
          : `You're about to strip admin access from ${target.email}. All their sessions will be revoked.`,
        newRole === "admin"
          ? `promote ${target.email} (account id ${target.id}) to admin`
          : `demote the admin ${target.email} (account id ${target.id}) to a regular user`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to change role");
    } finally {
      setBusyId(null);
    }
  }

  async function onDeleteUser() {
    const target = deleteTarget;
    if (!target) return;
    setDeleteTarget(null);
    setBusyId(target.id);
    setError("");
    try {
      await stepUp.run(
        async () => {
          await adminDeleteUser(target.id);
          setUsers((prev) => prev.filter((u) => u.id !== target.id));
          showToast(`Deleted ${target.name} (${target.email}) and all their sessions.`);
        },
        `You're about to permanently delete ${target.email}.`,
        `delete the user ${target.email} (account id ${target.id})`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete user");
    } finally {
      setBusyId(null);
    }
  }

  const selectClass =
    "rounded-sm border border-rule-strong bg-paper-raised px-2 py-1.5 text-xs text-ink outline-none transition-colors focus:border-accent disabled:opacity-50";

  return (
    <div>
      <PageTitle
        overline="Admin panel"
        title="User management"
        aside={
          <span className="flex items-center gap-3">
            <span className="tnum">
              {total} {total === 1 ? "user" : "users"}
              {search && " matched"}
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

      <ErrorNote>{error}</ErrorNote>

      {/* Sort + search controls — applied server-side so the order holds
          across pages. */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-xs text-ink-faint">
          <span>Sort by</span>
          <select value={sort} onChange={(e) => onSortChange(e.target.value as AdminUserSort)} className={selectClass}>
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
        <form
          className="ml-auto flex items-center gap-2"
          onSubmit={(e) => {
            // Enter submits immediately — no waiting out the debounce.
            e.preventDefault();
            setSearch(searchInput.trim());
            setPage(1);
          }}
        >
          <input
            type="search"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search name or email…"
            className={`${selectClass} w-52`}
            aria-label="Search users by name or email"
          />
          {search && (
            <button
              type="button"
              className="text-xs text-ink-faint transition-colors hover:text-ink"
              onClick={() => {
                setSearchInput("");
                setSearch("");
                setPage(1);
              }}
            >
              Clear
            </button>
          )}
        </form>
      </div>

      {loading ? (
        <p className="py-16 text-center text-sm text-ink-faint">Loading users…</p>
      ) : users.length === 0 ? (
        <p className="py-16 text-center text-sm text-ink-faint">
          {search ? `No users match "${search}".` : "No users."}
        </p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-sm border border-rule bg-paper-raised">
            <table className="w-full min-w-[1000px] text-sm">
              <thead>
                <tr className="border-b border-rule text-left text-xs font-semibold tracking-[0.08em] text-ink-faint uppercase">
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Email</th>
                  <th className="px-4 py-3">Role</th>
                  <th className="px-4 py-3">Registered</th>
                  <th className="px-4 py-3">Last login</th>
                  <th className="px-4 py-3 text-center">Active</th>
                  <th className="px-4 py-3 text-right">Risk score</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
            <tbody>
              {users.map((u) => {
                const isSelf = u.id === me?.id;
                const online = (u.activeSessions ?? 0) > 0;
                return (
                  <tr key={u.id} className="border-b border-rule last:border-b-0">
                    <td className="px-4 py-3 text-ink">
                      <button
                        className="text-left transition-colors hover:text-accent"
                        onClick={() => setActivityTarget(u)}
                        title="View activity log"
                      >
                        {u.name}
                      </button>
                      {isSelf && <span className="ml-2 text-xs text-ink-faint">(you)</span>}
                    </td>
                    <td className="px-4 py-3 text-ink-soft">{u.email}</td>
                    <td className="px-4 py-3">
                      <Stamp tone={u.role === "admin" ? "warn" : "neutral"}>
                        {u.role ?? "user"}
                      </Stamp>
                    </td>
                    <td className="tnum px-4 py-3 text-ink-soft">
                      {u.createdAt ? new Date(u.createdAt).toLocaleDateString() : "—"}
                    </td>
                    <td className="px-4 py-3 text-ink-soft">
                      {u.lastLoginAt ? timeAgo(u.lastLoginAt) : "never"}
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className="inline-flex items-center gap-1.5">
                        <span
                          className={`inline-block h-1.5 w-1.5 rounded-full ${
                            online ? "bg-accent" : "bg-rule"
                          }`}
                        />
                        <span className={`tnum text-sm ${online ? "text-ink" : "text-ink-faint"}`}>
                          {u.activeSessions ?? 0}
                        </span>
                      </span>
                    </td>
                    {/* Highest risk among this user's active sessions — the
                        account-level view of the per-session scores on the
                        All sessions page. */}
                    <td className="px-4 py-3 text-right">
                      <RiskCell score={u.riskScore ?? null} level={u.riskLevel ?? null} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-2">
                        <Button
                          variant="outline"
                          className="px-3 py-1.5 text-xs"
                          onClick={() => setActivityTarget(u)}
                        >
                          Logs
                        </Button>
                        <Button
                          variant="outline"
                          className="px-3 py-1.5 text-xs"
                          disabled={busyId === u.id || isSelf}
                          onClick={() => setRoleTarget(u)}
                          title={
                            isSelf
                              ? "Ask another admin to change your role"
                              : u.role === "admin"
                                ? "Demote to a regular user (OTP required)"
                                : "Promote to admin (OTP required)"
                          }
                        >
                          {u.role === "admin" ? "Demote" : "Promote"}
                        </Button>
                        <Button
                          variant="outline"
                          className="px-3 py-1.5 text-xs"
                          disabled={busyId === u.id || isSelf}
                          onClick={() => setRevokeTarget(u)}
                        >
                          Revoke sessions
                        </Button>
                        <Button
                          variant="danger"
                          className="px-3 py-1.5 text-xs"
                          disabled={busyId === u.id || isSelf}
                          onClick={() => setDeleteTarget(u)}
                        >
                          Delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
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
            label="users"
          />
        </>
      )}

      {activityTarget && (
        <ActivityDrawer
          user={activityTarget}
          refreshKey={activityRefresh}
          onRevokeRequest={(u) => setRevokeTarget(u)}
          onClose={() => setActivityTarget(null)}
        />
      )}

      <ConfirmDialog
        open={roleTarget !== null}
        title={roleTarget?.role === "admin" ? "Demote this admin?" : "Promote to admin?"}
        message={
          roleTarget
            ? roleTarget.role === "admin"
              ? `${roleTarget.email} will lose admin access. All their active sessions will be revoked immediately — they'll need to sign in again as a regular user. A confirmation code is required.`
              : `${roleTarget.email} will gain full admin access: user management, session control, and account deletion. A confirmation code is required.`
            : ""
        }
        confirmLabel={roleTarget?.role === "admin" ? "Demote to user" : "Promote to admin"}
        busy={busyId !== null}
        onConfirm={onToggleRole}
        onCancel={() => setRoleTarget(null)}
      />
      <ConfirmDialog
        open={revokeTarget !== null}
        title={revokeTarget?.id === me?.id ? "Revoke your own sessions?" : "Revoke all sessions?"}
        message={
          revokeTarget
            ? revokeTarget.id === me?.id
              ? `This will invalidate every active session for ${revokeTarget.email} — including the one you're using right now. You'll be signed out immediately and need to sign in again.`
              : `Every active session for ${revokeTarget.email} will be invalidated immediately. They will need to sign in again on all devices.`
            : ""
        }
        confirmLabel={revokeTarget?.id === me?.id ? "Revoke and sign out" : "Revoke sessions"}
        busy={busyId !== null}
        onConfirm={onRevokeSessions}
        onCancel={() => setRevokeTarget(null)}
      />
      <ConfirmDialog
        open={deleteTarget !== null}
        title="Delete user permanently?"
        message={
          deleteTarget
            ? `${deleteTarget.email} and all their sessions will be permanently deleted. This cannot be undone.`
            : ""
        }
        confirmLabel="Delete user"
        busy={busyId !== null}
        onConfirm={onDeleteUser}
        onCancel={() => setDeleteTarget(null)}
      />
      {stepUp.dialog}
      {toast}
    </div>
  );
}
