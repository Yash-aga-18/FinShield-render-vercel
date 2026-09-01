import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "./auth";
import { useIdleAutoLogout } from "./idleTimer";
import { ConfirmDialog, Stamp } from "./ui";
import { Brand } from "./pages/LoginPage";

/* App shell: slim top bar, small-caps nav links with underline-on-active,
   serif brand mark. Content column is centered with generous margins. */

function formatCountdown(ms: number): string {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/* First letters of the first two words — "John Snow" -> "JS". */
function initialsOf(name?: string | null): string {
  if (!name) return "·";
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "·";
  return (parts[0][0] + (parts[1]?.[0] ?? "")).toUpperCase();
}

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [confirmSignOut, setConfirmSignOut] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const [adminMenuOpen, setAdminMenuOpen] = useState(false);
  // Navigating between pages resets the 15-minute countdown (clicks/scrolls
  // deliberately do not — see idleTimer.ts).
  const location = useLocation();
  const { remaining, timeLeftMs, staySignedIn, logoutNow } = useIdleAutoLogout(
    location.pathname,
  );

  async function onSignOut() {
    setSigningOut(true);
    try {
      await logout();
      navigate("/login", { replace: true });
    } finally {
      setSigningOut(false);
      setConfirmSignOut(false);
    }
  }

  const links = [
    { to: "/sessions", label: "Sessions" },
    { to: "/profile", label: "Profile" },
  ];

  const adminLinks = [
    { to: "/admin", label: "Dashboard", end: true },
    { to: "/admin/users", label: "Users" },
    { to: "/admin/sessions", label: "All Sessions" },
  ];

  // Any /admin/* route being active makes the admin menu header highlighted.
  const adminMenuActive = location.pathname.startsWith("/admin");

  // Close the admin dropdown when clicking outside it or navigating away.
  useEffect(() => {
    setAdminMenuOpen(false);
  }, [location.pathname]);

  const adminMenuRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!adminMenuOpen) return;
    const onDocClick = (e: MouseEvent) => {
      if (adminMenuRef.current && !adminMenuRef.current.contains(e.target as Node)) {
        setAdminMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [adminMenuOpen]);

  return (
    <div className="relative z-1 min-h-screen">
      <header className="border-b border-rule bg-paper/90 backdrop-blur-[2px]">
        <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-6">
          <Brand />
          <nav className="flex items-center gap-5">
            {links.map((l) => (
              <NavLink
                key={l.to}
                to={l.to}
                className={({ isActive }) =>
                  `text-sm transition-colors ${
                    isActive
                      ? "font-medium text-accent-strong underline decoration-accent-strong decoration-2 underline-offset-8"
                      : "text-ink-soft hover:text-ink"
                  }`
                }
              >
                {l.label}
              </NavLink>
            ))}

            {/* Admin links collapsed into one dropdown — five flat links plus
                email + countdown + sign-out no longer fit the 56px bar.
                Opens on hover (desktop convention for nav menus); the click
                toggle stays for touch/keyboard users. */}
            {user?.role === "admin" && (
              <div
                ref={adminMenuRef}
                className="relative"
                onMouseEnter={() => setAdminMenuOpen(true)}
                onMouseLeave={() => setAdminMenuOpen(false)}
              >
                <button
                  onClick={() => setAdminMenuOpen((o) => !o)}
                  aria-expanded={adminMenuOpen}
                  aria-haspopup="menu"
                  className={`flex items-center gap-1.5 text-sm transition-colors ${
                    adminMenuActive
                      ? "font-medium text-accent-strong underline decoration-accent-strong decoration-2 underline-offset-8"
                      : "text-ink-soft hover:text-ink"
                  }`}
                >
                  Admin
                  <svg
                    width="10"
                    height="10"
                    viewBox="0 0 12 12"
                    aria-hidden="true"
                    className={`transition-transform ${adminMenuOpen ? "rotate-180" : ""}`}
                  >
                    <path d="M2 4.5L6 8.5L10 4.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </button>
                {adminMenuOpen && (
                  /* pt-2 (not mt-2): the padding is part of the hoverable
                     box, bridging the gap so moving from button to menu
                     never trips the container's onMouseLeave. */
                  <div className="absolute right-0 top-full z-10 pt-2">
                    <div
                      role="menu"
                      className="min-w-44 rounded-sm border border-rule bg-paper-raised py-1 shadow-sm"
                    >
                      {adminLinks.map((l) => (
                        <NavLink
                          key={l.to}
                          to={l.to}
                          end={"end" in l ? l.end : false}
                          role="menuitem"
                          className={({ isActive }) =>
                            `block px-4 py-2 text-sm transition-colors ${
                              isActive
                                ? "bg-accent-soft font-medium text-accent-strong"
                                : "text-ink-soft hover:bg-paper hover:text-ink"
                            }`
                          }
                        >
                          {l.label}
                        </NavLink>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Who is signed in — visible on every page. The initials disc
                keeps it compact on small screens where the name hides. */}
            <div
              className="flex items-center gap-2"
              title={user?.email}
              aria-label={`Signed in as ${user?.name ?? "user"}${user?.role === "admin" ? " (admin)" : ""}`}
            >
              <span className="flex h-7 w-7 items-center justify-center rounded-full border border-accent/30 bg-accent-soft text-xs font-semibold text-accent-strong">
                {initialsOf(user?.name)}
              </span>
              <span className="hidden max-w-32 truncate text-sm font-medium text-ink sm:inline">
                {user?.name}
              </span>
              {user?.role === "admin" && <Stamp tone="good">Admin</Stamp>}
            </div>
            {/* Live countdown to the 15-minute idle auto-logout. Activity
                anywhere resets it; the last minute also opens the warning
                dialog, so the chip turns amber as it approaches zero. */}
            {timeLeftMs !== null && timeLeftMs > 0 && (
              <span
                title="Time until automatic sign-out (resets on activity)"
                className={`tnum inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 font-mono text-xs ${
                  timeLeftMs <= 60_000
                    ? "border-amber-stamp/50 bg-amber-stamp/10 text-amber-stamp"
                    : "border-rule text-ink-soft"
                }`}
              >
                <svg width="12" height="12" viewBox="0 0 16 16" aria-hidden="true">
                  <circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
                  <path d="M8 4.5V8l2.5 1.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                </svg>
                {formatCountdown(timeLeftMs)}
              </span>
            )}
            <button
              onClick={() => setConfirmSignOut(true)}
              className="text-sm text-red-stamp transition-colors hover:text-red-deep"
            >
              Sign out
            </button>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-6 py-12">
        <Outlet />
      </main>

      <footer className="mx-auto max-w-5xl px-6 pb-8">
        <p className="border-t border-rule pt-4 text-xs text-ink-faint">
          FinShield Security Center — every action on this page is audit-logged. You are signed out
          automatically after 15 minutes of inactivity.
        </p>
      </footer>

      {/* Sign-out confirmation */}
      <ConfirmDialog
        open={confirmSignOut}
        title="Sign out?"
        message="You will need to sign in again to access your account on this device."
        confirmLabel="Sign out"
        busy={signingOut}
        onConfirm={onSignOut}
        onCancel={() => setConfirmSignOut(false)}
      />

      {/* Idle auto-logout warning (last minute) */}
      {remaining !== null && remaining > 0 && (
        <ConfirmDialog
          open
          title={`Still there? Signing out in ${formatCountdown(remaining)}`}
          message="For your security, this session ends automatically after 15 minutes of inactivity."
          confirmLabel="Stay signed in"
          danger={false}
          onConfirm={staySignedIn}
          onCancel={() =>
            logoutNow().finally(() => {
              window.location.href = "/login?reason=timeout";
            })
          }
        />
      )}
    </div>
  );
}
