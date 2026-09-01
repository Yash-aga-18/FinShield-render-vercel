import { useEffect, useRef, useState } from "react";
import { useAuth } from "./auth";
import { API_BASE } from "./api";

/* 15-minute auto-logout (strict policy):
   - The timer resets ONLY on a full page refresh or when the user navigates
     to another page inside the app (resetKey = current pathname).
   - Clicks, typing and scrolling deliberately do NOT reset it — idling on
     one page still counts as inactivity.
   - At 15:00 the session is signed out automatically.
   - In the last 60 seconds a "still there?" dialog shows a countdown with
     "Stay signed in" / "Sign out now" choices; "Stay signed in" pings the
     API (which refreshes the access token) and resets the timer. */

const TIMEOUT_MS = 15 * 60 * 1000;
const WARNING_MS = 60 * 1000;

export function useIdleAutoLogout(resetKey?: string) {
  const { user, logout } = useAuth();
  const [remaining, setRemaining] = useState<number | null>(null); // ms left in warning phase
  const [timeLeftMs, setTimeLeftMs] = useState<number | null>(null); // ms to auto-logout (for the top-bar clock)
  const deadlineRef = useRef<number>(Date.now() + TIMEOUT_MS);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!user) {
      setTimeLeftMs(null);
      return;
    }

    function tick() {
      const left = deadlineRef.current - Date.now();
      setTimeLeftMs(left > 0 ? left : 0);
      if (left <= 0) {
        setRemaining(null);
        logout().finally(() => {
          window.location.href = "/login?timeout=1";
        });
      } else if (left <= WARNING_MS) {
        setRemaining(left);
      } else {
        setRemaining(null);
      }
    }

    timerRef.current = setInterval(tick, 1000);
    tick();

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [user, logout]);

  // A page refresh remounts the app (fresh timer); an in-app route change
  // lands here — both restart the countdown. Mouse/key activity does not.
  useEffect(() => {
    if (!user) return;
    deadlineRef.current = Date.now() + TIMEOUT_MS;
    setRemaining(null);
    setTimeLeftMs(TIMEOUT_MS);
  }, [user, resetKey]);

  async function staySignedIn() {
    // Any authenticated call refreshes activity; /api/users/me is cheap.
    try {
      await fetch(`${API_BASE}/api/users/me`, { credentials: "include" });
    } catch {
      /* network hiccup — still reset the local timer */
    }
    deadlineRef.current = Date.now() + TIMEOUT_MS;
    setRemaining(null);
  }

  return { remaining, timeLeftMs, staySignedIn, logoutNow: logout };
}
