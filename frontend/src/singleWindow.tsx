// src/singleWindow.ts
//
// Single-window enforcement, WhatsApp-Web style: many banking/fintech sites
// allow the app in only a limited number of browser windows/tabs at a time
// — and when the limit is exceeded, the NEWEST windows are the ones that
// stay usable. The guard uses a BroadcastChannel:
//
//   1. A window joining the channel announces itself ("join") and becomes
//      active immediately — no waiting.
//   2. Every window keeps a member list of the windows it has heard from.
//      After any join/leave it recomputes: the newest `limit` windows are
//      active, anything older parks on a "moved to another window" screen.
//   3. A parked window can press "use this window instead" — that re-joins
//      with a fresh timestamp, making it the newest. Windows can swap, but
//      never more than `limit` are live.
//   4. When a window closes ("goodbye"), parked windows recompute and the
//      most recently parked one comes back on its own.
//
// The limit comes from the backend's MAX_APP_WINDOWS (via the public
// input-rules endpoint) so .env is the single source of truth; 0 disables
// the guard. Joins carry a timestamp (+ random id to break exact-millisecond
// ties — same machine, same clock). The state is purely client-side;
// sessions are untouched, so closing tabs never signs anyone out.

import { useCallback, useEffect, useRef, useState } from "react";

const CHANNEL_NAME = "finshield:window";

// Does the other window outrank ours? Newer timestamp wins; the random id
// only breaks exact-millisecond ties.
type Token = { ts: number; id: string };
const outranks = (theirs: Token, mine: Token) =>
  theirs.ts > mine.ts || (theirs.ts === mine.ts && theirs.id > mine.id);

export function useSingleWindowGuard(limit: number) {
  const [blocked, setBlocked] = useState(false);
  // Guard state lives in a ref (not the effect closure) so takeOver() —
  // which runs later — and the message handler share one source of truth.
  const guard = useRef({
    token: { ts: 0, id: Math.random().toString(36).slice(2) } as Token,
    // Windows heard from since this one joined, keyed by their id. A window
    // never hears about windows older than itself (they announced before it
    // existed) — which is fine: it can only ever be outranked by newer ones.
    members: new Map<string, number>(),
    channel: null as BroadcastChannel | null,
  });

  useEffect(() => {
    // Limit 0 = guard disabled; no BroadcastChannel (old browsers, jsdom)
    // = fail open rather than locking the user out of their own app.
    if (limit <= 0 || typeof BroadcastChannel === "undefined") return;

    const channel = new BroadcastChannel(CHANNEL_NAME);
    const g = guard.current;
    g.channel = channel;

    // The newest `limit` windows are active; anything older parks. A
    // window's rank is simply how many members outrank it — never more than
    // `limit` windows can pass this check at once.
    const evaluate = () => {
      let newer = 0;
      for (const [id, ts] of g.members) {
        if (outranks({ ts, id }, g.token)) newer += 1;
      }
      setBlocked(newer >= limit);
    };

    const onMessage = (event: MessageEvent) => {
      const msg = event.data;
      if (msg?.type === "join" && typeof msg.id === "string") {
        // A re-join with a fresh timestamp (the takeover button) replaces
        // the old entry, so a window that swapped in outranks everyone.
        g.members.set(msg.id, Number(msg.ts) || 0);
        evaluate();
      }
      if (msg?.type === "goodbye" && typeof msg.id === "string") {
        g.members.delete(msg.id);
        evaluate();
      }
    };
    channel.addEventListener("message", onMessage);

    // Join by claiming directly — the newest window wins. Any window that
    // gets pushed past the limit hears this join and parks itself.
    g.token = { ts: Date.now(), id: g.token.id };
    channel.postMessage({ type: "join", ...g.token });

    const onUnload = () => {
      channel.postMessage({ type: "goodbye", id: g.token.id });
    };
    window.addEventListener("beforeunload", onUnload);

    return () => {
      window.removeEventListener("beforeunload", onUnload);
      channel.removeEventListener("message", onMessage);
      channel.close();
      if (g.channel === channel) g.channel = null;
    };
  }, [limit]);

  // "Continue here instead": re-join with a fresh timestamp — this window
  // becomes the newest, and whichever window is pushed past the limit parks.
  const takeOver = useCallback(() => {
    const g = guard.current;
    g.token = { ts: Date.now(), id: g.token.id };
    g.channel?.postMessage({ type: "join", ...g.token });
    setBlocked(false);
  }, []);

  return { blocked, takeOver };
}

/* Full-screen blocker shown to the windows that were pushed aside. */
export function SingleWindowBlocked({
  onTakeOver,
  limit,
}: {
  onTakeOver: () => void;
  limit: number;
}) {
  return (
    <main className="flex min-h-screen items-center justify-center p-8">
      <div className="w-full max-w-md rounded-sm border border-rule bg-paper-raised p-8 text-center">
        <p className="mb-1 text-xs font-semibold tracking-[0.14em] text-accent uppercase">
          {limit === 1 ? "One window only" : `${limit} windows only`}
        </p>
        <h1 className="font-display mb-4 text-2xl font-medium text-ink">
          FinShield is open in {limit === 1 ? "another window" : "other windows"}
        </h1>
        <p className="mb-6 text-sm leading-relaxed text-ink-soft">
          For your security, your account is active in at most {limit} browser{" "}
          {limit === 1 ? "window" : "windows"} at a time — the one
          {limit > 1 ? "s" : ""} you opened most recently. Close the other{" "}
          {limit === 1 ? "window" : "windows"} to continue here, or take it back now (the other
          window{limit > 1 ? "s" : ""} will be disconnected).
        </p>
        <div className="flex flex-col gap-3">
          <button
            type="button"
            onClick={onTakeOver}
            className="rounded-sm border border-rule-strong bg-paper-raised px-4 py-2 text-sm font-medium text-ink transition-colors hover:bg-paper-sunken"
          >
            Use this window instead
          </button>
          <button type="button" className="link text-sm" onClick={() => window.location.reload()}>
            I closed the other window{limit > 1 ? "s" : ""} — refresh
          </button>
        </div>
      </div>
    </main>
  );
}
