import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../auth";
import { Brand } from "./LoginPage";

/* Landing page for the Google OAuth redirect. The backend has already set
   the auth cookies; we probe /api/users/me to load the user into context,
   then move on to the app. */
export default function OAuthSuccessPage() {
  const { user, loading, refreshUser } = useAuth();
  const [probed, setProbed] = useState(false);

  useEffect(() => {
    refreshUser().finally(() => setProbed(true));
  }, [refreshUser]);

  if (user) return <Navigate to="/sessions" replace />;
  if (loading || !probed) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-6">
        <Brand />
        <p className="text-sm text-ink-faint">Completing sign-in…</p>
      </div>
    );
  }
  // Cookies absent or invalid — bounce to login with an error.
  return <Navigate to="/login?error=oauth_failed" replace />;
}
