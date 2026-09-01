import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import { getInputRules } from "./api";
import Layout from "./Layout";
import AdminDashboardPage from "./pages/AdminDashboardPage";
import { SingleWindowBlocked, useSingleWindowGuard } from "./singleWindow";
import AdminSessionsPage from "./pages/AdminSessionsPage";
import AdminUsersPage from "./pages/AdminUsersPage";
import ForgotPasswordPage from "./pages/ForgotPasswordPage";
import LoginPage from "./pages/LoginPage";
import OAuthSuccessPage from "./pages/OAuthSuccessPage";
import PanicPage from "./pages/PanicPage";
import ProfilePage from "./pages/ProfilePage";
import RegisterPage from "./pages/RegisterPage";
import ResetPasswordPage from "./pages/ResetPasswordPage";
import SessionsPage from "./pages/SessionsPage";
import "./index.css";

function Protected({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-sm text-ink-faint">Checking your session…</p>
      </div>
    );
  }
  return user ? <>{children}</> : <Navigate to="/login" replace />;
}

function AdminOnly({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  return user?.role === "admin" ? <>{children}</> : <Navigate to="/sessions" replace />;
}

/* Fintech convention: the app may be open in only a limited number of
   browser windows (MAX_APP_WINDOWS on the backend). The newest windows
   always win; the windows they pushed aside render the blocker instead of
   the app. The limit is fetched from the public input-rules endpoint —
   while it loads the app renders unguarded, and the guard claims the app
   the moment it mounts, so a duplicate that slipped in during loading is
   still resolved. */
function SingleWindow({ children }: { children: React.ReactNode }) {
  const [limit, setLimit] = useState<number | null>(null);

  useEffect(() => {
    // If the rules can't be fetched, default to the strictest policy (1).
    getInputRules()
      .then((r) => setLimit(r.maxWindows))
      .catch(() => setLimit(1));
  }, []);

  if (limit === null || limit <= 0) return <>{children}</>;
  return <GuardedWindow limit={limit}>{children}</GuardedWindow>;
}

function GuardedWindow({ children, limit }: { children: React.ReactNode; limit: number }) {
  const { blocked, takeOver } = useSingleWindowGuard(limit);
  if (blocked) return <SingleWindowBlocked onTakeOver={takeOver} limit={limit} />;
  return <>{children}</>;
}

function PublicOnly({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  return user ? <Navigate to="/sessions" replace /> : <>{children}</>;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AuthProvider>
      <BrowserRouter>
        <SingleWindow>
          <Routes>
          <Route
            path="/login"
            element={
              <PublicOnly>
                <LoginPage />
              </PublicOnly>
            }
          />
          <Route
            path="/register"
            element={
              <PublicOnly>
                <RegisterPage />
              </PublicOnly>
            }
          />
          <Route
            path="/forgot-password"
            element={
              <PublicOnly>
                <ForgotPasswordPage />
              </PublicOnly>
            }
          />
          <Route path="/reset-password" element={<ResetPasswordPage />} />
          {/* Outcome screen for the single-use panic link from the
              sign-in-detected email — public, the work is already done
              server-side before the browser gets here. */}
          <Route path="/panic" element={<PanicPage />} />
          <Route
            path="/oauth/success"
            element={
              <PublicOnly>
                <OAuthSuccessPage />
              </PublicOnly>
            }
          />
          <Route
            element={
              <Protected>
                <Layout />
              </Protected>
            }
          >
            <Route path="/sessions" element={<SessionsPage />} />
            <Route path="/profile" element={<ProfilePage />} />
            <Route
              path="/admin"
              element={
                <AdminOnly>
                  <AdminDashboardPage />
                </AdminOnly>
              }
            />
            <Route
              path="/admin/users"
              element={
                <AdminOnly>
                  <AdminUsersPage />
                </AdminOnly>
              }
            />
            <Route
              path="/admin/sessions"
              element={
                <AdminOnly>
                  <AdminSessionsPage />
                </AdminOnly>
              }
            />
          </Route>
          <Route path="*" element={<Navigate to="/sessions" replace />} />
          </Routes>
        </SingleWindow>
      </BrowserRouter>
    </AuthProvider>
  </StrictMode>,
)
