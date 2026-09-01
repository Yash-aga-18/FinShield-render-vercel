import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import * as api from "./api";
import type { LoginResult, User } from "./api";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string, otpChannel?: "sms") => Promise<LoginResult>;
  register: (
    name: string,
    email: string,
    password: string,
  ) => Promise<
    Awaited<ReturnType<typeof api.register>>
  >;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  setUser: (user: User | null) => void;
}
const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refreshUser = useCallback(async () => {
    try {
      const { user } = await api.getProfile();
      setUser(user);
    } catch {
      setUser(null);
    }
  }, []);

  // On mount: probe the session via /api/users/me (auto-refreshes the access
  // token through the API client if it has expired).
  useEffect(() => {
    refreshUser().finally(() => setLoading(false));
  }, [refreshUser]);

  // otpChannel "sms" asks for the login code by text (accounts with a
  // verified phone) — passed through so the login screen can switch channels.
  const login = useCallback(async (email: string, password: string, otpChannel?: "sms") => {
    const res = await api.login(email, password, otpChannel);
    // requireOtp: the password checked out, but a code is still owed — no
    // session exists yet, so there is no user to sign in as.
    if (!res.requireOtp) setUser(res.user ?? null);
    return res;
  }, []);

  const register = useCallback(
    async (name: string, email: string, password: string) => {
      // Registration now returns "needs email verification" — the caller
      // (RegisterPage) runs the OTP step and signs in via verifyRegistrationOtp.
      // The response is passed through so the page can surface the dev code /
      // delivery warning when mail delivery is console-only.
      return api.register(name, email, password);
    },
    [],
  );

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setUser(null);
    }
  }, []);

  const value = useMemo(
    () => ({ user, loading, login, register, logout, refreshUser, setUser }),
    [user, loading, login, register, logout, refreshUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
