"use client";

import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useRouter } from "next/navigation";

import { fetchPrincipal, login as requestLogin, logout as requestLogout } from "@/services/authApi";
import { ACCESS_DENIED_EVENT, AUTH_EXPIRED_EVENT } from "@/services/apiClient";
import type { Principal, SessionState } from "@/types/auth";

type AuthContextValue = {
  state: SessionState;
  principal: Principal | null;
  bootstrap: () => Promise<void>;
  login: (username: string, password: string, returnPath?: string | null) => Promise<boolean>;
  logout: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
};

const AuthContext = createContext<AuthContextValue | null>(null);

const ALLOWED_RETURN_PATHS = new Set([
  "/", "/sources", "/operations", "/run-history", "/admin/users",
]);
const DETAIL_RETURN_PATH = /^\/(?:articles|vulnerabilities)\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function getSafeReturnPath(value: string | null): string {
  if (!value) return "/";
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return "/";
  }
  if (!decoded.startsWith("/") || decoded.startsWith("//")) return "/";
  return ALLOWED_RETURN_PATHS.has(decoded) || DETAIL_RETURN_PATH.test(decoded) ? decoded : "/";
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

export function AuthProvider({ children }: Readonly<{ children: ReactNode }>) {
  const [state, setState] = useState<SessionState>("bootstrapping");
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const controllerRef = useRef<AbortController | null>(null);
  const deniedPathRef = useRef<string | null>(null);
  const pathname = usePathname();
  const router = useRouter();

  const bootstrap = useCallback(async () => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setState("bootstrapping");
    try {
      const result = await fetchPrincipal(controller.signal);
      if (controller.signal.aborted || controllerRef.current !== controller) return;
      if (result.status === "authenticated") {
        setPrincipal(result.principal);
        setState("authenticated");
      } else {
        setPrincipal(null);
        setState(result.status === "anonymous" ? "anonymous" : "recoverable_error");
      }
    } catch (error) {
      if (controller.signal.aborted || controllerRef.current !== controller || isAbortError(error)) return;
      setPrincipal(null);
      setState("recoverable_error");
    } finally {
      if (controllerRef.current === controller) controllerRef.current = null;
    }
  }, []);

  useEffect(() => {
    void bootstrap();
    return () => controllerRef.current?.abort();
  }, [bootstrap]);

  useEffect(() => {
    const expired = () => {
      controllerRef.current?.abort();
      setPrincipal(null);
      setState("session_expired");
      router.replace("/login");
    };
    const denied = () => {
      deniedPathRef.current = pathname;
      setState("access_denied");
    };
    window.addEventListener(AUTH_EXPIRED_EVENT, expired);
    window.addEventListener(ACCESS_DENIED_EVENT, denied);
    return () => {
      window.removeEventListener(AUTH_EXPIRED_EVENT, expired);
      window.removeEventListener(ACCESS_DENIED_EVENT, denied);
    };
  }, [pathname, router]);

  useEffect(() => {
    if (
      state === "access_denied" &&
      principal &&
      deniedPathRef.current !== pathname
    ) {
      deniedPathRef.current = null;
      setState("authenticated");
    }
  }, [pathname, principal, state]);

  const login = useCallback(async (username: string, password: string, returnPath: string | null = null) => {
    controllerRef.current?.abort();
    setState("authenticating");
    const result = await requestLogin(username, password);
    if (result.status === "authenticated") {
      setPrincipal(result.principal);
      setState("authenticated");
      router.replace(getSafeReturnPath(returnPath));
      return true;
    }
    setPrincipal(null);
    setState(result.status === "invalid" ? "anonymous" : "recoverable_error");
    return false;
  }, [router]);

  const logout = useCallback(async () => {
    controllerRef.current?.abort();
    setState("logging_out");
    await requestLogout();
    setPrincipal(null);
    setState("anonymous");
    router.replace("/login");
  }, [router]);

  const value = useMemo<AuthContextValue>(() => ({
    state, principal, bootstrap, login, logout,
    hasPermission: (permission) => principal?.permissions.includes(permission) ?? false,
  }), [bootstrap, login, logout, principal, state]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("AuthProvider is required.");
  return value;
}
