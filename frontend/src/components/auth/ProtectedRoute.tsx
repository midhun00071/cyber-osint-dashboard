"use client";

import type { ReactNode } from "react";
import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";

import { AccessDenied } from "@/components/auth/AccessDenied";
import { getSafeReturnPath, useAuth } from "@/components/auth/AuthProvider";

export function ProtectedRoute({ children, permission }: Readonly<{ children: ReactNode; permission?: string }>) {
  const { bootstrap, hasPermission, state } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (state === "anonymous" || state === "session_expired") {
      const safeNext = allowReturnPath(pathname) ? `?next=${encodeURIComponent(pathname)}` : "";
      router.replace(`/login${safeNext}`);
    }
  }, [pathname, router, state]);

  if (state === "bootstrapping" || state === "authenticating" || state === "logging_out") {
    return <main className="authStatePage" aria-busy="true" role="status">Checking your secure session…</main>;
  }
  if (state === "recoverable_error") {
    return <main className="authStatePage" role="alert"><h1>Session check unavailable</h1><p>The server could not verify your session safely.</p><button type="button" onClick={() => void bootstrap()}>Try again</button></main>;
  }
  if (state === "access_denied" || (state === "authenticated" && permission && !hasPermission(permission))) {
    return <AccessDenied />;
  }
  if (state !== "authenticated") {
    return <main className="authStatePage" role="status">Redirecting to sign in…</main>;
  }
  return <>{children}</>;
}

export function allowReturnPath(pathname: string): boolean {
  return getSafeReturnPath(pathname) === pathname;
}
