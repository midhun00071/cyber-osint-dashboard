import type { ReactNode } from "react";

import { DashboardShell } from "@/components/dashboard/DashboardShell";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";

type DashboardLayoutProps = Readonly<{
  children: ReactNode;
}>;

export default function DashboardLayout({ children }: DashboardLayoutProps) {
  return <ProtectedRoute><DashboardShell>{children}</DashboardShell></ProtectedRoute>;
}
