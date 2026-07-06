import type { ReactNode } from "react";

import { DashboardShell } from "@/components/dashboard/DashboardShell";

type DashboardLayoutProps = Readonly<{
  children: ReactNode;
}>;

export default function DashboardLayout({ children }: DashboardLayoutProps) {
  return <DashboardShell>{children}</DashboardShell>;
}
