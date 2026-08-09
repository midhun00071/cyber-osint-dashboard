"use client";

import type { RefObject } from "react";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { useAuth } from "@/components/auth/AuthProvider";
import { NavigationItem } from "@/components/dashboard/NavigationItem";
import { StatusBadge } from "@/components/dashboard/StatusBadge";

type SidebarNavigationItem = {
  href: string;
  permission?: string;
  icon:
    | "overview"
    | "feed"
    | "vulnerabilities"
    | "uae"
    | "sources"
    | "operations"
    | "history"
    | "users"
    | "reports"
    | "health"
    | "audit"
    | "methodology";
  label: string;
};

const navigationItems: readonly SidebarNavigationItem[] = [
  { label: "Overview", icon: "overview", href: "/" },
  { label: "Threat Feed", icon: "feed", href: "/threat-feed" },
  { label: "Vulnerabilities", icon: "vulnerabilities", href: "/vulnerabilities" },
  { label: "UAE Intelligence", icon: "uae", href: "/uae-intelligence" },
  { label: "IOC Search", icon: "feed", href: "/ioc-search", permission: "analysis.use" },
  { label: "Sources", icon: "sources", href: "/sources" },
  { label: "Ingestion Operations", icon: "operations", href: "/ingestion-operations", permission: "ingestion.read" },
  { label: "Run History", icon: "history", href: "/run-history", permission: "ingestion.read" },
  { label: "Reports", icon: "reports", href: "/reports", permission: "report.read" },
  { label: "System Health", icon: "health", href: "/system-health", permission: "source.read" },
  { label: "Audit Log", icon: "audit", href: "/audit-log", permission: "audit.read" },
  { label: "Methodology", icon: "methodology", href: "/methodology" },
  { label: "User Access", icon: "users", href: "/admin/users", permission: "user.read" },
] as const;

type SidebarProps = Readonly<{
  className?: string;
  closeButtonRef?: RefObject<HTMLButtonElement | null>;
  onClose?: () => void;
  showCloseButton?: boolean;
}>;

export function Sidebar({
  className = "",
  closeButtonRef,
  onClose,
  showCloseButton,
}: SidebarProps) {
  const pathname = usePathname();
  const { hasPermission } = useAuth();
  const visibleItems = navigationItems.filter((item) => !item.permission || hasPermission(item.permission));
  return (
    <div className={`sidebar ${className}`}>
      <div className="sidebarHeader">
        <Link className="sidebarBrand" href="/" onClick={onClose}>
          <span className="brandMark" aria-hidden="true">
            AD
          </span>
          <span>
            <strong>Alpha Data</strong>
            <small>Cyber OSINT Dashboard</small>
          </span>
        </Link>
        {showCloseButton ? (
          <button
            aria-label="Close navigation"
            className="drawerCloseButton"
            onClick={onClose}
            ref={closeButtonRef}
            type="button"
          >
            <span aria-hidden="true">×</span>
          </button>
        ) : null}
      </div>

      <nav aria-label="Dashboard navigation" className="sidebarNav">
        {visibleItems.map((item) => (
          <NavigationItem
            active={pathname === item.href}
            href={item.href}
            icon={item.icon}
            key={item.label}
            label={item.label}
            onNavigate={onClose}
          />
        ))}
      </nav>

      <div className="scopePanel">
        <p className="panelEyebrow">Scope</p>
        <h2>Defensive OSINT only</h2>
        <p>
          Approved public intelligence only. Operator controls create bounded,
          audited evidence and never bypass source policy.
        </p>
      </div>

      <div className="sidebarStatus">
        <div>
          <p className="panelEyebrow">Project status</p>
          <h2>Authenticated operations</h2>
        </div>
        <StatusBadge label="Defensive OSINT" tone="info" />
      </div>
    </div>
  );
}
