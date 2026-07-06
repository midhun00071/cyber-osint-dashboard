import type { RefObject } from "react";

import Link from "next/link";

import { NavigationItem } from "@/components/dashboard/NavigationItem";
import { StatusBadge } from "@/components/dashboard/StatusBadge";

type SidebarNavigationItem = {
  active?: boolean;
  badge?: string;
  icon:
    | "overview"
    | "feed"
    | "vulnerabilities"
    | "uae"
    | "sources"
    | "methodology";
  label: string;
};

const navigationItems: readonly SidebarNavigationItem[] = [
  { label: "Overview", icon: "overview", active: true },
  { label: "Threat Feed", icon: "feed", badge: "Coming soon" },
  { label: "Vulnerabilities", icon: "vulnerabilities", badge: "Coming soon" },
  { label: "UAE Alerts", icon: "uae", badge: "Coming soon" },
  { label: "Sources", icon: "sources", badge: "Coming soon" },
  { label: "Methodology", icon: "methodology", badge: "Coming soon" },
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
        {navigationItems.map((item) => (
          <NavigationItem
            active={item.active}
            badge={item.badge}
            disabled={!item.active}
            href={item.active ? "/" : undefined}
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
          Public intelligence review shell. No exploit execution, scanning, or
          live collection controls are implemented.
        </p>
      </div>

      <div className="sidebarStatus">
        <div>
          <p className="panelEyebrow">Project status</p>
          <h2>Phase 1 shell</h2>
        </div>
        <StatusBadge label="Synthetic preview" tone="info" />
      </div>
    </div>
  );
}
