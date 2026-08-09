import type { ReactNode } from "react";
import Link from "next/link";

type NavigationIcon =
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

type NavigationItemProps = Readonly<{
  active?: boolean;
  badge?: string;
  disabled?: boolean;
  href?: string;
  icon: NavigationIcon;
  label: string;
  onNavigate?: () => void;
}>;

function Icon({ icon }: Readonly<{ icon: NavigationIcon }>) {
  const paths: Record<NavigationIcon, ReactNode> = {
    overview: (
      <>
        <rect height="7" width="7" x="3" y="3" />
        <rect height="7" width="7" x="14" y="3" />
        <rect height="7" width="7" x="3" y="14" />
        <rect height="7" width="7" x="14" y="14" />
      </>
    ),
    feed: (
      <>
        <path d="M5 5a14 14 0 0 1 14 14" />
        <path d="M5 11a8 8 0 0 1 8 8" />
        <circle cx="6" cy="18" r="1.5" />
      </>
    ),
    vulnerabilities: (
      <>
        <path d="M12 3 4 6v6c0 5 3.2 8 8 9 4.8-1 8-4 8-9V6l-8-3Z" />
        <path d="M12 8v5" />
        <path d="M12 17h.01" />
      </>
    ),
    uae: (
      <>
        <path d="M4 17h16" />
        <path d="M5 17V8l7-4 7 4v9" />
        <path d="M9 17v-6h6v6" />
      </>
    ),
    sources: (
      <>
        <path d="M6 5h12v14H6z" />
        <path d="M9 9h6" />
        <path d="M9 13h6" />
        <path d="M9 17h4" />
      </>
    ),
    operations: (
      <><path d="M4 7h16" /><path d="M4 12h16" /><path d="M4 17h16" /><circle cx="8" cy="7" r="1" /><circle cx="15" cy="12" r="1" /><circle cx="11" cy="17" r="1" /></>
    ),
    history: (
      <><circle cx="12" cy="12" r="8" /><path d="M12 7v5l3 2" /></>
    ),
    users: (
      <><circle cx="9" cy="8" r="3" /><path d="M4 19c0-3 2-5 5-5s5 2 5 5" /><path d="M16 7h4M18 5v4" /></>
    ),
    reports: (
      <><path d="M6 3h9l3 3v15H6z" /><path d="M9 11h6M9 15h6" /></>
    ),
    health: (
      <><path d="M3 12h4l2-5 4 10 2-5h6" /></>
    ),
    audit: (
      <><path d="M12 3 5 6v6c0 4 2.8 7 7 9 4.2-2 7-5 7-9V6z" /><path d="m9 12 2 2 4-5" /></>
    ),
    methodology: (
      <>
        <circle cx="12" cy="12" r="8" />
        <path d="M12 8v4l3 3" />
      </>
    ),
  };

  return (
    <svg
      aria-hidden="true"
      className="navIcon"
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="1.8"
      viewBox="0 0 24 24"
    >
      {paths[icon]}
    </svg>
  );
}

export function NavigationItem({
  active,
  badge,
  disabled,
  href,
  icon,
  label,
  onNavigate,
}: NavigationItemProps) {
  const content = (
    <>
      <Icon icon={icon} />
      <span className="navLabel">{label}</span>
      {badge ? <span className="navBadge">{badge}</span> : null}
    </>
  );

  if (disabled || !href) {
    return (
      <button
        aria-disabled="true"
        className="navItem navItemDisabled"
        disabled
        type="button"
      >
        {content}
      </button>
    );
  }

  return (
    <Link
      aria-current={active ? "page" : undefined}
      className={`navItem${active ? " navItemActive" : ""}`}
      href={href}
      onClick={onNavigate}
    >
      {content}
    </Link>
  );
}
