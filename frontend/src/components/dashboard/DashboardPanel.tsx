import type { ReactNode } from "react";

type DashboardPanelProps = Readonly<{
  children: ReactNode;
  className?: string;
  eyebrow: string;
  title: string;
}>;

export function DashboardPanel({
  children,
  className = "",
  eyebrow,
  title,
}: DashboardPanelProps) {
  const headingId = `panel-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;

  return (
    <section className={`dashboardPanel ${className}`} aria-labelledby={headingId}>
      <div className="panelHeader">
        <div>
          <p className="panelEyebrow">{eyebrow}</p>
          <h2 id={headingId}>{title}</h2>
        </div>
      </div>
      {children}
    </section>
  );
}
