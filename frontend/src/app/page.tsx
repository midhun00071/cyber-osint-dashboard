import { HealthStatusCard } from "@/components/HealthStatusCard";

const modules = [
  {
    title: "Backend API",
    description:
      "Secure endpoints provide normalized intelligence and operational health data.",
    status: "Available",
  },
  {
    title: "Data Ingestion",
    description:
      "Approved public sources will be collected with source terms and rate limits respected.",
    status: "Planned",
  },
  {
    title: "Processing & Enrichment",
    description:
      "Incoming records will be normalized, deduplicated, classified, and attributed.",
    status: "Planned",
  },
  {
    title: "Dashboard UI",
    description:
      "Analyst-focused views will support safe discovery, filtering, and reporting.",
    status: "In progress",
  },
] as const;

export default function HomePage() {
  return (
    <main>
      <header className="siteHeader">
        <div className="container headerContent">
          <a className="brand" href="#top" aria-label="Alpha Data home">
            <span className="brandMark" aria-hidden="true">
              A
            </span>
            <span>Alpha Data</span>
          </a>
          <span className="scopeBadge">Defensive OSINT</span>
        </div>
      </header>

      <div id="top" className="container pageContent">
        <section className="hero" aria-labelledby="page-title">
          <p className="eyebrow">Cyber intelligence workspace</p>
          <h1 id="page-title">Cyber OSINT Dashboard</h1>
          <p className="heroDescription">
            A defensive platform for collecting, organizing, and presenting
            trusted public cybersecurity intelligence for analyst review.
          </p>
        </section>

        <section className="statusSection" aria-labelledby="system-status-title">
          <div className="sectionHeading">
            <div>
              <p className="sectionLabel">Environment</p>
              <h2 id="system-status-title">System status</h2>
            </div>
            <p>Live connectivity check for the dashboard backend.</p>
          </div>
          <HealthStatusCard />
        </section>

        <section aria-labelledby="modules-title">
          <div className="sectionHeading">
            <div>
              <p className="sectionLabel">Architecture</p>
              <h2 id="modules-title">Module overview</h2>
            </div>
            <p>Core capabilities planned for the MVP.</p>
          </div>

          <div className="moduleGrid">
            {modules.map((module, index) => (
              <article className="moduleCard" key={module.title}>
                <div className="moduleCardTop">
                  <span className="moduleNumber" aria-hidden="true">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <span className="moduleStatus">{module.status}</span>
                </div>
                <h3>{module.title}</h3>
                <p>{module.description}</p>
              </article>
            ))}
          </div>
        </section>
      </div>

      <footer className="siteFooter">
        <div className="container">
          <p>Alpha Data · Public intelligence for defensive awareness</p>
        </div>
      </footer>
    </main>
  );
}
