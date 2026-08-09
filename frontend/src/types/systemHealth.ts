export type HealthState = "healthy" | "degraded" | "unhealthy" | "stale" | "disabled" | "unknown";
export type HealthComponentName = "backend" | "database" | "prefect_server" | "prefect_worker" | "ingestion_operations" | "source_freshness" | "storage" | "deployment_identity";
export type HealthComponent = { name: HealthComponentName; status: HealthState; summary: string; observations: Record<string, string | number | boolean | null> };
export type SystemHealth = { status: HealthState; generated_at: string; version: string; commit_sha: string | null; components: HealthComponent[] };
export type SystemHealthResult = { status: "success"; data: SystemHealth } | { status: "error" };
