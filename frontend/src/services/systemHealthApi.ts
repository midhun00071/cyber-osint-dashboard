import { apiFetch } from "@/services/apiClient";
import type { HealthComponent, HealthComponentName, HealthState, SystemHealth, SystemHealthResult } from "@/types/systemHealth";

const STATES = new Set<HealthState>(["healthy", "degraded", "unhealthy", "stale", "disabled", "unknown"]);
const NAMES = new Set<HealthComponentName>(["backend", "database", "prefect_server", "prefect_worker", "ingestion_operations", "source_freshness", "storage", "deployment_identity"]);
const COMMIT = /^[0-9a-f]{40}$/;
function object(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function component(value: unknown): HealthComponent | null {
  if (!object(value) || !NAMES.has(value.name as HealthComponentName) || !STATES.has(value.status as HealthState) || typeof value.summary !== "string" || !object(value.observations)) return null;
  for (const item of Object.values(value.observations)) if (item !== null && !["string", "number", "boolean"].includes(typeof item)) return null;
  return value as HealthComponent;
}
function health(value: unknown): SystemHealth | null {
  if (!object(value) || !STATES.has(value.status as HealthState) || typeof value.generated_at !== "string" || Number.isNaN(Date.parse(value.generated_at)) || typeof value.version !== "string") return null;
  if (value.commit_sha !== null && (typeof value.commit_sha !== "string" || !COMMIT.test(value.commit_sha))) return null;
  if (!Array.isArray(value.components) || value.components.length !== 8) return null;
  const components = value.components.map(component);
  if (components.some((item) => item === null) || new Set(components.map((item) => item?.name)).size !== 8) return null;
  return { status: value.status as HealthState, generated_at: value.generated_at, version: value.version, commit_sha: value.commit_sha as string | null, components: components as HealthComponent[] };
}
export async function fetchSystemHealth(signal?: AbortSignal): Promise<SystemHealthResult> {
  try {
    const response = await apiFetch("/api/v1/system/health", { signal });
    if (!response.ok) return { status: "error" };
    const validated = health(await response.json());
    return validated ? { status: "success", data: validated } : { status: "error" };
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}
