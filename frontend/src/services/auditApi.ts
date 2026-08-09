import { apiFetch } from "@/services/apiClient";
import type { AuditEvent, AuditFilters, AuditList, AuditResult } from "@/types/audit";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE = /^[A-Za-z0-9_.:-]{1,240}$/;
function object(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function event(value: unknown): AuditEvent | null {
  if (!object(value) || typeof value.public_id !== "string" || !UUID.test(value.public_id) || typeof value.occurred_at !== "string" || Number.isNaN(Date.parse(value.occurred_at))) return null;
  for (const name of ["actor_type", "actor_ref", "action", "target_type", "target_ref", "outcome"] as const) if (typeof value[name] !== "string" || value[name].length > 240) return null;
  if (value.correlation_id !== null && (typeof value.correlation_id !== "string" || !UUID.test(value.correlation_id))) return null;
  if (value.safe_detail !== null) {
    if (!object(value.safe_detail) || Object.keys(value.safe_detail).length > 6) return null;
    if (Object.entries(value.safe_detail).some(([key, item]) => !SAFE.test(key) || typeof item !== "string" || !SAFE.test(item))) return null;
  }
  return value as AuditEvent;
}
function list(value: unknown): AuditList | null {
  if (!object(value) || !Array.isArray(value.items) || !Number.isInteger(value.total) || !Number.isInteger(value.limit) || !Number.isInteger(value.offset)) return null;
  const items = value.items.map(event);
  if (items.some((item) => item === null) || (value.limit as number) < 1 || (value.limit as number) > 100 || (value.offset as number) < 0) return null;
  return { items: items as AuditEvent[], total: value.total as number, limit: value.limit as number, offset: value.offset as number };
}
export function buildAuditQuery(filters: AuditFilters): string {
  const limit = filters.limit ?? 25;
  const offset = filters.offset ?? 0;
  if (!Number.isInteger(limit) || limit < 1 || limit > 100 || !Number.isInteger(offset) || offset < 0 || offset > 100000) throw new Error("Invalid audit filters.");
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (filters.action) query.set("action", filters.action);
  if (filters.outcome) query.set("outcome", filters.outcome);
  if (filters.correlationId) query.set("correlation_id", filters.correlationId);
  if (filters.from) query.set("occurred_from", filters.from);
  if (filters.to) query.set("occurred_to", filters.to);
  return query.toString();
}
export async function fetchAuditEvents(filters: AuditFilters, signal?: AbortSignal): Promise<AuditResult> {
  try {
    const response = await apiFetch(`/api/v1/audit/events?${buildAuditQuery(filters)}`, { signal });
    if (!response.ok) return { status: "error" };
    const validated = list(await response.json());
    return validated ? { status: "success", data: validated } : { status: "error" };
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}
