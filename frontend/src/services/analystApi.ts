import { apiFetch } from "@/services/apiClient";
import type { AnalystList, AnalystResult, Indicator, ItemProvenance, ThreatEntity, UaeIntelligenceItem } from "@/types/analyst";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isList<T>(value: unknown, itemGuard: (item: unknown) => item is T): value is AnalystList<T> {
  if (!isObject(value)) return false;
  return Array.isArray(value.items) && value.items.every(itemGuard) &&
    Number.isInteger(value.total) && Number(value.total) >= 0 &&
    Number.isInteger(value.limit) && Number(value.limit) >= 1 && Number(value.limit) <= 100 &&
    Number.isInteger(value.offset) && Number(value.offset) >= 0;
}

function isThreatEntity(value: unknown): value is ThreatEntity {
  return isObject(value) && typeof value.public_id === "string" && typeof value.name === "string" &&
    typeof value.entity_type === "string" && Array.isArray(value.aliases) &&
    typeof value.source_slug === "string" && typeof value.source_name === "string" &&
    typeof value.source_url === "string" && typeof value.revoked === "boolean";
}

function isIndicator(value: unknown): value is Indicator {
  return isObject(value) && typeof value.public_id === "string" &&
    typeof value.observable_type === "string" && typeof value.normalized_value === "string" &&
    typeof value.status === "string" && Number.isInteger(value.provenance_count) && Number.isInteger(value.publication_count);
}

function isUaeItem(value: unknown): value is UaeIntelligenceItem {
  return isObject(value) && typeof value.public_id === "string" && typeof value.title === "string" &&
    typeof value.item_type === "string" && typeof value.relevance_label === "string" &&
    typeof value.relevance_status === "string" && Array.isArray(value.classification_tags);
}

async function fetchList<T>(path: string, guard: (item: unknown) => item is T, signal?: AbortSignal): Promise<AnalystResult<AnalystList<T>>> {
  try {
    const response = await apiFetch(path, { signal });
    if (!response.ok) return { status: "error" };
    const data: unknown = await response.json();
    return isList(data, guard) ? { status: "success", data } : { status: "error" };
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}

export function fetchThreatEntities(query: string, offset: number, signal?: AbortSignal) {
  const params = new URLSearchParams({ limit: "25", offset: String(offset) });
  if (query.trim()) params.set("q", query.trim());
  return fetchList(`/api/v1/analysis/threat-entities?${params}`, isThreatEntity, signal);
}

export function fetchIndicators(query: string, offset: number, signal?: AbortSignal) {
  const params = new URLSearchParams({ limit: "25", offset: String(offset), status: "active" });
  if (query.trim()) params.set("q", query.trim());
  return fetchList(`/api/v1/analysis/indicators?${params}`, isIndicator, signal);
}

export function fetchUaeIntelligence(relevance: string, query: string, offset: number, signal?: AbortSignal) {
  const params = new URLSearchParams({ limit: "25", offset: String(offset) });
  if (relevance) params.set("relevance", relevance);
  if (query.trim()) params.set("q", query.trim());
  return fetchList(`/api/v1/analysis/uae-intelligence?${params}`, isUaeItem, signal);
}

export async function fetchItemProvenance(publicId: string, signal?: AbortSignal): Promise<AnalystResult<ItemProvenance>> {
  try {
    const response = await apiFetch(`/api/v1/analysis/items/${encodeURIComponent(publicId)}/provenance`, { signal });
    if (response.status === 404) return { status: "not_found" };
    if (!response.ok) return { status: "error" };
    const data: unknown = await response.json();
    if (!isObject(data) || data.item_public_id !== publicId || !Array.isArray(data.sources) || !Array.isArray(data.classification_tags) || !Array.isArray(data.indicators)) return { status: "error" };
    return { status: "success", data: data as ItemProvenance };
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}
