import { apiFetch } from "@/services/apiClient";
import type {
  CycleList,
  CycleSummary,
  OperationResult,
  OperationsSummary,
  RunEvent,
  RunEventList,
  RunFilters,
  RunList,
  RunSummary,
  SourceList,
  SourceSummary,
} from "@/types/operations";

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function nullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function exactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return object(value) && Object.keys(value).length === keys.length && keys.every((key) => key in value);
}

const sourceActions = new Set(["manual_run", "retry", "pause", "resume", "disable", "enable"]);

function progress(value: unknown): SourceSummary["progress"] | null {
  if (!exactKeys(value, ["kind", "version", "committed_at", "fingerprint"])) return null;
  if (!["none", "checkpoint", "watermark"].includes(String(value.kind))) return null;
  if (!(value.version === null || typeof value.version === "number")) return null;
  if (!nullableString(value.committed_at)) return null;
  if (!(value.fingerprint === null || (typeof value.fingerprint === "string" && /^[0-9a-f]{64}$/.test(value.fingerprint)))) return null;
  return {
    kind: value.kind as SourceSummary["progress"]["kind"],
    version: value.version,
    committed_at: value.committed_at,
    fingerprint: value.fingerprint,
  };
}

function latestRun(value: unknown): SourceSummary["latest_run"] | undefined {
  if (value === null) {
    return null;
  }
  if (!exactKeys(value, ["public_id", "status", "trigger_type", "attempt_number", "started_at", "finished_at"])) return undefined;
  if (typeof value.public_id !== "string" || typeof value.status !== "string" || typeof value.trigger_type !== "string") return undefined;
  if (typeof value.attempt_number !== "number" || typeof value.started_at !== "string" || !nullableString(value.finished_at)) return undefined;
  return {
    public_id: value.public_id,
    status: value.status,
    trigger_type: value.trigger_type,
    attempt_number: value.attempt_number,
    started_at: value.started_at,
    finished_at: value.finished_at,
  };
}

function source(value: unknown): SourceSummary | null {
  if (!exactKeys(value, [
    "public_id", "slug", "name", "source_type", "content_type", "access_class", "policy_state",
    "operator_state", "effective_state", "credential_required", "credential_configured", "execution_available",
    "freshness", "progress", "latest_run", "quota_state", "backoff_until", "next_scheduled_at", "available_actions",
  ])) return null;
  if (typeof value.public_id !== "string" || typeof value.slug !== "string" || typeof value.name !== "string") return null;
  if (typeof value.source_type !== "string" || typeof value.content_type !== "string" || typeof value.access_class !== "string") return null;
  if (typeof value.policy_state !== "string" || typeof value.effective_state !== "string") return null;
  if (!["enabled", "paused", "disabled"].includes(String(value.operator_state))) return null;
  if (typeof value.credential_required !== "boolean" || typeof value.credential_configured !== "boolean") return null;
  if (typeof value.execution_available !== "boolean") return null;
  if (!["fresh", "stale", "never", "not_applicable"].includes(String(value.freshness))) return null;
  const parsedProgress = progress(value.progress);
  const parsedLatestRun = latestRun(value.latest_run);
  if (!parsedProgress || parsedLatestRun === undefined) return null;
  if (!nullableString(value.quota_state) || !nullableString(value.backoff_until) || !nullableString(value.next_scheduled_at)) return null;
  if (!Array.isArray(value.available_actions) || !value.available_actions.every((action) => typeof action === "string" && sourceActions.has(action))) return null;
  return {
    public_id: value.public_id,
    slug: value.slug,
    name: value.name,
    source_type: value.source_type,
    content_type: value.content_type,
    access_class: value.access_class,
    policy_state: value.policy_state,
    operator_state: value.operator_state as SourceSummary["operator_state"],
    effective_state: value.effective_state,
    credential_required: value.credential_required,
    credential_configured: value.credential_configured,
    execution_available: value.execution_available,
    freshness: value.freshness as SourceSummary["freshness"],
    progress: parsedProgress,
    latest_run: parsedLatestRun,
    quota_state: value.quota_state,
    backoff_until: value.backoff_until,
    next_scheduled_at: value.next_scheduled_at,
    available_actions: value.available_actions as SourceSummary["available_actions"],
  };
}

function counters(value: unknown): RunSummary["counters"] | null {
  if (!exactKeys(value, ["fetched", "created", "updated", "unchanged", "skipped", "failed", "error_count"])) return null;
  if (!["fetched", "created", "updated", "unchanged", "skipped", "failed", "error_count"].every((key) => typeof value[key] === "number")) return null;
  const fetched = value.fetched as number;
  const created = value.created as number;
  const updated = value.updated as number;
  const unchanged = value.unchanged as number;
  const skipped = value.skipped as number;
  const failed = value.failed as number;
  const errorCount = value.error_count as number;
  return {
    fetched,
    created,
    updated,
    unchanged,
    skipped,
    failed,
    error_count: errorCount,
  };
}

function run(value: unknown): RunSummary | null {
  if (!exactKeys(value, [
    "public_id", "cycle_public_id", "source_public_id", "source_slug", "source_name", "trigger_type",
    "status", "attempt_number", "retry_of_public_id", "accepted_at", "started_at", "finished_at",
    "duration_seconds", "retryable", "summary_message", "counters",
  ])) return null;
  if (typeof value.public_id !== "string" || typeof value.cycle_public_id !== "string" || typeof value.source_public_id !== "string") return null;
  if (typeof value.source_slug !== "string" || typeof value.source_name !== "string" || typeof value.trigger_type !== "string") return null;
  if (typeof value.status !== "string" || typeof value.attempt_number !== "number" || !nullableString(value.retry_of_public_id)) return null;
  if (typeof value.accepted_at !== "string" || typeof value.started_at !== "string" || !nullableString(value.finished_at)) return null;
  if (!(value.duration_seconds === null || typeof value.duration_seconds === "number")) return null;
  if (typeof value.retryable !== "boolean" || !nullableString(value.summary_message)) return null;
  const parsedCounters = counters(value.counters);
  if (!parsedCounters) return null;
  return {
    public_id: value.public_id,
    cycle_public_id: value.cycle_public_id,
    source_public_id: value.source_public_id,
    source_slug: value.source_slug,
    source_name: value.source_name,
    trigger_type: value.trigger_type,
    status: value.status,
    attempt_number: value.attempt_number,
    retry_of_public_id: value.retry_of_public_id,
    accepted_at: value.accepted_at,
    started_at: value.started_at,
    finished_at: value.finished_at,
    duration_seconds: value.duration_seconds,
    retryable: value.retryable,
    summary_message: value.summary_message,
    counters: parsedCounters,
  };
}

function cycle(value: unknown): CycleSummary | null {
  if (!exactKeys(value, [
    "public_id", "trigger_type", "status", "started_at", "finished_at", "duration_seconds",
    "sources_expected", "sources_started", "sources_completed", "sources_successful", "sources_non_successful",
    "summary_message",
  ])) return null;
  if (typeof value.public_id !== "string" || typeof value.trigger_type !== "string" || typeof value.status !== "string") return null;
  if (typeof value.started_at !== "string" || !nullableString(value.finished_at)) return null;
  if (!(value.duration_seconds === null || typeof value.duration_seconds === "number")) return null;
  if (!["sources_expected", "sources_started", "sources_completed", "sources_successful", "sources_non_successful"].every((key) => typeof value[key] === "number")) return null;
  if (!nullableString(value.summary_message)) return null;
  const sourcesExpected = value.sources_expected as number;
  const sourcesStarted = value.sources_started as number;
  const sourcesCompleted = value.sources_completed as number;
  const sourcesSuccessful = value.sources_successful as number;
  const sourcesNonSuccessful = value.sources_non_successful as number;
  return {
    public_id: value.public_id,
    trigger_type: value.trigger_type,
    status: value.status,
    started_at: value.started_at,
    finished_at: value.finished_at,
    duration_seconds: value.duration_seconds,
    sources_expected: sourcesExpected,
    sources_started: sourcesStarted,
    sources_completed: sourcesCompleted,
    sources_successful: sourcesSuccessful,
    sources_non_successful: sourcesNonSuccessful,
    summary_message: value.summary_message,
  };
}

function event(value: unknown): RunEvent | null {
  if (!exactKeys(value, ["sequence", "event_type", "from_status", "to_status", "message", "occurred_at"])) return null;
  if (typeof value.sequence !== "number" || typeof value.event_type !== "string") return null;
  if (!nullableString(value.from_status) || !nullableString(value.to_status) || !nullableString(value.message)) return null;
  if (typeof value.occurred_at !== "string") return null;
  return {
    sequence: value.sequence,
    event_type: value.event_type,
    from_status: value.from_status,
    to_status: value.to_status,
    message: value.message,
    occurred_at: value.occurred_at,
  };
}

function summary(value: unknown): OperationsSummary | null {
  if (!exactKeys(value, [
    "generated_at", "deployment_state", "configured_handler_count", "active_cycle_count", "active_run_count",
    "source_attention_count", "run_counts_by_status", "latest_cycle",
  ])) return null;
  if (typeof value.generated_at !== "string" || !["inactive", "available"].includes(String(value.deployment_state))) return null;
  if (typeof value.configured_handler_count !== "number" || typeof value.active_cycle_count !== "number") return null;
  if (typeof value.active_run_count !== "number" || typeof value.source_attention_count !== "number") return null;
  if (!object(value.run_counts_by_status)) return null;
  const runCounts: Record<string, number> = {};
  for (const [key, count] of Object.entries(value.run_counts_by_status)) {
    if (typeof count !== "number") return null;
    runCounts[key] = count;
  }
  const parsedLatestCycle = cycle(value.latest_cycle);
  if (value.latest_cycle !== null && !parsedLatestCycle) return null;
  return {
    generated_at: value.generated_at,
    deployment_state: value.deployment_state as OperationsSummary["deployment_state"],
    configured_handler_count: value.configured_handler_count,
    active_cycle_count: value.active_cycle_count,
    active_run_count: value.active_run_count,
    source_attention_count: value.source_attention_count,
    run_counts_by_status: runCounts,
    latest_cycle: parsedLatestCycle,
  };
}

function listShape<T>(value: unknown, parseItem: (item: unknown) => T | null): { items: T[]; total: number; limit: number; offset: number } | null {
  if (!exactKeys(value, ["items", "total", "limit", "offset"])) return null;
  if (!Array.isArray(value.items) || typeof value.total !== "number" || typeof value.limit !== "number" || typeof value.offset !== "number") return null;
  const items: T[] = [];
  for (const item of value.items) {
    const parsedItem = parseItem(item);
    if (!parsedItem) return null;
    items.push(parsedItem);
  }
  return { items, total: value.total, limit: value.limit, offset: value.offset };
}

async function result<T>(response: Response, parser: (value: unknown) => T | null): Promise<OperationResult<T>> {
  if (!response.ok) {
    let code: string | undefined;
    try {
      const value: unknown = await response.json();
      if (object(value) && object(value.detail) && typeof value.detail.code === "string") code = value.detail.code;
    } catch {
      /* sanitized status is sufficient */
    }
    return { status: "error", code };
  }
  const value: unknown = await response.json();
  const parsed = parser(value);
  return parsed === null ? { status: "error" } : { status: "success", data: parsed };
}

function boundedInteger(value: number | undefined, fallback: number, minimum: number, maximum: number): number {
  const selected = value ?? fallback;
  if (!Number.isInteger(selected) || selected < minimum || selected > maximum) {
    throw new RangeError("The operations query bound is invalid.");
  }
  return selected;
}

function awareTimestamp(value: string, name: string): string {
  if (!/(?:Z|[+-]\d{2}:\d{2})$/i.test(value) || Number.isNaN(Date.parse(value))) {
    throw new TypeError(`${name} must be a timezone-aware timestamp.`);
  }
  return value;
}

export function buildRunQuery(filters: RunFilters = {}): string {
  const params = new URLSearchParams();
  if (filters.sourceSlug) params.set("source_slug", filters.sourceSlug);
  if (filters.status) params.set("status", filters.status);
  if (filters.triggerType) params.set("trigger_type", filters.triggerType);
  if (filters.retryable !== undefined) params.set("retryable", String(filters.retryable));
  if (filters.from) params.set("from", awareTimestamp(filters.from, "from"));
  if (filters.to) params.set("to", awareTimestamp(filters.to, "to"));
  if (filters.from && filters.to) {
    const difference = Date.parse(filters.to) - Date.parse(filters.from);
    if (difference <= 0 || difference > 90 * 24 * 60 * 60 * 1000) {
      throw new RangeError("The operations date range is invalid.");
    }
  }
  params.set("limit", String(boundedInteger(filters.limit, 25, 1, 100)));
  params.set("offset", String(boundedInteger(filters.offset, 0, 0, 100000)));
  return params.toString();
}

export async function fetchSources(signal?: AbortSignal): Promise<OperationResult<SourceList>> {
  try {
    return result<SourceList>(
      await apiFetch("/api/v1/sources?limit=100&offset=0", { signal }),
      (value) => listShape(value, source),
    );
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}

export async function fetchOperationsSummary(signal?: AbortSignal): Promise<OperationResult<OperationsSummary>> {
  try {
    return result<OperationsSummary>(await apiFetch("/api/v1/ingestion/operations/summary", { signal }), summary);
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}

export async function fetchCycles(signal?: AbortSignal): Promise<OperationResult<CycleList>> {
  try {
    return result<CycleList>(
      await apiFetch("/api/v1/ingestion/cycles?limit=25&offset=0", { signal }),
      (value) => listShape(value, cycle),
    );
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}

export async function fetchRuns(filters: RunFilters = {}, signal?: AbortSignal): Promise<OperationResult<RunList>> {
  try {
    const query = buildRunQuery(filters);
    return result<RunList>(
      await apiFetch(`/api/v1/ingestion/runs?${query}`, { signal }),
      (value) => listShape(value, run),
    );
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}

export async function fetchRun(publicId: string, signal?: AbortSignal): Promise<OperationResult<RunSummary>> {
  try {
    return result<RunSummary>(
      await apiFetch(`/api/v1/ingestion/runs/${encodeURIComponent(publicId)}`, { signal }),
      run,
    );
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}

export async function fetchRunEvents(publicId: string, signal?: AbortSignal): Promise<OperationResult<RunEventList>> {
  try {
    return result<RunEventList>(
      await apiFetch(`/api/v1/ingestion/runs/${encodeURIComponent(publicId)}/events?limit=500&offset=0`, { signal }),
      (value) => listShape(value, event),
    );
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}

export async function controlSource(slug: string, operation: "pause" | "resume" | "disable" | "enable"): Promise<OperationResult<unknown>> {
  try {
    return result(await apiFetch(`/api/v1/sources/${encodeURIComponent(slug)}/${operation}`, { method: "POST", body: "{}" }), () => ({}));
  } catch {
    return { status: "error" };
  }
}

export async function requestManualRun(slug: string, idempotencyKey: string): Promise<OperationResult<unknown>> {
  try {
    return result(await apiFetch(`/api/v1/sources/${encodeURIComponent(slug)}/runs`, {
      method: "POST", body: "{}", headers: { "Idempotency-Key": idempotencyKey },
    }), () => ({}));
  } catch {
    return { status: "error" };
  }
}

export async function requestRetry(publicId: string): Promise<OperationResult<unknown>> {
  try {
    return result(await apiFetch(`/api/v1/ingestion/runs/${encodeURIComponent(publicId)}/retry`, {
      method: "POST", body: "{}",
    }), () => ({}));
  } catch {
    return { status: "error" };
  }
}
