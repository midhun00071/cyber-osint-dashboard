export type OperatorState = "enabled" | "paused" | "disabled";

export type SourceOperation = "manual_run" | "retry" | "pause" | "resume" | "disable" | "enable";

export type SourceSummary = {
  public_id: string;
  slug: string;
  name: string;
  source_type: string;
  content_type: string;
  access_class: string;
  policy_state: string;
  operator_state: OperatorState;
  effective_state: string;
  credential_required: boolean;
  credential_configured: boolean;
  execution_available: boolean;
  freshness: "fresh" | "stale" | "never" | "not_applicable";
  progress: { kind: "none" | "checkpoint" | "watermark"; version: number | null; committed_at: string | null; fingerprint: string | null };
  latest_run: { public_id: string; status: string; trigger_type: string; attempt_number: number; started_at: string; finished_at: string | null } | null;
  quota_state: string | null;
  backoff_until: string | null;
  next_scheduled_at: string | null;
  available_actions: SourceOperation[];
};

export type SourceList = { items: SourceSummary[]; total: number; limit: number; offset: number };

export type OperationsSummary = {
  generated_at: string;
  deployment_state: "inactive" | "available";
  configured_handler_count: number;
  active_cycle_count: number;
  active_run_count: number;
  source_attention_count: number;
  run_counts_by_status: Record<string, number>;
  latest_cycle: CycleSummary | null;
};

export type CycleSummary = {
  public_id: string; trigger_type: string; status: string; started_at: string;
  finished_at: string | null; duration_seconds: number | null;
  sources_expected: number; sources_started: number; sources_completed: number;
  sources_successful: number; sources_non_successful: number; summary_message: string | null;
};

export type CycleList = {
  items: CycleSummary[];
  total: number;
  limit: number;
  offset: number;
};

export type RunSummary = {
  public_id: string; cycle_public_id: string | null; source_public_id: string;
  source_slug: string; source_name: string; trigger_type: string; status: string;
  attempt_number: number; retry_of_public_id: string | null; accepted_at: string;
  started_at: string; finished_at: string | null; duration_seconds: number | null;
  retryable: boolean; summary_message: string | null;
  counters: { fetched: number; created: number; updated: number; unchanged: number; skipped: number; failed: number; error_count: number };
};

export type RunList = { items: RunSummary[]; total: number; limit: number; offset: number };

export type RunFilters = {
  sourceSlug?: string;
  status?: string;
  triggerType?: string;
  retryable?: boolean;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
};

export type RunEvent = {
  sequence: number;
  event_type: string;
  from_status: string | null;
  to_status: string | null;
  message: string | null;
  occurred_at: string;
};

export type RunEventList = {
  items: RunEvent[];
  total: number;
  limit: number;
  offset: number;
};

export type OperationResult<T> = { status: "success"; data: T } | { status: "error"; code?: string };
