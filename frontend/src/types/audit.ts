export type AuditEvent = {
  public_id: string; actor_type: string; actor_ref: string; action: string;
  target_type: string; target_ref: string; outcome: string; correlation_id: string | null;
  safe_detail: Record<string, string> | null; occurred_at: string;
};
export type AuditList = { items: AuditEvent[]; total: number; limit: number; offset: number };
export type AuditFilters = { action?: string; outcome?: string; correlationId?: string; from?: string; to?: string; limit?: number; offset?: number };
export type AuditResult = { status: "success"; data: AuditList } | { status: "error" };
