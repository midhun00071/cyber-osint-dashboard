export type EvidenceTag = {
  kind: "authority" | "emirate" | "language" | "sector";
  slug: string;
  label: string;
  confidence: number;
  evidence: string;
};

export type ThreatEntity = {
  public_id: string;
  entity_type: "threat_actor" | "campaign" | "malware_family" | "attack_technique";
  name: string;
  attack_id: string | null;
  aliases: string[];
  confidence: number | null;
  source_slug: string;
  source_name: string;
  source_url: string;
  content_sha256: string | null;
  stix_created_at: string;
  stix_modified_at: string;
  revoked: boolean;
};

export type Indicator = {
  public_id: string;
  observable_type: "ipv4" | "ipv6" | "domain" | "url" | "file_hash";
  normalized_value: string;
  hash_algorithm: string | null;
  status: "active" | "inactive" | "revoked" | "false_positive" | "archived";
  confidence: number | null;
  context_summary: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  expires_at: string | null;
  provenance_count: number;
  publication_count: number;
};

export type UaeIntelligenceItem = {
  public_id: string;
  title: string;
  summary: string | null;
  item_type: string;
  cve_id: string | null;
  severity: string | null;
  source_slug: string | null;
  source_name: string | null;
  source_url: string | null;
  published_at: string | null;
  modified_at: string | null;
  collected_at: string;
  last_seen_at: string;
  geographic_scope: string;
  relevance_status: string;
  relevance_label: "Direct UAE evidence" | "Potential UAE relevance" | "Global relevance" | "No demonstrated UAE relevance";
  relevance_confidence: number | null;
  relevance_reason: string | null;
  relevance_method: string;
  classification_tags: EvidenceTag[];
};

export type ItemProvenance = {
  item_public_id: string;
  sources: Array<{
    source_slug: string; source_name: string; source_url: string;
    content_sha256: string | null; published_at: string | null; modified_at: string | null;
    collected_at: string; first_seen_at: string; last_seen_at: string;
    import_runs: Array<{ public_id: string; action: string; status: string; started_at: string; completed_at: string | null; processed_at: string }>;
  }>;
  classification_tags: EvidenceTag[];
  indicators: Array<{ public_id: string; observable_type: string; normalized_value: string; hash_algorithm: string | null; status: string; confidence: number | null; context_summary: string | null; first_observed_at: string; last_observed_at: string }>;
};

export type AnalystList<T> = { items: T[]; total: number; limit: number; offset: number };
export type AnalystResult<T> = { status: "success"; data: T } | { status: "not_found" } | { status: "error" };
