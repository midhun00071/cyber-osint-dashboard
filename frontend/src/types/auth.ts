export type RoleKey =
  | "viewer"
  | "analyst"
  | "ingestion_operator"
  | "administrator";

export type Principal = {
  public_id: string;
  display_name: string;
  role: RoleKey;
  permissions: string[];
  account_expires_at: string | null;
};

export type SessionState =
  | "bootstrapping"
  | "anonymous"
  | "authenticating"
  | "authenticated"
  | "session_expired"
  | "access_denied"
  | "recoverable_error"
  | "logging_out";
