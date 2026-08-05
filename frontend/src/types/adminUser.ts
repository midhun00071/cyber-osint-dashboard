import type { RoleKey } from "@/types/auth";

export type AdminUser = {
  public_id: string; username: string; display_name: string;
  status: "active" | "disabled"; role: RoleKey; permissions: string[];
  account_expires_at: string | null; last_authenticated_at: string | null;
  created_at: string; updated_at: string;
};

export type AdminUserList = { items: AdminUser[]; total: number; limit: number; offset: number };

export type CreateAdminUser = {
  username: string;
  displayName: string;
  password: string;
  role: RoleKey;
  accountExpiresAt: string | null;
};
