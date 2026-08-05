"use client";

import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";

import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import {
  changeUserExpiry,
  changeUserRole,
  changeUserStatus,
  createAdminUser,
  fetchAdminUsers,
  revokeUserSessions,
} from "@/services/adminUsersApi";
import type { AdminUserList } from "@/types/adminUser";
import type { RoleKey } from "@/types/auth";

const ROLES: RoleKey[] = ["viewer", "analyst", "ingestion_operator", "administrator"];

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function expiryValue(value: string): string | null {
  return value ? new Date(value).toISOString() : null;
}

export default function AdminUsersPage() {
  const [data, setData] = useState<AdminUserList | null>(null);
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<RoleKey>("viewer");
  const [createExpiry, setCreateExpiry] = useState("");
  const [roleDrafts, setRoleDrafts] = useState<Record<string, RoleKey>>({});
  const [expiryDrafts, setExpiryDrafts] = useState<Record<string, string>>({});
  const mountedRef = useRef(false);

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const result = await fetchAdminUsers(signal);
      if (signal?.aborted || !mountedRef.current) return;
      if (result.status === "success") {
        setData(result.data);
        setError(false);
      } else setError(true);
    } catch (requestError) {
      if (!signal?.aborted && !isAbortError(requestError) && mountedRef.current) setError(true);
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    const controller = new AbortController();
    void load(controller.signal);
    return () => {
      mountedRef.current = false;
      controller.abort();
    };
  }, [load]);

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("create");
    try {
      const result = await createAdminUser({
        username,
        displayName,
        password,
        role,
        accountExpiresAt: expiryValue(createExpiry),
      });
      if (!mountedRef.current) return;
      if (result.status === "success") {
        setUsername("");
        setDisplayName("");
        setCreateExpiry("");
        setRole("viewer");
        await load();
      } else setError(true);
    } finally {
      if (mountedRef.current) {
        setPassword("");
        setBusy(null);
      }
    }
  }

  async function status(publicId: string, current: "active" | "disabled") {
    const next = current === "active" ? "disabled" : "active";
    if (next === "disabled" && !window.confirm("Disable this account? Existing sessions will be governed by the backend account policy.")) return;
    setBusy(`${publicId}:status`);
    const result = await changeUserStatus(publicId, next);
    if (!mountedRef.current) return;
    setBusy(null);
    if (result.status === "success") await load(); else setError(true);
  }

  async function updateRole(publicId: string, current: RoleKey) {
    const next = roleDrafts[publicId] ?? current;
    if (next === current) return;
    if (!window.confirm(`Change this account role from ${current} to ${next}?`)) return;
    setBusy(`${publicId}:role`);
    const result = await changeUserRole(publicId, next);
    if (!mountedRef.current) return;
    setBusy(null);
    if (result.status === "success") await load(); else setError(true);
  }

  async function updateExpiry(publicId: string, clear = false) {
    if (!window.confirm(clear ? "Remove this account expiry?" : "Change this account expiry?")) return;
    const next = clear ? null : expiryValue(expiryDrafts[publicId] ?? "");
    setBusy(`${publicId}:expiry`);
    const result = await changeUserExpiry(publicId, next);
    if (!mountedRef.current) return;
    setBusy(null);
    if (result.status === "success") await load(); else setError(true);
  }

  async function revoke(publicId: string) {
    if (!window.confirm("Revoke every active session for this user?")) return;
    setBusy(`${publicId}:sessions`);
    const ok = await revokeUserSessions(publicId);
    if (!mountedRef.current) return;
    setBusy(null);
    if (ok) await load(); else setError(true);
  }

  return (
    <ProtectedRoute permission="user.read">
      <section className="operationsPage">
        <header className="pageHeader"><p className="pageKicker">Administrator</p><h1>User access</h1><p>Allow-listed account state, role, expiry, and session controls. Backend authorization remains authoritative.</p></header>
        <section className="dashboardPanel"><h2>Create user</h2><form onSubmit={create}><label>Username<input required minLength={3} maxLength={64} value={username} onChange={(event) => setUsername(event.target.value)} /></label><label>Display name<input required minLength={1} maxLength={160} value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></label><label>Temporary password<input required minLength={12} maxLength={128} type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label><label>Role<select value={role} onChange={(event) => setRole(event.target.value as RoleKey)}>{ROLES.map((item) => <option key={item} value={item}>{item}</option>)}</select></label><label>Account expiry<input type="datetime-local" value={createExpiry} onChange={(event) => setCreateExpiry(event.target.value)} /></label><button disabled={busy !== null} type="submit">{busy === "create" ? "Creating…" : "Create user"}</button></form></section>
        {error ? <p className="inlineAlert" role="alert">User administration could not be completed safely.</p> : null}
        {!data ? <p role="status" aria-busy="true">Loading users…</p> : data.items.length === 0 ? <p>No user accounts are available.</p> : <div className="responsiveTable"><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Expiry</th><th>Last authenticated</th><th>Controls</th></tr></thead><tbody>{data.items.map((user) => <tr key={user.public_id}><td><strong>{user.display_name}</strong><small>{user.username}</small></td><td>{user.role}<select aria-label={`New role for ${user.username}`} value={roleDrafts[user.public_id] ?? user.role} onChange={(event) => setRoleDrafts({ ...roleDrafts, [user.public_id]: event.target.value as RoleKey })}>{ROLES.map((item) => <option key={item} value={item}>{item}</option>)}</select></td><td>{user.status}</td><td>{user.account_expires_at ? new Date(user.account_expires_at).toLocaleString() : "No expiry"}<input aria-label={`New expiry for ${user.username}`} type="datetime-local" value={expiryDrafts[user.public_id] ?? ""} onChange={(event) => setExpiryDrafts({ ...expiryDrafts, [user.public_id]: event.target.value })} /></td><td>{user.last_authenticated_at ? new Date(user.last_authenticated_at).toLocaleString() : "Never"}</td><td><div className="tableActions"><button disabled={busy !== null} onClick={() => void status(user.public_id, user.status)} type="button">{user.status === "active" ? "Disable" : "Enable"}</button><button disabled={busy !== null} onClick={() => void updateRole(user.public_id, user.role)} type="button">Change role</button><button disabled={busy !== null} onClick={() => void updateExpiry(user.public_id)} type="button">Change expiry</button><button disabled={busy !== null} onClick={() => void updateExpiry(user.public_id, true)} type="button">Clear expiry</button><button disabled={busy !== null} onClick={() => void revoke(user.public_id)} type="button">Revoke sessions</button></div></td></tr>)}</tbody></table></div>}
      </section>
    </ProtectedRoute>
  );
}
