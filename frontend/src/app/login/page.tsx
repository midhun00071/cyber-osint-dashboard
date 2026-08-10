"use client";

import { type FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { getSafeReturnPath, useAuth } from "@/components/auth/AuthProvider";

function returnDestination(): string {
  if (typeof window === "undefined") return "/";
  return getSafeReturnPath(new URLSearchParams(window.location.search).get("next"));
}

export default function LoginPage() {
  const { login, state } = useAuth();
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (state === "authenticated") router.replace(returnDestination());
  }, [router, state]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage(null);
    const accepted = await login(username, password, returnDestination());
    if (!accepted) setMessage("Sign in was not accepted. Check your credentials or try again.");
  }

  return (
    <main className="loginPage">
      <form className="loginCard" onSubmit={(event) => void submit(event)}>
        <span className="brandMark" aria-hidden="true">AD</span>
        <p className="panelEyebrow">Alpha Data</p>
        <h1>Secure sign in</h1>
        <p>Use your approved local dashboard account.</p>
        <label>Username<input id="login-username" name="username" autoComplete="username" minLength={3} maxLength={64} onChange={(event) => setUsername(event.target.value)} required value={username} /></label>
        <label>Password<input id="login-password" name="password" autoComplete="current-password" minLength={12} maxLength={128} onChange={(event) => setPassword(event.target.value)} required type="password" value={password} /></label>
        {message ? <p className="formError" role="alert">{message}</p> : null}
        <button disabled={state === "authenticating"} type="submit">{state === "authenticating" ? "Signing in…" : "Sign in"}</button>
      </form>
    </main>
  );
}
