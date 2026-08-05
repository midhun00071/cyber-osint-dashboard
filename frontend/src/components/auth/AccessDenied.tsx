"use client";

import Link from "next/link";

export function AccessDenied() {
  return (
    <main className="authStatePage" role="alert">
      <p className="panelEyebrow">Access control</p>
      <h1>Access denied</h1>
      <p>Your session is valid, but your role does not permit this action.</p>
      <Link className="safeSourceLink" href="/">Return to overview</Link>
    </main>
  );
}
