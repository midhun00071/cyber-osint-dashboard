"use client";

import type { RefObject } from "react";

import { useAuth } from "@/components/auth/AuthProvider";

type TopHeaderProps = Readonly<{
  drawerId: string;
  isDrawerOpen: boolean;
  onOpenDrawer: () => void;
  openButtonRef: RefObject<HTMLButtonElement | null>;
}>;

export function TopHeader({
  drawerId,
  isDrawerOpen,
  onOpenDrawer,
  openButtonRef,
}: TopHeaderProps) {
  const { logout, principal, state } = useAuth();
  return (
    <header className="topHeader">
      <div className="topHeaderTitleGroup">
        <button
          aria-controls={drawerId}
          aria-expanded={isDrawerOpen}
          aria-label="Open navigation"
          className="mobileNavButton"
          onClick={onOpenDrawer}
          ref={openButtonRef}
          type="button"
        >
          <span aria-hidden="true" />
          <span aria-hidden="true" />
          <span aria-hidden="true" />
        </button>
        <div>
          <p className="panelEyebrow">Overview</p>
          <h2>Dashboard command center</h2>
        </div>
      </div>

      <div className="identityControls">
        <div className="environmentIndicator">
          <span className="previewDot" aria-hidden="true" />
          <span><strong>{principal?.display_name ?? "Authenticated user"}</strong><small>{principal?.role.replace("_", " ")}</small></span>
        </div>
        <button disabled={state === "logging_out"} onClick={() => void logout()} type="button">
          {state === "logging_out" ? "Signing out…" : "Sign out"}
        </button>
      </div>
    </header>
  );
}
