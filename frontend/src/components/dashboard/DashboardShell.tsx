"use client";

import type { ReactNode } from "react";
import { useCallback, useEffect, useId, useRef, useState } from "react";

import { Sidebar } from "@/components/dashboard/Sidebar";
import { TopHeader } from "@/components/dashboard/TopHeader";

type DashboardShellProps = Readonly<{
  children: ReactNode;
}>;

export function DashboardShell({ children }: DashboardShellProps) {
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const drawerId = useId();
  const openButtonRef = useRef<HTMLButtonElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  const openDrawer = useCallback(() => {
    setIsDrawerOpen(true);
  }, []);

  const closeDrawer = useCallback(() => {
    setIsDrawerOpen(false);
    openButtonRef.current?.focus();
  }, []);

  useEffect(() => {
    if (!isDrawerOpen) {
      return undefined;
    }

    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") {
        closeDrawer();
      }
    }

    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [closeDrawer, isDrawerOpen]);

  useEffect(() => {
    if (isDrawerOpen) {
      closeButtonRef.current?.focus();
    }
  }, [isDrawerOpen]);

  useEffect(() => {
    if (!isDrawerOpen) {
      document.body.style.overflow = "";
      return undefined;
    }

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [isDrawerOpen]);

  return (
    <div className="dashboardShell">
      <Sidebar className="desktopSidebar" />

      <div className="dashboardSurface">
        <TopHeader
          drawerId={drawerId}
          isDrawerOpen={isDrawerOpen}
          onOpenDrawer={openDrawer}
          openButtonRef={openButtonRef}
        />
        <main className="dashboardMain">{children}</main>
      </div>

      {isDrawerOpen ? (
        <button
          aria-label="Close navigation overlay"
          className="drawerOverlay"
          onClick={closeDrawer}
          type="button"
        />
      ) : null}

      {isDrawerOpen ? (
        <aside
          aria-label="Mobile dashboard navigation"
          aria-modal="true"
          className="mobileDrawer"
          id={drawerId}
          role="dialog"
        >
          <Sidebar
            className="mobileSidebar"
            closeButtonRef={closeButtonRef}
            onClose={closeDrawer}
            showCloseButton
          />
        </aside>
      ) : null}
    </div>
  );
}
