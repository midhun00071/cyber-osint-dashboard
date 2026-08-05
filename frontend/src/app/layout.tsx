import type { Metadata } from "next";
import type { ReactNode } from "react";

import "../styles/globals.css";
import { AuthProvider } from "@/components/auth/AuthProvider";

export const metadata: Metadata = {
  title: "Alpha Data | Cyber OSINT Dashboard",
  description:
    "Defensive cybersecurity OSINT dashboard for public threat intelligence.",
};

type RootLayoutProps = Readonly<{
  children: ReactNode;
}>;

export default function RootLayout({ children }: RootLayoutProps) {
  return (
    <html lang="en">
      <body><AuthProvider>{children}</AuthProvider></body>
    </html>
  );
}
