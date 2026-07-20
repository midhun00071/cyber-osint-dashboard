import type { ReactNode } from "react";

import { getSafeExternalUrl } from "../utils/safeExternalUrl";

type SafeExternalLinkProps = Readonly<{
  children: ReactNode;
  className?: string;
  url: unknown;
}>;

export function SafeExternalLink({
  children,
  className,
  url,
}: SafeExternalLinkProps) {
  const safeUrl = getSafeExternalUrl(url);

  if (!safeUrl) {
    return (
      <span aria-disabled="true" className={className}>
        {children}
      </span>
    );
  }

  return (
    <a
      className={className}
      href={safeUrl}
      rel="noopener noreferrer"
      target="_blank"
    >
      {children}
    </a>
  );
}
