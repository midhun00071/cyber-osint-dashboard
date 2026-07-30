import { validatePublicEnvironment } from "@/config/publicEnvironment";

export const API_BASE_URL = validatePublicEnvironment(
  {
    NEXT_PUBLIC_APP_ENV:
      process.env.NEXT_PUBLIC_APP_ENV ??
      (process.env.NODE_ENV === "test" ? "test" : undefined),
    NEXT_PUBLIC_API_BASE_URL: process.env.NEXT_PUBLIC_API_BASE_URL,
  },
).apiBaseUrl;
