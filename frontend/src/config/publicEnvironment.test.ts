import { spawnSync } from "node:child_process";

import { describe, expect, test } from "vitest";

import {
  normalizePublicEnvironmentIdentity,
  validatePublicEnvironment,
} from "@/config/publicEnvironment";

const FRONTEND_ROOT = process.cwd();

function loadBuildConfiguration(
  environment: string,
  configuredUrl?: string,
) {
  const childEnvironment: NodeJS.ProcessEnv = {
    ...process.env,
    APP_ENV: environment,
    NEXT_PUBLIC_APP_ENV: environment,
  };
  if (configuredUrl === undefined) {
    delete childEnvironment.NEXT_PUBLIC_API_BASE_URL;
  } else {
    childEnvironment.NEXT_PUBLIC_API_BASE_URL = configuredUrl;
  }

  return spawnSync(
    process.execPath,
    ["--input-type=module", "--eval", "await import('./next.config.mjs')"],
    {
      cwd: FRONTEND_ROOT,
      encoding: "utf8",
      env: childEnvironment,
    },
  );
}


describe("public environment validation", () => {
  test.each(["local", "test"])(
    "uses the documented loopback fallback in %s",
    (environment) => {
      expect(
        validatePublicEnvironment({ NEXT_PUBLIC_APP_ENV: environment }).apiBaseUrl,
      ).toBe("http://localhost:8000");
    },
  );

  test.each(["staging", "production"])(
    "requires an explicit API URL in %s",
    (environment) => {
      expect(() =>
        validatePublicEnvironment({ NEXT_PUBLIC_APP_ENV: environment }),
      ).toThrow("NEXT_PUBLIC_API_BASE_URL");
    },
  );

  test("normalizes the development compatibility alias to local", () => {
    expect(normalizePublicEnvironmentIdentity(" DeVeLoPmEnT ")).toBe("local");
  });

  test("accepts and normalizes a valid HTTPS API URL", () => {
    expect(
      validatePublicEnvironment(
        {
          NEXT_PUBLIC_APP_ENV: "production",
          NEXT_PUBLIC_API_BASE_URL: " https://api.example.invalid/// ",
        },
      ).apiBaseUrl,
    ).toBe("https://api.example.invalid");
  });

  test.each(["staging", "production"])(
    "accepts representative non-loopback hosts in %s",
    (environment) => {
      for (const [configuredUrl, expectedUrl] of [
        ["https://api.example.invalid", "https://api.example.invalid"],
        ["https://192.0.2.10", "https://192.0.2.10"],
        ["https://[2001:db8::10]", "https://[2001:db8::10]"],
      ]) {
        expect(
          validatePublicEnvironment({
            NEXT_PUBLIC_APP_ENV: environment,
            NEXT_PUBLIC_API_BASE_URL: configuredUrl,
          }).apiBaseUrl,
        ).toBe(expectedUrl);
      }
    },
  );

  test.each([
    "ftp://api.example.invalid",
    "file:///tmp/api",
  ])("rejects unsupported schemes", (configuredUrl) => {
    expect(() =>
      validatePublicEnvironment(
        {
          NEXT_PUBLIC_APP_ENV: "local",
          NEXT_PUBLIC_API_BASE_URL: configuredUrl,
        },
      ),
    ).toThrow("HTTP or HTTPS");
  });

  test("rejects credential-bearing URLs without echoing the value", () => {
    const canary = "synthetic-test-secret";

    expect(() =>
      validatePublicEnvironment(
        {
          NEXT_PUBLIC_API_BASE_URL: `https://user:${canary}@api.example.invalid`,
          NEXT_PUBLIC_APP_ENV: "production",
        },
      ),
    ).toThrow("must not contain credentials");

    try {
      validatePublicEnvironment(
        {
          NEXT_PUBLIC_API_BASE_URL: `https://user:${canary}@api.example.invalid`,
          NEXT_PUBLIC_APP_ENV: "production",
        },
      );
    } catch (error) {
      expect(String(error)).not.toContain(canary);
    }
  });

  test.each(["staging", "production"])(
    "rejects HTTP in %s",
    (environment) => {
      expect(() =>
        validatePublicEnvironment(
          {
            NEXT_PUBLIC_APP_ENV: environment,
            NEXT_PUBLIC_API_BASE_URL: "http://api.example.invalid",
          },
        ),
      ).toThrow("must use HTTPS");
    },
  );

  test.each(["staging", "production"])(
    "rejects loopback aliases in %s",
    (environment) => {
      for (const configuredUrl of [
        "https://localhost:8000",
        "https://localhost.",
        "https://foo.localhost.",
        "https://127.0.0.1:8000",
        "https://127.1:8000",
        "https://[::1]:8000",
        "https://[::ffff:127.0.0.1]",
        "https://[::ffff:7f00:1]",
        "https://[::ffff:0.0.0.0]",
        "https://0.0.0.0:8000",
      ]) {
        expect(() =>
          validatePublicEnvironment({
            NEXT_PUBLIC_APP_ENV: environment,
            NEXT_PUBLIC_API_BASE_URL: configuredUrl,
          }),
        ).toThrow("non-loopback");
      }
    },
  );

  test.each(["staging", "production"])(
    "build configuration rejects loopback aliases in %s",
    (environment) => {
      for (const configuredUrl of [
        "https://localhost.",
        "https://foo.localhost.",
        "https://[::ffff:127.0.0.1]",
        "https://[::ffff:7f00:1]",
        "https://[::ffff:0.0.0.0]",
      ]) {
        const result = loadBuildConfiguration(environment, configuredUrl);
        const output = `${result.stdout}${result.stderr}`;

        expect(result.status).not.toBe(0);
        expect(output).toContain("non-loopback HTTPS");
        expect(output).not.toContain(configuredUrl);
      }
    },
  );

  test.each(["local", "test"])(
    "build configuration preserves the no-URL fallback in %s",
    (environment) => {
      expect(loadBuildConfiguration(environment).status).toBe(0);
    },
  );

  test.each(["staging", "production"])(
    "build configuration accepts representative non-loopback hosts in %s",
    (environment) => {
      for (const configuredUrl of [
        "https://api.example.invalid",
        "https://192.0.2.10",
        "https://[2001:db8::10]",
      ]) {
        expect(loadBuildConfiguration(environment, configuredUrl).status).toBe(0);
      }
    },
  );

  test("rejects a backend secret name from public configuration", () => {
    expect(() =>
      validatePublicEnvironment(
        {
          NEXT_PUBLIC_API_BASE_URL: "https://api.example.invalid",
          NEXT_PUBLIC_APP_ENV: "production",
          NEXT_PUBLIC_DATABASE_URL: "synthetic-test-secret",
        },
      ),
    ).toThrow("NEXT_PUBLIC_DATABASE_URL is secret-like");
  });

  test("rejects an unapproved secret-like public variable", () => {
    expect(() =>
      validatePublicEnvironment(
        {
          NEXT_PUBLIC_API_BASE_URL: "https://api.example.invalid",
          NEXT_PUBLIC_APP_ENV: "production",
          NEXT_PUBLIC_VENDOR_TOKEN: "synthetic-test-secret",
        },
      ),
    ).toThrow("NEXT_PUBLIC_VENDOR_TOKEN is secret-like");
  });

  test("returns only the approved public field", () => {
    const publicEnvironment = validatePublicEnvironment(
      {
        NEXT_PUBLIC_API_BASE_URL: "https://api.example.invalid",
        NEXT_PUBLIC_APP_ENV: "production",
        DATABASE_URL: "synthetic-test-secret",
        POSTGRES_PASSWORD: "synthetic-test-secret",
      },
    );

    expect(publicEnvironment).toEqual({
      apiBaseUrl: "https://api.example.invalid",
    });
    expect(JSON.stringify(publicEnvironment)).not.toContain("synthetic-test-secret");
  });

  test("requires the build-injected public environment identity", () => {
    expect(() =>
      validatePublicEnvironment({
        NEXT_PUBLIC_API_BASE_URL: "http://localhost:8000",
      }),
    ).toThrow("NEXT_PUBLIC_APP_ENV");
  });
});
