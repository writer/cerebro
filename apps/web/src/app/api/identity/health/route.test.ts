import { NextRequest } from "next/server";
import { afterEach, describe, expect, it } from "vitest";

import { GET } from "./route";

const originalIdentityProfile = process.env.CEREBRO_IDENTITY_PROFILE;
const originalTrustedHeaders = process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;

afterEach(() => {
  if (originalIdentityProfile === undefined) delete process.env.CEREBRO_IDENTITY_PROFILE;
  else process.env.CEREBRO_IDENTITY_PROFILE = originalIdentityProfile;
  if (originalTrustedHeaders === undefined) delete process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;
  else process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = originalTrustedHeaders;
});

describe("identity health", () => {
  it("rejects requests without a trusted identity", async () => {
    delete process.env.CEREBRO_IDENTITY_PROFILE;
    delete process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;

    const response = await GET(new NextRequest("http://localhost/api/identity/health", {
      headers: { "x-user-email": "spoofed@example.com" },
    }));

    expect(response.status).toBe(401);
    const payload = await response.json();
    expect(payload).toMatchObject({ code: "identity_missing" });
    expect(payload).not.toHaveProperty("config");
  });

  it("returns private diagnostics to a trusted user", async () => {
    delete process.env.CEREBRO_IDENTITY_PROFILE;
    process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = "x-user-email";

    const response = await GET(new NextRequest("http://localhost/api/identity/health", {
      headers: { "x-user-email": "user@example.com" },
    }));

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    await expect(response.json()).resolves.toMatchObject({
      current: { authenticated: true },
      config: { trustedHeaders: ["x-user-email"] },
    });
  });
});
