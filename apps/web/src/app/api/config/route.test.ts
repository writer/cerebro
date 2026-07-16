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

describe("public web config", () => {
  it("rejects requests without a trusted identity", async () => {
    delete process.env.CEREBRO_IDENTITY_PROFILE;
    delete process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;

    const response = await GET(new NextRequest("http://localhost/api/config"));

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({ code: "identity_missing" });
  });

  it("returns only the browser-facing API path to trusted users", async () => {
    delete process.env.CEREBRO_IDENTITY_PROFILE;
    process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = "x-user-email";

    const response = await GET(new NextRequest("http://localhost/api/config", {
      headers: { "x-user-email": "user@example.com" },
    }));
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(payload.apiBase).toBe("/api/cerebro");
    expect(JSON.stringify(payload)).not.toContain("localhost:8080");
  });
});
