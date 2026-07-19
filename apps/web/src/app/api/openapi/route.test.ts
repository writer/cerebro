import { NextRequest } from "next/server";
import { afterEach, describe, expect, it } from "vitest";

import { GET, parseOpenApiDocument } from "./route";

const originalFixtureMode = process.env.CEREBRO_WEB_FIXTURE_MODE;
const originalIdentityProfile = process.env.CEREBRO_IDENTITY_PROFILE;
const originalTrustedHeaders = process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;

afterEach(() => {
  if (originalFixtureMode === undefined) delete process.env.CEREBRO_WEB_FIXTURE_MODE;
  else process.env.CEREBRO_WEB_FIXTURE_MODE = originalFixtureMode;
  if (originalIdentityProfile === undefined) delete process.env.CEREBRO_IDENTITY_PROFILE;
  else process.env.CEREBRO_IDENTITY_PROFILE = originalIdentityProfile;
  if (originalTrustedHeaders === undefined) delete process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;
  else process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = originalTrustedHeaders;
});

describe("OpenAPI document parsing", () => {
  it("returns a parsed document for valid YAML", () => {
    expect(parseOpenApiDocument("openapi: 3.1.0\ninfo:\n  title: Cerebro\n  version: 1.0.0\n")).toMatchObject({
      openapi: "3.1.0",
    });
  });

  it("rejects malformed and non-document YAML", () => {
    expect(parseOpenApiDocument("openapi: [unterminated")).toBeNull();
    expect(parseOpenApiDocument("plain scalar")).toBeNull();
  });

  it("rejects schema requests without a trusted identity", async () => {
    delete process.env.CEREBRO_IDENTITY_PROFILE;
    delete process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;

    const response = await GET(new NextRequest("http://localhost/api/openapi"));

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      code: "identity_missing",
      permission: "cerebro:read",
    });
  });

  it("returns the fixture schema to a trusted reader", async () => {
    process.env.CEREBRO_WEB_FIXTURE_MODE = "1";
    delete process.env.CEREBRO_IDENTITY_PROFILE;
    process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = "x-user-email";

    const response = await GET(new NextRequest("http://localhost/api/openapi", {
      headers: { "x-user-email": "user@example.com" },
    }));

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ openapi: "3.1.0" });
  });
});
