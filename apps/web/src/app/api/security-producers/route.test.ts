import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { GET } from "./route";

const originalCatalog = process.env.CEREBRO_SECURITY_PRODUCERS_JSON;
const originalReadScopes = process.env.CEREBRO_AUTHZ_READ_SCOPES;
const originalIdentityProfile = process.env.CEREBRO_IDENTITY_PROFILE;
const originalTrustedHeaders = process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;

const restore = (name: string, value: string | undefined) => {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
};

const trustedRequest = () => new NextRequest("http://localhost/api/security-producers", {
  headers: { "x-user-email": "user@example.com" },
});

const encodedJson = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const proxyToken = (claims: Record<string, unknown>) =>
  `${encodedJson({ alg: "none", typ: "JWT" })}.${encodedJson(claims)}.synthetic-signature`;

afterEach(() => {
  restore("CEREBRO_SECURITY_PRODUCERS_JSON", originalCatalog);
  restore("CEREBRO_AUTHZ_READ_SCOPES", originalReadScopes);
  restore("CEREBRO_IDENTITY_PROFILE", originalIdentityProfile);
  restore("CEREBRO_TRUSTED_IDENTITY_HEADERS", originalTrustedHeaders);
  vi.restoreAllMocks();
});

describe("runtime security producer catalog", () => {
  it("rejects requests without a trusted identity", async () => {
    delete process.env.CEREBRO_IDENTITY_PROFILE;
    delete process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;
    process.env.CEREBRO_SECURITY_PRODUCERS_JSON = JSON.stringify([
      { id: "producer-one", label: "Producer One" },
    ]);

    const response = await GET(new NextRequest("http://localhost/api/security-producers"));

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    const body = await response.json();
    expect(body).toMatchObject({ permission: "cerebro:read" });
    expect(JSON.stringify(body)).not.toContain("Producer One");
  });

  it("requires read capability instead of identity access alone", async () => {
    process.env.CEREBRO_IDENTITY_PROFILE = "auth-proxy";
    process.env.CEREBRO_AUTHZ_READ_SCOPES = "cerebro:read";
    process.env.CEREBRO_SECURITY_PRODUCERS_JSON = JSON.stringify([
      { id: "producer-one", label: "Producer One" },
    ]);

    const identityOnly = await GET(new NextRequest("http://localhost/api/security-producers", {
      headers: { "x-auth-request-email": "user@example.com" },
    }));
    const identityOnlyBody = await identityOnly.json();

    const reader = await GET(new NextRequest("http://localhost/api/security-producers", {
      headers: {
        "x-auth-request-email": "user@example.com",
        "x-auth-request-id-token": proxyToken({
          email: "user@example.com",
          scope: "cerebro:read",
          sub: "synthetic-reader",
        }),
      },
    }));

    expect(identityOnly.status).toBe(403);
    expect(identityOnlyBody).toMatchObject({ permission: "cerebro:read" });
    expect(JSON.stringify(identityOnlyBody)).not.toContain("Producer One");
    expect(reader.status).toBe(200);
    await expect(reader.json()).resolves.toEqual({
      producers: [expect.objectContaining({ id: "producer-one" })],
    });
  });

  it("reads and sanitizes the current runtime value for every request", async () => {
    delete process.env.CEREBRO_IDENTITY_PROFILE;
    process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = "x-user-email";
    process.env.CEREBRO_SECURITY_PRODUCERS_JSON = JSON.stringify([
      {
        id: "producer-one",
        label: "First value",
        extra: "not-portable",
        responseActions: [{ id: "OPEN_TICKET", label: "Open ticket", extra: "not-portable" }],
      },
    ]);

    const first = await GET(trustedRequest());
    const firstBody = await first.json();

    process.env.CEREBRO_SECURITY_PRODUCERS_JSON = JSON.stringify([
      { id: "producer-two", label: "Second value" },
    ]);
    const second = await GET(trustedRequest());
    const secondBody = await second.json();

    expect(first.status).toBe(200);
    expect(first.headers.get("cache-control")).toBe("private, no-store");
    expect(firstBody.producers).toEqual([
      expect.objectContaining({ id: "producer-one", label: "First value" }),
    ]);
    expect(secondBody.producers).toEqual([
      expect.objectContaining({ id: "producer-two", label: "Second value" }),
    ]);
    expect(JSON.stringify(firstBody)).not.toContain("not-portable");
  });

  it("returns an empty catalog for malformed input without emitting its value", async () => {
    delete process.env.CEREBRO_IDENTITY_PROFILE;
    process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = "x-user-email";
    process.env.CEREBRO_SECURITY_PRODUCERS_JSON = "malformed-private-marker{";
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);

    const response = await GET(trustedRequest());
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toEqual({ producers: [] });
    expect(JSON.stringify(body)).not.toContain("malformed-private-marker");
    expect(error).not.toHaveBeenCalled();
    expect(warn).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });
});
