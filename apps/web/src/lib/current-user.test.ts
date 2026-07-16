import { createSign, generateKeyPairSync } from "crypto";
import type { KeyObject } from "crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  clearIdentityJwksCache,
  currentUserActor,
  currentUserActorLabel,
  currentUserAuditFields,
  currentUserFromHeaders,
  currentUserFromHeadersWithFallback,
  currentUserSourceLabel,
  identityHealthFromHeaders,
  identityPosture,
  identityRuntimeConfig,
  localCurrentUserFallback,
  resolveCurrentUserFromHeaders,
  type CurrentUser,
} from "./identity";
import cloudflareAccessFixture from "./fixtures/identity/cloudflare-access.json";
import localIdentityFixture from "./fixtures/identity/local.json";
import oktaProxyFixture from "./fixtures/identity/okta-proxy.json";

const identityEnvNames = [
  "CEREBRO_IDENTITY_AUDIENCE",
  "CEREBRO_IDENTITY_ISSUER",
  "CEREBRO_IDENTITY_JWKS_URL",
  "CEREBRO_IDENTITY_PROFILE",
  "CEREBRO_IDENTITY_REQUIRED",
  "CEREBRO_LOCAL_IDENTITY_FALLBACK",
  "CEREBRO_TRUSTED_IDENTITY_HEADERS",
];

const originalIdentityEnv = new Map(identityEnvNames.map((name) => [name, process.env[name]]));

afterEach(() => {
  for (const name of identityEnvNames) {
    const original = originalIdentityEnv.get(name);
    if (original === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = original;
    }
  }
  clearIdentityJwksCache();
  vi.restoreAllMocks();
});

const base64Json = (payload: Record<string, unknown>) => {
  const encoder = new TextEncoder();
  return globalThis.btoa(String.fromCharCode(...encoder.encode(JSON.stringify(payload))));
};

const base64UrlJson = (payload: Record<string, unknown>) =>
  base64Json(payload)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const jwtWithPayload = (payload: Record<string, unknown>) => {
  return `${base64UrlJson({ alg: "none", typ: "JWT" })}.${base64UrlJson(payload)}.c2lnbmF0dXJl`;
};

const signedJwtWithPayload = (payload: Record<string, unknown>, privateKey: KeyObject, kid = "test-key") => {
  const input = `${base64UrlJson({ alg: "RS256", kid, typ: "JWT" })}.${base64UrlJson(payload)}`;
  const signature = createSign("RSA-SHA256").update(input).end().sign(privateKey, "base64url");
  return `${input}.${signature}`;
};

const headersFromFixture = (fixture: {
  headers: Record<string, string>;
  jwtHeader?: string;
  jwtPayload?: Record<string, unknown>;
}) => {
  const headers = new Headers(fixture.headers);
  if (fixture.jwtHeader && fixture.jwtPayload) {
    headers.set(fixture.jwtHeader, jwtWithPayload(fixture.jwtPayload));
  }
  return headers;
};

const applyEnv = (env: Record<string, string>) => {
  for (const [key, value] of Object.entries(env)) {
    process.env[key] = value;
  }
};

describe("current user identity", () => {
  it("uses direct Okta or auth proxy headers first", () => {
    const user = currentUserFromHeaders(new Headers({
      "x-okta-email": "person@example.com",
      "x-okta-name": "Example Person",
      "x-okta-user": "person",
    }));

    expect(user).toMatchObject({
      actorId: "person@example.com",
      actorLabel: "person@example.com",
      confidence: "trusted-proxy",
      displayName: "Example Person",
      email: "person@example.com",
      initials: "EP",
      provider: "okta",
      username: "person",
      source: "headers",
    });
    expect(currentUserActor(user)).toBe("person@example.com");
    expect(currentUserActorLabel(user)).toBe("person@example.com");
  });

  it("derives useful initials from email-only identities", () => {
    const user = currentUserFromHeaders(new Headers({
      "x-okta-email": "First.Last+dev@Example.COM",
    }));

    expect(user).toMatchObject({
      actorId: "first.last+dev@example.com",
      actorLabel: "first.last+dev@example.com",
      confidence: "trusted-proxy",
      email: "first.last+dev@example.com",
      initials: "FL",
      username: "first.last+dev@example.com",
      source: "headers",
    });
    expect(currentUserActor(user)).toBe("first.last+dev@example.com");
  });

  it("promotes email-shaped auth usernames into email and username fields", () => {
    const user = currentUserFromHeaders(new Headers({
      "x-auth-request-user": "Session.User@Example.COM",
    }));

    expect(user).toMatchObject({
      actorId: "session.user@example.com",
      actorLabel: "session.user@example.com",
      confidence: "trusted-proxy",
      displayName: "Session.User@Example.COM",
      email: "session.user@example.com",
      initials: "SU",
      username: "Session.User@Example.COM",
      source: "headers",
    });
    expect(currentUserActor(user)).toBe("session.user@example.com");
  });

  it("extracts Cloudflare Access identities backed by Okta", () => {
    const user = currentUserFromHeaders(new Headers({
      "cf-access-authenticated-user-email": "okta.person@example.com",
      "cf-access-jwt-assertion": jwtWithPayload({
        email: "okta.person@example.com",
        name: "Okta Person",
        sub: "okta-subject",
      }),
    }));

    expect(user).toMatchObject({
      actorId: "okta-subject",
      actorLabel: "okta.person@example.com",
      confidence: "trusted-proxy",
      displayName: "Okta Person",
      email: "okta.person@example.com",
      initials: "OP",
      provider: "cloudflare-access",
      subject: "okta-subject",
      username: "okta.person@example.com",
      source: "headers",
    });
    expect(user?.evidence?.headers).toContain("cf-access-authenticated-user-email");
    expect(user?.evidence?.claims).toContain("sub");
    expect(currentUserActor(user)).toBe("okta-subject");
  });

  it("sanitizes identity strings from headers", () => {
    const unsafeName = ` Example\u0000 Person ${"x".repeat(200)}`;
    const unsafeEmail = "\u0000person@example.com\u0007";
    const user = currentUserFromHeaders(new Headers({
      "x-okta-name": encodeURIComponent(unsafeName),
      "x-okta-email": encodeURIComponent(unsafeEmail),
    }));

    expect(user?.displayName).toMatch(/^Example Person x+/);
    expect(user?.displayName).toHaveLength(160);
    expect(user?.displayName).not.toContain("\u0000");
    expect(user?.email).toBe("person@example.com");
  });

  it("extracts the current user from Azure client-principal headers", () => {
    const user = currentUserFromHeaders(new Headers({
      "x-ms-client-principal": base64Json({
        userDetails: "azure.person@example.com",
        userId: "azure-subject",
        claims: [
          { typ: "name", val: "Azure Person" },
          { typ: "preferred_username", val: "azure.person" },
        ],
      }),
    }));

    expect(user).toMatchObject({
      actorId: "azure-subject",
      actorLabel: "azure.person@example.com",
      confidence: "trusted-proxy",
      displayName: "Azure Person",
      email: "azure.person@example.com",
      initials: "AP",
      provider: "azure",
      subject: "azure-subject",
      username: "azure.person",
      source: "azure-client-principal",
    });
    expect(currentUserActor(user)).toBe("azure-subject");
  });

  it("extracts the current user from ALB OIDC claim headers", () => {
    const user = currentUserFromHeaders(new Headers({
      "x-amzn-oidc-data": jwtWithPayload({
        email: "alex.example@example.com",
        name: "Alex Example",
        preferred_username: "alex.example",
        sub: "00u123",
      }),
    }));

    expect(user).toMatchObject({
      actorId: "00u123",
      actorLabel: "alex.example@example.com",
      confidence: "trusted-proxy",
      displayName: "Alex Example",
      email: "alex.example@example.com",
      initials: "AE",
      provider: "alb-oidc",
      subject: "00u123",
      username: "alex.example",
      source: "jwt",
    });
    expect(currentUserActor(user)).toBe("00u123");
  });

  it("falls back to bearer JWT claims", () => {
    const user = currentUserFromHeaders(new Headers({
      authorization: `Bearer ${jwtWithPayload({
        email: "local.user@example.com",
        preferred_username: "local.user",
        given_name: "Local",
        family_name: "User",
      })}`,
    }));

    expect(user).toMatchObject({
      actorId: "local.user@example.com",
      actorLabel: "local.user@example.com",
      confidence: "unverified",
      displayName: "Local User",
      email: "local.user@example.com",
      initials: "LU",
      provider: "bearer-jwt",
      username: "local.user",
      source: "jwt",
    });
  });

  it("promotes email-shaped JWT preferred usernames when email is absent", () => {
    const user = currentUserFromHeaders(new Headers({
      "cf-access-jwt-assertion": jwtWithPayload({
        preferred_username: "okta.jwt@example.com",
        name: "JWT User",
        sub: "okta-jwt-subject",
      }),
    }));

    expect(user).toMatchObject({
      actorId: "okta-jwt-subject",
      actorLabel: "okta.jwt@example.com",
      confidence: "trusted-proxy",
      displayName: "JWT User",
      email: "okta.jwt@example.com",
      initials: "JU",
      provider: "cloudflare-access",
      subject: "okta-jwt-subject",
      username: "okta.jwt@example.com",
      source: "jwt",
    });
    expect(currentUserActor(user)).toBe("okta-jwt-subject");
  });

  it("validates configured JWT issuer and audience claims without overstating signature verification", () => {
    const previousIssuer = process.env.CEREBRO_IDENTITY_ISSUER;
    const previousAudience = process.env.CEREBRO_IDENTITY_AUDIENCE;
    process.env.CEREBRO_IDENTITY_ISSUER = "https://login.example.com/oauth2/default";
    process.env.CEREBRO_IDENTITY_AUDIENCE = "cerebro-web";
    try {
      const user = currentUserFromHeaders(new Headers({
        authorization: `Bearer ${jwtWithPayload({
          aud: "cerebro-web",
          email: "claims.user@example.com",
          exp: Math.floor(Date.now() / 1000) + 60,
          iss: "https://login.example.com/oauth2/default",
          name: "Claims User",
          sub: "claims-subject",
        })}`,
      }));

      expect(user).toMatchObject({
        actorId: "claims-subject",
        confidence: "claims-validated",
        provider: "bearer-jwt",
      });
      expect(user?.warnings).toBeUndefined();
      expect(user?.evidence?.jwt?.issuer).toBe("https://login.example.com/oauth2/default");
      expect(user?.evidence?.jwt?.audience).toBe("cerebro-web");
    } finally {
      if (previousIssuer === undefined) {
        delete process.env.CEREBRO_IDENTITY_ISSUER;
      } else {
        process.env.CEREBRO_IDENTITY_ISSUER = previousIssuer;
      }
      if (previousAudience === undefined) {
        delete process.env.CEREBRO_IDENTITY_AUDIENCE;
      } else {
        process.env.CEREBRO_IDENTITY_AUDIENCE = previousAudience;
      }
    }
  });

  it("extracts groups, roles, and scopes from identity claims", () => {
    const user = currentUserFromHeaders(new Headers({
      authorization: `Bearer ${jwtWithPayload({
        email: "entitled.user@example.com",
        groups: ["security", "grc"],
        roles: "admin analyst",
        scope: "controls:read evidence:write",
        sub: "entitled-subject",
      })}`,
    }));

    expect(user).toMatchObject({
      actorId: "entitled-subject",
      entitlements: {
        groups: ["security", "grc"],
        roles: ["admin", "analyst"],
        scopes: ["controls:read", "evidence:write"],
      },
    });
    expect(user?.evidence?.claims).toEqual(expect.arrayContaining(["groups", "roles", "scope"]));
  });

  it("flags conflicting direct and token identity signals", () => {
    const user = currentUserFromHeaders(new Headers({
      "x-okta-email": "alice@example.com",
      "x-okta-id-token": jwtWithPayload({
        email: "bob@example.com",
        name: "Bob Example",
        sub: "bob-subject",
      }),
    }));

    expect(user).toMatchObject({
      actorId: "alice@example.com",
      confidence: "conflict",
      email: "alice@example.com",
      provider: "okta",
    });
    expect(user?.conflicts?.join(" ")).toContain("alice@example.com");
    expect(user?.conflicts?.join(" ")).toContain("bob@example.com");
  });

  it("honors configured trusted identity header allowlists", () => {
    const previous = process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;
    process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = "x-okta-email";
    try {
      const user = currentUserFromHeaders(new Headers({
        "x-okta-email": "trusted@example.com",
        "x-user-email": "spoofed@example.com",
      }));

      expect(user).toMatchObject({
        actorId: "trusted@example.com",
        email: "trusted@example.com",
        provider: "okta",
      });
      expect(user?.evidence?.headers).toEqual(["x-okta-email"]);
    } finally {
      if (previous === undefined) {
        delete process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;
      } else {
        process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = previous;
      }
    }
  });

  it("honors deployment profile identity fixtures", () => {
    for (const fixture of [oktaProxyFixture, cloudflareAccessFixture]) {
      applyEnv(fixture.env);
      const user = currentUserFromHeaders(headersFromFixture(fixture));
      expect(user).toMatchObject(fixture.expected);
    }
  });

  it("keeps bearer tokens out of proxy-header profiles unless explicitly allowed", () => {
    process.env.CEREBRO_IDENTITY_PROFILE = "okta-proxy";
    const user = currentUserFromHeaders(new Headers({
      authorization: `Bearer ${jwtWithPayload({
        email: "bearer.user@example.com",
        sub: "bearer-subject",
      })}`,
      "x-user-email": "spoofed@example.com",
    }));

    expect(user).toBeNull();
  });

  it("uses configured JWKS to verify bearer JWT signatures", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const publicJwk = publicKey.export({ format: "jwk" });
    process.env.CEREBRO_IDENTITY_PROFILE = "oidc-bearer";
    process.env.CEREBRO_IDENTITY_ISSUER = "https://login.example.com/oauth2/default";
    process.env.CEREBRO_IDENTITY_AUDIENCE = "cerebro-web";
    process.env.CEREBRO_IDENTITY_JWKS_URL = "https://login.example.com/oauth2/default/v1/keys";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      keys: [{ ...publicJwk, alg: "RS256", kid: "test-key", use: "sig" }],
    })));

    const user = await resolveCurrentUserFromHeaders(new Headers({
      authorization: `Bearer ${signedJwtWithPayload({
        aud: "cerebro-web",
        email: "signed.user@example.com",
        exp: Math.floor(Date.now() / 1000) + 60,
        iss: "https://login.example.com/oauth2/default",
        name: "Signed User",
        sub: "signed-subject",
      }, privateKey)}`,
    }));

    expect(user).toMatchObject({
      actorId: "signed-subject",
      confidence: "signature-verified",
      provider: "bearer-jwt",
    });
    expect(user?.warnings).toBeUndefined();
    expect(user?.evidence?.jwt).toMatchObject({
      algorithm: "RS256",
      keyId: "test-key",
      signature: "verified",
    });
  });

  it("downgrades JWT identity when JWKS signature verification fails", async () => {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const { privateKey: otherPrivateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const publicJwk = publicKey.export({ format: "jwk" });
    process.env.CEREBRO_IDENTITY_PROFILE = "oidc-bearer";
    process.env.CEREBRO_IDENTITY_JWKS_URL = "https://login.example.com/oauth2/default/v1/keys";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      keys: [{ ...publicJwk, alg: "RS256", kid: "test-key", use: "sig" }],
    })));

    const user = await resolveCurrentUserFromHeaders(new Headers({
      authorization: `Bearer ${signedJwtWithPayload({
        email: "signed.user@example.com",
        name: "Signed User",
        sub: "signed-subject",
      }, otherPrivateKey)}`,
    }));

    expect(user).toMatchObject({
      actorId: "signed-subject",
      confidence: "unverified",
    });
    expect(user?.warnings).toContain("signature-invalid");
    expect(user?.evidence?.jwt?.signature).toBe("failed");
  });

  it("returns null when no current-user signal is available", () => {
    expect(currentUserFromHeaders(new Headers())).toBeNull();
  });

  it("uses a stable local fallback only when explicitly enabled", () => {
    const previous = process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK;
    process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK = "1";
    try {
      expect(currentUserFromHeadersWithFallback(new Headers())).toMatchObject({
        actorId: "local-developer",
        confidence: "fallback",
        displayName: "Local developer",
        initials: "LD",
        provider: "local",
        username: "local-developer",
        source: "local-fallback",
      });
      expect(currentUserActor(localCurrentUserFallback())).toBe("local-developer");
      expect(currentUserSourceLabel("local-fallback")).toBe("Local fallback");
    } finally {
      if (previous === undefined) {
        delete process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK;
      } else {
        process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK = previous;
      }
    }
  });

  it("uses the local identity fixture for local development fallback", () => {
    applyEnv(localIdentityFixture.env);

    expect(currentUserFromHeadersWithFallback(headersFromFixture(localIdentityFixture))).toMatchObject(localIdentityFixture.expected);
    expect(identityRuntimeConfig()).toMatchObject({
      fallbackEnabled: true,
      profile: "local",
    });
  });

  it("reports blocked identity health when fail-closed mode has no current user", async () => {
    process.env.CEREBRO_IDENTITY_REQUIRED = "1";

    await expect(identityHealthFromHeaders(new Headers())).resolves.toMatchObject({
      config: {
        required: true,
      },
      current: {
        authenticated: false,
        confidence: "none",
      },
      issues: ["identity-missing"],
      status: "blocked",
    });
  });

  it("uses the most stable available actor identifier", () => {
    const baseUser = {
      actorId: "subject-123",
      actorLabel: "display.user",
      confidence: "trusted-proxy",
      displayName: "Display User",
      initials: "DU",
      source: "headers",
      subject: "subject-123",
      username: "display.user",
    } satisfies CurrentUser;

    expect(currentUserActor({ ...baseUser, email: "display.user@example.com" })).toBe("subject-123");
    expect(currentUserActor(baseUser)).toBe("subject-123");
    expect(currentUserActorLabel({ ...baseUser, email: "display.user@example.com", actorLabel: "display.user@example.com" })).toBe("display.user@example.com");
    expect(currentUserActor({ ...baseUser, actorId: "", subject: undefined })).toBe("display.user");
    expect(currentUserActor({ ...baseUser, actorId: "", displayName: "", subject: undefined, username: undefined })).toBe("");
  });

  it("summarizes identity posture for product UI", () => {
    expect(identityPosture({ loading: true, user: null })).toMatchObject({
      label: "Resolving identity",
      state: "loading",
      tone: "neutral",
    });

    expect(identityPosture({ user: localCurrentUserFallback() })).toMatchObject({
      actor: "local-developer",
      displayName: "Local developer",
      label: "Local identity",
      sourceLabel: "Local fallback",
      state: "fallback",
      tone: "warning",
    });

    expect(identityPosture({
      user: {
        actorId: "subject-1",
        actorLabel: "person@example.com",
        confidence: "unverified",
        displayName: "Person Example",
        initials: "PE",
        source: "jwt",
        subject: "subject-1",
      },
    })).toMatchObject({
      actor: "subject-1",
      label: "Unverified claims",
      tone: "warning",
    });

    expect(identityPosture({ error: "missing headers", user: null })).toMatchObject({
      detail: "missing headers",
      label: "Identity unavailable",
      state: "unavailable",
    });
  });

  it("summarizes identity telemetry without raw actor values", () => {
    expect(currentUserAuditFields({
      actorId: "subject-1",
      actorLabel: "person@example.com",
      confidence: "conflict",
      conflicts: ["email mismatch"],
      displayName: "Person Example",
      entitlements: { groups: ["security"], scopes: ["controls:read"] },
      evidence: { claims: ["email", "groups"], headers: ["x-okta-email"] },
      initials: "PE",
      provider: "okta",
      source: "headers",
      warnings: ["issuer-mismatch"],
    })).toEqual({
      authenticated: true,
      claimCount: 2,
      confidence: "conflict",
      conflictCount: 1,
      groupCount: 1,
      headerCount: 1,
      provider: "okta",
      roleCount: 0,
      scopeCount: 1,
      source: "headers",
      warningCount: 1,
    });
  });
});
