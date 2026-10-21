import { afterEach, describe, expect, it, vi } from "vitest";

import {
  canActivate,
  connectionPayload,
  connectionToInput,
  enforcementBlocker,
  identityAdminFetch,
  IdentityAdminError,
  newConnectionDraft,
  parseCertificates,
  parseDomains,
  SECRET_REFERENCE_PATTERN,
  SSO_PROVIDER_PRESETS,
  testLoginHref,
  validateConnectionDraft,
  validatePolicy,
  type SSOConnection,
} from "./sso-admin";

const okta = SSO_PROVIDER_PRESETS[0];
const cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";

const connection = (overrides: Partial<SSOConnection> = {}): SSOConnection => ({
  id: "conn_1",
  name: "Okta",
  protocol: "oidc",
  status: "tested",
  domains: ["example.com"],
  oidc: { issuer: "https://example.okta.com", clientId: "abc", clientSecretRef: "env:OKTA_SECRET", scopes: ["openid"], groupsClaim: "groups", trustEmailClaim: false },
  roleMappings: [],
  defaultRoles: [],
  jitProvisioning: true,
  lastTest: { at: "2026-10-01T00:00:00Z", ok: true, actor: "a@example.com", detail: "" },
  createdAt: "",
  updatedAt: "",
  updatedBy: "",
  ...overrides,
});

describe("secret references", () => {
  it("accepts env and AWS Secrets Manager references only", () => {
    expect(SECRET_REFERENCE_PATTERN.test("env:OKTA_CLIENT_SECRET")).toBe(true);
    expect(SECRET_REFERENCE_PATTERN.test("aws-sm:us-east-1/cerebro/okta#client_secret")).toBe(true);
    expect(SECRET_REFERENCE_PATTERN.test("aws-sm:us-gov-west-1/okta")).toBe(true);
    expect(SECRET_REFERENCE_PATTERN.test("s3cr3t-value")).toBe(false);
    expect(SECRET_REFERENCE_PATTERN.test("env:1BAD")).toBe(false);
    expect(SECRET_REFERENCE_PATTERN.test("aws-sm:okta")).toBe(false);
    expect(SECRET_REFERENCE_PATTERN.test("env:A B")).toBe(false);
  });
});

describe("validateConnectionDraft", () => {
  it("requires OIDC issuer, client, secret reference, and a domain", () => {
    const errors = validateConnectionDraft(newConnectionDraft(okta, "oidc"));
    expect(Object.keys(errors).sort()).toEqual(["clientId", "clientSecretRef", "domains", "issuer"]);
  });

  it("rejects pasted secrets and plain-http issuers", () => {
    const draft = newConnectionDraft(okta, "oidc");
    const errors = validateConnectionDraft({
      ...draft,
      domains: ["example.com"],
      oidc: { ...draft.oidc!, issuer: "http://example.okta.com", clientId: "abc", clientSecretRef: "hunter2" },
    });
    expect(errors.issuer).toBeDefined();
    expect(errors.clientSecretRef).toMatch(/Never paste the secret/);
  });

  it("accepts a complete SAML draft and rejects non-PEM certificates", () => {
    const draft = newConnectionDraft(okta, "saml");
    const complete = {
      ...draft,
      domains: ["example.com"],
      saml: { ...draft.saml!, idpEntityId: "http://www.okta.com/exk1", idpSsoUrl: "https://example.okta.com/sso", idpCertificates: [cert] },
    };
    expect(validateConnectionDraft(complete)).toEqual({});
    expect(validateConnectionDraft({ ...complete, saml: { ...complete.saml, idpCertificates: ["MIIB"] } }).idpCertificates).toBeDefined();
  });

  it("flags invalid domains and incomplete group mappings", () => {
    const draft = newConnectionDraft(okta, "oidc");
    const errors = validateConnectionDraft({ ...draft, domains: ["not a domain"], roleMappings: [{ group: "admins", roles: [] }] });
    expect(errors.domains).toMatch(/not a valid domain/);
    expect(errors.roleMappings).toBeDefined();
  });
});

describe("parsers", () => {
  it("normalizes domains", () => {
    expect(parseDomains("Example.com, @corp.example.com example.com")).toEqual(["example.com", "corp.example.com"]);
  });

  it("splits a PEM bundle into certificates", () => {
    expect(parseCertificates(`${cert}\n\n${cert.replace("MIIB", "MIIC")}`)).toHaveLength(2);
  });
});

describe("connectionPayload", () => {
  it("trims values, drops empty mappings, and strips the issuer's trailing slash", () => {
    const draft = newConnectionDraft(okta, "oidc");
    const payload = connectionPayload({
      ...draft,
      name: " Okta ",
      oidc: { ...draft.oidc!, issuer: "https://example.okta.com/", clientId: " abc ", clientSecretRef: " env:X ", groupsClaim: "" },
      roleMappings: [{ group: " admins ", roles: ["cerebro.admin"] }, { group: "", roles: ["cerebro.viewer"] }],
    });
    expect(payload.name).toBe("Okta");
    expect(payload.oidc).toMatchObject({ issuer: "https://example.okta.com", clientId: "abc", clientSecretRef: "env:X", groupsClaim: "groups" });
    expect(payload.roleMappings).toEqual([{ group: "admins", roles: ["cerebro.admin"] }]);
    expect(payload.saml).toBeUndefined();
  });

  it("defaults trustEmailClaim off and sends it only as an explicit boolean", () => {
    const draft = newConnectionDraft(okta, "oidc");
    expect(draft.oidc?.trustEmailClaim).toBe(false);
    expect(connectionPayload(draft).oidc?.trustEmailClaim).toBe(false);
    expect(connectionPayload({ ...draft, oidc: { ...draft.oidc!, trustEmailClaim: true } }).oidc?.trustEmailClaim).toBe(true);
    const legacy = connection({ oidc: { issuer: "https://example.okta.com", clientId: "abc", clientSecretRef: "env:X", scopes: ["openid"], groupsClaim: "groups" } as SSOConnection["oidc"] });
    expect(connectionToInput(legacy).oidc?.trustEmailClaim).toBe(false);
  });

  it("omits an empty SAML metadata URL", () => {
    const payload = connectionPayload(newConnectionDraft(okta, "saml"));
    expect(payload.saml && "idpMetadataUrl" in payload.saml).toBe(false);
    expect(payload.oidc).toBeUndefined();
  });
});

describe("activation and enforcement", () => {
  it("only activates tested connections", () => {
    expect(canActivate(connection())).toBe(true);
    expect(canActivate(connection({ status: "draft" }))).toBe(false);
    expect(canActivate(connection({ status: "disabled", lastTest: undefined }))).toBe(false);
    expect(canActivate(connection({ status: "active" }))).toBe(false);
  });

  it("locks enforcement until an active connection exists and the admin holds an SSO session", () => {
    expect(enforcementBlocker({ connections: [connection()], currentSource: "sso-session" })).toBe("no_active_connection");
    const active = [connection({ status: "active" })];
    expect(enforcementBlocker({ connections: active, currentSource: "headers" })).toBe("not_signed_in_with_sso");
    expect(
      enforcementBlocker({
        connections: active,
        currentSource: "sso-session",
        status: { enforced: false, breakGlass: false, sessionSecretConfigured: false, publicUrlConfigured: true, activeConnections: 1, legacyIdentityActive: true },
      }),
    ).toBe("session_secret_missing");
    expect(enforcementBlocker({ connections: active, currentSource: "sso-session" })).toBeNull();
  });
});

describe("validatePolicy", () => {
  it("bounds lifetimes and keeps idle within the lifetime", () => {
    expect(validatePolicy({ enforced: false, sessionMaxLifetimeMinutes: 720, sessionIdleTimeoutMinutes: 60 })).toEqual({});
    expect(validatePolicy({ enforced: false, sessionMaxLifetimeMinutes: 5, sessionIdleTimeoutMinutes: 60 }).sessionMaxLifetimeMinutes).toBeDefined();
    expect(validatePolicy({ enforced: false, sessionMaxLifetimeMinutes: 30, sessionIdleTimeoutMinutes: 60 }).sessionIdleTimeoutMinutes).toMatch(/longer/);
  });
});

describe("testLoginHref", () => {
  it("starts a test sign-in that returns to the SSO tab", () => {
    const url = new URL(testLoginHref("conn 1"), "https://cerebro.example.com");
    expect(url.pathname).toBe("/api/auth/sso/test");
    expect(url.searchParams.get("connection")).toBe("conn 1");
    expect(url.searchParams.get("returnTo")).toBe("/admin/access?tab=sso");
  });
});

describe("identityAdminFetch", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("maps API error codes to readable messages", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: "connection_not_tested" }), { status: 409 })));
    await expect(identityAdminFetch("/connections/x", { method: "PUT" })).rejects.toMatchObject({
      code: "connection_not_tested",
      message: "Test sign-in with this connection before turning it on.",
      status: 409,
    });
  });

  it("explains a missing permission", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 403 })));
    const error = await identityAdminFetch("/policy").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(IdentityAdminError);
    expect((error as Error).message).toMatch(/identity:admin/);
  });

  it("sends JSON content type on every write, including bodiless DELETEs", async () => {
    const inits: RequestInit[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
      inits.push(init);
      return new Response(null, { status: 204 });
    }));
    await identityAdminFetch("/connections/x", { method: "DELETE" });
    await identityAdminFetch("/connections");
    const headersOf = (index: number) => inits[index].headers as Record<string, string>;
    expect(headersOf(0)["content-type"]).toBe("application/json");
    expect(headersOf(1)["content-type"]).toBeUndefined();
  });

  it("returns undefined for 204", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204 })));
    await expect(identityAdminFetch("/connections/x", { method: "DELETE" })).resolves.toBeUndefined();
  });
});
