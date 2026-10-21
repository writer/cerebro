import { afterEach, describe, expect, it } from "vitest";

import { oidcCallbackPath, publicOrigin, ssoBreakGlassEnabled, ssoRequired, ssoRoutes } from "./config";
import { isSameOriginRequest } from "./http";
import { sanitizeReturnTo } from "./return-to";
import { computeSessionRoles, connectionAllowsEmail, connectionForEmail, emailDomain } from "./roles";
import { parseSecretRef, resolveSecretRef, SecretRefError, setSecretsManagerFetcherForTests } from "./secret-ref";
import { openTransaction, sealTransaction, TransactionError, TX_TTL_SECONDS, type LoginTransaction } from "./tx";

const envNames = ["CEREBRO_WEB_PUBLIC_URL", "CEREBRO_SSO_TEST_SECRET", "OTHER_SECRET", "CEREBRO_SSO_SECRET_ENV_ALLOWLIST", "CEREBRO_SSO_AWS_SECRET_PREFIXES", "CEREBRO_SSO_OIDC_CALLBACK_PATH", "CEREBRO_SSO_BREAK_GLASS", "CEREBRO_SSO_REQUIRED", "CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS"];
const originalEnv = new Map(envNames.map((name) => [name, process.env[name]]));

afterEach(() => {
  for (const name of envNames) {
    const original = originalEnv.get(name);
    if (original === undefined) delete process.env[name];
    else process.env[name] = original;
  }
  setSecretsManagerFetcherForTests(null);
});

describe("sanitizeReturnTo", () => {
  it("keeps same-origin relative paths with query and hash", () => {
    expect(sanitizeReturnTo("/findings?status=open#top")).toBe("/findings?status=open#top");
    expect(sanitizeReturnTo("/admin/access")).toBe("/admin/access");
  });

  it.each([
    "//evil.example.com/x",
    "/\\evil.example.com",
    "\\\\evil.example.com",
    "https://evil.example.com",
    "javascript:alert(1)",
    "findings",
    "/\tfoo",
    "/ foo",
    "/foo\nbar",
    "/login",
    "/login?returnTo=/x",
    "/api/auth/logout",
    "",
    "/" + "a".repeat(5000),
  ])("rejects %j", (value) => {
    expect(sanitizeReturnTo(value)).toBe("/");
  });

  it("rejects non-strings and supports a fallback", () => {
    expect(sanitizeReturnTo(undefined)).toBe("/");
    expect(sanitizeReturnTo(42, "/home")).toBe("/home");
  });

  it("does not let path normalization escape to a scheme-relative URL", () => {
    expect(sanitizeReturnTo("/./%2F%2Fevil.example.com")).not.toMatch(/^\/\//);
    expect(sanitizeReturnTo("/..//evil.example.com")).toBe("/");
  });
});

describe("secret references", () => {
  it("parses env and aws-sm references", () => {
    expect(parseSecretRef("env:CEREBRO_SSO_OKTA")).toEqual({ kind: "env", name: "CEREBRO_SSO_OKTA" });
    expect(parseSecretRef("aws-sm:us-east-1/cerebro/sso/okta#client_secret")).toEqual({
      kind: "aws-sm",
      region: "us-east-1",
      secretId: "cerebro/sso/okta",
      field: "client_secret",
    });
    expect(parseSecretRef("aws-sm:us-west-2:cerebro/sso/okta")).toEqual({
      kind: "aws-sm",
      region: "us-west-2",
      secretId: "cerebro/sso/okta",
    });
    expect(parseSecretRef("aws-sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:sso-abc")).toMatchObject({
      kind: "aws-sm",
      region: "eu-west-1",
    });
  });

  it.each([
    "",
    "plain-secret",
    "env:",
    "env:BAD-NAME",
    "env:A B",
    "aws-sm:",
    "aws-sm:not a region/x",
    "aws-sm:us-east-1/",
    "aws-sm:us-east-1/x#bad field",
    "aws-sm:arn:aws:iam::123:role/x",
    "file:/etc/passwd",
  ])("rejects %j", (ref) => {
    expect(() => parseSecretRef(ref)).toThrow(SecretRefError);
  });

  it("only resolves env references in the SSO namespace or allowlist", async () => {
    process.env.CEREBRO_SSO_TEST_SECRET = "s3cret";
    process.env.OTHER_SECRET = "server-secret";
    await expect(resolveSecretRef("env:CEREBRO_SSO_TEST_SECRET")).resolves.toBe("s3cret");
    await expect(resolveSecretRef("env:OTHER_SECRET")).rejects.toThrow(/allowed namespace/);
    process.env.CEREBRO_SSO_SECRET_ENV_ALLOWLIST = "OTHER_SECRET";
    await expect(resolveSecretRef("env:OTHER_SECRET")).resolves.toBe("server-secret");
  });

  it("restricts aws-sm ids to configured prefixes and never leaks values in errors", async () => {
    setSecretsManagerFetcherForTests(async () => JSON.stringify({ client_secret: "top-secret-value" }));
    await expect(resolveSecretRef("aws-sm:us-east-1/cerebro/sso/a#client_secret", 1)).rejects.toThrow(/allowed namespace/);
    process.env.CEREBRO_SSO_AWS_SECRET_PREFIXES = "cerebro/sso/";
    await expect(resolveSecretRef("aws-sm:us-east-1/cerebro/sso/a#client_secret", 1)).resolves.toBe("top-secret-value");
    await expect(resolveSecretRef("aws-sm:us-east-1/prod/db#client_secret", 1)).rejects.toThrow(SecretRefError);
    const error = await resolveSecretRef("aws-sm:us-east-1/cerebro/sso/b#missing", 1).catch((err: Error) => err);
    expect(error).toBeInstanceOf(SecretRefError);
    expect(String((error as Error).message)).not.toContain("top-secret-value");
  });
});

describe("login transaction cookie", () => {
  const secret = new TextEncoder().encode("x".repeat(48));
  const tx: LoginTransaction = {
    connectionId: "conn-1",
    state: "state-1",
    nonce: "nonce-1",
    codeVerifier: "verifier",
    returnTo: "/findings",
    test: false,
    createdAt: "2026-01-01T00:00:00Z",
  };

  it("round-trips and is opaque", async () => {
    const sealed = await sealTransaction(tx, secret);
    expect(sealed).not.toContain("state-1");
    await expect(openTransaction(sealed, secret)).resolves.toMatchObject(tx);
  });

  it("rejects tampering and the wrong key", async () => {
    const sealed = await sealTransaction(tx, secret);
    const parts = sealed.split(".");
    parts[3] = parts[3].slice(0, -2) + (parts[3].endsWith("AA") ? "BB" : "AA");
    await expect(openTransaction(parts.join("."), secret)).rejects.toBeInstanceOf(TransactionError);
    await expect(openTransaction(sealed, new TextEncoder().encode("y".repeat(48)))).rejects.toBeInstanceOf(TransactionError);
  });

  it("reports expiry", async () => {
    const issuedAt = 1_800_000_000;
    const sealed = await sealTransaction(tx, secret, issuedAt);
    const error = await openTransaction(sealed, secret, new Date((issuedAt + TX_TTL_SECONDS + 5) * 1000)).catch((err) => err);
    expect(error).toBeInstanceOf(TransactionError);
    expect((error as TransactionError).expired).toBe(true);
  });
});

describe("session roles and domain routing", () => {
  it("unions default and group-mapped roles and drops unknown names", () => {
    const roles = computeSessionRoles(
      {
        defaultRoles: ["viewer", "not-a-real-role"],
        roleMappings: [{ group: "Security-Admins", roles: ["admin"] }, { group: "other", roles: ["cerebro.responder"] }],
      },
      ["security-admins"],
    );
    expect(roles).toContain("viewer");
    expect(roles).toContain("admin");
    expect(roles).not.toContain("cerebro.responder");
    expect(roles).not.toContain("not-a-real-role");
  });

  it("never applies CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS to SSO session roles", () => {
    process.env.CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS = JSON.stringify({ groups: { "security-admins": ["cerebro.admin"] } });
    const roles = computeSessionRoles({ defaultRoles: [], roleMappings: [] }, ["security-admins"]);
    expect(roles).toEqual([]);
  });

  it("matches exact email domains only", () => {
    expect(emailDomain("A@Example.COM")).toBe("example.com");
    expect(emailDomain("@example.com")).toBe("");
    expect(connectionAllowsEmail({ domains: ["example.com"] }, "a@example.com")).toBe(true);
    expect(connectionAllowsEmail({ domains: ["example.com"] }, "a@evil-example.com")).toBe(false);
    expect(connectionAllowsEmail({ domains: ["example.com"] }, "a@sub.example.com")).toBe(false);
  });

  it("routes only to active connections", () => {
    const connections = [
      { id: "draft", status: "draft" as const, domains: ["example.com"] },
      { id: "live", status: "active" as const, domains: ["example.com"] },
    ];
    expect(connectionForEmail(connections, "a@example.com")?.id).toBe("live");
    expect(connectionForEmail(connections, "a@other.com")).toBeNull();
  });
});

describe("public origin and same-origin checks", () => {
  it("never derives the public origin from the request outside development", () => {
    delete process.env.CEREBRO_WEB_PUBLIC_URL;
    expect(publicOrigin("https://attacker.example.com/api/auth/sso/start")).toBeNull();
    process.env.CEREBRO_WEB_PUBLIC_URL = "https://cerebro.example.com/some/path";
    expect(publicOrigin("https://attacker.example.com/api/auth/sso/start")).toBe("https://cerebro.example.com");
    process.env.CEREBRO_WEB_PUBLIC_URL = "http://cerebro.example.com";
    expect(publicOrigin()).toBeNull();
  });

  it("accepts only the configured Origin or a same-origin fetch", () => {
    process.env.CEREBRO_WEB_PUBLIC_URL = "https://cerebro.example.com";
    const post = (headers: Record<string, string>) =>
      new Request("https://cerebro.example.com/api/auth/logout", { method: "POST", headers });
    expect(isSameOriginRequest(post({ origin: "https://cerebro.example.com" }))).toBe(true);
    expect(isSameOriginRequest(post({ origin: "https://evil.example.com" }))).toBe(false);
    expect(isSameOriginRequest(post({ origin: "null" }))).toBe(false);
    expect(isSameOriginRequest(post({ "sec-fetch-site": "same-origin" }))).toBe(true);
    expect(isSameOriginRequest(post({ "sec-fetch-site": "cross-site" }))).toBe(false);
    expect(isSameOriginRequest(post({}))).toBe(false);
  });
});

describe("deployment SSO settings", () => {
  it("uses the ALB callback path only when explicitly selected", () => {
    delete process.env.CEREBRO_SSO_OIDC_CALLBACK_PATH;
    expect(ssoRoutes("https://cerebro.example.com").oidcRedirectUri).toBe("https://cerebro.example.com/api/auth/oidc/callback");
    process.env.CEREBRO_SSO_OIDC_CALLBACK_PATH = "/oauth2/idpresponse";
    expect(ssoRoutes("https://cerebro.example.com").oidcRedirectUri).toBe("https://cerebro.example.com/oauth2/idpresponse");
    process.env.CEREBRO_SSO_OIDC_CALLBACK_PATH = "/somewhere/else";
    expect(oidcCallbackPath()).toBe("/api/auth/oidc/callback");
  });

  it("refuses break-glass when SSO is required by the deployment", () => {
    process.env.CEREBRO_SSO_BREAK_GLASS = "true";
    delete process.env.CEREBRO_SSO_REQUIRED;
    expect(ssoBreakGlassEnabled()).toBe(true);
    process.env.CEREBRO_SSO_REQUIRED = "true";
    expect(ssoRequired()).toBe(true);
    expect(ssoBreakGlassEnabled()).toBe(false);
  });
});
