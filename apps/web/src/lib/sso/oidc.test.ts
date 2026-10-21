import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { LoginError, type SSOConnection } from "./types";

const ISSUER = "https://idp.example.com";
const ORIGIN = "https://cerebro.example.com";
const CLIENT_ID = "cerebro-web";

const idp = vi.hoisted(() => ({
  idToken: "",
  tokenRequests: [] as URLSearchParams[],
  jwks: { keys: [] as unknown[] },
}));

vi.mock("./safe-fetch", async (importOriginal) => {
  const original = await importOriginal<typeof import("./safe-fetch")>();
  return {
    ...original,
    safeFetch: vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.href === `${ISSUER}/token`) {
        idp.tokenRequests.push(new URLSearchParams(String(init?.body ?? "")));
        return Response.json({ access_token: "at", token_type: "Bearer", id_token: idp.idToken, expires_in: 300 });
      }
      if (url.href === `${ISSUER}/jwks`) return Response.json(idp.jwks);
      return new Response("not found", { status: 404 });
    }),
  };
});

const { finishOidcLogin, setOidcDiscoveryForTests } = await import("./oidc");

let signingKey: CryptoKey;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256");
  signingKey = pair.privateKey;
  idp.jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" }] };
});

const originalSecret = process.env.CEREBRO_SSO_TEST_CLIENT_SECRET;

beforeEach(() => {
  process.env.CEREBRO_SSO_TEST_CLIENT_SECRET = "client-secret";
  idp.tokenRequests = [];
  setOidcDiscoveryForTests(async () => ({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    jwks_uri: `${ISSUER}/jwks`,
    id_token_signing_alg_values_supported: ["RS256"],
  }));
});

afterEach(() => {
  if (originalSecret === undefined) delete process.env.CEREBRO_SSO_TEST_CLIENT_SECRET;
  else process.env.CEREBRO_SSO_TEST_CLIENT_SECRET = originalSecret;
});

const connection: SSOConnection = {
  id: "conn-oidc",
  name: "Example OIDC",
  protocol: "oidc",
  status: "active",
  domains: ["example.com"],
  oidc: {
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecretRef: "env:CEREBRO_SSO_TEST_CLIENT_SECRET",
    scopes: ["openid", "email", "profile"],
    groupsClaim: "groups",
  },
  roleMappings: [],
  defaultRoles: [],
  jitProvisioning: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  updatedBy: "test",
};

const checks = { state: "expected-state", nonce: "expected-nonce", codeVerifier: "v".repeat(43) };

const issueIdToken = async (claims: Record<string, unknown> = {}, key: CryptoKey | Uint8Array = signingKey, alg = "RS256") =>
  new SignJWT({
    iss: ISSUER,
    aud: CLIENT_ID,
    email: "Jane.Doe@Example.com",
    email_verified: true,
    name: "Jane Doe",
    groups: ["security"],
    nonce: checks.nonce,
    ...claims,
  })
    .setProtectedHeader({ alg, kid: "k1" })
    .setSubject("jane-subject")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(key);

const loginErrorCode = async (promise: Promise<unknown>) => {
  const error = await promise.then(() => null, (err: unknown) => err);
  expect(error).toBeInstanceOf(LoginError);
  return (error as LoginError).code;
};

describe("finishOidcLogin", () => {
  it("exchanges the code with PKCE and returns the verified identity", async () => {
    idp.idToken = await issueIdToken();
    const identity = await finishOidcLogin(connection, ORIGIN, "?code=abc&state=expected-state", checks);
    expect(identity).toEqual({ subject: "jane-subject", email: "jane.doe@example.com", name: "Jane Doe", groups: ["security"] });
    expect(idp.tokenRequests[0].get("code_verifier")).toBe(checks.codeVerifier);
    expect(idp.tokenRequests[0].get("redirect_uri")).toBe(`${ORIGIN}/api/auth/oidc/callback`);
  });

  it("rejects a state mismatch before calling the token endpoint", async () => {
    idp.idToken = await issueIdToken();
    expect(await loginErrorCode(finishOidcLogin(connection, ORIGIN, "?code=abc&state=attacker-state", checks))).toBe("invalid_response");
    expect(idp.tokenRequests).toHaveLength(0);
  });

  it("rejects a nonce mismatch", async () => {
    idp.idToken = await issueIdToken({ nonce: "replayed-nonce" });
    expect(await loginErrorCode(finishOidcLogin(connection, ORIGIN, "?code=abc&state=expected-state", checks))).toBe("invalid_response");
  });

  it("rejects ID tokens signed by an unknown key or with a shared-secret algorithm", async () => {
    const other = await generateKeyPair("RS256");
    idp.idToken = await issueIdToken({}, other.privateKey);
    expect(await loginErrorCode(finishOidcLogin(connection, ORIGIN, "?code=abc&state=expected-state", checks))).toBe("invalid_response");
    idp.idToken = await issueIdToken({}, new TextEncoder().encode("client-secret".padEnd(32, "x")), "HS256");
    expect(await loginErrorCode(finishOidcLogin(connection, ORIGIN, "?code=abc&state=expected-state", checks))).toBe("invalid_response");
  });

  it("rejects tokens for another audience", async () => {
    idp.idToken = await issueIdToken({ aud: "someone-else" });
    expect(await loginErrorCode(finishOidcLogin(connection, ORIGIN, "?code=abc&state=expected-state", checks))).toBe("invalid_response");
  });

  it("refuses unverified email addresses", async () => {
    idp.idToken = await issueIdToken({ email_verified: false });
    expect(await loginErrorCode(finishOidcLogin(connection, ORIGIN, "?code=abc&state=expected-state", checks))).toBe("access_denied");
  });

  it.each([
    ["absent", undefined],
    ["null", null],
    ["the string true", "true"],
    ["the string false", "false"],
    ["a number", 1],
  ])("requires email_verified to be boolean true (%s)", async (_label, value) => {
    idp.idToken = await issueIdToken({ email_verified: value });
    expect(await loginErrorCode(finishOidcLogin(connection, ORIGIN, "?code=abc&state=expected-state", checks))).toBe("access_denied");
  });

  it("accepts an unverified email claim only when the connection trusts the IdP for email", async () => {
    const trusting: SSOConnection = { ...connection, oidc: { ...connection.oidc!, trustEmailClaim: true } };
    idp.idToken = await issueIdToken({ email_verified: undefined });
    await expect(finishOidcLogin(trusting, ORIGIN, "?code=abc&state=expected-state", checks)).resolves.toMatchObject({
      email: "jane.doe@example.com",
    });
  });

  it("maps an IdP access_denied error", async () => {
    expect(await loginErrorCode(finishOidcLogin(connection, ORIGIN, "?error=access_denied&state=expected-state", checks))).toBe("access_denied");
  });
});
