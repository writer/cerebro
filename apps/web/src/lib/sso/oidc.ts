import * as client from "openid-client";

import { isDevelopment, ssoRoutes } from "./config";
import { safeFetch, UnsafeUrlError } from "./safe-fetch";
import { resolveSecretRef, SecretRefError } from "./secret-ref";
import { LoginError, type AssertedIdentity, type SSOConnection, type SSOOidcConfig } from "./types";

const DISCOVERY_TTL_MS = 10 * 60_000;
const OIDC_FETCH_TIMEOUT_MS = 10_000;
const OIDC_FETCH_MAX_BYTES = 1024 * 1024;

/** Asymmetric algorithms only: no `none`, no HS* (a shared-secret MAC would let the client forge ID tokens). */
export const ALLOWED_ID_TOKEN_ALGS = ["RS256", "ES256", "PS256", "RS384", "ES384", "PS384", "RS512", "ES512", "PS512", "EdDSA"] as const;

export const oidcFetch: client.CustomFetch = (url, options) =>
  safeFetch(url, options as RequestInit, { timeoutMs: OIDC_FETCH_TIMEOUT_MS, maxBytes: OIDC_FETCH_MAX_BYTES });

const insecureAllowed = (issuer: string) => {
  if (!isDevelopment()) return false;
  try {
    return new URL(issuer).protocol === "http:";
  } catch {
    return false;
  }
};

type CachedMetadata = { metadata: client.ServerMetadata; fetchedAt: number };
const discoveryCache = new Map<string, CachedMetadata>();
const discoveryInflight = new Map<string, Promise<client.ServerMetadata>>();

export const clearOidcDiscoveryCache = () => {
  discoveryCache.clear();
  discoveryInflight.clear();
};

let discoveryImpl = async (issuer: string): Promise<client.ServerMetadata> => {
  const config = await client.discovery(new URL(issuer), "cerebro-discovery", undefined, client.None(), {
    [client.customFetch]: oidcFetch,
    timeout: OIDC_FETCH_TIMEOUT_MS / 1000,
    ...(insecureAllowed(issuer) ? { execute: [client.allowInsecureRequests] } : {}),
  });
  return { ...config.serverMetadata() };
};

export const setOidcDiscoveryForTests = (impl: ((issuer: string) => Promise<client.ServerMetadata>) | null) => {
  clearOidcDiscoveryCache();
  if (impl) discoveryImpl = impl;
};

/** Discovery document for an issuer, cached for 10 minutes per issuer. */
export const discoverIssuer = async (issuer: string, nowMs = Date.now()): Promise<client.ServerMetadata> => {
  const cached = discoveryCache.get(issuer);
  if (cached && nowMs - cached.fetchedAt < DISCOVERY_TTL_MS) return cached.metadata;
  let inflight = discoveryInflight.get(issuer);
  if (!inflight) {
    inflight = discoveryImpl(issuer)
      .then((metadata) => {
        discoveryCache.set(issuer, { metadata, fetchedAt: nowMs });
        return metadata;
      })
      .finally(() => discoveryInflight.delete(issuer));
    discoveryInflight.set(issuer, inflight);
  }
  return inflight;
};

export const chooseIdTokenAlg = (supported: readonly string[] | undefined) => {
  if (!supported || supported.length === 0) return "RS256";
  const alg = ALLOWED_ID_TOKEN_ALGS.find((candidate) => supported.includes(candidate));
  if (!alg) throw new LoginError("misconfigured", "The identity provider does not offer an allowed ID token signing algorithm.");
  return alg;
};

export const chooseClientAuth = (metadata: client.ServerMetadata, clientSecret: string): client.ClientAuth => {
  const methods = metadata.token_endpoint_auth_methods_supported;
  if (!methods || methods.length === 0 || methods.includes("client_secret_basic")) return client.ClientSecretBasic(clientSecret);
  if (methods.includes("client_secret_post")) return client.ClientSecretPost(clientSecret);
  throw new LoginError("misconfigured", "The identity provider does not support client_secret_basic or client_secret_post.");
};

const configurationFor = (metadata: client.ServerMetadata, oidc: SSOOidcConfig, auth: client.ClientAuth) => {
  const config = new client.Configuration(
    metadata,
    oidc.clientId,
    { id_token_signed_response_alg: chooseIdTokenAlg(metadata.id_token_signing_alg_values_supported) },
    auth,
  );
  config[client.customFetch] = oidcFetch;
  config.timeout = OIDC_FETCH_TIMEOUT_MS / 1000;
  // OIDC Core lets a client trust a token-endpoint ID token on TLS alone, and openid-client does by default.
  // Verifying the signature against the issuer's JWKS as well keeps a misrouted or spoofed token endpoint
  // response from minting identities.
  client.enableNonRepudiationChecks(config);
  if (insecureAllowed(oidc.issuer)) client.allowInsecureRequests(config);
  return config;
};

const requireOidc = (connection: SSOConnection) => {
  if (connection.protocol !== "oidc" || !connection.oidc) {
    throw new LoginError("misconfigured", "Connection is not an OIDC connection.");
  }
  return connection.oidc;
};

const mapSetupError = (error: unknown): never => {
  if (error instanceof LoginError) throw error;
  if (error instanceof SecretRefError || error instanceof UnsafeUrlError) {
    throw new LoginError("misconfigured", error.message);
  }
  throw new LoginError("misconfigured", "The identity provider could not be reached or returned invalid metadata.");
};

export type OidcStart = {
  url: URL;
  state: string;
  nonce: string;
  codeVerifier: string;
};

export const startOidcLogin = async (connection: SSOConnection, origin: string, loginHint?: string): Promise<OidcStart> => {
  const oidc = requireOidc(connection);
  let config: client.Configuration;
  try {
    config = configurationFor(await discoverIssuer(oidc.issuer), oidc, client.None());
  } catch (error) {
    return mapSetupError(error);
  }
  const codeVerifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  const scopes = oidc.scopes?.length ? oidc.scopes : ["openid", "email", "profile"];
  const parameters: Record<string, string> = {
    redirect_uri: ssoRoutes(origin).oidcRedirectUri,
    response_type: "code",
    scope: Array.from(new Set(["openid", ...scopes])).join(" "),
    state,
    nonce,
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: "S256",
  };
  if (loginHint) parameters.login_hint = loginHint;
  return { url: client.buildAuthorizationUrl(config, parameters), state, nonce, codeVerifier };
};

const stringClaim = (value: unknown) => (typeof value === "string" ? value.trim() : "");

export const groupsFromClaim = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    return Array.from(new Set(value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean)));
  }
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return [];
};

export type OidcCallbackChecks = {
  state: string;
  nonce: string;
  codeVerifier: string;
};

/**
 * Exchanges the authorization code and validates the ID token (signature via JWKS, iss, aud, exp, nonce,
 * algorithm allowlist). The callback URL is rebuilt from the configured public origin, never from Host.
 */
export const finishOidcLogin = async (
  connection: SSOConnection,
  origin: string,
  search: string,
  checks: OidcCallbackChecks,
): Promise<AssertedIdentity> => {
  const oidc = requireOidc(connection);
  let config: client.Configuration;
  try {
    const metadata = await discoverIssuer(oidc.issuer);
    const clientSecret = await resolveSecretRef(oidc.clientSecretRef);
    config = configurationFor(metadata, oidc, chooseClientAuth(metadata, clientSecret));
  } catch (error) {
    return mapSetupError(error);
  }
  const currentUrl = new URL(ssoRoutes(origin).oidcRedirectUri);
  currentUrl.search = search;

  let tokens: Awaited<ReturnType<typeof client.authorizationCodeGrant>>;
  try {
    tokens = await client.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: checks.codeVerifier,
      expectedState: checks.state,
      expectedNonce: checks.nonce,
      idTokenExpected: true,
    });
  } catch (error) {
    if (error instanceof client.AuthorizationResponseError && error.error === "access_denied") {
      throw new LoginError("access_denied", "The identity provider denied the sign-in.");
    }
    throw new LoginError("invalid_response", "The identity provider response could not be validated.");
  }
  const claims = tokens.claims();
  if (!claims) throw new LoginError("invalid_response", "The identity provider did not return an ID token.");
  const groupsClaim = oidc.groupsClaim || "groups";

  let email = stringClaim(claims.email);
  let name = stringClaim(claims.name);
  let groups = groupsFromClaim(claims[groupsClaim]);
  let emailVerified = claims.email_verified;

  const metadata = config.serverMetadata();
  if ((!email || groups.length === 0 || !name) && metadata.userinfo_endpoint && tokens.access_token) {
    try {
      const userinfo = await client.fetchUserInfo(config, tokens.access_token, claims.sub);
      if (!email) {
        email = stringClaim(userinfo.email);
        emailVerified = userinfo.email_verified;
      }
      if (!name) name = stringClaim(userinfo.name);
      if (groups.length === 0) groups = groupsFromClaim(userinfo[groupsClaim]);
    } catch {
      // ID token claims are authoritative; userinfo only fills gaps.
    }
  }
  if (!email) throw new LoginError("invalid_response", "The identity provider did not return an email address.");
  if (emailVerified === false) throw new LoginError("access_denied", "The identity provider reports the email address as unverified.");
  if (!name) {
    name = [stringClaim(claims.given_name), stringClaim(claims.family_name)].filter(Boolean).join(" ") || email;
  }
  return { subject: claims.sub, email: email.toLowerCase(), name, groups };
};

/** RP-initiated logout URL (id_token_hint omitted), or null when the IdP does not advertise end_session_endpoint. */
export const oidcEndSessionUrl = async (connection: SSOConnection, origin: string): Promise<string | null> => {
  if (connection.protocol !== "oidc" || !connection.oidc) return null;
  try {
    const metadata = await discoverIssuer(connection.oidc.issuer);
    if (!metadata.end_session_endpoint) return null;
    const config = configurationFor(metadata, connection.oidc, client.None());
    return client.buildEndSessionUrl(config, {
      client_id: connection.oidc.clientId,
      post_logout_redirect_uri: ssoRoutes(origin).loginUrl,
    }).toString();
  } catch {
    return null;
  }
};
