export type CurrentUser = {
  actorId: string;
  actorLabel: string;
  confidence: IdentityConfidence;
  displayName: string;
  initials: string;
  email?: string;
  username?: string;
  subject?: string;
  provider?: IdentityProvider;
  source: "headers" | "jwt" | "azure-client-principal" | "local-fallback";
  entitlements?: IdentityEntitlements;
  evidence?: IdentityEvidence;
  conflicts?: string[];
  warnings?: string[];
};

export type CurrentUserResponse = {
  authenticated: boolean;
  fallback?: boolean;
  user: CurrentUser | null;
};

export type IdentityConfidence =
  | "trusted-proxy"
  | "claims-validated"
  | "signature-verified"
  | "unverified"
  | "conflict"
  | "fallback";

export type IdentityDeploymentProfile =
  | "auto"
  | "auth-proxy"
  | "azure-client-principal"
  | "cloudflare-access"
  | "local"
  | "oidc-bearer"
  | "okta-proxy";

export type IdentityProvider =
  | "alb-oidc"
  | "auth-proxy"
  | "authentik"
  | "azure"
  | "bearer-jwt"
  | "cloudflare-access"
  | "google-iap"
  | "okta"
  | "oauth2-proxy"
  | "local";

export type IdentityEvidence = {
  claims?: string[];
  headers?: string[];
  inferred?: string[];
  jwt?: {
    algorithm?: string;
    audience?: string;
    expiresAt?: string;
    issuer?: string;
    keyId?: string;
    notBefore?: string;
    signature?: "verified" | "unverified" | "failed";
  };
};

export type IdentityEntitlements = {
  groups?: string[];
  roles?: string[];
  scopes?: string[];
};

export type IdentityPosture = {
  actor: string;
  detail: string;
  displayName: string;
  initials: string;
  label: string;
  sourceLabel: string;
  state: "loading" | "resolved" | "fallback" | "unavailable";
  tone: "success" | "warning" | "neutral";
};

export type IdentityRuntimeConfig = {
  audienceConfigured: boolean;
  fallbackEnabled: boolean;
  issuerConfigured: boolean;
  jwksConfigured: boolean;
  profile: IdentityDeploymentProfile;
  required: boolean;
  trustedHeaders: string[];
};

export type IdentityHealth = {
  checkedAt: string;
  config: IdentityRuntimeConfig;
  current: {
    authenticated: boolean;
    claimCount: number;
    confidence: IdentityConfidence | "none";
    conflictCount: number;
    headerCount: number;
    provider: IdentityProvider | "none";
    source: CurrentUser["source"] | "none";
    warningCount: number;
  };
  issues: string[];
  status: "ready" | "degraded" | "blocked";
};

type IdentityClaims = {
  email?: string;
  entitlements?: IdentityEntitlements;
  name?: string;
  subject?: string;
  username?: string;
};

type IdentityCandidate = {
  claims: IdentityClaims;
  confidence: IdentityConfidence;
  evidence: IdentityEvidence;
  provider?: IdentityProvider;
  source: CurrentUser["source"];
  warnings?: string[];
};

type HeaderMatch = {
  name: string;
  value: string;
};

const DISPLAY_NAME_HEADERS = [
  "x-okta-name",
  "x-auth-request-name",
  "x-authentik-name",
  "x-forwarded-name",
  "x-user-display-name",
  "x-user-full-name",
  "x-user-name",
];

const EMAIL_HEADERS = [
  "x-okta-email",
  "x-auth-request-email",
  "x-authentik-email",
  "x-forwarded-user-email",
  "x-forwarded-email",
  "x-user-email",
  "x-email",
  "x-ms-client-principal-name",
  "x-goog-authenticated-user-email",
  "cf-access-authenticated-user-email",
];

const USERNAME_HEADERS = [
  "x-okta-user",
  "x-auth-request-user",
  "x-auth-request-preferred-username",
  "x-authentik-username",
  "x-forwarded-user",
  "x-forwarded-preferred-username",
  "x-remote-user",
  "x-preferred-username",
  "x-user",
  "x-webauth-user",
];

const SUBJECT_HEADERS = [
  "x-amzn-oidc-identity",
  "x-auth-request-subject",
  "x-user-id",
  "x-subject",
];

const JWT_HEADERS = [
  "x-amzn-oidc-data",
  "x-id-token",
  "x-auth-request-id-token",
  "x-okta-id-token",
  "cf-access-jwt-assertion",
];

const cleanString = (value: unknown, maxLength = 160) => {
  if (typeof value !== "string") return "";
  return value.replace(/[\u0000-\u001F\u007F]/g, "").trim().slice(0, maxLength);
};

const firstNonEmpty = (...values: unknown[]) => values.map((value) => cleanString(value)).find(Boolean) ?? "";

const cleanStringList = (value: unknown, separator: RegExp = /[\s,]+/) => {
  if (Array.isArray(value)) return value.map((item) => cleanString(item)).filter(Boolean);
  const cleaned = cleanString(value, 4000);
  if (!cleaned) return [];
  return cleaned.split(separator).map((item) => cleanString(item)).filter(Boolean);
};

const parseBooleanEnv = (value: string | undefined) => {
  if (value === undefined) return undefined;
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return undefined;
};

const IDENTITY_PROFILES = [
  "auto",
  "auth-proxy",
  "azure-client-principal",
  "cloudflare-access",
  "local",
  "oidc-bearer",
  "okta-proxy",
] as const satisfies readonly IdentityDeploymentProfile[];

const identityProfileDefaults: Record<IdentityDeploymentProfile, string[]> = {
  auto: [],
  "auth-proxy": [
    "x-auth-request-email",
    "x-auth-request-id-token",
    "x-auth-request-name",
    "x-auth-request-preferred-username",
    "x-auth-request-subject",
    "x-auth-request-user",
  ],
  "azure-client-principal": ["x-ms-client-principal", "x-ms-client-principal-name"],
  "cloudflare-access": ["cf-access-authenticated-user-email", "cf-access-jwt-assertion"],
  local: [],
  "oidc-bearer": ["authorization"],
  "okta-proxy": [
    "x-okta-email",
    "x-okta-id-token",
    "x-okta-name",
    "x-okta-user",
  ],
};

const configuredIdentityProfile = (): IdentityDeploymentProfile => {
  const configured = cleanString(process.env.CEREBRO_IDENTITY_PROFILE).toLowerCase();
  return IDENTITY_PROFILES.includes(configured as IdentityDeploymentProfile)
    ? configured as IdentityDeploymentProfile
    : "auto";
};

const configuredJwksUrl = () => cleanString(process.env.CEREBRO_IDENTITY_JWKS_URL, 2048);

const looksLikeEmail = (value: string) =>
  /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(value);

const normalizeFederatedHeaderValue = (value: string) => {
  if (value.startsWith("accounts.google.com:")) {
    return value.slice("accounts.google.com:".length);
  }
  return value;
};

const configuredTrustedHeaderNames = () => {
  const explicit = (process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS ?? "")
    .split(",")
    .map((name) => name.trim().toLowerCase())
    .filter(Boolean);
  if (explicit.length > 0) return explicit;
  return identityProfileDefaults[configuredIdentityProfile()];
};

const allowedHeaderNames = (names: string[]) => {
  const trusted = configuredTrustedHeaderNames();
  if (trusted.length === 0) return names;
  const trustedSet = new Set(trusted);
  return names.filter((name) => trustedSet.has(name.toLowerCase()));
};

const identityHeaderAllowed = (name: string) => {
  const trusted = configuredTrustedHeaderNames();
  if (trusted.length === 0) return true;
  return trusted.includes(name.toLowerCase());
};

const firstHeaderMatch = (headers: Headers, names: string[], maxLength = 8000): HeaderMatch | null => {
  for (const name of names) {
    const value = headers.get(name);
    const first = cleanString(value?.split(",")[0], maxLength);
    if (first) return { name, value: normalizeFederatedHeaderValue(first) };
  }
  return null;
};

const firstHeader = (headers: Headers, names: string[], maxLength = 8000) =>
  firstHeaderMatch(headers, names, maxLength)?.value ?? "";

const providerForHeader = (headerNames: string[]): IdentityProvider | undefined => {
  const names = headerNames.map((name) => name.toLowerCase());
  if (names.some((name) => name.startsWith("cf-access-"))) return "cloudflare-access";
  if (names.some((name) => name.startsWith("x-okta-"))) return "okta";
  if (names.some((name) => name.startsWith("x-auth-request-"))) return "oauth2-proxy";
  if (names.some((name) => name.startsWith("x-authentik-"))) return "authentik";
  if (names.some((name) => name.startsWith("x-amzn-oidc-"))) return "alb-oidc";
  if (names.some((name) => name.startsWith("x-ms-client-principal"))) return "azure";
  if (names.some((name) => name.startsWith("x-goog-"))) return "google-iap";
  if (names.length > 0) return "auth-proxy";
  return undefined;
};

const decodeURIComponentSafe = (value: string) => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

const initialsFrom = (displayName: string, email?: string, username?: string) => {
  const source = firstNonEmpty(displayName, email, username);
  const localPart = source.includes("@") ? source.split("@", 1)[0] : source;
  const parts = localPart
    .replace(/[_./+-]+/g, " ")
    .split(/\s+/)
    .map((part) => part.replace(/[^a-zA-Z0-9]/g, ""))
    .filter(Boolean);

  if (parts.length >= 2) {
    return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
  }
  if (parts.length === 1) {
    return parts[0].slice(0, 2).toUpperCase();
  }
  return "?";
};

const displayNameFrom = (claims: IdentityClaims) =>
  firstNonEmpty(
    claims.name,
    claims.email,
    claims.username,
    claims.subject,
  );

const actorLabelFrom = (claims: IdentityClaims, email: string, username: string) =>
  firstNonEmpty(email, username, claims.name, claims.subject);

const actorIdFrom = (claims: IdentityClaims, email: string, username: string) =>
  firstNonEmpty(claims.subject, email, username, claims.name);

const hasEntitlements = (entitlements: IdentityEntitlements | undefined) =>
  Boolean(entitlements?.groups?.length || entitlements?.roles?.length || entitlements?.scopes?.length);

const currentUserFromCandidate = (candidate: IdentityCandidate): CurrentUser | null => {
  const { claims } = candidate;
  const displayName = displayNameFrom(claims);
  if (!displayName) return null;

  const rawEmail = cleanString(claims.email);
  const rawUsername = cleanString(claims.username);
  const email = (rawEmail || (looksLikeEmail(rawUsername) ? rawUsername : "")).toLowerCase();
  const username = rawUsername || email;
  const subject = cleanString(claims.subject);
  const actorId = actorIdFrom({ ...claims, subject }, email, username);
  const actorLabel = actorLabelFrom(claims, email, username);
  if (!actorId) return null;

  const inferred = [
    ...(candidate.evidence.inferred ?? []),
    ...(!rawEmail && email ? ["email-from-username"] : []),
    ...(!rawUsername && email ? ["username-from-email"] : []),
  ];

  return {
    actorId,
    actorLabel,
    confidence: candidate.confidence,
    displayName,
    initials: initialsFrom(displayName, email, username),
    ...(email ? { email } : {}),
    ...(username ? { username } : {}),
    ...(subject ? { subject } : {}),
    ...(candidate.provider ? { provider: candidate.provider } : {}),
    source: candidate.source,
    ...(hasEntitlements(claims.entitlements) ? { entitlements: claims.entitlements } : {}),
    evidence: {
      ...candidate.evidence,
      ...(inferred.length > 0 ? { inferred } : {}),
    },
    ...(candidate.warnings?.length ? { warnings: candidate.warnings } : {}),
  };
};

const claimMatch = (claims: Record<string, unknown>, keys: string[]) => {
  for (const key of keys) {
    const value = cleanString(claims[key]);
    if (value) return { key, value };
  }
  return null;
};

const identityClaimsFromRecord = (claims: Record<string, unknown>): { claims: IdentityClaims; claimNames: string[] } => {
  const givenName = claimMatch(claims, ["given_name", "first_name"]);
  const familyName = claimMatch(claims, ["family_name", "last_name"]);
  const email = claimMatch(claims, ["email", "preferred_email", "email_address", "upn"]);
  const name = claimMatch(claims, ["name", "display_name", "full_name"]);
  const subject = claimMatch(claims, ["sub", "subject", "uid", "oid"]);
  const username = claimMatch(claims, ["preferred_username", "username", "login", "nickname", "cognito:username"]);
  const groups = cleanStringList(claims.groups ?? claims.group ?? claims["cognito:groups"]);
  const roles = cleanStringList(claims.roles ?? claims.role);
  const scopes = cleanStringList(claims.scope ?? claims.scp);
  const derivedName = [givenName?.value, familyName?.value].filter(Boolean).join(" ");
  const claimNames = [
    email?.key,
    name?.key,
    givenName?.key,
    familyName?.key,
    subject?.key,
    username?.key,
    groups.length > 0 ? "groups" : undefined,
    roles.length > 0 ? "roles" : undefined,
    scopes.length > 0 ? (claims.scope ? "scope" : "scp") : undefined,
  ].filter((key): key is string => Boolean(key));

  return {
    claims: {
      email: email?.value,
      ...(groups.length > 0 || roles.length > 0 || scopes.length > 0 ? {
        entitlements: {
          ...(groups.length > 0 ? { groups } : {}),
          ...(roles.length > 0 ? { roles } : {}),
          ...(scopes.length > 0 ? { scopes } : {}),
        },
      } : {}),
      name: firstNonEmpty(name?.value, derivedName),
      subject: subject?.value,
      username: username?.value,
    },
    claimNames,
  };
};

const decodeBase64 = (value: string) => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = globalThis.atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
};

const decodeBase64Bytes = (value: string) => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = globalThis.atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

const arrayBufferFromBytes = (bytes: Uint8Array) =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

type ParsedJwt = {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: Uint8Array;
  signingInput: string;
};

const parseJwt = (token: string): ParsedJwt | null => {
  const [encodedHeader, encodedPayload, encodedSignature] = cleanString(token, 12000).split(".");
  if (!encodedHeader || !encodedPayload || !encodedSignature) return null;
  try {
    return {
      header: JSON.parse(decodeBase64(encodedHeader)) as Record<string, unknown>,
      payload: JSON.parse(decodeBase64(encodedPayload)) as Record<string, unknown>,
      signature: decodeBase64Bytes(encodedSignature),
      signingInput: `${encodedHeader}.${encodedPayload}`,
    };
  } catch {
    return null;
  }
};

const bearerToken = (authorization: string | null) => {
  const match = cleanString(authorization, 8000).match(/^Bearer\s+(.+)$/i);
  return match?.[1] ?? "";
};

const jwtDate = (value: unknown) => {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  return new Date(value * 1000).toISOString();
};

const audienceMatches = (claim: unknown, expected: string) => {
  if (Array.isArray(claim)) return claim.some((value) => cleanString(value) === expected);
  return cleanString(claim) === expected;
};

const jwtValidationWarnings = (payload: Record<string, unknown>) => {
  const warnings: string[] = [];
  const nowSeconds = Date.now() / 1000;
  const issuer = process.env.CEREBRO_IDENTITY_ISSUER;
  const audience = process.env.CEREBRO_IDENTITY_AUDIENCE;
  const exp = typeof payload.exp === "number" ? payload.exp : null;
  const nbf = typeof payload.nbf === "number" ? payload.nbf : null;

  if (issuer && cleanString(payload.iss) !== issuer) warnings.push("issuer-mismatch");
  if (audience && !audienceMatches(payload.aud, audience)) warnings.push("audience-mismatch");
  if (exp && exp < nowSeconds) warnings.push("token-expired");
  if (nbf && nbf > nowSeconds) warnings.push("token-not-yet-valid");
  return warnings;
};

const jwtEvidenceFromPayload = (payload: Record<string, unknown>) => ({
  audience: Array.isArray(payload.aud) ? payload.aud.map((value) => cleanString(value)).filter(Boolean).join(",") : cleanString(payload.aud),
  expiresAt: jwtDate(payload.exp),
  issuer: cleanString(payload.iss),
  notBefore: jwtDate(payload.nbf),
});

type JwtSignatureEvidence = NonNullable<IdentityEvidence["jwt"]>["signature"];

const jwtEvidenceFromParts = (
  payload: Record<string, unknown>,
  header: Record<string, unknown>,
  signature?: JwtSignatureEvidence,
) => ({
  ...jwtEvidenceFromPayload(payload),
  algorithm: cleanString(header.alg),
  keyId: cleanString(header.kid),
  ...(signature ? { signature } : {}),
});

type JwtSignatureVerification = {
  algorithm?: string;
  keyId?: string;
  verified: boolean;
  warning?: string;
};

type IdentityJsonWebKey = JsonWebKey & {
  alg?: string;
  kid?: string;
  use?: string;
};

type JsonWebKeySet = {
  keys?: IdentityJsonWebKey[];
};

const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const jwksCache = new Map<string, { expiresAt: number; keys: IdentityJsonWebKey[] }>();

export const clearIdentityJwksCache = () => {
  jwksCache.clear();
};

const rsaJwtAlgorithms: Record<string, RsaHashedImportParams> = {
  RS256: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  RS384: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
  RS512: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
};

const fetchJwks = async (jwksUrl: string) => {
  const cached = jwksCache.get(jwksUrl);
  if (cached && cached.expiresAt > Date.now()) return cached.keys;

  const response = await fetch(jwksUrl, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`jwks-fetch-failed-${response.status}`);
  }
  const payload = await response.json() as JsonWebKeySet;
  const keys = Array.isArray(payload.keys) ? payload.keys : [];
  jwksCache.set(jwksUrl, {
    expiresAt: Date.now() + JWKS_CACHE_TTL_MS,
    keys,
  });
  return keys;
};

const verifyJwtSignature = async (token: string, jwksUrl: string): Promise<JwtSignatureVerification> => {
  const parsed = parseJwt(token);
  if (!parsed) return { verified: false, warning: "token-unparseable" };
  const algorithm = cleanString(parsed.header.alg);
  const keyId = cleanString(parsed.header.kid);
  const importParams = rsaJwtAlgorithms[algorithm];
  if (!importParams) {
    return { algorithm, keyId, verified: false, warning: "signature-algorithm-unsupported" };
  }
  if (!globalThis.crypto?.subtle) {
    return { algorithm, keyId, verified: false, warning: "signature-verifier-unavailable" };
  }

  try {
    const keys = await fetchJwks(jwksUrl);
    const candidates = keys.filter((key) =>
      key.kty === "RSA" &&
      (!keyId || key.kid === keyId) &&
      (!key.alg || key.alg === algorithm) &&
      (!key.use || key.use === "sig"),
    );
    if (candidates.length === 0) {
      return { algorithm, keyId, verified: false, warning: "signature-key-not-found" };
    }

    const signingInput = arrayBufferFromBytes(new TextEncoder().encode(parsed.signingInput));
    const signature = arrayBufferFromBytes(parsed.signature);
    for (const key of candidates) {
      const cryptoKey = await globalThis.crypto.subtle.importKey(
        "jwk",
        key,
        importParams,
        false,
        ["verify"],
      );
      const verified = await globalThis.crypto.subtle.verify(
        importParams,
        cryptoKey,
        signature,
        signingInput,
      );
      if (verified) return { algorithm, keyId, verified: true };
    }
    return { algorithm, keyId, verified: false, warning: "signature-invalid" };
  } catch (error) {
    const message = error instanceof Error ? error.message : "signature-verification-failed";
    return { algorithm, keyId, verified: false, warning: message };
  }
};

const jwtConfidence = (
  warnings: string[],
  provider: IdentityProvider,
  signatureVerified = false,
): IdentityConfidence => {
  if (warnings.length > 0) return "unverified";
  if (signatureVerified) return "signature-verified";
  if (process.env.CEREBRO_IDENTITY_ISSUER || process.env.CEREBRO_IDENTITY_AUDIENCE) return "claims-validated";
  if (provider === "bearer-jwt") return "unverified";
  return "trusted-proxy";
};

const currentUserFromJwt = (token: string, provider: IdentityProvider, source: CurrentUser["source"] = "jwt") => {
  const parsed = parseJwt(token);
  if (!parsed) return null;
  const { claims, claimNames } = identityClaimsFromRecord(parsed.payload);
  const warnings = jwtValidationWarnings(parsed.payload);
  return currentUserFromCandidate({
    claims,
    confidence: jwtConfidence(warnings, provider),
    evidence: {
      claims: claimNames,
      jwt: jwtEvidenceFromParts(parsed.payload, parsed.header, "unverified"),
    },
    provider,
    source,
    warnings,
  });
};

const currentUserFromVerifiedJwt = async (token: string, provider: IdentityProvider, source: CurrentUser["source"] = "jwt") => {
  const parsed = parseJwt(token);
  if (!parsed) return null;
  const { claims, claimNames } = identityClaimsFromRecord(parsed.payload);
  const warnings = jwtValidationWarnings(parsed.payload);
  const jwksUrl = configuredJwksUrl();
  const signature = jwksUrl
    ? await verifyJwtSignature(token, jwksUrl)
    : { verified: false, warning: "jwks-not-configured" } satisfies JwtSignatureVerification;
  const nextWarnings = [
    ...warnings,
    ...(signature.verified ? [] : [signature.warning ?? "signature-not-verified"]),
  ];
  return currentUserFromCandidate({
    claims,
    confidence: jwtConfidence(nextWarnings, provider, signature.verified),
    evidence: {
      claims: claimNames,
      jwt: jwtEvidenceFromParts(parsed.payload, {
        ...parsed.header,
        ...(signature.algorithm ? { alg: signature.algorithm } : {}),
        ...(signature.keyId ? { kid: signature.keyId } : {}),
      }, signature.verified ? "verified" : "failed"),
    },
    provider,
    source,
    warnings: nextWarnings,
  });
};

const currentUserFromAzureClientPrincipal = (value: string) => {
  try {
    const principal = JSON.parse(decodeBase64(value)) as {
      userDetails?: unknown;
      userId?: unknown;
      claims?: { typ?: unknown; val?: unknown }[];
    };
    const claims: Record<string, unknown> = {
      email: principal.userDetails,
      sub: principal.userId,
    };
    for (const claim of principal.claims ?? []) {
      const key = cleanString(claim.typ);
      if (key) claims[key] = claim.val;
    }
    const normalized = identityClaimsFromRecord(claims);
    return currentUserFromCandidate({
      claims: normalized.claims,
      confidence: "trusted-proxy",
      evidence: {
        claims: normalized.claimNames,
        headers: ["x-ms-client-principal"],
      },
      provider: "azure",
      source: "azure-client-principal",
    });
  } catch {
    return null;
  }
};

export const currentUserActor = (user: CurrentUser | null | undefined) =>
  firstNonEmpty(user?.actorId, user?.subject, user?.email, user?.username, user?.displayName);

export const currentUserActorLabel = (user: CurrentUser | null | undefined) =>
  firstNonEmpty(user?.actorLabel, user?.email, user?.username, user?.displayName, user?.subject);

export const localCurrentUserFallback = (): CurrentUser => ({
  actorId: "local-developer",
  actorLabel: "local-developer",
  confidence: "fallback",
  displayName: "Local developer",
  initials: "LD",
  provider: "local",
  username: "local-developer",
  source: "local-fallback",
});

export const identityDeploymentProfile = () => configuredIdentityProfile();

export const identityRequired = () =>
  parseBooleanEnv(process.env.CEREBRO_IDENTITY_REQUIRED) ??
  (process.env.NODE_ENV === "production" && identityDeploymentProfile() !== "local");

export const localIdentityFallbackEnabled = () =>
  parseBooleanEnv(process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK) ??
  (identityDeploymentProfile() === "local" || process.env.NODE_ENV === "development");

export const identityRuntimeConfig = (): IdentityRuntimeConfig => ({
  audienceConfigured: Boolean(process.env.CEREBRO_IDENTITY_AUDIENCE),
  fallbackEnabled: localIdentityFallbackEnabled(),
  issuerConfigured: Boolean(process.env.CEREBRO_IDENTITY_ISSUER),
  jwksConfigured: Boolean(configuredJwksUrl()),
  profile: identityDeploymentProfile(),
  required: identityRequired(),
  trustedHeaders: configuredTrustedHeaderNames(),
});

export const currentUserSourceLabel = (source: CurrentUser["source"] | null | undefined) => {
  switch (source) {
    case "headers":
      return "Auth proxy headers";
    case "jwt":
      return "JWT claims";
    case "azure-client-principal":
      return "Azure client principal";
    case "local-fallback":
      return "Local fallback";
    default:
      return "Unavailable";
  }
};

export const currentUserConfidenceLabel = (confidence: IdentityConfidence | null | undefined) => {
  switch (confidence) {
    case "trusted-proxy":
      return "Trusted proxy";
    case "claims-validated":
      return "Claims validated";
    case "signature-verified":
      return "Signature verified";
    case "unverified":
      return "Unverified claims";
    case "conflict":
      return "Conflicting signals";
    case "fallback":
      return "Fallback";
    default:
      return "Unknown";
  }
};

export const currentUserSourceDetail = (source: CurrentUser["source"] | null | undefined) => {
  switch (source) {
    case "headers":
      return "Okta or auth proxy headers supplied the current user.";
    case "jwt":
      return "A bearer or identity-token JWT supplied the current user.";
    case "azure-client-principal":
      return "Azure Static Web Apps client-principal claims supplied the current user.";
    case "local-fallback":
      return "No upstream identity header was present, so local development uses a stable fallback identity.";
    default:
      return "No current-user signal was found on the request.";
  }
};

export const currentUserConfidenceDetail = (user: CurrentUser | null | undefined) => {
  if (!user) return "No current-user signal was found on the request.";
  if (user.conflicts?.length) return `Conflicting identity signals: ${user.conflicts.join("; ")}.`;
  if (user.warnings?.length) return `Identity claims need attention: ${user.warnings.join(", ")}.`;
  switch (user.confidence) {
    case "trusted-proxy":
      return "Identity was supplied by configured proxy or platform headers.";
    case "claims-validated":
      return "JWT claims matched the configured issuer, audience, and time window. Signature verification is not performed in this UI layer.";
    case "signature-verified":
      return "JWT signature verification and configured claim checks passed.";
    case "unverified":
      return "JWT claims were decoded for display. Treat them as diagnostic unless the upstream proxy enforces token verification.";
    case "fallback":
      return "No upstream identity header was present, so local development uses a stable fallback identity.";
    default:
      return currentUserSourceDetail(user.source);
  }
};

export const currentUserAuditFields = (user: CurrentUser | null | undefined) => ({
  authenticated: Boolean(user && user.source !== "local-fallback"),
  claimCount: user?.evidence?.claims?.length ?? 0,
  confidence: user?.confidence ?? "none",
  conflictCount: user?.conflicts?.length ?? 0,
  groupCount: user?.entitlements?.groups?.length ?? 0,
  headerCount: user?.evidence?.headers?.length ?? 0,
  provider: user?.provider ?? "none",
  roleCount: user?.entitlements?.roles?.length ?? 0,
  scopeCount: user?.entitlements?.scopes?.length ?? 0,
  source: user?.source ?? "none",
  warningCount: user?.warnings?.length ?? 0,
});

export const identityPosture = ({
  error,
  loading = false,
  user,
}: {
  error?: string | null;
  loading?: boolean;
  user: CurrentUser | null | undefined;
}): IdentityPosture => {
  if (loading) {
    return {
      actor: "",
      detail: "Resolving current user identity.",
      displayName: "Loading identity",
      initials: "?",
      label: "Resolving identity",
      sourceLabel: "Loading",
      state: "loading",
      tone: "neutral",
    };
  }

  if (!user) {
    return {
      actor: "",
      detail: error || "No current-user signal was found on the request.",
      displayName: "Identity unavailable",
      initials: "?",
      label: "Identity unavailable",
      sourceLabel: "Unavailable",
      state: "unavailable",
      tone: "warning",
    };
  }

  const actor = currentUserActor(user);
  const sourceLabel = currentUserSourceLabel(user.source);
  const warning = Boolean(user.conflicts?.length || user.warnings?.length || user.confidence === "unverified");
  return {
    actor,
    detail: currentUserConfidenceDetail(user),
    displayName: user.displayName,
    initials: user.initials,
    label: user.source === "local-fallback" ? "Local identity" : warning ? currentUserConfidenceLabel(user.confidence) : "Identity verified",
    sourceLabel,
    state: user.source === "local-fallback" ? "fallback" : "resolved",
    tone: user.source === "local-fallback" || warning ? "warning" : "success",
  };
};

const candidateConflict = (primary: CurrentUser, secondary: CurrentUser) => {
  const conflicts: string[] = [];
  if (primary.email && secondary.email && primary.email.toLowerCase() !== secondary.email.toLowerCase()) {
    conflicts.push(`email ${primary.email} != ${secondary.email}`);
  }
  if (primary.subject && secondary.subject && primary.subject !== secondary.subject) {
    conflicts.push(`subject ${primary.subject} != ${secondary.subject}`);
  }
  if (primary.username && secondary.username && primary.username.toLowerCase() !== secondary.username.toLowerCase()) {
    conflicts.push(`username ${primary.username} != ${secondary.username}`);
  }
  return conflicts;
};

const withCandidateConflicts = (primary: CurrentUser, alternates: CurrentUser[]) => {
  const conflicts = alternates.flatMap((alternate) => candidateConflict(primary, alternate));
  if (conflicts.length === 0) return primary;
  return {
    ...primary,
    confidence: "conflict" as const,
    conflicts: [...(primary.conflicts ?? []), ...conflicts],
  };
};

const uniqueStrings = (...values: (string[] | undefined)[]) =>
  Array.from(new Set(values.flatMap((value) => value ?? []).filter(Boolean)));

const shouldPreferAlternateDisplayName = (primary: CurrentUser, alternate: CurrentUser) => {
  const primaryDisplay = primary.displayName.toLowerCase();
  const generatedDisplays = [
    primary.email,
    primary.username,
    primary.subject,
    primary.actorId,
    primary.actorLabel,
  ].map((value) => value?.toLowerCase());
  const alternateDisplay = alternate.displayName.toLowerCase();
  const alternateGeneratedDisplays = [
    alternate.email,
    alternate.username,
    alternate.subject,
    alternate.actorId,
    alternate.actorLabel,
  ].map((value) => value?.toLowerCase());

  return generatedDisplays.includes(primaryDisplay) && !alternateGeneratedDisplays.includes(alternateDisplay);
};

const mergeComplementaryCandidates = (primary: CurrentUser, alternates: CurrentUser[]) =>
  alternates.reduce((merged, alternate) => {
    if (candidateConflict(merged, alternate).length > 0) return merged;

    const email = merged.email || alternate.email;
    const username = merged.username || alternate.username || email;
    const subject = merged.subject || alternate.subject;
    const displayName = shouldPreferAlternateDisplayName(merged, alternate) ? alternate.displayName : merged.displayName;
    const actorLabel = firstNonEmpty(email, username, displayName, subject);
    const actorId = firstNonEmpty(subject, email, username, displayName);
    const groups = uniqueStrings(merged.entitlements?.groups, alternate.entitlements?.groups);
    const roles = uniqueStrings(merged.entitlements?.roles, alternate.entitlements?.roles);
    const scopes = uniqueStrings(merged.entitlements?.scopes, alternate.entitlements?.scopes);

    return {
      ...merged,
      actorId,
      actorLabel,
      displayName,
      email,
      entitlements: {
        ...(groups.length > 0 ? { groups } : {}),
        ...(roles.length > 0 ? { roles } : {}),
        ...(scopes.length > 0 ? { scopes } : {}),
      },
      evidence: {
        claims: uniqueStrings(merged.evidence?.claims, alternate.evidence?.claims),
        headers: uniqueStrings(merged.evidence?.headers, alternate.evidence?.headers),
        inferred: uniqueStrings(merged.evidence?.inferred, alternate.evidence?.inferred),
        jwt: merged.evidence?.jwt ?? alternate.evidence?.jwt,
      },
      initials: initialsFrom(displayName, email, username),
      subject,
      username,
      warnings: uniqueStrings(merged.warnings, alternate.warnings),
    };
  }, primary);

const directHeaderCandidate = (headers: Headers): CurrentUser | null => {
  const matches = [
    firstHeaderMatch(headers, allowedHeaderNames(EMAIL_HEADERS)),
    firstHeaderMatch(headers, allowedHeaderNames(DISPLAY_NAME_HEADERS)),
    firstHeaderMatch(headers, allowedHeaderNames(SUBJECT_HEADERS)),
    firstHeaderMatch(headers, allowedHeaderNames(USERNAME_HEADERS)),
  ];
  const headerNames = matches.map((match) => match?.name).filter((name): name is string => Boolean(name));
  return currentUserFromCandidate({
    claims: {
      email: decodeURIComponentSafe(matches[0]?.value ?? ""),
      name: decodeURIComponentSafe(matches[1]?.value ?? ""),
      subject: matches[2]?.value ?? "",
      username: decodeURIComponentSafe(matches[3]?.value ?? ""),
    },
    confidence: "trusted-proxy",
    evidence: { headers: headerNames },
    provider: providerForHeader(headerNames),
    source: "headers",
  });
};

export const currentUserFromHeaders = (headers: Headers): CurrentUser | null => {
  const candidates: CurrentUser[] = [];
  const directUser = directHeaderCandidate(headers);
  if (directUser) candidates.push(directUser);

  const azurePrincipal = firstHeader(headers, allowedHeaderNames(["x-ms-client-principal"]));
  if (azurePrincipal) {
    const user = currentUserFromAzureClientPrincipal(azurePrincipal);
    if (user) candidates.push(user);
  }

  for (const header of allowedHeaderNames(JWT_HEADERS)) {
    const token = headers.get(header);
    if (!token) continue;
    const user = currentUserFromJwt(token, providerForHeader([header]) ?? "auth-proxy");
    if (user) candidates.push(user);
  }

  const authorizationToken = identityHeaderAllowed("authorization")
    ? bearerToken(headers.get("authorization"))
    : "";
  if (authorizationToken) {
    const user = currentUserFromJwt(authorizationToken, "bearer-jwt");
    if (user) candidates.push(user);
  }

  const preferred = candidates[0];
  if (!preferred) return null;
  return withCandidateConflicts(mergeComplementaryCandidates(preferred, candidates.slice(1)), candidates.slice(1));
};

export const currentUserFromHeadersWithFallback = (headers: Headers): CurrentUser | null =>
  currentUserFromHeaders(headers) ?? (localIdentityFallbackEnabled() ? localCurrentUserFallback() : null);

export const resolveCurrentUserFromHeaders = async (headers: Headers): Promise<CurrentUser | null> => {
  if (!configuredJwksUrl()) return currentUserFromHeaders(headers);

  const candidates: CurrentUser[] = [];
  const directUser = directHeaderCandidate(headers);
  if (directUser) candidates.push(directUser);

  const azurePrincipal = firstHeader(headers, allowedHeaderNames(["x-ms-client-principal"]));
  if (azurePrincipal) {
    const user = currentUserFromAzureClientPrincipal(azurePrincipal);
    if (user) candidates.push(user);
  }

  for (const header of allowedHeaderNames(JWT_HEADERS)) {
    const token = headers.get(header);
    if (!token) continue;
    const user = await currentUserFromVerifiedJwt(token, providerForHeader([header]) ?? "auth-proxy");
    if (user) candidates.push(user);
  }

  const authorizationToken = identityHeaderAllowed("authorization")
    ? bearerToken(headers.get("authorization"))
    : "";
  if (authorizationToken) {
    const user = await currentUserFromVerifiedJwt(authorizationToken, "bearer-jwt");
    if (user) candidates.push(user);
  }

  const preferred = candidates[0];
  if (!preferred) return null;
  return withCandidateConflicts(mergeComplementaryCandidates(preferred, candidates.slice(1)), candidates.slice(1));
};

export const resolveCurrentUserFromHeadersWithFallback = async (headers: Headers): Promise<CurrentUser | null> =>
  await resolveCurrentUserFromHeaders(headers) ?? (localIdentityFallbackEnabled() ? localCurrentUserFallback() : null);

export const identityHealthFromHeaders = async (headers: Headers): Promise<IdentityHealth> => {
  const user = await resolveCurrentUserFromHeadersWithFallback(headers);
  const audit = currentUserAuditFields(user);
  const issues = [
    ...(!user ? ["identity-missing"] : []),
    ...(user?.source === "local-fallback" && identityRequired() ? ["local-fallback-disabled-by-required-identity"] : []),
    ...(user?.confidence === "unverified" && identityRequired() ? ["unverified-identity-blocked"] : []),
    ...(user?.conflicts?.length ? ["identity-conflict"] : []),
    ...(user?.warnings ?? []),
  ];
  const blocked = identityRequired() && (
    !user ||
    user.source === "local-fallback" ||
    user.confidence === "conflict" ||
    user.confidence === "unverified" ||
    Boolean(user.warnings?.length)
  );
  return {
    checkedAt: new Date().toISOString(),
    config: identityRuntimeConfig(),
    current: {
      authenticated: audit.authenticated,
      claimCount: audit.claimCount,
      confidence: user?.confidence ?? "none",
      conflictCount: audit.conflictCount,
      headerCount: audit.headerCount,
      provider: user?.provider ?? "none",
      source: user?.source ?? "none",
      warningCount: audit.warningCount,
    },
    issues,
    status: blocked ? "blocked" : issues.length > 0 ? "degraded" : "ready",
  };
};
