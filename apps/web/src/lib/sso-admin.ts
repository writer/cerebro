export type SSOProtocol = "oidc" | "saml";
export type SSOConnectionStatus = "draft" | "tested" | "active" | "disabled";

export type SSOOidcSettings = {
  issuer: string;
  clientId: string;
  clientSecretRef: string;
  scopes: string[];
  groupsClaim: string;
};

export type SSOSamlSettings = {
  idpEntityId: string;
  idpSsoUrl: string;
  idpCertificates: string[];
  idpMetadataUrl?: string;
  wantAssertionsSigned: boolean;
  emailAttribute: string;
  nameAttribute: string;
  groupsAttribute: string;
  nameIdFormat: string;
};

export type SSORoleMapping = { group: string; roles: string[] };

export type SSOConnection = {
  id: string;
  name: string;
  protocol: SSOProtocol;
  status: SSOConnectionStatus;
  domains: string[];
  oidc?: SSOOidcSettings;
  saml?: SSOSamlSettings;
  roleMappings: SSORoleMapping[];
  defaultRoles: string[];
  jitProvisioning: boolean;
  /** Seeded from stack configuration; the API refuses edits, status changes, and deletion. */
  managed?: boolean;
  lastTest?: { at: string; ok: boolean; actor: string; detail: string };
  createdAt: string;
  updatedAt: string;
  updatedBy: string;
};

export type SSOConnectionInput = Omit<SSOConnection, "id" | "lastTest" | "createdAt" | "updatedAt" | "updatedBy">;

export type SSOPolicy = {
  enforced: boolean;
  sessionMaxLifetimeMinutes: number;
  sessionIdleTimeoutMinutes: number;
  updatedAt?: string;
  updatedBy?: string;
};

export type SSOStatus = {
  enforced: boolean;
  breakGlass: boolean;
  /** CEREBRO_SSO_REQUIRED: deployment forces SSO, so the policy toggle and break-glass do nothing. */
  required?: boolean;
  sessionSecretConfigured: boolean;
  publicUrlConfigured: boolean;
  activeConnections: number;
  legacyIdentityActive: boolean;
};

export type SSOServiceProviderInfo = {
  redirectUri: string;
  acsUrl: string;
  entityId: string;
  metadataUrl: string;
  initiateLoginUrl: string;
  scimBaseUrl: string;
};

export type SCIMToken = {
  id: string;
  name: string;
  prefix: string;
  connectionId?: string;
  createdAt: string;
  lastUsedAt?: string;
  createdBy: string;
};

export type DirectoryUser = {
  id: string;
  userName: string;
  email: string;
  name: string;
  active: boolean;
  groups: string[];
  source: "scim" | "jit";
  connectionId: string;
  lastLoginAt?: string;
};

export type DirectoryGroup = { id: string; displayName: string; memberCount: number; connectionId: string };

export type SSOProviderPreset = {
  id: "okta" | "entra" | "google" | "other";
  label: string;
  protocols: SSOProtocol[];
  issuerPlaceholder: string;
  groupsClaim: string;
};

export const SSO_PROVIDER_PRESETS: SSOProviderPreset[] = [
  { id: "okta", label: "Okta", protocols: ["oidc", "saml"], issuerPlaceholder: "https://your-org.okta.com", groupsClaim: "groups" },
  {
    id: "entra",
    label: "Microsoft Entra ID",
    protocols: ["oidc", "saml"],
    issuerPlaceholder: "https://login.microsoftonline.com/<tenant-id>/v2.0",
    groupsClaim: "groups",
  },
  { id: "google", label: "Google Workspace", protocols: ["saml", "oidc"], issuerPlaceholder: "https://accounts.google.com", groupsClaim: "groups" },
  { id: "other", label: "Other provider", protocols: ["oidc", "saml"], issuerPlaceholder: "https://idp.example.com", groupsClaim: "groups" },
];

export const DEFAULT_OIDC_SCOPES = ["openid", "email", "profile", "groups"];
export const DEFAULT_SAML_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

export const emptyOidcSettings = (groupsClaim = "groups"): SSOOidcSettings => ({
  issuer: "",
  clientId: "",
  clientSecretRef: "",
  scopes: [...DEFAULT_OIDC_SCOPES],
  groupsClaim,
});

export const emptySamlSettings = (): SSOSamlSettings => ({
  idpEntityId: "",
  idpSsoUrl: "",
  idpCertificates: [],
  idpMetadataUrl: "",
  wantAssertionsSigned: true,
  emailAttribute: "email",
  nameAttribute: "name",
  groupsAttribute: "groups",
  nameIdFormat: DEFAULT_SAML_NAME_ID_FORMAT,
});

export const newConnectionDraft = (preset: SSOProviderPreset, protocol: SSOProtocol): SSOConnectionInput => ({
  name: preset.id === "other" ? "" : preset.label,
  protocol,
  status: "draft",
  domains: [],
  ...(protocol === "oidc" ? { oidc: emptyOidcSettings(preset.groupsClaim) } : { saml: emptySamlSettings() }),
  roleMappings: [],
  defaultRoles: [],
  jitProvisioning: true,
});

export const connectionToInput = (connection: SSOConnection): SSOConnectionInput => ({
  name: connection.name,
  protocol: connection.protocol,
  status: connection.status,
  domains: [...connection.domains],
  ...(connection.oidc ? { oidc: { ...connection.oidc, scopes: [...connection.oidc.scopes] } } : {}),
  ...(connection.saml ? { saml: { ...connection.saml, idpCertificates: [...connection.saml.idpCertificates] } } : {}),
  roleMappings: connection.roleMappings.map((mapping) => ({ group: mapping.group, roles: [...mapping.roles] })),
  defaultRoles: [...connection.defaultRoles],
  jitProvisioning: connection.jitProvisioning,
});

// Shape check only; the web server also limits which env names and secret ids a reference may name.
export const SECRET_REFERENCE_PATTERN = /^(env:[A-Za-z_][A-Za-z0-9_]*|aws-sm:(arn:[a-z-]+:secretsmanager:|[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-\d[:/])[A-Za-z0-9/_+=.@:-]+(#[A-Za-z0-9_.-]+)?)$/;

const HOSTNAME_PATTERN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export const parseList = (value: string, separator: RegExp = /[\s,]+/) =>
  Array.from(new Set(value.split(separator).map((item) => item.trim()).filter(Boolean)));

export const parseDomains = (value: string) =>
  parseList(value.toLowerCase()).map((domain) => domain.replace(/^@/, ""));

// PEM blocks are split on their BEGIN markers so a pasted bundle of rotation
// certificates becomes one entry per certificate.
export const parseCertificates = (value: string) =>
  value
    .split(/(?=-----BEGIN CERTIFICATE-----)/)
    .map((block) => block.trim())
    .filter(Boolean);

const isHttpsUrl = (value: string) => {
  try {
    const url = new URL(value);
    if (url.protocol === "https:") return true;
    return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  } catch {
    return false;
  }
};

export type ConnectionDraftErrors = Partial<Record<
  "name" | "domains" | "issuer" | "clientId" | "clientSecretRef" | "idpEntityId" | "idpSsoUrl" | "idpCertificates" | "roleMappings",
  string
>>;

export function validateConnectionDraft(draft: SSOConnectionInput): ConnectionDraftErrors {
  const errors: ConnectionDraftErrors = {};
  if (!draft.name.trim()) errors.name = "Give the connection a name.";
  if (draft.domains.length === 0) {
    errors.domains = "Add at least one email domain that signs in with this connection.";
  } else {
    const invalid = draft.domains.find((domain) => !HOSTNAME_PATTERN.test(domain));
    if (invalid) errors.domains = `${invalid} is not a valid domain.`;
  }
  if (draft.protocol === "oidc") {
    const oidc = draft.oidc;
    if (!oidc || !isHttpsUrl(oidc.issuer)) errors.issuer = "Enter the issuer as an https URL.";
    if (!oidc?.clientId.trim()) errors.clientId = "Enter the client ID from your identity provider.";
    if (!oidc || !SECRET_REFERENCE_PATTERN.test(oidc.clientSecretRef.trim())) {
      errors.clientSecretRef = "Use env:CEREBRO_SSO_NAME or aws-sm:<region>/<secret-id>[#field]. Never paste the secret itself.";
    }
  } else {
    const saml = draft.saml;
    if (!saml?.idpEntityId.trim()) errors.idpEntityId = "Enter the identity provider's entity ID (issuer).";
    if (!saml || !isHttpsUrl(saml.idpSsoUrl)) errors.idpSsoUrl = "Enter the single sign-on URL as an https URL.";
    if (!saml || saml.idpCertificates.length === 0) {
      errors.idpCertificates = "Add the identity provider's signing certificate.";
    } else if (saml.idpCertificates.length > 3) {
      errors.idpCertificates = "Keep at most 3 certificates (current plus rotation).";
    } else if (saml.idpCertificates.some((cert) => !/^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----$/.test(cert))) {
      errors.idpCertificates = "Certificates must be PEM blocks (-----BEGIN CERTIFICATE-----).";
    }
  }
  if (draft.roleMappings.some((mapping) => !mapping.group.trim() || mapping.roles.length === 0)) {
    errors.roleMappings = "Each group mapping needs a group name and a role.";
  }
  return errors;
}

// The API resets a connection to draft when protocol settings change, so the
// payload drops empty optional fields instead of sending placeholders.
export function connectionPayload(draft: SSOConnectionInput): SSOConnectionInput {
  const base = {
    name: draft.name.trim(),
    protocol: draft.protocol,
    status: draft.status,
    domains: draft.domains,
    roleMappings: draft.roleMappings
      .map((mapping) => ({ group: mapping.group.trim(), roles: mapping.roles }))
      .filter((mapping) => mapping.group && mapping.roles.length > 0),
    defaultRoles: draft.defaultRoles,
    jitProvisioning: draft.jitProvisioning,
  };
  if (draft.protocol === "oidc" && draft.oidc) {
    return {
      ...base,
      oidc: {
        ...draft.oidc,
        issuer: draft.oidc.issuer.trim().replace(/\/+$/, ""),
        clientId: draft.oidc.clientId.trim(),
        clientSecretRef: draft.oidc.clientSecretRef.trim(),
        groupsClaim: draft.oidc.groupsClaim.trim() || "groups",
        scopes: draft.oidc.scopes.length > 0 ? draft.oidc.scopes : [...DEFAULT_OIDC_SCOPES],
      },
    };
  }
  const saml = draft.saml ?? emptySamlSettings();
  const { idpMetadataUrl, ...rest } = saml;
  return {
    ...base,
    saml: {
      ...rest,
      ...(idpMetadataUrl?.trim() ? { idpMetadataUrl: idpMetadataUrl.trim() } : {}),
      idpEntityId: saml.idpEntityId.trim(),
      idpSsoUrl: saml.idpSsoUrl.trim(),
    },
  };
}

export const connectionStatusLabel: Record<SSOConnectionStatus, string> = {
  draft: "Not tested",
  tested: "Ready to turn on",
  active: "On",
  disabled: "Off",
};

export const protocolLabel: Record<SSOProtocol, string> = { oidc: "OIDC", saml: "SAML 2.0" };

export const activeConnections = (connections: SSOConnection[]) =>
  connections.filter((connection) => connection.status === "active");

export const canActivate = (connection: SSOConnection) =>
  connection.status !== "active" && Boolean(connection.lastTest?.ok) && connection.status !== "draft";

export type EnforcementBlocker = "no_active_connection" | "not_signed_in_with_sso" | "session_secret_missing" | null;

// Enforcing SSO while signed in some other way would sign the admin out with no
// proven path back in, so the toggle stays locked until they hold an SSO session.
export function enforcementBlocker(input: {
  connections: SSOConnection[];
  currentSource?: string | null;
  status?: SSOStatus | null;
}): EnforcementBlocker {
  if (activeConnections(input.connections).length === 0) return "no_active_connection";
  if (input.status && !input.status.sessionSecretConfigured) return "session_secret_missing";
  if (input.currentSource !== "sso-session") return "not_signed_in_with_sso";
  return null;
}

export const enforcementBlockerCopy: Record<Exclude<EnforcementBlocker, null>, string> = {
  no_active_connection: "Turn on at least one tested connection first.",
  not_signed_in_with_sso: "Sign in through SSO first, so you know the connection lets you back in.",
  session_secret_missing: "Set CEREBRO_WEB_SESSION_SECRET on the web service first.",
};

export type PolicyErrors = Partial<Record<"sessionMaxLifetimeMinutes" | "sessionIdleTimeoutMinutes", string>>;

export function validatePolicy(policy: SSOPolicy): PolicyErrors {
  const errors: PolicyErrors = {};
  const max = policy.sessionMaxLifetimeMinutes;
  const idle = policy.sessionIdleTimeoutMinutes;
  if (!Number.isInteger(max) || max < 15 || max > 43200) errors.sessionMaxLifetimeMinutes = "Between 15 minutes and 30 days.";
  if (!Number.isInteger(idle) || idle < 5 || idle > 10080) {
    errors.sessionIdleTimeoutMinutes = "Between 5 minutes and 7 days.";
  } else if (!errors.sessionMaxLifetimeMinutes && idle > max) {
    errors.sessionIdleTimeoutMinutes = "Can't be longer than the session lifetime.";
  }
  return errors;
}

export const durationLabel = (minutes: number) => {
  if (minutes % 1440 === 0) return `${minutes / 1440} day${minutes === 1440 ? "" : "s"}`;
  if (minutes % 60 === 0) return `${minutes / 60} hour${minutes === 60 ? "" : "s"}`;
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
};

export const testLoginHref = (connectionId: string) =>
  `/api/auth/sso/start?${new URLSearchParams({ connection: connectionId, test: "1", returnTo: "/admin/access?tab=sso" })}`;

export class IdentityAdminError extends Error {
  constructor(message: string, readonly status: number, readonly code?: string) {
    super(message);
  }
}

const errorCopy: Record<string, string> = {
  connection_not_tested: "Test sign-in with this connection before turning it on.",
  no_active_connection: "Turn on at least one tested connection before requiring SSO.",
  domain_conflict: "Another connection already uses one of these domains.",
};

export async function identityAdminFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api/admin/identity${path}`, {
    cache: "no-store",
    ...init,
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (!response.ok) {
    const record = (body && typeof body === "object" ? body : {}) as { error?: unknown; code?: unknown };
    const code = typeof record.code === "string" ? record.code : typeof record.error === "string" && /^[a-z_]+$/.test(record.error) ? record.error : undefined;
    const message =
      (code && errorCopy[code]) ||
      (typeof record.error === "string" && !/^[a-z_]+$/.test(record.error) ? record.error : "") ||
      (response.status === 403 ? "You need the identity:admin permission to change sign-in settings." : `Request failed (HTTP ${response.status}).`);
    throw new IdentityAdminError(message, response.status, code);
  }
  return body as T;
}

export const jsonBody = (value: unknown): RequestInit => ({ body: JSON.stringify(value) });
