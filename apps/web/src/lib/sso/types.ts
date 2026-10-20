export type SSOProtocol = "oidc" | "saml";
export type SSOConnectionStatus = "draft" | "tested" | "active" | "disabled";

export type SSOOidcConfig = {
  issuer: string;
  clientId: string;
  clientSecretRef: string;
  scopes: string[];
  groupsClaim: string;
};

export type SSOSamlConfig = {
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

export type SSOConnection = {
  id: string;
  name: string;
  protocol: SSOProtocol;
  status: SSOConnectionStatus;
  domains: string[];
  oidc?: SSOOidcConfig;
  saml?: SSOSamlConfig;
  roleMappings: { group: string; roles: string[] }[];
  defaultRoles: string[];
  jitProvisioning: boolean;
  managed?: boolean;
  lastTest?: { at: string; ok: boolean; actor: string; detail: string };
  createdAt: string;
  updatedAt: string;
  updatedBy: string;
};

export type SSOPolicy = {
  enforced: boolean;
  sessionMaxLifetimeMinutes: number;
  sessionIdleTimeoutMinutes: number;
  updatedAt?: string;
  updatedBy?: string;
};

export const DEFAULT_SSO_POLICY: SSOPolicy = {
  enforced: false,
  sessionMaxLifetimeMinutes: 720,
  sessionIdleTimeoutMinutes: 60,
};

export type SSOSession = {
  id: string;
  connectionId: string;
  subject: string;
  email: string;
  name: string;
  groups: string[];
  roles: string[];
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  idleTimeoutMinutes: number;
};

export type SSOSessionCreate = {
  tokenHash: string;
  connectionId: string;
  subject: string;
  email: string;
  name: string;
  groups: string[];
  roles: string[];
  expiresAt: string;
  idleTimeoutMinutes: number;
  userAgent?: string;
  ipHash?: string;
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

/** Identity asserted by the IdP after protocol validation, before Cerebro policy checks. */
export type AssertedIdentity = {
  subject: string;
  email: string;
  name: string;
  groups: string[];
};

export type LoginErrorCode =
  | "access_denied"
  | "domain_not_allowed"
  | "not_provisioned"
  | "expired"
  | "invalid_response"
  | "misconfigured";

export const LOGIN_ERROR_CODES: readonly LoginErrorCode[] = [
  "access_denied",
  "domain_not_allowed",
  "not_provisioned",
  "expired",
  "invalid_response",
  "misconfigured",
];

export class LoginError extends Error {
  code: LoginErrorCode;

  constructor(code: LoginErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}
