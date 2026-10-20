import { createHash } from "crypto";

const MIN_SESSION_SECRET_BYTES = 32;

const truthy = (value: string | undefined) =>
  ["1", "true", "yes", "on"].includes((value ?? "").trim().toLowerCase());

export const isDevelopment = () => process.env.NODE_ENV === "development";

/**
 * Set when nothing in front of the console authenticates users (no ALB OIDC). Proxy identity headers are then
 * forgeable by any caller, so SSO is enforced regardless of the stored policy and break-glass is refused.
 */
export const ssoRequired = () => truthy(process.env.CEREBRO_SSO_REQUIRED);

export const ssoBreakGlassRequested = () => truthy(process.env.CEREBRO_SSO_BREAK_GLASS);

export const ssoBreakGlassEnabled = () => ssoBreakGlassRequested() && !ssoRequired();

export const DEFAULT_OIDC_CALLBACK_PATH = "/api/auth/oidc/callback";
// The path an AWS ALB OIDC listener uses, so an IdP app registered for the ALB can be reused unchanged.
export const ALB_OIDC_CALLBACK_PATH = "/oauth2/idpresponse";

export const oidcCallbackPath = () => {
  const configured = (process.env.CEREBRO_SSO_OIDC_CALLBACK_PATH ?? "").trim();
  return configured === ALB_OIDC_CALLBACK_PATH ? ALB_OIDC_CALLBACK_PATH : DEFAULT_OIDC_CALLBACK_PATH;
};

/** Raw bytes of CEREBRO_WEB_SESSION_SECRET, or null when it is unset or shorter than 32 bytes. */
export const sessionSecretBytes = (): Uint8Array | null => {
  const raw = process.env.CEREBRO_WEB_SESSION_SECRET ?? "";
  const bytes = Buffer.from(raw, "utf8");
  if (bytes.byteLength < MIN_SESSION_SECRET_BYTES) return null;
  return new Uint8Array(bytes);
};

export const sessionSecretConfigured = () => sessionSecretBytes() !== null;

const parsePublicOrigin = (value: string | undefined) => {
  const trimmed = (value ?? "").trim();
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (url.username || url.password) return null;
    if (url.protocol === "http:" && !isDevelopment()) return null;
    return url.origin;
  } catch {
    return null;
  }
};

export const configuredPublicOrigin = () => parsePublicOrigin(process.env.CEREBRO_WEB_PUBLIC_URL);

export const publicUrlConfigured = () => configuredPublicOrigin() !== null;

/**
 * External origin used for redirect URIs, the ACS URL, and the SP entity ID. The request origin is only
 * trusted in development: elsewhere the Host header is attacker-influenced and would let a crafted request
 * steer IdP redirects or SAML audience values.
 */
export const publicOrigin = (requestUrl?: string | URL | null) => {
  const configured = configuredPublicOrigin();
  if (configured) return configured;
  if (isDevelopment() && requestUrl) {
    try {
      return new URL(requestUrl).origin;
    } catch {
      return null;
    }
  }
  return null;
};

/** Cookies use the `__Host-` prefix and `Secure` everywhere except plain-http development. */
export const cookiesSecure = () => {
  const configured = configuredPublicOrigin();
  if (configured) return configured.startsWith("https:");
  return !isDevelopment();
};

export const SESSION_COOKIE_SECURE_NAME = "__Host-cerebro_session";
export const SESSION_COOKIE_DEV_NAME = "cerebro_session";
export const TX_COOKIE_SECURE_NAME = "__Host-cerebro_sso_tx";
export const TX_COOKIE_DEV_NAME = "cerebro_sso_tx";

export const sessionCookieName = () => (cookiesSecure() ? SESSION_COOKIE_SECURE_NAME : SESSION_COOKIE_DEV_NAME);
export const txCookieName = () => (cookiesSecure() ? TX_COOKIE_SECURE_NAME : TX_COOKIE_DEV_NAME);

export const ssoRoutes = (origin: string) => ({
  oidcRedirectUri: `${origin}${oidcCallbackPath()}`,
  samlAcsUrl: `${origin}/api/auth/saml/acs`,
  // Connection-independent so admins can copy it into the IdP before the connection exists. The tx cookie,
  // not the entity ID, decides which connection validates a SAML response.
  samlEntityId: `${origin}/api/auth/saml/metadata`,
  samlMetadataUrl: `${origin}/api/auth/saml/metadata`,
  scimBaseUrl: `${origin}/scim/v2`,
  loginUrl: `${origin}/login`,
});

/** IdP-initiated start URL for one connection; empty until the connection has an id. */
export const connectionStartUrl = (origin: string, connectionId: string) =>
  connectionId ? `${origin}/api/auth/sso/start?${new URLSearchParams({ connection: connectionId })}` : "";

/** Keyed hash for values (like client IPs) that should be correlatable without being stored in clear. */
export const keyedHash = (value: string) => {
  const secret = sessionSecretBytes();
  const hash = createHash("sha256");
  if (secret) hash.update(secret);
  return hash.update(value).digest("hex");
};

let startupNoticeLogged = false;

export const logSsoStartupNotice = () => {
  if (startupNoticeLogged) return;
  startupNoticeLogged = true;
  if (ssoBreakGlassEnabled()) {
    console.warn("CEREBRO_SSO_BREAK_GLASS is enabled: SSO policy enforcement is ignored and legacy identity headers are accepted.");
  } else if (ssoBreakGlassRequested()) {
    console.warn("CEREBRO_SSO_BREAK_GLASS is ignored because CEREBRO_SSO_REQUIRED is set.");
  }
};
