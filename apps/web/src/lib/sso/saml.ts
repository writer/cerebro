import { randomBytes } from "crypto";
import {
  generateServiceProviderMetadata,
  SAML,
  SamlStatusError,
  ValidateInResponseTo,
  type CacheProvider,
  type Profile,
} from "@node-saml/node-saml";
import { parseDomFromString, xpath } from "@node-saml/node-saml/lib/xml";

import { ssoRoutes } from "./config";
import { AssertionReplayedError, consumeSamlAssertion } from "./identity-api";
import { LoginError, type AssertedIdentity, type SSOConnection, type SSOSamlConfig } from "./types";

const CLOCK_SKEW_MS = 120_000;
const REQUEST_ID_TTL_MS = 10 * 60_000;
const DEFAULT_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

const requireSaml = (connection: SSOConnection): SSOSamlConfig => {
  if (connection.protocol !== "saml" || !connection.saml) {
    throw new LoginError("misconfigured", "Connection is not a SAML connection.");
  }
  if (!connection.saml.idpCertificates?.length) {
    throw new LoginError("misconfigured", "SAML connection has no IdP signing certificate.");
  }
  return connection.saml;
};

export const samlServiceProvider = (origin: string) => {
  const routes = ssoRoutes(origin);
  return { entityId: routes.samlEntityId, acsUrl: routes.samlAcsUrl };
};

/** Cache provider that knows exactly one request id: the one bound to this browser's transaction cookie. */
export const transactionCacheProvider = (requestId: string | undefined, createdAt: string): CacheProvider => ({
  saveAsync: async () => null,
  getAsync: async (key: string) => (requestId && key === requestId ? createdAt : null),
  removeAsync: async () => null,
});

const noopCacheProvider: CacheProvider = {
  saveAsync: async (_key: string, value: string) => ({ value, createdAt: Date.now() }),
  getAsync: async () => null,
  removeAsync: async () => null,
};

export const samlClientFor = (
  connection: SSOConnection,
  origin: string,
  cacheProvider: CacheProvider = noopCacheProvider,
  generateUniqueId?: () => string,
) => {
  const saml = requireSaml(connection);
  const sp = samlServiceProvider(origin);
  const wantAssertionsSigned = saml.wantAssertionsSigned !== false;
  return new SAML({
    entryPoint: saml.idpSsoUrl,
    issuer: sp.entityId,
    callbackUrl: sp.acsUrl,
    audience: sp.entityId,
    idpCert: saml.idpCertificates,
    idpIssuer: saml.idpEntityId,
    // Some signature is always required: the assertion's by default, otherwise the whole response's.
    wantAssertionsSigned,
    wantAuthnResponseSigned: !wantAssertionsSigned,
    acceptedClockSkewMs: CLOCK_SKEW_MS,
    identifierFormat: saml.nameIdFormat || DEFAULT_NAME_ID_FORMAT,
    disableRequestedAuthnContext: true,
    validateInResponseTo: ValidateInResponseTo.always,
    requestIdExpirationPeriodMs: REQUEST_ID_TTL_MS,
    cacheProvider,
    signatureAlgorithm: "sha256",
    ...(generateUniqueId ? { generateUniqueId } : {}),
  });
};

export const generateSamlRequestId = () => `_${randomBytes(20).toString("hex")}`;

export const startSamlLogin = async (connection: SSOConnection, origin: string) => {
  const requestId = generateSamlRequestId();
  const client = samlClientFor(connection, origin, noopCacheProvider, () => requestId);
  const url = await client.getAuthorizeUrlAsync("", undefined, {});
  return { url: new URL(url), requestId };
};

/** SP metadata does not depend on IdP settings, so it is available before the IdP side is configured. */
export const samlServiceProviderMetadata = (origin: string, saml?: Pick<SSOSamlConfig, "nameIdFormat" | "wantAssertionsSigned">) => {
  const sp = samlServiceProvider(origin);
  return generateServiceProviderMetadata({
    issuer: sp.entityId,
    callbackUrl: sp.acsUrl,
    identifierFormat: saml?.nameIdFormat || DEFAULT_NAME_ID_FORMAT,
    wantAssertionsSigned: saml?.wantAssertionsSigned !== false,
  });
};

const attributeValues = (profile: Profile, name: string): string[] => {
  if (!name) return [];
  const attributes = (profile.attributes ?? {}) as Record<string, unknown>;
  const raw = Object.hasOwn(attributes, name) ? attributes[name] : undefined;
  const values = Array.isArray(raw) ? raw : raw === undefined ? [] : [raw];
  return values.filter((value): value is string => typeof value === "string").map((value) => value.trim()).filter(Boolean);
};

const looksLikeEmail = (value: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

export const identityFromSamlProfile = (profile: Profile, saml: SSOSamlConfig): AssertedIdentity => {
  const nameId = typeof profile.nameID === "string" ? profile.nameID.trim() : "";
  const email = attributeValues(profile, saml.emailAttribute || "email")[0] || (looksLikeEmail(nameId) ? nameId : "");
  if (!email || !looksLikeEmail(email)) {
    throw new LoginError("invalid_response", "The SAML assertion did not include an email address.");
  }
  const name = attributeValues(profile, saml.nameAttribute || "name")[0] || email;
  const groups = Array.from(new Set(attributeValues(profile, saml.groupsAttribute || "groups")));
  return { subject: nameId || email, email: email.toLowerCase(), name, groups };
};

/**
 * Defense in depth beyond node-saml: no DTDs at all (xmldom only warns about them), and a present Destination
 * must name our ACS URL exactly.
 */
const assertResponseShape = async (samlResponse: string, acsUrl: string) => {
  const xml = Buffer.from(samlResponse, "base64").toString("utf8");
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) {
    throw new LoginError("invalid_response", "SAML responses must not contain a document type declaration.");
  }
  const doc = await parseDomFromString(xml);
  const destinations = xpath.selectAttributes(doc, "/*[local-name()='Response']/@Destination");
  const destination = destinations[0]?.nodeValue;
  if (destination && destination !== acsUrl) {
    throw new LoginError("invalid_response", "SAML response Destination does not match this service provider.");
  }
};

const BEARER_METHOD = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

export type VerifiedBearerAssertion = {
  assertionId: string;
  notOnOrAfter: string;
};

/**
 * SAML Profiles §4.1.4.3: checks the bearer SubjectConfirmationData inside the signature-verified assertion.
 * node-saml reads InResponseTo from the outer Response (unsigned when only the assertion is signed) and skips
 * the assertion-level comparison when the assertion omits it, so this is the binding that actually counts.
 */
export const verifyBearerConfirmation = async (
  assertionXml: string,
  requestId: string,
  acsUrl: string,
  nowMs = Date.now(),
): Promise<VerifiedBearerAssertion> => {
  let doc: Document;
  try {
    doc = await parseDomFromString(assertionXml);
  } catch {
    throw new LoginError("invalid_response", "The verified SAML assertion could not be parsed.");
  }
  const assertion = doc.documentElement;
  if (!assertion || assertion.localName !== "Assertion") {
    throw new LoginError("invalid_response", "The verified SAML data is not an assertion.");
  }
  const assertionId = assertion.getAttribute("ID")?.trim() ?? "";
  if (!assertionId) throw new LoginError("invalid_response", "The SAML assertion has no ID.");
  const confirmations = xpath
    .selectElements(assertion, "./*[local-name()='Subject']/*[local-name()='SubjectConfirmation']")
    .filter((confirmation) => confirmation.getAttribute("Method") === BEARER_METHOD)
    .flatMap((confirmation) => xpath.selectElements(confirmation, "./*[local-name()='SubjectConfirmationData']"));
  const matching = confirmations.filter((data) => {
    const notOnOrAfterMs = Date.parse(data.getAttribute("NotOnOrAfter") ?? "");
    return (
      data.getAttribute("InResponseTo") === requestId &&
      data.getAttribute("Recipient") === acsUrl &&
      Number.isFinite(notOnOrAfterMs) &&
      notOnOrAfterMs > nowMs
    );
  });
  if (matching.length !== 1) {
    throw new LoginError("invalid_response", "The SAML assertion is not a bearer assertion for this browser's request.");
  }
  return {
    assertionId,
    notOnOrAfter: new Date(Date.parse(matching[0].getAttribute("NotOnOrAfter") ?? "")).toISOString(),
  };
};

const mapSamlError = (error: unknown): never => {
  if (error instanceof LoginError) throw error;
  if (error instanceof SamlStatusError) {
    throw new LoginError("access_denied", "The identity provider did not authenticate the user.");
  }
  const message = error instanceof Error ? error.message : "";
  if (/expired/i.test(message)) throw new LoginError("expired", "The SAML assertion has expired.");
  throw new LoginError("invalid_response", "The SAML response could not be validated.");
};

/**
 * Validates an HTTP-POST SAMLResponse: IdP signature, issuer, audience, time window, the signed bearer
 * confirmation (InResponseTo bound to the transaction cookie, Recipient, NotOnOrAfter), and one-time use of
 * the assertion. Unsolicited (IdP-initiated) responses have no InResponseTo and are rejected.
 */
export const finishSamlLogin = async (
  connection: SSOConnection,
  origin: string,
  samlResponse: string,
  tx: { samlRequestId?: string; createdAt: string },
): Promise<AssertedIdentity> => {
  const saml = requireSaml(connection);
  if (!tx.samlRequestId) throw new LoginError("invalid_response", "No SAML request is pending for this browser.");
  const client = samlClientFor(connection, origin, transactionCacheProvider(tx.samlRequestId, tx.createdAt));
  let profile: Profile | null;
  try {
    await assertResponseShape(samlResponse, samlServiceProvider(origin).acsUrl);
    const result = await client.validatePostResponseAsync({ SAMLResponse: samlResponse });
    if (result.loggedOut) throw new LoginError("invalid_response", "Unexpected SAML logout response.");
    profile = result.profile;
  } catch (error) {
    return mapSamlError(error);
  }
  if (!profile) throw new LoginError("invalid_response", "The SAML response did not contain an assertion.");
  if (profile.inResponseTo !== tx.samlRequestId) {
    throw new LoginError("invalid_response", "SAML response does not answer this browser's request.");
  }
  // node-saml only compares idpIssuer on logout messages; profile.issuer comes from the signed assertion.
  if (saml.idpEntityId && profile.issuer !== saml.idpEntityId) {
    throw new LoginError("invalid_response", "SAML assertion issuer does not match the configured IdP entity ID.");
  }
  const assertionXml = typeof profile.getAssertionXml === "function" ? profile.getAssertionXml() : "";
  if (!assertionXml) throw new LoginError("invalid_response", "The SAML response did not contain a verified assertion.");
  const bearer = await verifyBearerConfirmation(assertionXml, tx.samlRequestId, samlServiceProvider(origin).acsUrl);
  const identity = identityFromSamlProfile(profile, saml);
  try {
    await consumeSamlAssertion({
      connectionId: connection.id,
      assertionId: bearer.assertionId,
      requestId: tx.samlRequestId,
      notOnOrAfter: bearer.notOnOrAfter,
    });
  } catch (error) {
    if (error instanceof AssertionReplayedError) {
      throw new LoginError("invalid_response", "This SAML assertion or request was already used.");
    }
    throw error;
  }
  return identity;
};
