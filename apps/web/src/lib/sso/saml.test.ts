import { generateKeyPairSync } from "crypto";
import { signSamlPost } from "@node-saml/node-saml/lib/saml-post-signing";
import { describe, expect, it } from "vitest";

import { finishSamlLogin, samlServiceProvider } from "./saml";
import { LoginError, type SSOConnection } from "./types";

const ORIGIN = "https://cerebro.example.com";
const IDP_ENTITY_ID = "https://idp.example.com/metadata";
const REQUEST_ID = "_request-bound-to-this-browser";

const idpKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const otherKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = (key: typeof idpKeys.publicKey) => key.export({ type: "spki", format: "pem" }).toString();
const privatePem = (key: typeof idpKeys.privateKey) => key.export({ type: "pkcs8", format: "pem" }).toString();

const connection: SSOConnection = {
  id: "conn-saml",
  name: "Example SAML",
  protocol: "saml",
  status: "active",
  domains: ["example.com"],
  saml: {
    idpEntityId: IDP_ENTITY_ID,
    idpSsoUrl: "https://idp.example.com/sso",
    idpCertificates: [pem(idpKeys.publicKey)],
    wantAssertionsSigned: true,
    emailAttribute: "email",
    nameAttribute: "name",
    groupsAttribute: "groups",
    nameIdFormat: "",
  },
  roleMappings: [],
  defaultRoles: [],
  jitProvisioning: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  updatedBy: "test",
};

const sp = samlServiceProvider(ORIGIN);

type ResponseOptions = {
  inResponseTo?: string | null;
  destination?: string;
  audience?: string;
  issuer?: string;
  notOnOrAfter?: Date;
  signingKey?: string | null;
};

const samlResponse = ({
  inResponseTo = REQUEST_ID,
  destination = sp.acsUrl,
  audience = sp.entityId,
  issuer = IDP_ENTITY_ID,
  notOnOrAfter = new Date(Date.now() + 5 * 60_000),
  signingKey = privatePem(idpKeys.privateKey),
}: ResponseOptions = {}) => {
  const now = new Date().toISOString();
  const later = notOnOrAfter.toISOString();
  const before = new Date(notOnOrAfter.getTime() - 10 * 60_000).toISOString();
  const irt = inResponseTo === null ? "" : ` InResponseTo="${inResponseTo}"`;
  const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion1" Version="2.0" IssueInstant="${now}"><saml:Issuer>${issuer}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">Jane.Doe@Example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${irt} NotOnOrAfter="${later}" Recipient="${sp.acsUrl}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${before}" NotOnOrAfter="${later}"><saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${now}" SessionIndex="_session1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>Jane.Doe@Example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="name"><saml:AttributeValue>Jane Doe</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue>security</saml:AttributeValue><saml:AttributeValue>eng</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`;
  const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response1" Version="2.0" IssueInstant="${now}" Destination="${destination}"${irt}><saml:Issuer>${issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${assertion}</samlp:Response>`;
  const signed = signingKey
    ? signSamlPost(response, "/*[local-name(.)='Response']/*[local-name(.)='Assertion']", {
      privateKey: signingKey,
      signatureAlgorithm: "sha256",
      digestAlgorithm: "sha256",
    })
    : response;
  return Buffer.from(signed, "utf8").toString("base64");
};

const tx = { samlRequestId: REQUEST_ID, createdAt: new Date().toISOString() };

const loginErrorCode = async (promise: Promise<unknown>) => {
  const error = await promise.then(() => null, (err: unknown) => err);
  expect(error).toBeInstanceOf(LoginError);
  return (error as LoginError).code;
};

describe("finishSamlLogin", () => {
  it("accepts a signed assertion that answers this browser's request", async () => {
    await expect(finishSamlLogin(connection, ORIGIN, samlResponse(), tx)).resolves.toEqual({
      subject: "Jane.Doe@Example.com",
      email: "jane.doe@example.com",
      name: "Jane Doe",
      groups: ["security", "eng"],
    });
  });

  it("rejects unsolicited IdP-initiated responses", async () => {
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, samlResponse({ inResponseTo: null }), tx))).toBe("invalid_response");
  });

  it("rejects a response to a different request", async () => {
    const other = samlResponse({ inResponseTo: "_some-other-request" });
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, other, tx))).toBe("invalid_response");
  });

  it("rejects when the browser has no pending SAML request", async () => {
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, samlResponse(), { createdAt: tx.createdAt }))).toBe("invalid_response");
  });

  it("rejects unsigned assertions and signatures from another key", async () => {
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, samlResponse({ signingKey: null }), tx))).toBe("invalid_response");
    const forged = samlResponse({ signingKey: privatePem(otherKeys.privateKey) });
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, forged, tx))).toBe("invalid_response");
  });

  it("rejects a wrong audience, issuer, or Destination", async () => {
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, samlResponse({ audience: "https://other-sp.example.com" }), tx))).toBe("invalid_response");
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, samlResponse({ issuer: "https://evil-idp.example.com" }), tx))).toBe("invalid_response");
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, samlResponse({ destination: "https://other-sp.example.com/acs" }), tx))).toBe("invalid_response");
  });

  it("rejects expired assertions", async () => {
    const expired = samlResponse({ notOnOrAfter: new Date(Date.now() - 10 * 60_000) });
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, expired, tx))).not.toBeNull();
  });

  it("rejects documents with a DOCTYPE", async () => {
    const xml = Buffer.from(samlResponse(), "base64").toString("utf8");
    const withDoctype = Buffer.from(`<!DOCTYPE r [<!ENTITY x "y">]>${xml}`, "utf8").toString("base64");
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, withDoctype, tx))).toBe("invalid_response");
  });
});
