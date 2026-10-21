import { generateKeyPairSync } from "crypto";
import { signSamlPost } from "@node-saml/node-saml/lib/saml-post-signing";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { LoginError, type SSOConnection } from "./types";

const replay = vi.hoisted(() => ({
  consumed: [] as { connectionId: string; assertionId: string; requestId: string; notOnOrAfter: string }[],
}));

vi.mock("./identity-api", () => {
  class AssertionReplayedError extends Error {}
  return {
    AssertionReplayedError,
    // Mirrors Go: an assertion id (per connection) or a request id is accepted once.
    consumeSamlAssertion: vi.fn(async (input: (typeof replay.consumed)[number]) => {
      const seen = replay.consumed.some(
        (entry) =>
          (entry.connectionId === input.connectionId && entry.assertionId === input.assertionId) || entry.requestId === input.requestId,
      );
      if (seen) throw new AssertionReplayedError("replayed");
      replay.consumed.push(input);
    }),
  };
});

const { finishSamlLogin, samlServiceProvider, verifyBearerConfirmation } = await import("./saml");

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
  /** Bearer SubjectConfirmationData InResponseTo inside the signed assertion; defaults to inResponseTo. */
  assertionInResponseTo?: string | null;
  recipient?: string;
  assertionId?: string;
  destination?: string;
  audience?: string;
  issuer?: string;
  notOnOrAfter?: Date;
  signingKey?: string | null;
};

let assertionCounter = 0;

const samlResponse = ({
  inResponseTo = REQUEST_ID,
  assertionInResponseTo,
  recipient = sp.acsUrl,
  assertionId = `_assertion${++assertionCounter}`,
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
  const subjectIrtValue = assertionInResponseTo === undefined ? inResponseTo : assertionInResponseTo;
  const subjectIrt = subjectIrtValue === null ? "" : ` InResponseTo="${subjectIrtValue}"`;
  const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${now}"><saml:Issuer>${issuer}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">Jane.Doe@Example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${subjectIrt} NotOnOrAfter="${later}" Recipient="${recipient}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${before}" NotOnOrAfter="${later}"><saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${now}" SessionIndex="_session1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>Jane.Doe@Example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="name"><saml:AttributeValue>Jane Doe</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue>security</saml:AttributeValue><saml:AttributeValue>eng</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`;
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

beforeEach(() => {
  replay.consumed = [];
});

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

  it("records the verified assertion id, request id, and bearer NotOnOrAfter as consumed", async () => {
    await finishSamlLogin(connection, ORIGIN, samlResponse({ assertionId: "_consumed-once" }), tx);
    expect(replay.consumed).toEqual([
      expect.objectContaining({ connectionId: "conn-saml", assertionId: "_consumed-once", requestId: REQUEST_ID }),
    ]);
    expect(Date.parse(replay.consumed[0].notOnOrAfter)).toBeGreaterThan(Date.now());
  });

  it("rejects a replayed response", async () => {
    const response = samlResponse();
    await expect(finishSamlLogin(connection, ORIGIN, response, tx)).resolves.toMatchObject({ email: "jane.doe@example.com" });
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, response, tx))).toBe("invalid_response");
  });

  it("rejects a second assertion for an already answered request", async () => {
    await finishSamlLogin(connection, ORIGIN, samlResponse(), tx);
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, samlResponse(), tx))).toBe("invalid_response");
  });

  it("rejects a signed assertion without InResponseTo even when the unsigned Response carries the request id", async () => {
    const unsolicited = samlResponse({ inResponseTo: REQUEST_ID, assertionInResponseTo: null });
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, unsolicited, tx))).toBe("invalid_response");
    expect(replay.consumed).toEqual([]);
  });

  it("rejects when the outer Response and the signed assertion name different requests", async () => {
    const assertionForOther = samlResponse({ inResponseTo: REQUEST_ID, assertionInResponseTo: "_some-other-request" });
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, assertionForOther, tx))).toBe("invalid_response");
    const outerForOther = samlResponse({ inResponseTo: "_some-other-request", assertionInResponseTo: REQUEST_ID });
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, outerForOther, tx))).toBe("invalid_response");
    expect(replay.consumed).toEqual([]);
  });

  it("rejects a signed bearer Recipient naming another ACS URL", async () => {
    const elsewhere = samlResponse({ recipient: "https://other-sp.example.com/api/auth/saml/acs" });
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, elsewhere, tx))).toBe("invalid_response");
    expect(replay.consumed).toEqual([]);
  });

  it("rejects documents with a DOCTYPE", async () => {
    const xml = Buffer.from(samlResponse(), "base64").toString("utf8");
    const withDoctype = Buffer.from(`<!DOCTYPE r [<!ENTITY x "y">]>${xml}`, "utf8").toString("base64");
    expect(await loginErrorCode(finishSamlLogin(connection, ORIGIN, withDoctype, tx))).toBe("invalid_response");
  });
});

const assertionXml = (attributes: string, method = "urn:oasis:names:tc:SAML:2.0:cm:bearer", id = ' ID="_a1"') =>
  `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"${id} Version="2.0"><saml:Subject><saml:NameID>a@example.com</saml:NameID><saml:SubjectConfirmation Method="${method}"><saml:SubjectConfirmationData ${attributes}/></saml:SubjectConfirmation></saml:Subject></saml:Assertion>`;

describe("verifyBearerConfirmation", () => {
  const later = new Date(Date.now() + 5 * 60_000).toISOString();
  const valid = `InResponseTo="${REQUEST_ID}" Recipient="${sp.acsUrl}" NotOnOrAfter="${later}"`;

  it("returns the assertion id and NotOnOrAfter for a matching bearer confirmation", async () => {
    await expect(verifyBearerConfirmation(assertionXml(valid), REQUEST_ID, sp.acsUrl)).resolves.toEqual({
      assertionId: "_a1",
      notOnOrAfter: later,
    });
  });

  it("rejects an expired NotOnOrAfter, a missing NotOnOrAfter, and a missing InResponseTo", async () => {
    const afterExpiry = Date.parse(later) + 1;
    expect(await loginErrorCode(verifyBearerConfirmation(assertionXml(valid), REQUEST_ID, sp.acsUrl, afterExpiry))).toBe("invalid_response");
    const noExpiry = `InResponseTo="${REQUEST_ID}" Recipient="${sp.acsUrl}"`;
    expect(await loginErrorCode(verifyBearerConfirmation(assertionXml(noExpiry), REQUEST_ID, sp.acsUrl))).toBe("invalid_response");
    const noIrt = `Recipient="${sp.acsUrl}" NotOnOrAfter="${later}"`;
    expect(await loginErrorCode(verifyBearerConfirmation(assertionXml(noIrt), REQUEST_ID, sp.acsUrl))).toBe("invalid_response");
  });

  it("rejects non-bearer confirmations and assertions without an ID", async () => {
    const holderOfKey = assertionXml(valid, "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
    expect(await loginErrorCode(verifyBearerConfirmation(holderOfKey, REQUEST_ID, sp.acsUrl))).toBe("invalid_response");
    expect(await loginErrorCode(verifyBearerConfirmation(assertionXml(valid, undefined, ""), REQUEST_ID, sp.acsUrl))).toBe("invalid_response");
  });
});
