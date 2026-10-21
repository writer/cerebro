import { parseDomFromString, xpath } from "@node-saml/node-saml/lib/xml";

import { safeFetch } from "./safe-fetch";

export const MAX_METADATA_BYTES = 1024 * 1024;
const METADATA_FETCH_TIMEOUT_MS = 5_000;
const MAX_CERTIFICATES = 3;
const REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

export class MetadataError extends Error {}

export type ParsedIdpMetadata = {
  idpEntityId: string;
  idpSsoUrl: string;
  idpCertificates: string[];
};

const toPem = (base64: string) => {
  const body = base64.replace(/\s+/g, "");
  if (!body || !/^[A-Za-z0-9+/=]+$/.test(body)) return null;
  const lines = body.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
};

/**
 * Extracts IdP settings from SAML metadata. Documents with a DOCTYPE are refused outright, which rules out
 * external entities and entity-expansion attacks regardless of parser behavior.
 */
export const parseIdpMetadata = async (xml: string): Promise<ParsedIdpMetadata> => {
  if (Buffer.byteLength(xml, "utf8") > MAX_METADATA_BYTES) throw new MetadataError("Metadata is larger than 1 MB.");
  if (/<!DOCTYPE/i.test(xml) || /<!ENTITY/i.test(xml)) throw new MetadataError("Metadata must not contain a DOCTYPE.");
  let doc: Document;
  try {
    doc = await parseDomFromString(xml);
  } catch {
    throw new MetadataError("Metadata is not well-formed XML.");
  }
  const descriptors = xpath.selectElements(
    doc,
    "//*[local-name()='EntityDescriptor'][*[local-name()='IDPSSODescriptor']]",
  );
  const descriptor = descriptors[0];
  if (!descriptor) throw new MetadataError("Metadata does not describe a SAML identity provider.");
  const idpEntityId = descriptor.getAttribute("entityID")?.trim() ?? "";
  if (!idpEntityId) throw new MetadataError("Metadata is missing the IdP entityID.");

  const idp = xpath.selectElements(descriptor, "./*[local-name()='IDPSSODescriptor']")[0];
  const ssoServices = xpath.selectElements(idp, "./*[local-name()='SingleSignOnService']");
  const redirect = ssoServices.find((service) => service.getAttribute("Binding") === REDIRECT_BINDING);
  const idpSsoUrl = redirect?.getAttribute("Location")?.trim() ?? "";
  if (!idpSsoUrl) throw new MetadataError("Metadata has no HTTP-Redirect SingleSignOnService.");
  try {
    if (new URL(idpSsoUrl).protocol !== "https:") throw new Error("not https");
  } catch {
    throw new MetadataError("The IdP SSO URL must be an https URL.");
  }

  const keyDescriptors = xpath
    .selectElements(idp, "./*[local-name()='KeyDescriptor']")
    .filter((key) => {
      const use = key.getAttribute("use");
      return !use || use === "signing";
    });
  const certificates: string[] = [];
  for (const key of keyDescriptors) {
    for (const cert of xpath.selectElements(key, ".//*[local-name()='X509Certificate']")) {
      const pem = toPem(cert.textContent ?? "");
      if (pem && !certificates.includes(pem)) certificates.push(pem);
    }
  }
  if (certificates.length === 0) throw new MetadataError("Metadata has no signing certificate.");
  return { idpEntityId, idpSsoUrl, idpCertificates: certificates.slice(0, MAX_CERTIFICATES) };
};

export const fetchIdpMetadata = async (url: string) => {
  const response = await safeFetch(url, { headers: { Accept: "application/samlmetadata+xml, application/xml, text/xml" } }, {
    timeoutMs: METADATA_FETCH_TIMEOUT_MS,
    maxBytes: MAX_METADATA_BYTES,
  });
  if (!response.ok) throw new MetadataError(`Metadata URL returned status ${response.status}.`);
  return response.text();
};
