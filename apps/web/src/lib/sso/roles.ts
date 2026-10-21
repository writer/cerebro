import { knownAuthorizationRoles } from "@/lib/rbac";

import type { SSOConnection } from "./types";

/**
 * roles = defaultRoles ∪ this connection's group mappings, restricted to role names that have a built-in
 * permission bundle. CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS is deliberately not applied: every connected IdP (and
 * its SCIM client) controls its own group names, so a global name-based mapping would let any of them mint
 * roles meant for another.
 */
export const computeSessionRoles = (
  connection: Pick<SSOConnection, "defaultRoles" | "roleMappings">,
  groups: string[],
): string[] => {
  const normalizedGroups = new Set(groups.map((group) => group.trim().toLowerCase()).filter(Boolean));
  const mapped = (connection.roleMappings ?? [])
    .filter((mapping) => normalizedGroups.has((mapping.group ?? "").trim().toLowerCase()))
    .flatMap((mapping) => mapping.roles ?? []);
  return knownAuthorizationRoles([...(connection.defaultRoles ?? []), ...mapped]);
};

export const emailDomain = (email: string) => {
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return "";
  return email.slice(at + 1).trim().toLowerCase().replace(/\.$/, "");
};

export const connectionAllowsEmail = (connection: Pick<SSOConnection, "domains">, email: string) => {
  const domain = emailDomain(email);
  if (!domain) return false;
  return (connection.domains ?? []).some((candidate) => candidate.trim().toLowerCase() === domain);
};

/** Picks the active connection that owns an email domain. Domains are unique across connections in Go. */
export const connectionForEmail = <T extends Pick<SSOConnection, "domains" | "status">>(connections: T[], email: string) => {
  const domain = emailDomain(email);
  if (!domain) return null;
  return connections.find((connection) =>
    connection.status === "active" && (connection.domains ?? []).some((candidate) => candidate.trim().toLowerCase() === domain),
  ) ?? null;
};
