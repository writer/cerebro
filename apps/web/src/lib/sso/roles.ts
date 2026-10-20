import { knownAuthorizationRoles, roleClaimMappings, rolesFromClaimMappings, type RoleClaimMapping } from "@/lib/rbac";

import type { SSOConnection } from "./types";

/**
 * roles = defaultRoles ∪ connection group mappings ∪ CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS (groups), restricted
 * to role names that have a built-in permission bundle.
 */
export const computeSessionRoles = (
  connection: Pick<SSOConnection, "defaultRoles" | "roleMappings">,
  groups: string[],
  envMappings: RoleClaimMapping[] = roleClaimMappings(),
): string[] => {
  const normalizedGroups = new Set(groups.map((group) => group.trim().toLowerCase()).filter(Boolean));
  const mapped = (connection.roleMappings ?? [])
    .filter((mapping) => normalizedGroups.has((mapping.group ?? "").trim().toLowerCase()))
    .flatMap((mapping) => mapping.roles ?? []);
  const fromEnv = rolesFromClaimMappings(
    {
      actorId: "",
      actorLabel: "",
      confidence: "signature-verified",
      displayName: "",
      initials: "",
      source: "sso-session",
      entitlements: { groups: Array.from(normalizedGroups) },
    },
    envMappings.filter((mapping) => mapping.claim === "groups"),
  );
  return knownAuthorizationRoles([...(connection.defaultRoles ?? []), ...mapped, ...fromEnv]);
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
