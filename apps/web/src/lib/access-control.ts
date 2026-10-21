export type AccessPermissionRow = {
  permission: string;
  requiredGroups: string[];
  requiredRoles: string[];
  requiredScopes: string[];
  restricted: boolean;
  granted: boolean;
};

export type AccessRole = { description: string; permissions: string[]; role: string };

export type AccessClaimMapping = { claim: string; value: string; roles: string[] };

export type AccessControl = {
  deployment: {
    builtinRbacRequired: boolean;
    globalRequiredGroups: string[];
    identityRequired: boolean;
  };
  permissions: AccessPermissionRow[];
  roleClaimMappings: AccessClaimMapping[];
  roles: AccessRole[];
  sampleMappings?: boolean;
  viewer: {
    confidence: string;
    entitlements: { groups?: string[]; roles?: string[]; scopes?: string[] };
    mappedRoles: string[];
    permissions: string[];
    provider: string;
  };
};

export type AccessRoleRow = AccessRole & {
  grantedTo: string[];
  yours: boolean;
};

const mappingLabel = (mapping: AccessClaimMapping) =>
  mapping.claim === "groups" ? mapping.value : `${mapping.claim}: ${mapping.value}`;

// Roles some group actually grants come first: those are the ones that decide
// who can do what in this deployment.
export function accessRoleRows(data: AccessControl): AccessRoleRow[] {
  const yourRoles = new Set(
    [...(data.viewer.entitlements.roles ?? []), ...data.viewer.mappedRoles].map((role) => role.toLowerCase()),
  );
  return data.roles
    .map((role) => ({
      ...role,
      grantedTo: data.roleClaimMappings.filter((mapping) => mapping.roles.includes(role.role)).map(mappingLabel),
      yours: yourRoles.has(role.role.toLowerCase()),
    }))
    .sort((a, b) => Number(b.grantedTo.length > 0) - Number(a.grantedTo.length > 0) || a.role.localeCompare(b.role));
}

export function deniedPermissions(data: AccessControl): string[] {
  return data.permissions.filter((row) => !row.granted).map((row) => row.permission);
}
