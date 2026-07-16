import type { CurrentUser } from "@/lib/identity";

export type AuthorizationPermission =
  | "agent:ask"
  | "cerebro:read"
  | "cerebro:write"
  | "identity:read"
  | "preferences:write"
  | "findings:write"
  | "grc:inventory:write"
  | "grc:policies:write"
  | "dashboards:write"
  | "connector-credentials:read"
  | "connector-credentials:write"
  | "connector-definitions:write"
  | "connectors:write"
  | "runtime-response:write"
  | "reports:run"
  | "knowledge:write"
  | "workflow:replay"
  | "sources:preview"
  | "source-runtimes:write"
  | "jobs:write";

const permissionOrder: AuthorizationPermission[] = [
  "identity:read",
  "agent:ask",
  "cerebro:read",
  "preferences:write",
  "cerebro:write",
  "findings:write",
  "grc:inventory:write",
  "grc:policies:write",
  "dashboards:write",
  "connector-credentials:read",
  "connector-credentials:write",
  "connector-definitions:write",
  "connectors:write",
  "runtime-response:write",
  "reports:run",
  "knowledge:write",
  "workflow:replay",
  "sources:preview",
  "source-runtimes:write",
  "jobs:write",
];

const allPermissions = permissionOrder;
const viewerPermissions: AuthorizationPermission[] = ["identity:read", "agent:ask", "cerebro:read", "preferences:write"];
const findingManagerPermissions: AuthorizationPermission[] = [
  ...viewerPermissions,
  "findings:write",
];
const grcReviewerPermissions: AuthorizationPermission[] = [
  ...viewerPermissions,
  "grc:inventory:write",
  "grc:policies:write",
  "dashboards:write",
];

const rolePermissionBundles: Record<string, AuthorizationPermission[]> = {
  "cerebro.viewer": viewerPermissions,
  viewer: viewerPermissions,
  reader: viewerPermissions,
  read_only: viewerPermissions,
  "cerebro.analyst": [
    ...viewerPermissions,
    "findings:write",
    "grc:inventory:write",
    "grc:policies:write",
    "dashboards:write",
  ],
  analyst: [
    ...viewerPermissions,
    "findings:write",
    "grc:inventory:write",
    "grc:policies:write",
    "dashboards:write",
  ],
  editor: [
    ...viewerPermissions,
    "findings:write",
    "grc:inventory:write",
    "grc:policies:write",
    "dashboards:write",
  ],
  "cerebro.finding_manager": findingManagerPermissions,
  "cerebro.grc_reviewer": grcReviewerPermissions,
  "cerebro.connector_manager": [
    ...viewerPermissions,
    "connector-credentials:read",
    "connector-credentials:write",
    "connector-definitions:write",
    "connectors:write",
  ],
  "cerebro.responder": [
    ...viewerPermissions,
    "runtime-response:write",
  ],
  "cerebro.source_manager": [
    ...viewerPermissions,
    "reports:run",
    "sources:preview",
    "source-runtimes:write",
  ],
  "cerebro.job_manager": [
    ...viewerPermissions,
    "jobs:write",
  ],
  "cerebro.admin": allPermissions,
  admin: allPermissions,
  owner: allPermissions,
};

const canonicalRoleLabels: Record<string, string> = {
  "cerebro.viewer": "cerebro.viewer",
  viewer: "cerebro.viewer",
  reader: "cerebro.viewer",
  read_only: "cerebro.viewer",
  "cerebro.analyst": "cerebro.analyst",
  analyst: "cerebro.analyst",
  editor: "cerebro.analyst",
  "cerebro.finding_manager": "cerebro.finding_manager",
  "cerebro.grc_reviewer": "cerebro.grc_reviewer",
  "cerebro.connector_manager": "cerebro.connector_manager",
  "cerebro.responder": "cerebro.responder",
  "cerebro.source_manager": "cerebro.source_manager",
  "cerebro.job_manager": "cerebro.job_manager",
  "cerebro.admin": "cerebro.admin",
  admin: "cerebro.admin",
  owner: "cerebro.admin",
};

const explicitCerebroRoles = new Set([
  "cerebro.viewer",
  "cerebro.analyst",
  "cerebro.finding_manager",
  "cerebro.grc_reviewer",
  "cerebro.connector_manager",
  "cerebro.responder",
  "cerebro.source_manager",
  "cerebro.job_manager",
  "cerebro.admin",
]);

const scopePermissionBundles: Record<string, AuthorizationPermission[]> = {
  "cerebro.cosmo.security.read": viewerPermissions,
  "cerebro.user_preferences.write": ["preferences:write"],
  "cerebro.finding_candidates.promote": ["findings:write"],
  "cerebro.findings.write": ["findings:write"],
  "cerebro.grc.inventory.write": ["grc:inventory:write"],
  "cerebro.grc.policy_lifecycle.write": ["grc:policies:write"],
  "cerebro.dashboards.write": ["dashboards:write"],
  "cerebro.connector_credentials.read": ["connector-credentials:read"],
  "cerebro.connector_credentials.write": ["connector-credentials:write"],
  "cerebro.runtime_response.write": ["runtime-response:write"],
  "cerebro.reports.run": ["reports:run"],
  "cerebro.knowledge.write": ["knowledge:write"],
  "cerebro.workflow.replay": ["workflow:replay"],
  "cerebro.sources.preview": ["sources:preview"],
  "cerebro.connector_definitions.write": ["connector-definitions:write"],
  "cerebro.connectors.write": ["connectors:write"],
  "cerebro.jobs.write": ["jobs:write"],
  "cerebro.source_runtimes.write": ["source-runtimes:write"],
};

const directPermissionScopes = new Set<AuthorizationPermission>(permissionOrder);

const readOnlyPostPaths = new Set([
  "grc/control-packets",
  "grc/control-packets/export",
  "grc/control-packs",
  "grc/control-packs/preview",
]);

const cleanList = (values: string[] | undefined) =>
  Array.from(new Set((values ?? []).map((value) => value.trim().toLowerCase()).filter(Boolean)));

const orderedPermissions = (values: Iterable<AuthorizationPermission>) => {
  const actual = new Set(values);
  return permissionOrder.filter((permission) => actual.has(permission));
};

const hasPermissionScope = (scope: string): scope is AuthorizationPermission =>
  directPermissionScopes.has(scope as AuthorizationPermission);

export const effectiveAuthorizationPermissionsForUser = (
  user: CurrentUser | null | undefined,
): AuthorizationPermission[] => {
  const permissions = new Set<AuthorizationPermission>();
  for (const role of cleanList(user?.entitlements?.roles)) {
    for (const permission of rolePermissionBundles[role] ?? []) {
      permissions.add(permission);
    }
  }
  for (const scope of cleanList(user?.entitlements?.scopes)) {
    if (hasPermissionScope(scope)) {
      permissions.add(scope);
    }
    for (const permission of scopePermissionBundles[scope] ?? []) {
      permissions.add(permission);
    }
  }
  return orderedPermissions(permissions);
};

export const authorizationRoleLabelsForUser = (user: CurrentUser | null | undefined) =>
  Array.from(new Set(cleanList(user?.entitlements?.roles).flatMap((role) => canonicalRoleLabels[role] ?? [])));

export const hasExplicitCerebroRoleOrScope = (user: CurrentUser | null | undefined) =>
  cleanList(user?.entitlements?.roles).some((role) => explicitCerebroRoles.has(role)) ||
  cleanList(user?.entitlements?.scopes).some((scope) => hasPermissionScope(scope) || scope in scopePermissionBundles);

export const userHasAuthorizationPermission = (
  user: CurrentUser | null | undefined,
  permission: AuthorizationPermission,
) => effectiveAuthorizationPermissionsForUser(user).includes(permission);

export const permissionForCerebroProxyRequest = (
  method: string,
  path: string,
): AuthorizationPermission => {
  const normalizedMethod = method.trim().toUpperCase();
  const normalizedPath = normalizeCerebroProxyPath(path);

  if (normalizedMethod === "GET") {
    if (matchesConnectorCredentialPath(normalizedPath)) return "connector-credentials:read";
    if (normalizedPath.startsWith("sources/")) return "sources:preview";
    return "cerebro:read";
  }

  if (normalizedMethod === "PATCH") {
    if (normalizedPath.startsWith("grc/dashboards/")) return "dashboards:write";
    if (normalizedPath.startsWith("grc/inventory/")) return "grc:inventory:write";
    if (normalizedPath.startsWith("grc/policy-lifecycle/")) return "grc:policies:write";
    return "cerebro:write";
  }

  if (normalizedMethod === "PUT") {
    if (normalizedPath === "user/preferences") return "preferences:write";
    if (normalizedPath.startsWith("connector-definitions/")) return "connector-definitions:write";
    if (normalizedPath.startsWith("source-runtimes/")) return "source-runtimes:write";
    if (matchesFindingLifecyclePath(normalizedPath)) return "findings:write";
    return "cerebro:write";
  }

  if (normalizedMethod === "DELETE") {
    if (normalizedPath.startsWith("grc/dashboards/")) return "dashboards:write";
    return "cerebro:write";
  }

  if (normalizedMethod !== "POST") {
    return "cerebro:write";
  }

  if (normalizedPath === "grc/ask") return "agent:ask";
  if (normalizedPath === "grc/dashboards") return "dashboards:write";
  if (normalizedPath.startsWith("grc/dashboards/") && normalizedPath.endsWith("/clone")) return "dashboards:write";
  if (normalizedPath === "grc/findings/triage") return "findings:write";
  if (normalizedPath === "grc/questionnaire-runs") return "grc:inventory:write";
  if (normalizedPath.startsWith("grc/questionnaire-runs/") && (
    normalizedPath.endsWith("/process") ||
    normalizedPath.endsWith("/assignments") ||
    normalizedPath.endsWith("/questions") ||
    normalizedPath.endsWith("/vendor-link") ||
    normalizedPath.endsWith("/decisions") ||
    normalizedPath.endsWith("/comments")
  )) return "grc:inventory:write";
  if (normalizedPath === "grc/vendors") return "grc:inventory:write";
  if (normalizedPath.startsWith("grc/vendors/") && normalizedPath.endsWith("/actions")) return "grc:inventory:write";
  if (normalizedPath.startsWith("grc/vendor-discoveries/") && normalizedPath.endsWith("/decision")) return "grc:inventory:write";
  if (normalizedPath === "grc/vendor-discoveries/sync") return "grc:inventory:write";
  if (normalizedPath === "grc/policy-lifecycle/actions") return "grc:policies:write";
  if (normalizedPath === "grc/policy-lifecycle/uploads") return "grc:policies:write";
  if (normalizedPath.startsWith("grc/policy-lifecycle/uploads/") && normalizedPath.endsWith("/replay")) return "grc:policies:write";
  if (normalizedPath === "grc/vendors/uploads") return "grc:inventory:write";
  if (normalizedPath.startsWith("grc/vendors/uploads/") && normalizedPath.endsWith("/replay")) return "grc:inventory:write";
  if (readOnlyPostPaths.has(normalizedPath)) return "cerebro:read";
  if (normalizedPath.startsWith("grc/control-packs/")) return "cerebro:read";
  if (matchesReportRunPath(normalizedPath)) return "reports:run";
  if (matchesKnowledgeWritePath(normalizedPath)) return "knowledge:write";
  if (normalizedPath === "platform/workflow/replay") return "workflow:replay";
  if (matchesConnectorCredentialWritePath(normalizedPath)) return "connector-credentials:write";
  if (matchesConnectorDefinitionWritePath(normalizedPath)) return "connector-definitions:write";
  if (matchesConnectorWritePath(normalizedPath)) return "connectors:write";
  if (matchesFindingLifecyclePath(normalizedPath) || matchesFindingCandidatePath(normalizedPath)) return "findings:write";
  if (normalizedPath.startsWith("grc/inventory/")) return "grc:inventory:write";
  if (matchesRuntimeResponseWritePath(normalizedPath)) return "runtime-response:write";
  if (matchesJobWritePath(normalizedPath)) return "jobs:write";
  if (matchesSourceRuntimeWritePath(normalizedPath)) return "source-runtimes:write";
  return "cerebro:write";
};

const normalizeCerebroProxyPath = (path: string) =>
  path.trim().replace(/^\/+/, "").replace(/\/+$/, "");

const matchesReportRunPath = (path: string) =>
  path.startsWith("reports/") && path.endsWith("/runs");

const matchesKnowledgeWritePath = (path: string) =>
  path === "platform/knowledge/decisions" ||
  path === "platform/knowledge/actions" ||
  path === "platform/knowledge/actions/recommendation" ||
  path === "platform/knowledge/outcomes";

const matchesConnectorCredentialPath = (path: string) =>
  path.startsWith("connectors/") && (path.endsWith("/credentials") || path.includes("/credentials/"));

const matchesConnectorCredentialWritePath = (path: string) =>
  path.startsWith("connectors/") && (
    path.endsWith("/credentials") ||
    path.endsWith("/rotate") ||
    path.endsWith("/revoke")
  );

const matchesConnectorDefinitionWritePath = (path: string) =>
  path === "connector-definitions" ||
  path === "connector-definitions/plan" ||
  path === "connector-definitions/preview" ||
  path === "connector-definitions/validate" ||
  (path.startsWith("connector-definitions/") && path.endsWith("/promote"));

const matchesConnectorWritePath = (path: string) =>
  path.startsWith("connectors/") && (path.endsWith("/preflight") || path.endsWith("/connections") || path.endsWith("/deposits"));

const matchesFindingLifecyclePath = (path: string) =>
  path.startsWith("findings/") && (
    path.endsWith("/resolve") ||
    path.endsWith("/suppress") ||
    path.endsWith("/assign") ||
    path.endsWith("/due") ||
    path.endsWith("/notes") ||
    path.endsWith("/tickets") ||
    path.endsWith("/external-refs")
  );

const matchesFindingCandidatePath = (path: string) =>
  path.startsWith("finding-candidates/") && (path.endsWith("/promote") || path.endsWith("/reject"));

const matchesRuntimeResponseWritePath = (path: string) =>
  path === "platform/runtime-response/actions" ||
  (path.startsWith("platform/runtime-response/blocklist/") && path.endsWith("/revoke"));

const matchesJobWritePath = (path: string) =>
  path === "platform/jobs" ||
  (path.startsWith("platform/jobs/") && path.endsWith("/cancel"));

const matchesSourceRuntimeWritePath = (path: string) =>
  path.startsWith("source-runtimes/") && (
    path.endsWith("/sync") ||
    path.endsWith("/claims") ||
    path.endsWith("/graph-ingest-runs") ||
    path.endsWith("/finding-candidates/evaluate") ||
    path.endsWith("/finding-rules/evaluate") ||
    path.endsWith("/findings/evaluate")
  );
