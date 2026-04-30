import {
  Client,
  type Claim,
  type GraphNeighborhood,
  type GraphNeighborhoodError,
  type GraphSummary,
  type IntegrationClient,
} from "./index.js";

export interface JiraAdminPosture {
  email: string;
  displayName?: string;
  role?: string;
}

export interface JiraProjectPosture {
  key: string;
  name?: string;
  classification?: string;
  issueLevelSecurityEnabled?: boolean;
  anonymousBrowseEnabled?: boolean;
  serviceDeskPublicPortalEnabled?: boolean;
}

export interface JiraMarketplaceAppPosture {
  key: string;
  name?: string;
  approvedBySecurity?: boolean;
  scopes?: string[];
}

export interface JiraWorkspacePosture {
  workspaceKey: string;
  workspaceName?: string;
  eventId?: string;
  ssoEnforced?: boolean;
  mfaRequiredForAdmins?: boolean;
  atlassianGuardEnabled?: boolean;
  auditLogExportEnabled?: boolean;
  apiTokenExpirationEnforced?: boolean;
  publicSignupEnabled?: boolean;
  anonymousAccessEnabled?: boolean;
  approvedMarketplaceAppsOnly?: boolean;
  admins?: JiraAdminPosture[];
  projects?: JiraProjectPosture[];
  apps?: JiraMarketplaceAppPosture[];
}

export interface JiraWorkspaceGraphLayering {
  workspace: GraphNeighborhood | GraphNeighborhoodError;
  projects: Record<string, GraphNeighborhood | GraphNeighborhoodError>;
  summary: GraphSummary;
}

export interface JiraPostureFinding {
  id: string;
  severity: string;
  title: string;
  summary: string;
  resource_urns: string[];
  attributes?: Record<string, string>;
}

export interface OnboardJiraWorkspacePostureOptions {
  baseUrl: string;
  apiKey?: string;
  tenantId: string;
  runtimeId: string;
  posture: JiraWorkspacePosture;
}

export interface OnboardJiraWorkspacePostureResult {
  workspace_urn: string;
  write_result: Record<string, unknown>;
  submitted_claims: Claim[];
  persisted_claims: Claim[];
  graph_layering: JiraWorkspaceGraphLayering;
  graph_summary: GraphSummary;
  posture_findings: JiraPostureFinding[];
}

export function buildJiraWorkspaceClaims(integration: IntegrationClient, posture: JiraWorkspacePosture): Claim[] {
  const workspaceKey = requireValue(posture.workspaceKey, "posture.workspaceKey");
  const workspaceName = posture.workspaceName?.trim() || workspaceKey;
  const workspaceRef = integration.ref("workspace", workspaceKey, workspaceName);
  const sourceEventId = posture.eventId?.trim();
  const sharedOptions = sourceEventId ? { source_event_id: sourceEventId } : {};
  const admins = posture.admins ?? [];
  const projects = posture.projects ?? [];
  const apps = posture.apps ?? [];

  const claims: Claim[] = [
    integration.exists(workspaceRef, sharedOptions),
    integration.attr(workspaceRef, "platform", "jira", sharedOptions),
    integration.attr(workspaceRef, "vendor", "atlassian", sharedOptions),
    integration.attr(workspaceRef, "sso_enforced", boolValue(defaultBool(posture.ssoEnforced, true)), sharedOptions),
    integration.attr(
      workspaceRef,
      "mfa_required_for_admins",
      boolValue(defaultBool(posture.mfaRequiredForAdmins, true)),
      sharedOptions,
    ),
    integration.attr(
      workspaceRef,
      "atlassian_guard_enabled",
      boolValue(defaultBool(posture.atlassianGuardEnabled, true)),
      sharedOptions,
    ),
    integration.attr(
      workspaceRef,
      "audit_log_export_enabled",
      boolValue(defaultBool(posture.auditLogExportEnabled, true)),
      sharedOptions,
    ),
    integration.attr(
      workspaceRef,
      "api_token_expiration_enforced",
      boolValue(defaultBool(posture.apiTokenExpirationEnforced, true)),
      sharedOptions,
    ),
    integration.attr(
      workspaceRef,
      "public_signup_enabled",
      boolValue(defaultBool(posture.publicSignupEnabled, false)),
      sharedOptions,
    ),
    integration.attr(
      workspaceRef,
      "anonymous_access_enabled",
      boolValue(defaultBool(posture.anonymousAccessEnabled, false)),
      sharedOptions,
    ),
    integration.attr(
      workspaceRef,
      "approved_marketplace_apps_only",
      boolValue(defaultBool(posture.approvedMarketplaceAppsOnly, true)),
      sharedOptions,
    ),
    integration.attr(workspaceRef, "admin_count", String(admins.length), sharedOptions),
    integration.attr(workspaceRef, "project_count", String(projects.length), sharedOptions),
    integration.attr(workspaceRef, "installed_app_count", String(apps.length), sharedOptions),
  ];

  for (const admin of admins) {
    const email = requireValue(admin.email, "posture.admins[].email");
    const adminRef = integration.ref("user", email, admin.displayName?.trim() || email);
    claims.push(integration.exists(adminRef, sharedOptions));
    claims.push(integration.rel(adminRef, "administers", workspaceRef, sharedOptions));
    claims.push(integration.attr(adminRef, "role", admin.role?.trim() || "site_admin", sharedOptions));
  }

  for (const project of projects) {
    const key = requireValue(project.key, "posture.projects[].key");
    const projectRef = integration.ref("project", key, project.name?.trim() || key);
    claims.push(integration.exists(projectRef, sharedOptions));
    claims.push(integration.rel(projectRef, "belongs_to", workspaceRef, sharedOptions));
    claims.push(
      integration.attr(projectRef, "classification", project.classification?.trim() || "internal", sharedOptions),
    );
    claims.push(
      integration.attr(
        projectRef,
        "issue_level_security_enabled",
        boolValue(defaultBool(project.issueLevelSecurityEnabled, true)),
        sharedOptions,
      ),
    );
    claims.push(
      integration.attr(
        projectRef,
        "anonymous_browse_enabled",
        boolValue(defaultBool(project.anonymousBrowseEnabled, false)),
        sharedOptions,
      ),
    );
    claims.push(
      integration.attr(
        projectRef,
        "service_desk_public_portal_enabled",
        boolValue(defaultBool(project.serviceDeskPublicPortalEnabled, false)),
        sharedOptions,
      ),
    );
  }

  for (const app of apps) {
    const key = requireValue(app.key, "posture.apps[].key");
    const appRef = integration.ref("app", key, app.name?.trim() || key);
    claims.push(integration.exists(appRef, sharedOptions));
    claims.push(integration.rel(appRef, "installed_on", workspaceRef, sharedOptions));
    claims.push(
      integration.attr(
        appRef,
        "approved_by_security",
        boolValue(defaultBool(app.approvedBySecurity, true)),
        sharedOptions,
      ),
    );
    const scopes = (app.scopes ?? []).map((scope) => scope.trim()).filter(Boolean);
    if (scopes.length > 0) {
      claims.push(integration.attr(appRef, "scopes", scopes.join(","), sharedOptions));
    }
  }

  return claims;
}

export async function loadJiraWorkspaceGraphLayering(
  integration: IntegrationClient,
  posture: JiraWorkspacePosture,
): Promise<JiraWorkspaceGraphLayering> {
  const workspaceKey = requireValue(posture.workspaceKey, "posture.workspaceKey");
  const workspaceRef = integration.ref("workspace", workspaceKey, posture.workspaceName?.trim() || workspaceKey);
  const projectEntries = (posture.projects ?? []).map((project) => {
    const projectKey = requireValue(project.key, "posture.projects[].key");
    const projectRef = integration.ref("project", projectKey, project.name?.trim() || projectKey);
    return [projectKey, projectRef] as const;
  });
  const workspaceLayering = await integration.graphLayering([workspaceRef], 50);
  const projectLayering = await integration.graphLayering(
    projectEntries.map(([, projectRef]) => projectRef),
    12,
  );
  const combinedLayering = {
    ...workspaceLayering,
    ...projectLayering,
  };
  return {
    workspace: workspaceLayering[workspaceRef.urn] ?? {
      root_urn: workspaceRef.urn,
      error: "missing graph response",
    },
    projects: Object.fromEntries(
      projectEntries.map(([projectKey, projectRef]) => [
        projectKey,
        projectLayering[projectRef.urn] ?? {
          root_urn: projectRef.urn,
          error: "missing graph response",
        },
      ]),
    ),
    summary: integration.graphSummary(combinedLayering),
  };
}

export function buildJiraPostureFindings(
  integration: IntegrationClient,
  posture: JiraWorkspacePosture,
  graphSummary: GraphSummary | Record<string, unknown>,
): JiraPostureFinding[] {
  const findings: JiraPostureFinding[] = [];
  const workspaceKey = requireValue(posture.workspaceKey, "posture.workspaceKey");
  const workspaceName = posture.workspaceName?.trim() || workspaceKey;
  const workspaceRef = integration.ref("workspace", workspaceKey, workspaceName);

  if (defaultBool(posture.publicSignupEnabled, false)) {
    findings.push(
      finding(
        "jira_workspace_public_signup_enabled",
        "HIGH",
        "Jira workspace allows self-service signup",
        `${workspaceName} allows self-service signup, which increases exposure to unmanaged identities.`,
        [workspaceRef.urn],
      ),
    );
  }
  if (defaultBool(posture.anonymousAccessEnabled, false)) {
    findings.push(
      finding(
        "jira_workspace_anonymous_access_enabled",
        "HIGH",
        "Jira workspace permits anonymous access",
        `${workspaceName} exposes content to unauthenticated users.`,
        [workspaceRef.urn],
      ),
    );
  }
  if (!defaultBool(posture.approvedMarketplaceAppsOnly, true)) {
    findings.push(
      finding(
        "jira_workspace_marketplace_policy_open",
        "MEDIUM",
        "Jira workspace does not restrict marketplace apps",
        `${workspaceName} allows marketplace apps outside the approved set.`,
        [workspaceRef.urn],
      ),
    );
  }

  const relationCounts = asNumberRecord(graphSummary["relation_counts_by_type"]);
  const adminCount = relationCounts.administers ?? 0;
  if (adminCount > 5) {
    findings.push(
      finding(
        "jira_workspace_admin_sprawl",
        "MEDIUM",
        "Jira workspace has elevated admin sprawl",
        `${workspaceName} has ${adminCount} admin relationships in the graph neighborhood.`,
        [workspaceRef.urn],
        { admin_count: String(adminCount) },
      ),
    );
  }

  for (const project of posture.projects ?? []) {
    const projectKey = requireValue(project.key, "posture.projects[].key");
    const projectName = project.name?.trim() || projectKey;
    const projectRef = integration.ref("project", projectKey, projectName);
    const classification = project.classification?.trim() || "internal";
    if (classification === "restricted" && !defaultBool(project.issueLevelSecurityEnabled, true)) {
      findings.push(
        finding(
          `jira_project_${projectKey.toLowerCase()}_restricted_issue_security_disabled`,
          "HIGH",
          "Restricted Jira project lacks issue-level security",
          `${projectName} is marked restricted but issue-level security is disabled.`,
          [projectRef.urn, workspaceRef.urn],
        ),
      );
    }
    if (defaultBool(project.anonymousBrowseEnabled, false)) {
      findings.push(
        finding(
          `jira_project_${projectKey.toLowerCase()}_anonymous_browse_enabled`,
          "HIGH",
          "Jira project allows anonymous browsing",
          `${projectName} allows anonymous issue browsing.`,
          [projectRef.urn, workspaceRef.urn],
        ),
      );
    }
    if (defaultBool(project.serviceDeskPublicPortalEnabled, false)) {
      findings.push(
        finding(
          `jira_project_${projectKey.toLowerCase()}_public_portal_enabled`,
          classification === "restricted" ? "HIGH" : "MEDIUM",
          "Jira project exposes a public service desk portal",
          `${projectName} exposes a public portal for ${classification} data.`,
          [projectRef.urn, workspaceRef.urn],
        ),
      );
    }
  }

  for (const app of posture.apps ?? []) {
    if (defaultBool(app.approvedBySecurity, true)) {
      continue;
    }
    const appKey = requireValue(app.key, "posture.apps[].key");
    const appName = app.name?.trim() || appKey;
    const appRef = integration.ref("app", appKey, appName);
    findings.push(
      finding(
        `jira_app_${appKey.toLowerCase()}_unapproved`,
        "MEDIUM",
        "Unapproved Jira marketplace app is installed",
        `${appName} is installed on ${workspaceName} without security approval.`,
        [appRef.urn, workspaceRef.urn],
      ),
    );
  }

  return findings;
}

export async function onboardJiraWorkspacePosture(
  options: OnboardJiraWorkspacePostureOptions,
): Promise<OnboardJiraWorkspacePostureResult> {
  const client = new Client({
    baseUrl: options.baseUrl,
    apiKey: options.apiKey?.trim() || undefined,
  });
  const integration = client.integration({
    runtimeId: options.runtimeId.trim(),
    tenantId: options.tenantId.trim(),
    integration: "jira",
  });
  const runtimeConfig: Record<string, string> = {};
  const workspaceKey = requireValue(options.posture.workspaceKey, "posture.workspaceKey");
  const sourceEventId = options.posture.eventId?.trim();
  if (workspaceKey) {
    runtimeConfig.workspace = workspaceKey;
  }
  await integration.ensureRuntime(runtimeConfig);
  const claims = buildJiraWorkspaceClaims(integration, options.posture);
  const writeResult = await integration.writeClaims(claims, { replace_existing: true });
  const persisted = await integration.listClaims({
    limit: 100,
    status: "asserted",
    ...(sourceEventId ? { source_event_id: sourceEventId } : {}),
  });
  const graphLayering = await loadJiraWorkspaceGraphLayering(integration, options.posture);
  return {
    workspace_urn: claims[0]?.subject_urn ?? "",
    write_result: writeResult,
    submitted_claims: claims,
    persisted_claims: Array.isArray(persisted["claims"]) ? (persisted["claims"] as Claim[]) : [],
    graph_layering: graphLayering,
    graph_summary: graphLayering.summary,
    posture_findings: buildJiraPostureFindings(integration, options.posture, graphLayering.summary),
  };
}

function requireValue(value: unknown, name: string): string {
  if (typeof value !== "string") {
    throw new Error(`${name} is required`);
  }
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`${name} is required`);
  }
  return normalized;
}

function finding(
  id: string,
  severity: string,
  title: string,
  summary: string,
  resourceUrns: string[],
  attributes?: Record<string, string>,
): JiraPostureFinding {
  return {
    id,
    severity,
    title,
    summary,
    resource_urns: resourceUrns,
    ...(attributes ? { attributes } : {}),
  };
}

function boolValue(value: boolean): string {
  return value ? "true" : "false";
}

function defaultBool(value: unknown, defaultValue: boolean): boolean {
  if (value === undefined || value === null) {
    return defaultValue;
  }
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (!normalized) {
      return defaultValue;
    }
    if (["1", "true", "t", "yes", "y", "on"].includes(normalized)) {
      return true;
    }
    if (["0", "false", "f", "no", "n", "off"].includes(normalized)) {
      return false;
    }
  }
  return Boolean(value);
}

function asNumberRecord(value: unknown): Record<string, number> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  const result: Record<string, number> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (typeof raw === "number") {
      result[key] = raw;
    }
  }
  return result;
}
