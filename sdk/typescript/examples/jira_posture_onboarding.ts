import { Client, type Claim, type IntegrationClient } from "../src/index.js";

declare const process: {
  env: Record<string, string | undefined>;
  argv?: string[];
};

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

export interface OnboardWorkspacePostureOptions {
  baseUrl: string;
  apiKey?: string;
  tenantId: string;
  runtimeId: string;
  posture: JiraWorkspacePosture;
}

export function buildWorkspaceClaims(integration: IntegrationClient, posture: JiraWorkspacePosture): Claim[] {
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
    integration.attr(workspaceRef, "sso_enforced", boolValue(posture.ssoEnforced ?? true), sharedOptions),
    integration.attr(
      workspaceRef,
      "mfa_required_for_admins",
      boolValue(posture.mfaRequiredForAdmins ?? true),
      sharedOptions,
    ),
    integration.attr(
      workspaceRef,
      "atlassian_guard_enabled",
      boolValue(posture.atlassianGuardEnabled ?? true),
      sharedOptions,
    ),
    integration.attr(
      workspaceRef,
      "audit_log_export_enabled",
      boolValue(posture.auditLogExportEnabled ?? true),
      sharedOptions,
    ),
    integration.attr(
      workspaceRef,
      "api_token_expiration_enforced",
      boolValue(posture.apiTokenExpirationEnforced ?? true),
      sharedOptions,
    ),
    integration.attr(
      workspaceRef,
      "public_signup_enabled",
      boolValue(posture.publicSignupEnabled ?? false),
      sharedOptions,
    ),
    integration.attr(
      workspaceRef,
      "anonymous_access_enabled",
      boolValue(posture.anonymousAccessEnabled ?? false),
      sharedOptions,
    ),
    integration.attr(
      workspaceRef,
      "approved_marketplace_apps_only",
      boolValue(posture.approvedMarketplaceAppsOnly ?? true),
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
        boolValue(project.issueLevelSecurityEnabled ?? true),
        sharedOptions,
      ),
    );
    claims.push(
      integration.attr(
        projectRef,
        "anonymous_browse_enabled",
        boolValue(project.anonymousBrowseEnabled ?? false),
        sharedOptions,
      ),
    );
    claims.push(
      integration.attr(
        projectRef,
        "service_desk_public_portal_enabled",
        boolValue(project.serviceDeskPublicPortalEnabled ?? false),
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
        boolValue(app.approvedBySecurity ?? true),
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

export async function onboardWorkspacePosture(options: OnboardWorkspacePostureOptions): Promise<Record<string, unknown>> {
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
  const workspaceKey = options.posture.workspaceKey.trim();
  if (workspaceKey) {
    runtimeConfig.workspace = workspaceKey;
  }
  await integration.ensureRuntime(runtimeConfig);
  const claims = buildWorkspaceClaims(integration, options.posture);
  const writeResult = await integration.writeClaims(claims);
  const persisted = await integration.listClaims({ limit: 100 });
  const graphLayering = await loadGraphLayering(integration, options.posture);
  return {
    workspace_urn: claims[0]?.subject_urn ?? "",
    write_result: writeResult,
    submitted_claims: claims,
    persisted_claims: Array.isArray(persisted["claims"]) ? persisted["claims"] : [],
    graph_layering: graphLayering,
    graph_summary: graphLayering["summary"] ?? {},
    posture_findings: buildPostureFindings(
      integration,
      options.posture,
      graphLayering["summary"] as Record<string, unknown>,
    ),
  };
}

async function main(): Promise<void> {
  const baseUrl = process.env.CEREBRO_BASE_URL?.trim() ?? "";
  if (!baseUrl) {
    throw new Error("CEREBRO_BASE_URL is required");
  }
  const result = await onboardWorkspacePosture({
    baseUrl,
    apiKey: process.env.CEREBRO_API_KEY?.trim(),
    tenantId: process.env.CEREBRO_TENANT_ID?.trim() || "writer",
    runtimeId: process.env.CEREBRO_RUNTIME_ID?.trim() || "writer-jira-posture",
    posture: {
      workspaceKey: process.env.JIRA_WORKSPACE?.trim() || "writer",
      workspaceName: process.env.JIRA_WORKSPACE_NAME?.trim() || "Writer Jira",
      eventId: process.env.JIRA_EVENT_ID?.trim() || "jira-posture-snapshot-1",
      ssoEnforced: envBool("JIRA_SSO_ENFORCED", true),
      mfaRequiredForAdmins: envBool("JIRA_MFA_REQUIRED_FOR_ADMINS", true),
      atlassianGuardEnabled: envBool("JIRA_ATLASSIAN_GUARD_ENABLED", true),
      auditLogExportEnabled: envBool("JIRA_AUDIT_LOG_EXPORT_ENABLED", true),
      apiTokenExpirationEnforced: envBool("JIRA_API_TOKEN_EXPIRATION_ENFORCED", true),
      publicSignupEnabled: envBool("JIRA_PUBLIC_SIGNUP_ENABLED", false),
      anonymousAccessEnabled: envBool("JIRA_ANONYMOUS_ACCESS_ENABLED", false),
      approvedMarketplaceAppsOnly: envBool("JIRA_APPROVED_MARKETPLACE_APPS_ONLY", true),
      admins: [
        {
          email: process.env.JIRA_ADMIN_1_EMAIL?.trim() || "alice@writer.com",
          displayName: process.env.JIRA_ADMIN_1_NAME?.trim() || "Alice",
          role: process.env.JIRA_ADMIN_1_ROLE?.trim() || "site_admin",
        },
        {
          email: process.env.JIRA_ADMIN_2_EMAIL?.trim() || "bob@writer.com",
          displayName: process.env.JIRA_ADMIN_2_NAME?.trim() || "Bob",
          role: process.env.JIRA_ADMIN_2_ROLE?.trim() || "org_admin",
        },
      ],
      projects: [
        {
          key: process.env.JIRA_PROJECT_1_KEY?.trim() || "ENG",
          name: process.env.JIRA_PROJECT_1_NAME?.trim() || "Engineering",
          classification: process.env.JIRA_PROJECT_1_CLASSIFICATION?.trim() || "internal",
          issueLevelSecurityEnabled: envBool("JIRA_PROJECT_1_ISSUE_SECURITY_ENABLED", true),
          anonymousBrowseEnabled: envBool("JIRA_PROJECT_1_ANONYMOUS_BROWSE_ENABLED", false),
          serviceDeskPublicPortalEnabled: envBool("JIRA_PROJECT_1_PUBLIC_PORTAL_ENABLED", false),
        },
        {
          key: process.env.JIRA_PROJECT_2_KEY?.trim() || "SEC",
          name: process.env.JIRA_PROJECT_2_NAME?.trim() || "Security",
          classification: process.env.JIRA_PROJECT_2_CLASSIFICATION?.trim() || "restricted",
          issueLevelSecurityEnabled: envBool("JIRA_PROJECT_2_ISSUE_SECURITY_ENABLED", true),
          anonymousBrowseEnabled: envBool("JIRA_PROJECT_2_ANONYMOUS_BROWSE_ENABLED", false),
          serviceDeskPublicPortalEnabled: envBool("JIRA_PROJECT_2_PUBLIC_PORTAL_ENABLED", false),
        },
      ],
      apps: [
        {
          key: process.env.JIRA_APP_1_KEY?.trim() || "slack",
          name: process.env.JIRA_APP_1_NAME?.trim() || "Slack for Jira",
          approvedBySecurity: envBool("JIRA_APP_1_APPROVED_BY_SECURITY", true),
          scopes: [
            process.env.JIRA_APP_1_SCOPE_1?.trim() || "read:project:jira",
            process.env.JIRA_APP_1_SCOPE_2?.trim() || "write:comment:jira",
          ],
        },
      ],
    },
  });
  console.log(JSON.stringify(result, null, 2));
}

if (typeof process !== "undefined" && process.env) {
  const entrypoint = process.argv?.[1] ?? "";
  if (entrypoint.endsWith("jira_posture_onboarding.ts") || entrypoint.endsWith("jira_posture_onboarding.js")) {
    void main();
  }
}

function envBool(name: string, defaultValue: boolean): boolean {
  const raw = process.env[name]?.trim().toLowerCase();
  if (!raw) {
    return defaultValue;
  }
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

function boolValue(value: boolean): string {
  return value ? "true" : "false";
}

async function loadGraphLayering(
  integration: IntegrationClient,
  posture: JiraWorkspacePosture,
): Promise<Record<string, unknown>> {
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

export function buildPostureFindings(
  integration: IntegrationClient,
  posture: JiraWorkspacePosture,
  graphSummary: Record<string, unknown>,
): Array<Record<string, unknown>> {
  const findings: Array<Record<string, unknown>> = [];
  const workspaceKey = requireValue(posture.workspaceKey, "posture.workspaceKey");
  const workspaceName = posture.workspaceName?.trim() || workspaceKey;
  const workspaceRef = integration.ref("workspace", workspaceKey, workspaceName);

  if (posture.publicSignupEnabled ?? false) {
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
  if (posture.anonymousAccessEnabled ?? false) {
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
  if (!(posture.approvedMarketplaceAppsOnly ?? true)) {
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
    if (classification === "restricted" && !(project.issueLevelSecurityEnabled ?? true)) {
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
    if (project.anonymousBrowseEnabled ?? false) {
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
    if (project.serviceDeskPublicPortalEnabled ?? false) {
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
    if (app.approvedBySecurity ?? true) {
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

function requireValue(value: string, name: string): string {
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
): Record<string, unknown> {
  return {
    id,
    severity,
    title,
    summary,
    resource_urns: resourceUrns,
    ...(attributes ? { attributes } : {}),
  };
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
