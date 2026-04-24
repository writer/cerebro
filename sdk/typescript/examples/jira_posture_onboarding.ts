import {
  type JiraWorkspacePosture,
  onboardJiraWorkspacePosture,
} from "../src/jira.js";

declare const process: {
  env: Record<string, string | undefined>;
  argv?: string[];
};

async function main(): Promise<void> {
  const baseUrl = process.env.CEREBRO_BASE_URL?.trim() ?? "";
  if (!baseUrl) {
    throw new Error("CEREBRO_BASE_URL is required");
  }
  const result = await onboardJiraWorkspacePosture({
    baseUrl,
    apiKey: process.env.CEREBRO_API_KEY?.trim(),
    tenantId: process.env.CEREBRO_TENANT_ID?.trim() || "writer",
    runtimeId: process.env.CEREBRO_RUNTIME_ID?.trim() || "writer-jira-posture",
    posture: buildWorkspacePostureFromEnv(),
  });
  console.log(JSON.stringify(result, null, 2));
}

function buildWorkspacePostureFromEnv(): JiraWorkspacePosture {
  return {
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
  };
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
