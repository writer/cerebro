import { Client, type Claim, type IntegrationClient } from "../src/index.js";

declare const process: {
  env: Record<string, string | undefined>;
  argv?: string[];
};

export interface JiraIssuePayload {
  workspace?: string;
  eventId?: string;
  projectKey?: string;
  key?: string | null;
  summary?: string | null;
  status?: string | null;
  priority?: string;
  assigneeEmail?: string;
  reporterEmail?: string;
}

export interface OnboardIssueOptions {
  baseUrl: string;
  apiKey?: string;
  tenantId: string;
  runtimeId: string;
  issue: JiraIssuePayload;
}

export function buildIssueClaims(integration: IntegrationClient, issue: JiraIssuePayload): Claim[] {
  const issueKey = requireValue(issue.key, "issue.key");
  const summary = requireValue(issue.summary, "issue.summary");
  const status = requireValue(issue.status, "issue.status");

  const issueRef = integration.ref("ticket", issueKey, issueKey);
  const sourceEventId = issue.eventId?.trim();
  const sharedOptions = sourceEventId ? { source_event_id: sourceEventId } : {};
  const claims: Claim[] = [
    integration.exists(issueRef, sharedOptions),
    integration.attr(issueRef, "summary", summary, sharedOptions),
    integration.attr(issueRef, "status", status, sharedOptions),
  ];

  const projectKey = issue.projectKey?.trim();
  if (projectKey) {
    claims.push(
      integration.rel(
        issueRef,
        "belongs_to",
        integration.ref("project", projectKey, projectKey),
        sharedOptions,
      ),
    );
  }

  const assigneeEmail = issue.assigneeEmail?.trim();
  if (assigneeEmail) {
    claims.push(
      integration.rel(
        issueRef,
        "assigned_to",
        integration.ref("user", assigneeEmail, assigneeEmail),
        sharedOptions,
      ),
    );
  }

  const reporterEmail = issue.reporterEmail?.trim();
  if (reporterEmail) {
    claims.push(
      integration.rel(
        issueRef,
        "reported_by",
        integration.ref("user", reporterEmail, reporterEmail),
        sharedOptions,
      ),
    );
  }

  const priority = issue.priority?.trim();
  if (priority) {
    claims.push(integration.attr(issueRef, "priority", priority, sharedOptions));
  }

  return claims;
}

export async function onboardIssue(options: OnboardIssueOptions): Promise<Record<string, unknown>> {
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
  const workspace = options.issue.workspace?.trim();
  if (workspace) {
    runtimeConfig.workspace = workspace;
  }
  await integration.ensureRuntime(runtimeConfig);
  const claims = buildIssueClaims(integration, options.issue);
  const writeResult = await integration.writeClaims(claims);
  const subjectUrn = claims[0]?.subject_urn ?? "";
  const claimResult = await integration.listClaims(subjectUrn ? { subject_urn: subjectUrn, limit: 20 } : { limit: 20 });
  return {
    writeResult,
    claims: Array.isArray(claimResult["claims"]) ? claimResult["claims"] : [],
  };
}

async function main(): Promise<void> {
  const baseUrl = process.env.CEREBRO_BASE_URL?.trim() ?? "";
  if (!baseUrl) {
    throw new Error("CEREBRO_BASE_URL is required");
  }
  const result = await onboardIssue({
    baseUrl,
    apiKey: process.env.CEREBRO_API_KEY?.trim(),
    tenantId: process.env.CEREBRO_TENANT_ID?.trim() || "writer",
    runtimeId: process.env.CEREBRO_RUNTIME_ID?.trim() || "writer-jira",
    issue: {
      workspace: process.env.JIRA_WORKSPACE?.trim() || "writer",
      eventId: process.env.JIRA_EVENT_ID?.trim() || "jira-event-1",
      projectKey: process.env.JIRA_PROJECT_KEY?.trim() || "ENG",
      key: process.env.JIRA_ISSUE_KEY?.trim() || "ENG-123",
      summary: process.env.JIRA_ISSUE_SUMMARY?.trim() || "Claim-first Jira onboarding example",
      status: process.env.JIRA_ISSUE_STATUS?.trim() || "in_progress",
      priority: process.env.JIRA_ISSUE_PRIORITY?.trim() || "high",
      assigneeEmail: process.env.JIRA_ASSIGNEE_EMAIL?.trim() || "alice@writer.com",
      reporterEmail: process.env.JIRA_REPORTER_EMAIL?.trim() || "bob@writer.com",
    },
  });
  console.log(JSON.stringify(result, null, 2));
}

if (typeof process !== "undefined" && process.env) {
  const entrypoint = process.argv?.[1] ?? "";
  if (entrypoint.endsWith("jira_onboarding.ts") || entrypoint.endsWith("jira_onboarding.js")) {
    void main();
  }
}

function requireValue(value: string | undefined | null, name: string): string {
  if (typeof value !== "string") {
    throw new Error(`${name} is required`);
  }
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`${name} is required`);
  }
  return normalized;
}
