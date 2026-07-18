import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { InfisicalClient } from "../../infisical/client.js";
import { trimForSlack } from "../../slack/format.js";
import { TicketingClient, TicketingConfigurationError } from "../../ticketing/client.js";
import { limit, shortError, stringList, stringValue, unique } from "./normalizers.js";
import type { SecurityToolDeps } from "./types.js";
import { toolResult } from "./tool-result.js";

export function createTicketTools(deps: SecurityToolDeps): AgentTool[] {
  const client = createTicketingClient(deps);
  const draftProperties = {
    title: Type.String(),
    description: Type.String(),
    finding_id: Type.Optional(Type.String()),
    runtime_id: Type.Optional(Type.String()),
    severity: Type.Optional(Type.String()),
    owner: Type.Optional(Type.String()),
    evidence_refs: Type.Optional(Type.Array(Type.String())),
    labels: Type.Optional(Type.Array(Type.String())),
  };
  const jiraDraftParams = Type.Object({
    ...draftProperties,
    project_key: Type.Optional(Type.String()),
    issue_type: Type.Optional(Type.String()),
  });
  const jiraSearchParams = Type.Object({
    jql: Type.Optional(Type.String()),
    query: Type.Optional(Type.String()),
    project_key: Type.Optional(Type.String()),
    max_results: Type.Optional(Type.Number()),
    limit: Type.Optional(Type.Number()),
    next_page_token: Type.Optional(Type.String()),
  });
  const jiraUpdateParams = Type.Object({
    issue_key: Type.String(),
    comment: Type.Optional(Type.String()),
    labels_add: Type.Optional(Type.Array(Type.String())),
    labels_remove: Type.Optional(Type.Array(Type.String())),
    transition_id: Type.Optional(Type.String()),
    transition_name: Type.Optional(Type.String()),
    execute: Type.Optional(Type.Boolean()),
  });
  const linearDraftParams = Type.Object({
    ...draftProperties,
    team_id: Type.Optional(Type.String()),
    priority: Type.Optional(Type.Number()),
  });

  return [
    {
      name: "ticketing_status",
      label: "Ticketing status",
      description: "Report Jira and Linear defaults plus Jira search and issue create readiness. This does not create tickets.",
      parameters: Type.Object({}),
      execute: async () => toolResult(ticketingStatus(deps)),
    },
    {
      name: "jira_issue_search",
      label: "Search Jira issues",
      description: "Search Jira issues with JQL or a bounded query/project filter. Read-only; use before creating or updating tickets to avoid duplicate work.",
      parameters: jiraSearchParams,
      execute: async (_toolCallId, params) => {
        const args = params as JiraSearchArgs;
        return toolResult(await jiraIssueSearch(deps, client, args));
      },
    },
    {
      name: "jira_issue_draft",
      label: "Jira issue draft",
      description: "Build a bounded Jira issue payload for an operator to review. It does not create a Jira issue.",
      parameters: jiraDraftParams,
      execute: async (_toolCallId, params) => {
        const args = params as JiraTicketArgs;
        return toolResult(jiraIssueDraft(deps, args));
      },
    },
    {
      name: "jira_issue_create",
      label: "Create Jira issue",
      description: "Create one Jira issue after an explicit ticket creation request. Returns a draft and missing config when Jira is not ready.",
      parameters: jiraDraftParams,
      execute: async (_toolCallId, params) => {
        const args = params as JiraTicketArgs;
        return toolResult(await jiraIssueCreate(deps, client, args));
      },
    },
    {
      name: "jira_issue_update",
      label: "Jira issue update",
      description: "Update one Jira issue after an explicit ticket update request. With execute omitted or false, returns the exact pending update without writing.",
      parameters: jiraUpdateParams,
      execute: async (_toolCallId, params) => {
        const args = params as JiraUpdateArgs;
        return toolResult(await jiraIssueUpdate(deps, client, args));
      },
    },
    {
      name: "linear_issue_draft",
      label: "Linear issue draft",
      description: "Build a bounded Linear issue payload for an operator to review. It does not create a Linear issue.",
      parameters: linearDraftParams,
      execute: async (_toolCallId, params) => {
        const args = params as LinearTicketArgs;
        return toolResult(linearIssueDraft(deps, args));
      },
    },
    {
      name: "linear_issue_create",
      label: "Create Linear issue",
      description: "Create one Linear issue after an explicit ticket creation request. Returns a draft and missing config when Linear is not ready.",
      parameters: linearDraftParams,
      execute: async (_toolCallId, params) => {
        const args = params as LinearTicketArgs;
        return toolResult(await linearIssueCreate(deps, client, args));
      },
    },
  ];
}

interface TicketDraftArgs {
  title?: string;
  description?: string;
  finding_id?: string;
  runtime_id?: string;
  severity?: string;
  owner?: string;
  evidence_refs?: string[];
  labels?: string[];
}

type JiraTicketArgs = TicketDraftArgs & { project_key?: string; issue_type?: string };
type LinearTicketArgs = TicketDraftArgs & { team_id?: string; priority?: number };
interface JiraSearchArgs {
  jql?: string;
  query?: string;
  project_key?: string;
  max_results?: number;
  limit?: number;
  next_page_token?: string;
}
type JiraUpdateArgs = {
  issue_key?: string;
  comment?: string;
  labels_add?: string[];
  labels_remove?: string[];
  transition_id?: string;
  transition_name?: string;
  execute?: boolean;
};

interface JiraDraftResult {
  system: "jira";
  created: false;
  ready_for_operator: boolean;
  missing: string[];
  issue: {
    project_key?: string;
    issue_type: string;
    summary: string;
    description: string;
    labels: string[];
  };
  web_url_hint?: string;
}

interface LinearDraftResult {
  system: "linear";
  created: false;
  ready_for_operator: boolean;
  missing: string[];
  issue: {
    team_id?: string;
    title: string;
    description: string;
    priority?: number;
    labels: string[];
  };
}

export function ticketingStatus(deps: SecurityToolDeps): Record<string, unknown> {
  return {
    jira: {
      draft_available: true,
      search_available: Boolean(deps.config.ticketing.jira.baseUrl && hasJiraTokenPath(deps)),
      search_available_with_args: Boolean(deps.config.ticketing.jira.baseUrl && hasJiraTokenPath(deps)),
      update_available_with_args: Boolean(deps.config.ticketing.jira.baseUrl && hasJiraTokenPath(deps)),
      create_available_with_args: Boolean(deps.config.ticketing.jira.baseUrl && hasJiraTokenPath(deps)),
      create_available_with_defaults: Boolean(deps.config.ticketing.jira.baseUrl && deps.config.ticketing.jira.defaultProjectKey && hasJiraTokenPath(deps)),
      base_url_configured: Boolean(deps.config.ticketing.jira.baseUrl),
      default_project_key_configured: Boolean(deps.config.ticketing.jira.defaultProjectKey),
      default_issue_type: deps.config.ticketing.jira.defaultIssueType,
      auth_mode: deps.config.ticketing.jira.authEmail ? "basic" : "bearer",
      auth_email_configured: Boolean(deps.config.ticketing.jira.authEmail),
      api_token_configured: Boolean(deps.config.ticketing.jira.apiToken),
      api_token_infisical_mirror_configured: Boolean(deps.config.ticketing.jira.apiTokenInfisicalSecretName),
      api_token_infisical_secret_name: deps.config.ticketing.jira.apiTokenInfisicalSecretName,
      infisical_runtime_configured: infisicalRuntimeConfigured(deps),
    },
    linear: {
      draft_available: true,
      create_available_with_args: hasLinearTokenPath(deps),
      create_available_with_defaults: Boolean(deps.config.ticketing.linear.defaultTeamId && hasLinearTokenPath(deps)),
      default_team_id_configured: Boolean(deps.config.ticketing.linear.defaultTeamId),
      api_key_configured: Boolean(deps.config.ticketing.linear.apiKey),
      api_key_infisical_mirror_configured: Boolean(deps.config.ticketing.linear.apiKeyInfisicalSecretName),
      api_key_infisical_secret_name: deps.config.ticketing.linear.apiKeyInfisicalSecretName,
      infisical_runtime_configured: infisicalRuntimeConfigured(deps),
    },
    max_description_chars: deps.config.ticketing.maxDescriptionChars,
    timeout_ms: deps.config.ticketing.timeoutMs,
    note: "Jira search is read-only and returns bounded issue summaries. Draft tools prepare reviewable payloads. Create tools write one Jira or Linear issue when auth and target defaults or arguments are configured.",
  };
}

function jiraIssueDraft(
  deps: SecurityToolDeps,
  args: JiraTicketArgs,
): JiraDraftResult {
  const projectKey = stringValue(args.project_key) ?? deps.config.ticketing.jira.defaultProjectKey;
  const issueType = stringValue(args.issue_type) ?? deps.config.ticketing.jira.defaultIssueType;
  const labels = ticketLabels(args, "cerebro");
  const description = ticketDescription(deps, args);
  const title = stringValue(args.title) ?? "";
  return {
    system: "jira",
    created: false,
    ready_for_operator: Boolean(projectKey && title && description.trim()),
    missing: [
      projectKey ? undefined : "project_key",
      title ? undefined : "title",
      description.trim() ? undefined : "description",
    ].filter((item): item is string => Boolean(item)),
    issue: {
      project_key: projectKey,
      issue_type: issueType,
      summary: trimForSlack(title, 255),
      description,
      labels,
    },
    web_url_hint: deps.config.ticketing.jira.baseUrl && projectKey
      ? `${deps.config.ticketing.jira.baseUrl}/jira/software/c/projects/${encodeURIComponent(projectKey)}/issues`
      : undefined,
  };
}

function linearIssueDraft(
  deps: SecurityToolDeps,
  args: LinearTicketArgs,
): LinearDraftResult {
  const teamId = stringValue(args.team_id) ?? deps.config.ticketing.linear.defaultTeamId;
  const description = ticketDescription(deps, args);
  const title = stringValue(args.title) ?? "";
  return {
    system: "linear",
    created: false,
    ready_for_operator: Boolean(teamId && title && description.trim()),
    missing: [
      teamId ? undefined : "team_id",
      title ? undefined : "title",
      description.trim() ? undefined : "description",
    ].filter((item): item is string => Boolean(item)),
    issue: {
      team_id: teamId,
      title: trimForSlack(title, 255),
      description,
      priority: normalizeLinearPriority(args.priority),
      labels: ticketLabels(args, "cerebro"),
    },
  };
}

async function jiraIssueCreate(
  deps: SecurityToolDeps,
  client: TicketingClient,
  args: JiraTicketArgs,
): Promise<Record<string, unknown>> {
  const draft = jiraIssueDraft(deps, args);
  const missing = unique([
    ...draft.missing,
    deps.config.ticketing.jira.baseUrl ? "" : "jira_base_url",
    hasJiraTokenPath(deps) ? "" : "jira_api_token",
  ].filter(Boolean));
  if (missing.length > 0) {
    return createNotReady(draft, missing, "Jira issue was not created because ticketing config or required issue fields are missing.");
  }
  try {
    const created = await client.createJiraIssue({
      projectKey: draft.issue.project_key ?? "",
      issueType: draft.issue.issue_type,
      summary: draft.issue.summary,
      description: draft.issue.description,
      labels: draft.issue.labels,
    });
    return {
      ...created,
      draft: draft.issue,
    };
  } catch (error) {
    return createFailed(draft, error);
  }
}

async function jiraIssueSearch(
  deps: SecurityToolDeps,
  client: TicketingClient,
  args: JiraSearchArgs,
): Promise<Record<string, unknown>> {
  const jql = stringValue(args.jql);
  const query = stringValue(args.query);
  const projectKey = stringValue(args.project_key);
  const maxResults = limit(args.max_results ?? args.limit ?? 25, 50);
  const missing = unique([
    jql || query || projectKey ? "" : "jql_or_query",
    deps.config.ticketing.jira.baseUrl ? "" : "jira_base_url",
    hasJiraTokenPath(deps) ? "" : "jira_api_token",
  ].filter(Boolean));
  if (missing.length > 0) {
    return {
      system: "jira",
      searched: false,
      attempted: false,
      error: "ticketing_not_configured",
      missing,
      jql,
      query,
      project_key: projectKey,
      max_results: maxResults,
      note: "Jira search was not run because ticketing config, JQL, query, or project key is missing.",
    };
  }
  try {
    return await client.searchJiraIssues({
      jql,
      query,
      projectKey,
      maxResults,
      nextPageToken: stringValue(args.next_page_token),
    });
  } catch (error) {
    if (error instanceof TicketingConfigurationError) {
      return {
        system: "jira",
        searched: false,
        attempted: false,
        error: "ticketing_not_configured",
        missing: error.missing,
        jql,
        query,
        project_key: projectKey,
        max_results: maxResults,
        note: error.message,
      };
    }
    return {
      system: "jira",
      searched: false,
      attempted: true,
      error: "ticketing_request_failed",
      message: shortError(error),
      jql,
      query,
      project_key: projectKey,
      max_results: maxResults,
    };
  }
}

async function jiraIssueUpdate(
  deps: SecurityToolDeps,
  client: TicketingClient,
  args: JiraUpdateArgs,
): Promise<Record<string, unknown>> {
  const draft = jiraIssueUpdateDraft(args);
  if (args.execute !== true) return draft;
  const missing = unique([
    ...draft.missing,
    ...jiraRuntimeMissing(deps),
  ]);
  if (missing.length > 0) {
    return {
      ...draft,
      error: "ticketing_not_configured",
      missing,
      note: "Jira issue was not updated because ticketing config or required update fields are missing.",
    };
  }
  try {
    const updated = await client.updateJiraIssue({
      issueKey: draft.update.issue_key,
      comment: draft.update.comment,
      labelsAdd: draft.update.labels_add,
      labelsRemove: draft.update.labels_remove,
      transitionId: draft.update.transition_id,
      transitionName: draft.update.transition_name,
    });
    return {
      ...updated,
      requested_update: draft.update,
    };
  } catch (error) {
    if (error instanceof TicketingConfigurationError) {
      return {
        ...draft,
        error: "ticketing_not_configured",
        missing: unique([...draft.missing, ...error.missing]),
        note: error.message,
      };
    }
    return {
      ...draft,
      attempted: true,
      error: "ticketing_request_failed",
      message: shortError(error),
    };
  }
}

async function linearIssueCreate(
  deps: SecurityToolDeps,
  client: TicketingClient,
  args: LinearTicketArgs,
): Promise<Record<string, unknown>> {
  const draft = linearIssueDraft(deps, args);
  const missing = unique([
    ...draft.missing,
    hasLinearTokenPath(deps) ? "" : "linear_api_key",
  ].filter(Boolean));
  if (missing.length > 0) {
    return createNotReady(draft, missing, "Linear issue was not created because ticketing config or required issue fields are missing.");
  }
  try {
    const created = await client.createLinearIssue({
      teamId: draft.issue.team_id ?? "",
      title: draft.issue.title,
      description: draft.issue.description,
      priority: draft.issue.priority,
      labels: draft.issue.labels,
    });
    return {
      ...created,
      draft: draft.issue,
    };
  } catch (error) {
    return createFailed(draft, error);
  }
}

function jiraIssueUpdateDraft(args: JiraUpdateArgs): {
  system: "jira";
  updated: false;
  attempted: false;
  ready_for_operator: boolean;
  execute_required: boolean;
  missing: string[];
  update: {
    issue_key: string;
    comment?: string;
    labels_add: string[];
    labels_remove: string[];
    transition_id?: string;
    transition_name?: string;
  };
  note: string;
} {
  const issueKey = stringValue(args.issue_key) ?? "";
  const comment = stringValue(args.comment);
  const labelsAdd = stringList(args.labels_add) ?? [];
  const labelsRemove = stringList(args.labels_remove) ?? [];
  const transitionId = stringValue(args.transition_id);
  const transitionName = stringValue(args.transition_name);
  const hasOperation = Boolean(comment || labelsAdd.length || labelsRemove.length || transitionId || transitionName);
  const missing = [
    issueKey ? undefined : "issue_key",
    hasOperation ? undefined : "comment_or_labels_or_transition",
  ].filter((item): item is string => Boolean(item));
  return {
    system: "jira",
    updated: false,
    attempted: false,
    ready_for_operator: missing.length === 0,
    execute_required: true,
    missing,
    update: {
      issue_key: issueKey,
      comment,
      labels_add: labelsAdd,
      labels_remove: labelsRemove,
      transition_id: transitionId,
      transition_name: transitionName,
    },
    note: "Set execute=true only after the operator has asked for this Jira update.",
  };
}

function ticketDescription(deps: SecurityToolDeps, args: TicketDraftArgs): string {
  const description = stringValue(args.description) ?? "";
  const lines = [
    description,
    "",
    stringValue(args.finding_id) ? `Finding: ${stringValue(args.finding_id)}` : "",
    stringValue(args.runtime_id) ? `Runtime: ${stringValue(args.runtime_id)}` : "",
    stringValue(args.severity) ? `Severity: ${stringValue(args.severity)}` : "",
    stringValue(args.owner) ? `Owner: ${stringValue(args.owner)}` : "",
    ...(stringList(args.evidence_refs) ?? []).map((ref) => `Evidence: ${ref}`),
  ].filter((line, index, all) => line || (index > 0 && all[index - 1] !== ""));
  return trimForSlack(lines.join("\n").trim(), deps.config.ticketing.maxDescriptionChars);
}

function ticketLabels(args: TicketDraftArgs, fallback: string): string[] {
  return unique([
    fallback,
    args.finding_id ? "finding" : "",
    args.runtime_id ? "runtime" : "",
    ...(stringList(args.labels) ?? []),
  ].map((label) => label.trim().toLowerCase()).filter(Boolean)).slice(0, 10);
}

function normalizeLinearPriority(value: number | undefined): number | undefined {
  if (value === undefined || Number.isNaN(value)) return undefined;
  return Math.max(0, Math.min(4, Math.floor(value)));
}

export function createTicketingClient(deps: SecurityToolDeps): TicketingClient {
  const jiraSecretName = deps.config.ticketing.jira.apiTokenInfisicalSecretName;
  const linearSecretName = deps.config.ticketing.linear.apiKeyInfisicalSecretName;
  const infisical = jiraSecretName || linearSecretName ? deps.infisical ?? new InfisicalClient(deps.config) : undefined;
  return new TicketingClient(deps.config, {
    jiraApiTokenProviderName: jiraSecretName ? `infisical:${jiraSecretName}` : undefined,
    jiraApiTokenProvider: jiraSecretName && infisical
      ? () => infisical.secretValueForRuntime({ secretName: jiraSecretName }, { requireAllowSecretValues: false })
      : undefined,
    linearApiKeyProviderName: linearSecretName ? `infisical:${linearSecretName}` : undefined,
    linearApiKeyProvider: linearSecretName && infisical
      ? () => infisical.secretValueForRuntime({ secretName: linearSecretName }, { requireAllowSecretValues: false })
      : undefined,
  });
}

function jiraRuntimeMissing(deps: SecurityToolDeps): string[] {
  return [
    deps.config.ticketing.jira.baseUrl ? undefined : "jira_base_url",
    hasJiraTokenPath(deps) ? undefined : "jira_api_token",
  ].filter((item): item is string => Boolean(item));
}

function createNotReady(
  draft: JiraDraftResult | LinearDraftResult,
  missing: string[],
  note: string,
): Record<string, unknown> {
  return {
    ...draft,
    attempted: false,
    error: "ticketing_not_configured",
    missing,
    note,
  };
}

function createFailed(draft: JiraDraftResult | LinearDraftResult, error: unknown): Record<string, unknown> {
  if (error instanceof TicketingConfigurationError) {
    return createNotReady(draft, unique([...draft.missing, ...error.missing]), error.message);
  }
  return {
    ...draft,
    attempted: true,
    error: "ticketing_request_failed",
    message: shortError(error),
  };
}

function hasJiraTokenPath(deps: SecurityToolDeps): boolean {
  return Boolean(
    deps.config.ticketing.jira.apiToken
    || (deps.config.ticketing.jira.apiTokenInfisicalSecretName && (deps.infisical || infisicalRuntimeConfigured(deps))),
  );
}

function hasLinearTokenPath(deps: SecurityToolDeps): boolean {
  return Boolean(
    deps.config.ticketing.linear.apiKey
    || (deps.config.ticketing.linear.apiKeyInfisicalSecretName && (deps.infisical || infisicalRuntimeConfigured(deps))),
  );
}

function infisicalRuntimeConfigured(deps: SecurityToolDeps): boolean {
  return Boolean(
    deps.config.infisical.enabled
    && deps.config.infisical.projectId
    && deps.config.infisical.identityId,
  );
}
