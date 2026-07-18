import type { AppConfig } from "../config/index.js";

const LINEAR_GRAPHQL_URL = "https://api.linear.app/graphql";

export interface JiraCreateIssueInput {
  projectKey: string;
  issueType: string;
  summary: string;
  description: string;
  labels: string[];
}

export interface JiraSearchIssuesInput {
  jql?: string;
  query?: string;
  projectKey?: string;
  limit?: number;
  maxResults?: number;
  nextPageToken?: string;
}

export interface JiraUpdateIssueInput {
  issueKey: string;
  comment?: string;
  labelsAdd?: string[];
  labelsRemove?: string[];
  transitionId?: string;
  transitionName?: string;
}

export interface LinearCreateIssueInput {
  teamId: string;
  title: string;
  description: string;
  priority?: number;
  labels: string[];
}

interface TicketingClientOptions {
  fetchImpl?: typeof fetch;
  jiraApiTokenProvider?: () => Promise<string | undefined>;
  jiraApiTokenProviderName?: string;
  linearApiKeyProvider?: () => Promise<string | undefined>;
  linearApiKeyProviderName?: string;
}

interface TokenState {
  token?: string;
  source: string;
  error?: string;
}

export class TicketingConfigurationError extends Error {
  readonly code = "ticketing_not_configured";

  constructor(readonly missing: string[], message = `Ticketing is missing: ${missing.join(", ")}`) {
    super(message);
    this.name = "TicketingConfigurationError";
  }
}

export class TicketingClient {
  private cachedJiraApiToken?: string;
  private cachedLinearApiKey?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly config: AppConfig, private readonly options: TicketingClientOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async createJiraIssue(input: JiraCreateIssueInput): Promise<Record<string, unknown>> {
    if (!input.projectKey) throw new TicketingConfigurationError(["project_key"]);

    const { baseUrl, tokenState } = await this.jiraRequestState();
    const body = await this.requestJson<Record<string, unknown>>(`${baseUrl}/rest/api/3/issue`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: jiraAuthorization(this.config.ticketing.jira.authEmail, tokenState.token),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        fields: {
          project: { key: input.projectKey },
          issuetype: { name: input.issueType },
          summary: input.summary,
          description: jiraDescriptionAdf(input.description),
          labels: input.labels,
        },
      }),
    });

    const key = stringField(body, "key");
    const id = stringField(body, "id");
    return {
      system: "jira",
      created: true,
      id,
      key,
      self: stringField(body, "self"),
      web_url: key ? `${baseUrl}/browse/${encodeURIComponent(key)}` : undefined,
      api_token_source: tokenState.source,
      issue: {
        project_key: input.projectKey,
        issue_type: input.issueType,
        summary: input.summary,
        labels: input.labels,
      },
    };
  }

  async searchJiraIssues(input: JiraSearchIssuesInput): Promise<Record<string, unknown>> {
    const { baseUrl, tokenState } = await this.jiraRequestState();
    const jql = jiraSearchJql(input);
    if (!jql) throw new TicketingConfigurationError(["jql"]);
    const maxResults = limit(input.maxResults ?? input.limit, 25, 50);
    const body = await this.requestJson<Record<string, unknown>>(`${baseUrl}/rest/api/3/search/jql`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: jiraAuthorization(this.config.ticketing.jira.authEmail, tokenState.token),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        fields: [
          "summary",
          "status",
          "assignee",
          "reporter",
          "priority",
          "issuetype",
          "created",
          "updated",
          "duedate",
          "labels",
          "project",
        ],
        jql,
        maxResults,
        nextPageToken: input.nextPageToken,
      }),
    });

    const issues = arrayField(body, "issues").map((issue) => jiraIssueSummary(issue, baseUrl));
    return {
      system: "jira",
      searched: true,
      jql,
      max_results: maxResults,
      result_count: issues.length,
      is_last: booleanField(body, "isLast"),
      next_page_token: stringField(body, "nextPageToken"),
      api_token_source: tokenState.source,
      issues,
    };
  }

  async updateJiraIssue(input: JiraUpdateIssueInput): Promise<Record<string, unknown>> {
    const issueKey = input.issueKey.trim();
    if (!issueKey) throw new TicketingConfigurationError(["issue_key"]);

    const { baseUrl, tokenState } = await this.jiraRequestState();
    const operations: Array<Record<string, unknown>> = [];
    const trimmedComment = input.comment?.trim();
    if (trimmedComment) {
      const comment = await this.requestJson<Record<string, unknown>>(`${baseUrl}/rest/api/3/issue/${encodeURIComponent(issueKey)}/comment`, {
        method: "POST",
        headers: {
          Accept: "application/json",
          Authorization: jiraAuthorization(this.config.ticketing.jira.authEmail, tokenState.token),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ body: jiraDescriptionAdf(trimmedComment) }),
      });
      operations.push({
        action: "comment_added",
        id: stringField(comment, "id"),
        self: stringField(comment, "self"),
      });
    }

    const labelsAdd = cleanLabels(input.labelsAdd);
    const labelsRemove = cleanLabels(input.labelsRemove);
    if (labelsAdd.length || labelsRemove.length) {
      await this.requestJson<Record<string, unknown>>(`${baseUrl}/rest/api/3/issue/${encodeURIComponent(issueKey)}`, {
        method: "PUT",
        headers: {
          Accept: "application/json",
          Authorization: jiraAuthorization(this.config.ticketing.jira.authEmail, tokenState.token),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          update: {
            labels: [
              ...labelsAdd.map((label) => ({ add: label })),
              ...labelsRemove.map((label) => ({ remove: label })),
            ],
          },
        }),
      });
      operations.push({
        action: "labels_updated",
        add: labelsAdd,
        remove: labelsRemove,
      });
    }

    const transitionId = await this.resolveJiraTransitionId(baseUrl, tokenState.token, issueKey, input);
    if (transitionId) {
      await this.requestJson<Record<string, unknown>>(`${baseUrl}/rest/api/3/issue/${encodeURIComponent(issueKey)}/transitions`, {
        method: "POST",
        headers: {
          Accept: "application/json",
          Authorization: jiraAuthorization(this.config.ticketing.jira.authEmail, tokenState.token),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ transition: { id: transitionId } }),
      });
      operations.push({
        action: "transitioned",
        transition_id: transitionId,
        requested_transition_name: input.transitionName,
      });
    }

    if (operations.length === 0) {
      throw new TicketingConfigurationError(["comment_or_labels_or_transition"], "No Jira update operation was supplied.");
    }
    return {
      system: "jira",
      updated: true,
      key: issueKey,
      web_url: `${baseUrl}/browse/${encodeURIComponent(issueKey)}`,
      api_token_source: tokenState.source,
      operations,
    };
  }

  async createLinearIssue(input: LinearCreateIssueInput): Promise<Record<string, unknown>> {
    if (!input.teamId) throw new TicketingConfigurationError(["team_id"]);

    const tokenState = await this.linearApiKeyState();
    if (!tokenState.token) {
      throw new TicketingConfigurationError(["linear_api_key"], tokenState.error ?? "No Linear API key is configured.");
    }

    const variables: Record<string, unknown> = {
      input: {
        teamId: input.teamId,
        title: input.title,
        description: input.description,
        priority: input.priority,
      },
    };
    const body = await this.requestJson<Record<string, unknown>>(LINEAR_GRAPHQL_URL, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${tokenState.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: [
          "mutation IssueCreate($input: IssueCreateInput!) {",
          "  issueCreate(input: $input) {",
          "    success",
          "    issue { id identifier title url }",
          "  }",
          "}",
        ].join("\n"),
        variables,
      }),
    });

    const errors = arrayField(body, "errors");
    if (errors.length > 0) {
      throw new Error(`Linear GraphQL returned errors: ${JSON.stringify(errors).slice(0, 500)}`);
    }
    const issueCreate = objectField(objectField(body, "data"), "issueCreate");
    if (issueCreate?.success !== true) {
      throw new Error(`Linear issueCreate did not return success: ${JSON.stringify(issueCreate ?? body).slice(0, 500)}`);
    }
    const issue = objectField(issueCreate, "issue");
    return {
      system: "linear",
      created: true,
      api_key_source: tokenState.source,
      issue: {
        id: stringField(issue, "id"),
        identifier: stringField(issue, "identifier"),
        title: stringField(issue, "title"),
        url: stringField(issue, "url"),
        team_id: input.teamId,
        priority: input.priority,
      },
      requested_labels: input.labels,
    };
  }

  private async jiraApiTokenState(): Promise<TokenState> {
    const envToken = this.config.ticketing.jira.apiToken?.trim();
    if (envToken) return { token: envToken, source: "env" };
    if (this.cachedJiraApiToken) return { token: this.cachedJiraApiToken, source: this.options.jiraApiTokenProviderName ?? "provider" };
    if (!this.options.jiraApiTokenProvider) return { source: "missing" };
    return this.providedTokenState(this.options.jiraApiTokenProvider, this.options.jiraApiTokenProviderName ?? "provider", "jira");
  }

  private async linearApiKeyState(): Promise<TokenState> {
    const envToken = this.config.ticketing.linear.apiKey?.trim();
    if (envToken) return { token: envToken, source: "env" };
    if (this.cachedLinearApiKey) return { token: this.cachedLinearApiKey, source: this.options.linearApiKeyProviderName ?? "provider" };
    if (!this.options.linearApiKeyProvider) return { source: "missing" };
    return this.providedTokenState(this.options.linearApiKeyProvider, this.options.linearApiKeyProviderName ?? "provider", "linear");
  }

  private async jiraRequestState(): Promise<{ baseUrl: string; tokenState: TokenState & { token: string } }> {
    const baseUrl = this.config.ticketing.jira.baseUrl;
    if (!baseUrl) throw new TicketingConfigurationError(["jira_base_url"]);

    const tokenState = await this.jiraApiTokenState();
    if (!tokenState.token) {
      throw new TicketingConfigurationError(["jira_api_token"], tokenState.error ?? "No Jira API token is configured.");
    }
    return { baseUrl, tokenState: tokenState as TokenState & { token: string } };
  }

  private async resolveJiraTransitionId(
    baseUrl: string,
    token: string,
    issueKey: string,
    input: JiraUpdateIssueInput,
  ): Promise<string | undefined> {
    const explicit = input.transitionId?.trim();
    if (explicit) return explicit;
    const requestedName = input.transitionName?.trim();
    if (!requestedName) return undefined;
    const body = await this.requestJson<Record<string, unknown>>(`${baseUrl}/rest/api/3/issue/${encodeURIComponent(issueKey)}/transitions`, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: jiraAuthorization(this.config.ticketing.jira.authEmail, token),
      },
    });
    const transition = arrayField(body, "transitions")
      .map(objectFrom)
      .find((item) => stringField(item, "name")?.toLowerCase() === requestedName.toLowerCase());
    const id = stringField(transition, "id");
    if (!id) {
      throw new Error(`Jira transition not found: ${requestedName}`);
    }
    return id;
  }

  private async providedTokenState(
    provider: () => Promise<string | undefined>,
    source: string,
    system: "jira" | "linear",
  ): Promise<TokenState> {
    try {
      const provided = (await provider())?.trim();
      if (!provided) return { source, error: "provider returned no token" };
      if (system === "jira") this.cachedJiraApiToken = provided;
      if (system === "linear") this.cachedLinearApiKey = provided;
      return { token: provided, source };
    } catch (error) {
      return { source, error: shortError(error) };
    }
  }

  private async requestJson<T>(url: string, init: RequestInit): Promise<T> {
    const response = await this.fetchImpl(url, {
      ...init,
      signal: init.signal ?? AbortSignal.timeout(this.config.ticketing.timeoutMs),
    });
    const text = await response.text();
    const body = parseJson(text);
    if (!response.ok) {
      throw new Error(`Ticketing request failed with ${response.status}: ${JSON.stringify(body).slice(0, 500)}`);
    }
    return body as T;
  }
}

function jiraAuthorization(email: string | undefined, token: string): string {
  const trimmedEmail = email?.trim();
  if (!trimmedEmail) return `Bearer ${token}`;
  return `Basic ${Buffer.from(`${trimmedEmail}:${token}`).toString("base64")}`;
}

function jiraSearchJql(input: JiraSearchIssuesInput): string | undefined {
  const explicit = input.jql?.trim();
  if (explicit) return explicit;
  const parts: string[] = [];
  const project = input.projectKey?.trim();
  if (project) parts.push(`project = ${quoteJiraValue(project)}`);
  const query = input.query?.trim();
  if (query) parts.push(`text ~ ${quoteJiraValue(query)}`);
  return parts.length ? `${parts.join(" AND ")} ORDER BY updated DESC` : undefined;
}

function quoteJiraValue(value: string): string {
  return `"${value.replace(/["\\]/g, "\\$&")}"`;
}

function jiraDescriptionAdf(description: string): Record<string, unknown> {
  const content = description.split(/\r?\n/).map((line) => ({
    type: "paragraph",
    content: line ? [{ type: "text", text: line }] : [],
  }));
  return {
    type: "doc",
    version: 1,
    content: content.length > 0 ? content : [{ type: "paragraph", content: [] }],
  };
}

function cleanLabels(values: string[] | undefined): string[] {
  return [...new Set((values ?? []).map((value) => value.trim().toLowerCase()).filter(Boolean))].slice(0, 20);
}

function objectFrom(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function objectField(value: unknown, key: string): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const field = (value as Record<string, unknown>)[key];
  return field && typeof field === "object" && !Array.isArray(field) ? field as Record<string, unknown> : undefined;
}

function stringField(value: unknown, key: string): string | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const field = (value as Record<string, unknown>)[key];
  return typeof field === "string" ? field : undefined;
}

function arrayField(value: unknown, key: string): unknown[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  const field = (value as Record<string, unknown>)[key];
  return Array.isArray(field) ? field : [];
}

function booleanField(value: unknown, key: string): boolean | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const field = (value as Record<string, unknown>)[key];
  return typeof field === "boolean" ? field : undefined;
}

function stringArrayField(value: unknown, key: string): string[] {
  return arrayField(value, key).filter((item): item is string => typeof item === "string");
}

function jiraIssueSummary(issue: unknown, baseUrl: string): Record<string, unknown> {
  const fields = objectField(issue, "fields");
  const key = stringField(issue, "key");
  const status = objectField(fields, "status");
  const statusCategory = objectField(status, "statusCategory");
  return {
    id: stringField(issue, "id"),
    key,
    self: stringField(issue, "self"),
    web_url: key ? `${baseUrl}/browse/${encodeURIComponent(key)}` : undefined,
    summary: stringField(fields, "summary"),
    issue_type: stringField(objectField(fields, "issuetype"), "name"),
    status: status ? {
      name: stringField(status, "name"),
      category: stringField(statusCategory, "name"),
    } : undefined,
    assignee: jiraUserSummary(objectField(fields, "assignee")),
    reporter: jiraUserSummary(objectField(fields, "reporter")),
    priority: stringField(objectField(fields, "priority"), "name"),
    project_key: stringField(objectField(fields, "project"), "key"),
    created: stringField(fields, "created"),
    updated: stringField(fields, "updated"),
    due_date: stringField(fields, "duedate"),
    labels: stringArrayField(fields, "labels"),
  };
}

function jiraUserSummary(user: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!user) return undefined;
  return {
    account_id: stringField(user, "accountId"),
    display_name: stringField(user, "displayName"),
    active: booleanField(user, "active"),
    email: stringField(user, "emailAddress"),
  };
}

function parseJson(text: string): unknown {
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return text.slice(0, 500);
  }
}

function shortError(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 300) : String(error).slice(0, 300);
}

function limit(value: number | undefined, fallback: number, max: number): number {
  if (!value || Number.isNaN(value)) return fallback;
  return Math.max(1, Math.min(max, Math.floor(value)));
}
