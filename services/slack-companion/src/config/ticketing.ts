import type { ParsedEnv } from "./env.js";
import type { AppConfig } from "./types.js";

export function buildTicketingConfig(parsed: ParsedEnv): AppConfig["ticketing"] {
  return {
    jira: {
      baseUrl: parsed.JIRA_BASE_URL?.replace(/\/$/, ""),
      authEmail: parsed.JIRA_AUTH_EMAIL,
      apiToken: parsed.JIRA_API_TOKEN,
      apiTokenInfisicalSecretName: parsed.JIRA_API_TOKEN_INFISICAL_SECRET_NAME,
      defaultProjectKey: parsed.JIRA_DEFAULT_PROJECT_KEY,
      defaultIssueType: parsed.JIRA_DEFAULT_ISSUE_TYPE,
    },
    linear: {
      apiKey: parsed.LINEAR_API_KEY,
      apiKeyInfisicalSecretName: parsed.LINEAR_API_KEY_INFISICAL_SECRET_NAME,
      defaultTeamId: parsed.LINEAR_DEFAULT_TEAM_ID,
    },
    maxDescriptionChars: parsed.TICKETING_MAX_DESCRIPTION_CHARS,
    timeoutMs: parsed.TICKETING_TIMEOUT_MS,
  };
}
