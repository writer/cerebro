import type { SlackNotificationPreferencesV1 } from "@writer/cerebro-slack-companion";

export interface ArchetypeWorkspaceRuntimeConfig {
  allowedEmailDomains: ReadonlySet<string>;
  baseUrl: string;
  oktaApiToken: string;
  oktaDomain: string;
  timeoutMs: number;
}

export interface SlackRuntimeConfig {
  allowedTeamIds: ReadonlySet<string>;
  archetype?: ArchetypeWorkspaceRuntimeConfig;
  appToken: string;
  appName: string;
  botToken: string;
  cerebroBaseUrl: string;
  cerebroReadApiKey: string;
  cerebroTenantId: string;
  slackAnswerAuthorityUrl: string;
  environmentLabel: string;
  learningTableName?: string;
  lifecycleChannelIds: ReadonlySet<string>;
  lifecycleNoticesEnabled: boolean;
  memoryDirectory: string;
  notificationPreferences: SlackNotificationPreferencesV1;
  port: number;
  production: boolean;
  rustAgentEnabled: boolean;
  computerSandboxGateways: readonly ComputerSandboxGatewayRuntimeConfig[];
}

export interface ComputerSandboxGatewayRuntimeConfig {
  baseUrl: string;
  providerId: string;
  timeoutMs: number;
  token: string;
}

export class SlackRuntimeConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SlackRuntimeConfigError";
  }
}

export function loadSlackRuntimeConfig(
  env: NodeJS.ProcessEnv = process.env,
): SlackRuntimeConfig {
  const allowedTeamIds = new Set(csv(required(env.SLACK_ALLOWED_TEAM_IDS)));
  if (allowedTeamIds.size === 0) {
    throw new SlackRuntimeConfigError("At least one Slack workspace must be allowed.");
  }
  const baseUrl = validatedBaseUrl(required(env.CEREBRO_BASE_URL));
  const archetype = archetypeConfig(env);
  const lifecycleNoticesEnabled = optionalBooleanBinding(
    env.SLACK_LIFECYCLE_NOTICES_ENABLED,
    false,
  );
  const lifecycleChannelIds = new Set(
    csv(env.SLACK_LIFECYCLE_CHANNEL_IDS?.trim() ?? ""),
  );
  const learningTableName = env.SECURITY_LEARNING_TABLE_NAME?.trim();
  const production = booleanBinding(env.CEREBRO_SLACK_PRODUCTION);
  const rustAgentEnabled = optionalBooleanBinding(
    env.CEREBRO_SLACK_AGENT_ENABLED,
    false,
  );
  if (production && !rustAgentEnabled) {
    throw new SlackRuntimeConfigError(
      "Production Slack requires the Rust agent runtime.",
    );
  }
  if (
    lifecycleNoticesEnabled
    && (lifecycleChannelIds.size === 0 || !learningTableName)
  ) {
    throw new SlackRuntimeConfigError(
      "Slack lifecycle notices require a learning table and at least one channel.",
    );
  }
  return Object.freeze({
    allowedTeamIds,
    ...(archetype === undefined ? {} : { archetype }),
    appToken: required(env.SLACK_APP_TOKEN),
    appName: required(env.CEREBRO_SLACK_APP_NAME),
    botToken: required(env.SLACK_BOT_TOKEN),
    cerebroBaseUrl: baseUrl,
    cerebroReadApiKey: required(env.CEREBRO_READ_API_KEY),
    cerebroTenantId: required(env.CEREBRO_TENANT_ID),
    slackAnswerAuthorityUrl: validatedLoopbackUrl(
      env.CEREBRO_SLACK_ANSWER_AUTHORITY_URL?.trim() || "http://127.0.0.1:8091",
    ),
    environmentLabel: required(env.CEREBRO_SLACK_ENVIRONMENT_LABEL),
    ...(learningTableName ? { learningTableName } : {}),
    lifecycleChannelIds,
    lifecycleNoticesEnabled,
    memoryDirectory: env.CEREBRO_SLACK_RUNTIME_MEMORY_DIR?.trim()
      || "/memory/slack-runtime",
    notificationPreferences: notificationPreferences(env),
    port: port(env.PORT),
    production,
    rustAgentEnabled,
    computerSandboxGateways: computerSandboxGateways(env),
  });
}

function notificationPreferences(env: NodeJS.ProcessEnv): SlackNotificationPreferencesV1 {
  const enabled = csv(env.CEREBRO_SLACK_NOTIFICATION_CLASSES?.trim()
    || "alert,digest,followup");
  if (enabled.some((value) => !["alert", "digest", "followup"].includes(value))) {
    throw new SlackRuntimeConfigError("Slack notification classes are invalid.");
  }
  const minimumSeverity = env.CEREBRO_SLACK_NOTIFICATION_MINIMUM_SEVERITY?.trim() || "low";
  if (!["critical", "high", "medium", "low"].includes(minimumSeverity)) {
    throw new SlackRuntimeConfigError("Slack notification minimum severity is invalid.");
  }
  return Object.freeze({
    digest_hour: positiveInteger(env.CEREBRO_SLACK_NOTIFICATION_DIGEST_HOUR, 8, 0, 23, "Slack notification digest hour"),
    enabled_classes: Object.freeze(enabled) as SlackNotificationPreferencesV1["enabled_classes"],
    minimum_severity: minimumSeverity as SlackNotificationPreferencesV1["minimum_severity"],
    quiet_hours_end: positiveInteger(env.CEREBRO_SLACK_NOTIFICATION_QUIET_END, 7, 0, 23, "Slack notification quiet-hours end"),
    quiet_hours_start: positiveInteger(env.CEREBRO_SLACK_NOTIFICATION_QUIET_START, 22, 0, 23, "Slack notification quiet-hours start"),
    schema_version: "slack-notification-preferences/v1",
    timezone: env.CEREBRO_SLACK_NOTIFICATION_TIMEZONE?.trim() || "America/Los_Angeles",
  });
}

function computerSandboxGateways(
  env: NodeJS.ProcessEnv,
): readonly ComputerSandboxGatewayRuntimeConfig[] {
  const raw = env.CEREBRO_COMPUTER_SANDBOX_GATEWAYS_JSON?.trim();
  if (!raw) return Object.freeze([]);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new SlackRuntimeConfigError("Computer sandbox gateway configuration is invalid.");
  }
  if (!Array.isArray(parsed) || parsed.length > 8) {
    throw new SlackRuntimeConfigError("Computer sandbox gateway configuration is invalid.");
  }
  if (parsed.length === 0) return Object.freeze([]);
  const providerIds = new Set<string>();
  const bindings = parsed.map((item) => {
    if (
      item === null
      || typeof item !== "object"
      || Array.isArray(item)
      || JSON.stringify(Object.keys(item).sort()) !==
        JSON.stringify(["base_url", "provider_id", "timeout_ms", "token_env"])
    ) {
      throw new SlackRuntimeConfigError("Computer sandbox gateway configuration is invalid.");
    }
    const record = item as Record<string, unknown>;
    const providerId = String(record.provider_id ?? "");
    const tokenEnv = String(record.token_env ?? "");
    const timeoutMs = Number(record.timeout_ms);
    if (
      !/^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/u.test(providerId)
      || providerIds.has(providerId)
      || !/^CEREBRO_COMPUTER_SANDBOX_TOKEN_[A-Z0-9_]+$/u.test(tokenEnv)
      || !Number.isSafeInteger(timeoutMs)
      || timeoutMs < 1_000
      || timeoutMs > 120_000
    ) {
      throw new SlackRuntimeConfigError("Computer sandbox gateway configuration is invalid.");
    }
    providerIds.add(providerId);
    return Object.freeze({
      baseUrl: validatedBaseUrl(String(record.base_url ?? "")),
      providerId,
      timeoutMs,
      token: required(env[tokenEnv]),
    });
  });
  return Object.freeze(bindings);
}

function archetypeConfig(
  env: NodeJS.ProcessEnv,
): ArchetypeWorkspaceRuntimeConfig | undefined {
  const enabled = optionalBooleanBinding(env.ARCHETYPE_WORKSPACE_ENABLED, false);
  if (!enabled) {
    const unexpected = [
      env.ARCHETYPE_BASE_URL,
      env.ARCHETYPE_ALLOWED_EMAIL_DOMAINS,
      env.OKTA_DOMAIN,
      env.OKTA_API_TOKEN,
    ].some((value) => Boolean(value?.trim()));
    if (unexpected) {
      throw new SlackRuntimeConfigError(
        "Archetype workspace bindings require ARCHETYPE_WORKSPACE_ENABLED=true.",
      );
    }
    return undefined;
  }
  const allowedEmailDomains = new Set(
    csv(required(env.ARCHETYPE_ALLOWED_EMAIL_DOMAINS))
      .map((value) => value.toLowerCase()),
  );
  if (
    allowedEmailDomains.size === 0
    || [...allowedEmailDomains].some((domain) =>
      !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)
    )
  ) {
    throw new SlackRuntimeConfigError(
      "Archetype allowed email domains are invalid.",
    );
  }
  return Object.freeze({
    allowedEmailDomains,
    baseUrl: validatedBaseUrl(required(env.ARCHETYPE_BASE_URL)),
    oktaApiToken: required(env.OKTA_API_TOKEN),
    oktaDomain: validatedOktaDomain(required(env.OKTA_DOMAIN)),
    timeoutMs: positiveInteger(
      env.ARCHETYPE_REQUEST_TIMEOUT_MS,
      10_000,
      1_000,
      30_000,
      "Archetype request timeout",
    ),
  });
}

function booleanBinding(value: string | undefined): boolean {
  const normalized = required(value);
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  throw new SlackRuntimeConfigError("A required boolean runtime binding is invalid.");
}

function optionalBooleanBinding(
  value: string | undefined,
  fallback: boolean,
): boolean {
  if (value === undefined || value.trim() === "") return fallback;
  return booleanBinding(value);
}

function required(value: string | undefined): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new SlackRuntimeConfigError("A required runtime binding is missing.");
  }
  return normalized;
}

function csv(value: string): string[] {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function port(value: string | undefined): number {
  const parsed = Number(value ?? "3000");
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65_535) {
    throw new SlackRuntimeConfigError("The runtime port is invalid.");
  }
  return parsed;
}

function positiveInteger(
  value: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  field: string,
): number {
  const parsed = Number(value ?? String(fallback));
  if (
    !Number.isSafeInteger(parsed)
    || parsed < minimum
    || parsed > maximum
  ) {
    throw new SlackRuntimeConfigError(`${field} is invalid.`);
  }
  return parsed;
}

function validatedBaseUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new SlackRuntimeConfigError("The Cerebro service binding is invalid.");
  }
  const localHttp = parsed.protocol === "http:"
    && (parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost");
  if ((parsed.protocol !== "https:" && !localHttp) || parsed.username || parsed.password) {
    throw new SlackRuntimeConfigError("The Cerebro service binding is invalid.");
  }
  parsed.pathname = parsed.pathname.replace(/\/$/, "");
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString().replace(/\/$/, "");
}

function validatedLoopbackUrl(value: string): string {
  const parsed = new URL(validatedBaseUrl(value));
  if (parsed.protocol !== "http:" || (parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost")) {
    throw new SlackRuntimeConfigError(
      "The Rust Slack answer authority must use a loopback HTTP binding.",
    );
  }
  return parsed.toString().replace(/\/$/, "");
}

function validatedOktaDomain(value: string): string {
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//iu.test(value)
    ? value
    : `https://${value}`;
  return validatedBaseUrl(candidate);
}
