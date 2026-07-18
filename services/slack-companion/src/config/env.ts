import { z } from "zod";
import { blankToUndefined } from "./parsing.js";

const coreEnv = {
  NODE_ENV: z.string().default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
};

const slackEnv = {
  SLACK_BOT_TOKEN: z.string().optional(),
  SLACK_SIGNING_SECRET: z.string().optional(),
  SLACK_SOCKET_MODE: z.string().default("true"),
  SLACK_APP_TOKEN: z.string().optional(),
  SLACK_DEFAULT_CHANNEL_ID: z.string().optional(),
  SLACK_ALLOWED_TEAM_IDS: z.string().optional(),
  SLACK_AUDIT_LOGS_TOKEN: z.string().optional(),
  SLACK_FINDING_WRITE_USER_IDS: z.string().optional(),
  SLACK_SOURCE_WRITE_USER_IDS: z.string().optional(),
  SLACK_RESPONSE_WRITE_USER_IDS: z.string().optional(),
  SLACK_GRAPH_ACTION_USER_IDS: z.string().optional(),
  SLACK_AUTONOMY_APPROVAL_USER_IDS: z.string().optional(),
  SLACK_OPERATOR_USER_IDS: z.string().optional(),
  SLACK_TRIAGE_CHANNEL_IDS: z.string().optional(),
  SLACK_RISK_ATTESTATION_CHANNEL_IDS: z.string().optional(),
  SLACK_RISK_ATTESTATION_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
  SLACK_TRIAGE_CHANNEL_POLICIES: z.string().optional(),
  SLACK_TRIAGE_AUTO_REPLY: z.string().default("true"),
  SLACK_LIFECYCLE_NOTICES_ENABLED: z.string().default("true"),
  SLACK_LIFECYCLE_CHANNEL_IDS: z.string().optional(),
  SLACK_RESEARCH_MAX_CHANNELS: z.coerce.number().int().positive().default(30),
  SLACK_RESEARCH_HISTORY_LIMIT: z.coerce.number().int().positive().default(500),
  SLACK_ASSISTANT_BOT_USER_IDS: z.string().optional(),
  SLACK_ASSISTANT_BOT_COOLDOWN_SECONDS: z.coerce.number().int().nonnegative().default(600),
  SLACK_ASSISTANT_BOT_MAX_HANDOFFS_PER_THREAD: z.coerce.number().int().nonnegative().default(2),
  SLACK_ASSISTANT_BOT_HANDOFF_WINDOW_SECONDS: z.coerce.number().int().positive().default(3_600),
  SLACK_ASSISTANT_BOT_HANDOFF_POLICIES_JSON: z.string().optional(),
};

const cerebroEnv = {
  CEREBRO_BASE_URL: z.string().url(),
  CEREBRO_TENANT_ID: z.string().min(1),
  CEREBRO_REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),
  CEREBRO_WEB_BASE_URL: z.string().url().optional(),
  CEREBRO_DEFAULT_RUNTIME_IDS: z.string().optional(),
  CEREBRO_COMPANION_RUNTIME_ID: z.string().default("writer-slack-companion"),
  CEREBRO_ASSISTANT_HELP_MENTION: z.preprocess(blankToUndefined, z.string().optional()),
  CEREBRO_READ_API_KEY: z.string().min(1),
  CEREBRO_FINDINGS_API_KEY: z.string().optional(),
  CEREBRO_SOURCE_API_KEY: z.string().optional(),
  CEREBRO_RUNTIME_RESPONSE_API_KEY: z.string().optional(),
  CEREBRO_GRAPH_ACTION_API_KEY: z.string().optional(),
  CEREBRO_SLACK_USER_MAP_JSON: z.string().optional(),
};

const evidenceCasEnv = {
  EVIDENCE_CAS_BASE_URL: z.preprocess((value) => {
    if (typeof value !== "string") return value;
    const trimmed = value.trim();
    if (!trimmed || trimmed === "[secret]") return undefined;
    return trimmed;
  }, z.string().url().optional()),
  EVIDENCE_CAS_READ_TOKEN: z.string().optional(),
  EVIDENCE_CAS_READ_TOKEN_INFISICAL_SECRET_NAME: z.preprocess(blankToUndefined, z.string().default("EVIDENCE_CAS_READ_TOKEN")),
  EVIDENCE_CAS_DEFAULT_BUCKET: z.string().default("cases"),
  EVIDENCE_CAS_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),
};

const infisicalEnv = {
  INFISICAL_ENABLED: z.string().default("true"),
  INFISICAL_BASE_URL: z.string().url().default("https://app.infisical.com"),
  INFISICAL_PROJECT_ID: z.preprocess(blankToUndefined, z.string().optional()),
  INFISICAL_PROJECT_SLUG: z.string().default("wi-cerebro-slack-companion"),
  INFISICAL_ENVIRONMENT: z.string().default("dev"),
  INFISICAL_SECRET_PATH: z.string().default("/"),
  INFISICAL_IDENTITY_ID: z.preprocess(blankToUndefined, z.string().optional()),
  INFISICAL_AWS_REGION: z.string().default(process.env.AWS_REGION ?? "us-east-1"),
  INFISICAL_STS_ENDPOINT: z.preprocess(blankToUndefined, z.string().url().optional()),
  INFISICAL_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),
  INFISICAL_CACHE_TTL_MS: z.coerce.number().int().positive().default(600_000),
  INFISICAL_ALLOW_SECRET_VALUES: z.string().default("false"),
};

const pantherMcpEnv = {
  PANTHER_MCP_ENABLED: z.string().default("false"),
  PANTHER_MCP_URL: z.preprocess(blankToUndefined, z.string().url().optional()),
  PANTHER_MCP_AUTH_TOKEN: z.preprocess(blankToUndefined, z.string().optional()),
  PANTHER_MCP_ALLOWED_TOOLS: z.string().optional(),
  PANTHER_MCP_ALLOW_MUTATING_TOOLS: z.string().default("false"),
  PANTHER_MCP_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),
};

const triageEnv = {
  CEREBRO_TRIAGE_ENABLED: z.string().default("true"),
  CEREBRO_TRIAGE_THREAD_STATE_TABLE_NAME: z.string().optional(),
  CEREBRO_TRIAGE_MIN_CONFIDENCE: z.coerce.number().min(0).max(1).default(0),
  CEREBRO_TRIAGE_MAX_RESEARCH_STEPS: z.coerce.number().int().positive().default(12),
  CEREBRO_TRIAGE_TIMEOUT_MS: z.coerce.number().int().positive().default(300_000),
  CEREBRO_TRIAGE_MAX_CONCURRENT: z.coerce.number().int().positive().default(2),
  CEREBRO_TRIAGE_PROMPT_MAX_CHARS: z.coerce.number().int().positive().default(240_000),
  CEREBRO_TRIAGE_PROMPT_COMPACTION_TARGET_CHARS: z.coerce.number().int().positive().default(180_000),
  CEREBRO_WORK_LOOP_DUPLICATE_COOLDOWN_MS: z.coerce.number().int().nonnegative().default(600_000),
  CEREBRO_WORK_QUEUE_ENABLED: z.string().default("false"),
  CEREBRO_WORK_QUEUE_URL: z.preprocess(blankToUndefined, z.string().url().optional()),
  CEREBRO_WORK_QUEUE_PUBLISHER_INTERVAL_MS: z.coerce.number().int().min(250).default(1_000),
  CEREBRO_WORK_QUEUE_PUBLISHER_BATCH_SIZE: z.coerce.number().int().min(1).max(100).default(50),
  CEREBRO_WORK_QUEUE_CONSUMER_COUNT: z.coerce.number().int().min(1).max(32).default(2),
  CEREBRO_WORK_QUEUE_VISIBILITY_TIMEOUT_SECONDS: z.coerce.number().int().min(60).max(43_200).default(90),
  CEREBRO_ASSISTANT_RUNTIME: z.enum(["pi", "flue"]).default("pi"),
  PI_ENABLED: z.string().default("true"),
  PI_PROVIDER: z.string().default("amazon-bedrock"),
  PI_MODEL: z.string().default("us.anthropic.claude-opus-4-8"),
  PI_THINKING_LEVEL: z.enum(["off", "minimal", "low", "medium", "high", "xhigh"]).default("medium"),
  PI_EXECUTION_MODEL: z.preprocess(blankToUndefined, z.string().optional()),
  PI_EXECUTION_THINKING_LEVEL: z.preprocess(blankToUndefined, z.enum(["off", "minimal", "low", "medium", "high", "xhigh"]).optional()),
};

const learningEnv = {
  SECURITY_LEARNING_ENABLED: z.string().default("true"),
  SECURITY_LEARNING_TABLE_NAME: z.string().optional(),
  SECURITY_LEARNING_MAX_SEARCH_RESULTS: z.coerce.number().int().positive().default(6),
  CEREBRO_SLACK_CHANNEL_LEARNING_ENABLED: z.string().default("true"),
  CEREBRO_SLACK_CHANNEL_LEARNING_EXCLUDED_CHANNEL_IDS: z.string().optional(),
  CEREBRO_SLACK_CHANNEL_LEARNING_BATCH_SIZE: z.coerce.number().int().min(2).max(50).default(12),
  CEREBRO_SLACK_CHANNEL_LEARNING_FLUSH_INTERVAL_MS: z.coerce.number().int().min(30_000).default(600_000),
  CEREBRO_DAILY_NOTES_ENABLED: z.string().default("true"),
  CEREBRO_DAILY_NOTES_TIME_ZONE: z.string().default("America/Los_Angeles"),
  CEREBRO_DAILY_NOTES_CONSOLIDATION_HOUR: z.coerce.number().int().min(0).max(23).default(2),
  CEREBRO_DAILY_NOTES_CONSOLIDATION_MINUTE: z.coerce.number().int().min(0).max(59).default(30),
  CEREBRO_DAILY_NOTES_NIGHT_START_HOUR: z.coerce.number().int().min(0).max(23).default(0),
  CEREBRO_DAILY_NOTES_NIGHT_END_HOUR: z.coerce.number().int().min(1).max(24).default(6),
  CEREBRO_DAILY_NOTES_CHECK_INTERVAL_MS: z.coerce.number().int().positive().default(900_000),
  CEREBRO_DAILY_NOTES_RETENTION_DAYS: z.coerce.number().int().positive().default(30),
  SECURITY_WORKING_MEMORY_ENABLED: z.string().default("true"),
  SECURITY_WORKING_MEMORY_DIR: z.string().optional(),
  SECURITY_WORKING_MEMORY_CHAR_LIMIT: z.coerce.number().int().positive().default(2200),
  SECURITY_TEAM_MEMORY_CHAR_LIMIT: z.coerce.number().int().positive().default(1375),
  SECURITY_LEARNING_DOCS_ENABLED: z.string().default("true"),
  SECURITY_LEARNING_DOCS_DIR: z.string().optional(),
  SECURITY_LEARNING_DOCS_CHAR_LIMIT: z.coerce.number().int().positive().default(12_000),
};

const codeEnv = {
  CEREBRO_CODE_WRITE_ENABLED: z.string().default("true"),
  CEREBRO_CODE_WORKSPACE_DIR: z.string().default("/memory/code"),
  CEREBRO_CODE_DEFAULT_REPO: z.string().default("writer/cerebro"),
  CEREBRO_CODE_REPO_PATH_PREFIX: z.string().default("services/slack-companion"),
  CEREBRO_CODE_WRITE_ALLOWED_ORGS: z.string().default("Writer,WriterColab,WriterInternal"),
  CEREBRO_CODE_BRANCH_PREFIX: z.string().default("cerebro/runtime"),
  CEREBRO_CODE_MAX_FILE_BYTES: z.coerce.number().int().positive().default(120_000),
  CEREBRO_CODE_MAX_FILES: z.coerce.number().int().positive().default(12),
  CEREBRO_CODE_SHELL_ENABLED: z.string().default("false"),
  CEREBRO_CODE_SHELL_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),
  CEREBRO_CODE_SHELL_MAX_OUTPUT_BYTES: z.coerce.number().int().positive().default(24_000),
  CEREBRO_CODE_SHELL_MAX_COMMAND_BYTES: z.coerce.number().int().positive().default(4_000),
  CEREBRO_CODE_GITHUB_TOKEN: z.string().optional(),
  CEREBRO_CODE_GITHUB_APP_ID: z.string().optional(),
  CEREBRO_CODE_GITHUB_INSTALLATION_ID: z.string().optional(),
  CEREBRO_CODE_GITHUB_PRIVATE_KEY_BASE64: z.string().optional(),
};

const codeModeEnv = {
  CEREBRO_CODE_MODE_ENABLED: z.string().default("true"),
  CEREBRO_CODE_MODE_MAX_TOOL_CALLS: z.coerce.number().int().min(1).max(24).default(8),
  CEREBRO_CODE_MODE_MAX_SIDE_EFFECT_CALLS: z.coerce.number().int().min(1).max(1).default(1),
  CEREBRO_CODE_MODE_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(120_000).default(30_000),
  CEREBRO_CODE_MODE_MEMORY_LIMIT_BYTES: z.coerce.number().int().min(32 * 1024 * 1024).max(256 * 1024 * 1024).default(64 * 1024 * 1024),
  CEREBRO_CODE_MODE_MAX_SCRIPT_BYTES: z.coerce.number().int().min(1_024).max(128 * 1024).default(24 * 1024),
  CEREBRO_CODE_MODE_MAX_OUTPUT_BYTES: z.coerce.number().int().min(1_024).max(512 * 1024).default(64 * 1024),
};

const ticketingEnv = {
  JIRA_BASE_URL: z.preprocess(blankToUndefined, z.string().url().optional()),
  JIRA_AUTH_EMAIL: z.preprocess(blankToUndefined, z.string().optional()),
  JIRA_API_TOKEN: z.preprocess(blankToUndefined, z.string().optional()),
  JIRA_API_TOKEN_INFISICAL_SECRET_NAME: z.preprocess(blankToUndefined, z.string().default("JIRA_API_TOKEN")),
  JIRA_DEFAULT_PROJECT_KEY: z.preprocess(blankToUndefined, z.string().optional()),
  JIRA_DEFAULT_ISSUE_TYPE: z.string().default("Task"),
  LINEAR_API_KEY: z.preprocess(blankToUndefined, z.string().optional()),
  LINEAR_API_KEY_INFISICAL_SECRET_NAME: z.preprocess(blankToUndefined, z.string().default("LINEAR_API_KEY")),
  LINEAR_DEFAULT_TEAM_ID: z.preprocess(blankToUndefined, z.string().optional()),
  TICKETING_MAX_DESCRIPTION_CHARS: z.coerce.number().int().positive().default(6000),
  TICKETING_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),
};

const complianceContextEnv = {
  CEREBRO_COMPLIANCE_CONTEXT_ENABLED: z.string().default("true"),
  CEREBRO_COMPLIANCE_CONTEXT_REPO: z.string().default("writer/cerebro"),
  CEREBRO_COMPLIANCE_CONTEXT_REF: z.string().default("main"),
  CEREBRO_COMPLIANCE_CONTEXT_LOCAL_DIR: z.preprocess(blankToUndefined, z.string().optional()),
  CEREBRO_COMPLIANCE_CONTEXT_CACHE_TTL_MS: z.coerce.number().int().positive().default(3_600_000),
  CEREBRO_COMPLIANCE_CONTEXT_FETCH_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
  CEREBRO_COMPLIANCE_CONTEXT_MAX_FILE_BYTES: z.coerce.number().int().positive().default(250_000),
  CEREBRO_COMPLIANCE_CONTEXT_MAX_TOTAL_BYTES: z.coerce.number().int().positive().default(600_000),
};

const selfRepairEnv = {
  CEREBRO_SELF_REPAIR_ENABLED: z.string().default("true"),
  CEREBRO_SELF_REPAIR_CREATE_PR: z.string().default("true"),
  CEREBRO_SELF_REPAIR_THRESHOLD: z.coerce.number().int().positive().default(2),
  CEREBRO_SELF_REPAIR_LOOKBACK_HOURS: z.coerce.number().int().positive().default(24),
  CEREBRO_SELF_REPAIR_COOLDOWN_HOURS: z.coerce.number().int().positive().default(168),
};

const improvementEnv = {
  CEREBRO_IMPROVEMENT_ENABLED: z.string().default("false"),
  CEREBRO_IMPROVEMENT_TABLE_NAME: z.preprocess(blankToUndefined, z.string().optional()),
  CEREBRO_IMPROVEMENT_ARTIFACT_BUCKET: z.preprocess(blankToUndefined, z.string().optional()),
  CEREBRO_IMPROVEMENT_QUEUE_URL: z.preprocess(blankToUndefined, z.string().url().optional()),
  CEREBRO_IMPROVEMENT_PROMOTION_KEY_ID: z.preprocess(blankToUndefined, z.string().optional()),
  CEREBRO_IMPROVEMENT_DELEGATION_KEY_ID: z.preprocess(blankToUndefined, z.string().optional()),
  CEREBRO_IMPROVEMENT_DELEGATION_ROLLOUT_MODE: z.enum(["disabled", "shadow", "canary", "active"]).default("active"),
  CEREBRO_IMPROVEMENT_DELEGATION_CANARY_BASIS_POINTS: z.coerce.number().int().min(0).max(10_000).default(1_000),
  CEREBRO_IMPROVEMENT_DELEGATION_TTL_SECONDS: z.coerce.number().int().min(900).max(3_600).default(1_200),
  CEREBRO_IMPROVEMENT_DELEGATION_POLICY_VERSION: z.string().min(1).max(100).default("cerebro-improvement-author-v1"),
  CEREBRO_IMPROVEMENT_DELEGATION_TOOLSET_VERSION: z.string().min(1).max(100).default("candidate-author-v1"),
  CEREBRO_IMPROVEMENT_DELEGATION_MAX_SOURCE_CALLS: z.coerce.number().int().min(2).max(8).default(8),
  CEREBRO_IMPROVEMENT_DELEGATION_MAX_RUNTIME_MS: z.coerce.number().int().min(30_000).max(600_000).default(300_000),
  CEREBRO_IMPROVEMENT_SIGNAL_THRESHOLD: z.coerce.number().int().positive().default(2),
  CEREBRO_IMPROVEMENT_POLL_INTERVAL_MS: z.coerce.number().int().positive().default(5_000),
  CEREBRO_IMPROVEMENT_STALE_RUN_HOURS: z.coerce.number().int().positive().default(72),
};

const autonomyEnv = {
  CEREBRO_AUTONOMY_GOALS_ENABLED: z.string().default("true"),
  CEREBRO_AUTONOMY_GOALS_TABLE_NAME: z.string().optional(),
  CEREBRO_AUTONOMY_GOALS_LEGACY_TABLE_NAME: z.string().optional(),
  CEREBRO_AUTONOMY_GOALS_MAX_LIST: z.coerce.number().int().positive().default(10),
  CEREBRO_AUTONOMY_RUNNER_ENABLED: z.string().default("true"),
  CEREBRO_AUTONOMY_RUNNER_POLL_INTERVAL_MS: z.coerce.number().int().positive().default(60_000),
  CEREBRO_AUTONOMY_RUNNER_LEASE_MS: z.coerce.number().int().positive().default(120_000),
  CEREBRO_AUTONOMY_RUNNER_MAX_GOALS_PER_TICK: z.coerce.number().int().positive().default(1),
  CEREBRO_AUTONOMY_QUEUE_ENABLED: z.string().default("false"),
  CEREBRO_AUTONOMY_QUEUE_URL: z.preprocess(blankToUndefined, z.string().url().optional()),
  CEREBRO_AUTONOMY_QUEUE_PUBLISHER_INTERVAL_MS: z.coerce.number().int().min(250).default(1_000),
  CEREBRO_AUTONOMY_QUEUE_PUBLISHER_BATCH_SIZE: z.coerce.number().int().min(1).max(100).default(50),
  CEREBRO_AUTONOMY_QUEUE_RECONCILE_INTERVAL_MS: z.coerce.number().int().min(10_000).default(300_000),
  CEREBRO_AUTONOMY_QUEUE_CONSUMER_COUNT: z.coerce.number().int().min(1).max(32).default(2),
  CEREBRO_AUTONOMY_QUEUE_VISIBILITY_TIMEOUT_SECONDS: z.coerce.number().int().min(60).max(43_200).default(900),
};

const schedulesEnv = {
  CEREBRO_SCHEDULES_ENABLED: z.string().default("true"),
  CEREBRO_SCHEDULES_TABLE_NAME: z.string().optional(),
  CEREBRO_SCHEDULES_POLL_INTERVAL_MS: z.coerce.number().int().positive().default(60_000),
  CEREBRO_SCHEDULES_MAX_CONCURRENT: z.coerce.number().int().positive().default(1),
  CEREBRO_SCHEDULES_DEFAULT_CHANNEL_ID: z.string().optional(),
  CEREBRO_SCHEDULES_DEFAULT_TIME_ZONE: z.string().default("America/Los_Angeles"),
};

const telemetryEnv = {
  CEREBRO_TELEMETRY_ENABLED: z.string().default("true"),
  CEREBRO_METRICS_ENABLED: z.string().default("true"),
  CEREBRO_TELEMETRY_SERVICE_NAME: z.string().default("cerebro-slack-companion"),
  CEREBRO_DEPLOYMENT_ENVIRONMENT: z.string().optional(),
  OTEL_RESOURCE_ATTRIBUTES: z.string().optional(),
};

const coordinationEnv = {
  CEREBRO_COMPANION_VERSION: z.string().default("local"),
  CEREBRO_COMPANION_COMMIT_SUBJECT: z.string().optional(),
  CEREBRO_HA_EVENT_DEDUPE_ENABLED: z.string().default("true"),
  CEREBRO_HA_EVENT_DEDUPE_TTL_SECONDS: z.coerce.number().int().positive().default(86_400),
  CEREBRO_LIFECYCLE_NOTICE_TTL_SECONDS: z.coerce.number().int().positive().default(3_600),
  CEREBRO_DEPLOYMENT_FENCE_ENABLED: z.string().default("true"),
  CEREBRO_DEPLOYMENT_FENCE_CACHE_MS: z.coerce.number().int().positive().default(5_000),
  ECS_CLUSTER_NAME: z.string().optional(),
  ECS_SERVICE_NAME: z.string().optional(),
};

const a2aEnv = {
  CEREBRO_A2A_ENABLED: z.string().default("true"),
  CEREBRO_A2A_INSTANCE_ID: z.preprocess(blankToUndefined, z.string().optional()),
  CEREBRO_A2A_LABEL: z.string().default("primary"),
  CEREBRO_A2A_ROLE: z.string().default("generalist"),
  CEREBRO_A2A_CAPABILITIES: z.string().default("slack,security,goals,research"),
  CEREBRO_A2A_HEARTBEAT_INTERVAL_MS: z.coerce.number().int().min(1_000).default(5_000),
  CEREBRO_A2A_INSTANCE_TTL_SECONDS: z.coerce.number().int().min(10).default(30),
  CEREBRO_A2A_INBOX_POLL_INTERVAL_MS: z.coerce.number().int().min(250).default(2_000),
  CEREBRO_A2A_DRAIN_TIMEOUT_MS: z.coerce.number().int().min(250).max(10_000).default(4_000),
  CEREBRO_ENSEMBLE_ENABLED: z.string().default("true"),
  CEREBRO_ENSEMBLE_MAX_PEERS: z.coerce.number().int().min(1).max(4).default(2),
  CEREBRO_ENSEMBLE_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(120_000).default(45_000),
  CEREBRO_WORK_FLEET_ENABLED: z.string().default("false"),
  CEREBRO_WORK_FLEET_MAX_PEERS: z.coerce.number().int().min(1).max(6).default(3),
  CEREBRO_WORK_FLEET_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(120_000).default(60_000),
  CEREBRO_FLEET_MODEL_MAX_CONCURRENT: z.coerce.number().int().min(1).max(32).default(6),
  CEREBRO_FLEET_SOURCE_MAX_CONCURRENT: z.coerce.number().int().min(1).max(32).default(8),
  CEREBRO_FLEET_RATE_LEASE_MS: z.coerce.number().int().min(1_000).max(600_000).default(120_000),
  CEREBRO_FLEET_RATE_WAIT_MS: z.coerce.number().int().min(0).max(120_000).default(15_000),
};

export const envSchema = z.object({
  ...coreEnv,
  ...slackEnv,
  ...cerebroEnv,
  ...evidenceCasEnv,
  ...infisicalEnv,
  ...pantherMcpEnv,
  ...triageEnv,
  ...learningEnv,
  ...codeEnv,
  ...codeModeEnv,
  ...ticketingEnv,
  ...complianceContextEnv,
  ...selfRepairEnv,
  ...improvementEnv,
  ...autonomyEnv,
  ...schedulesEnv,
  ...telemetryEnv,
  ...coordinationEnv,
  ...a2aEnv,
});

export type ParsedEnv = z.infer<typeof envSchema>;
