import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config/index.js";

test("loadConfig defaults Opus 4.8 to the Bedrock US inference profile", () => {
  const config = loadConfig(minimalEnv());

  assert.equal(config.triage.pi.provider, "amazon-bedrock");
  assert.equal(config.triage.pi.model, "us.anthropic.claude-opus-4-8");
  assert.equal(config.triage.pi.thinkingLevel, "medium");
  assert.equal(config.triage.pi.executionModel, "us.anthropic.claude-opus-4-8");
  assert.equal(config.triage.pi.executionThinkingLevel, "medium");
  assert.equal(config.triage.assistantRuntime, "pi");
  assert.equal(config.triage.timeoutMs, 300_000);
  assert.equal(config.cerebro.requestTimeoutMs, 15_000);
  assert.equal(config.triage.promptMaxChars, 240_000);
  assert.equal(config.triage.promptCompactionTargetChars, 180_000);
  assert.equal(config.triage.duplicateQuestionCooldownMs, 600_000);
  assert.equal(config.triage.workQueueEnabled, false);
  assert.equal(config.triage.workQueueUrl, undefined);
  assert.equal(config.triage.workQueueVisibilityTimeoutSeconds, 90);
  assert.equal(config.learning.channelLearningEnabled, true);
  assert.deepEqual([...config.learning.channelLearningExcludedChannelIds], []);
  assert.equal(config.learning.channelLearningBatchSize, 12);
  assert.equal(config.learning.channelLearningFlushIntervalMs, 600_000);
  assert.equal(config.slack.assistantBotCooldownSeconds, 600);
  assert.equal(config.slack.assistantBotMaxHandoffsPerThread, 2);
  assert.equal(config.slack.assistantBotHandoffWindowSeconds, 3_600);
  assert.deepEqual([...config.slack.assistantBotUserIds], []);
  assert.deepEqual(config.slack.assistantBotHandoffPolicies, []);
  assert.equal(config.complianceContext.enabled, true);
  assert.equal(config.complianceContext.repo, "writer/cerebro");
  assert.equal(config.complianceContext.ref, "main");
  assert.equal(config.complianceContext.cacheTtlMs, 3_600_000);
  assert.deepEqual([...config.code.writeAllowedOrgs], ["Writer", "WriterColab", "WriterInternal"]);
  assert.equal(config.evidenceCas.readTokenInfisicalSecretName, "EVIDENCE_CAS_READ_TOKEN");
  assert.equal(config.ticketing.jira.defaultIssueType, "Task");
  assert.equal(config.ticketing.jira.apiTokenInfisicalSecretName, "JIRA_API_TOKEN");
  assert.equal(config.ticketing.linear.apiKeyInfisicalSecretName, "LINEAR_API_KEY");
  assert.equal(config.ticketing.maxDescriptionChars, 6000);
  assert.equal(config.ticketing.timeoutMs, 15_000);
  assert.equal(config.pantherMcp.enabled, false);
  assert.equal(config.pantherMcp.url, undefined);
  assert.equal(config.pantherMcp.timeoutMs, 15_000);
  assert.equal(config.pantherMcp.allowedTools.has("list_alerts"), true);
  assert.equal(config.pantherMcp.allowMutatingTools, false);
  assert.equal(config.a2a.enabled, true);
  assert.equal(config.a2a.label, "primary");
  assert.equal(config.a2a.role, "generalist");
  assert.deepEqual(config.a2a.capabilities, ["slack", "security", "goals", "research"]);
  assert.match(config.a2a.instanceId, /^primary-/);
  assert.equal(config.a2a.ensembleEnabled, true);
  assert.equal(config.a2a.ensembleMaxPeers, 2);
  assert.equal(config.a2a.ensembleTimeoutMs, 45_000);
  assert.equal(config.a2a.workFleetEnabled, false);
  assert.equal(config.a2a.workFleetMaxPeers, 3);
  assert.equal(config.a2a.workFleetTimeoutMs, 60_000);
  assert.equal(config.a2a.modelMaxConcurrent, 6);
  assert.equal(config.a2a.sourceMaxConcurrent, 8);
  assert.doesNotMatch(config.triage.pi.model, /^anthropic\./);
});

test("loadConfig accepts differentiated A2A fleet identity and timing", () => {
  const config = loadConfig(minimalEnv({
    CEREBRO_A2A_INSTANCE_ID: "response-canary-task-1",
    CEREBRO_A2A_LABEL: "Response Canary",
    CEREBRO_A2A_ROLE: "Analyst",
    CEREBRO_A2A_CAPABILITIES: "security,research,goals",
    CEREBRO_A2A_HEARTBEAT_INTERVAL_MS: "3000",
    CEREBRO_A2A_INSTANCE_TTL_SECONDS: "20",
    CEREBRO_A2A_INBOX_POLL_INTERVAL_MS: "750",
    CEREBRO_A2A_DRAIN_TIMEOUT_MS: "6000",
    CEREBRO_ENSEMBLE_ENABLED: "false",
    CEREBRO_ENSEMBLE_MAX_PEERS: "3",
    CEREBRO_ENSEMBLE_TIMEOUT_MS: "30000",
    CEREBRO_WORK_FLEET_ENABLED: "false",
    CEREBRO_WORK_FLEET_MAX_PEERS: "4",
    CEREBRO_WORK_FLEET_TIMEOUT_MS: "40000",
    CEREBRO_FLEET_MODEL_MAX_CONCURRENT: "5",
    CEREBRO_FLEET_SOURCE_MAX_CONCURRENT: "7",
    CEREBRO_FLEET_RATE_LEASE_MS: "90000",
    CEREBRO_FLEET_RATE_WAIT_MS: "12000",
  }));

  assert.equal(config.a2a.instanceId, "response-canary-task-1");
  assert.equal(config.a2a.label, "response-canary");
  assert.equal(config.a2a.role, "analyst");
  assert.deepEqual(config.a2a.capabilities, ["security", "research", "goals"]);
  assert.equal(config.a2a.heartbeatIntervalMs, 3_000);
  assert.equal(config.a2a.instanceTtlSeconds, 20);
  assert.equal(config.a2a.inboxPollIntervalMs, 750);
  assert.equal(config.a2a.drainTimeoutMs, 6_000);
  assert.equal(config.a2a.ensembleEnabled, false);
  assert.equal(config.a2a.ensembleMaxPeers, 3);
  assert.equal(config.a2a.ensembleTimeoutMs, 30_000);
  assert.equal(config.a2a.workFleetEnabled, false);
  assert.equal(config.a2a.workFleetMaxPeers, 4);
  assert.equal(config.a2a.workFleetTimeoutMs, 40_000);
  assert.equal(config.a2a.modelMaxConcurrent, 5);
  assert.equal(config.a2a.sourceMaxConcurrent, 7);
  assert.equal(config.a2a.rateLeaseMs, 90_000);
  assert.equal(config.a2a.rateWaitMs, 12_000);
});

test("loadConfig accepts a bounded Cerebro request timeout", () => {
  const config = loadConfig(minimalEnv({ CEREBRO_REQUEST_TIMEOUT_MS: "2500" }));

  assert.equal(config.cerebro.requestTimeoutMs, 2_500);
});

test("loadConfig accepts the deployed commit subject", () => {
  const config = loadConfig(minimalEnv({
    CEREBRO_COMPANION_VERSION: "sha-1234567",
    CEREBRO_COMPANION_COMMIT_SUBJECT: "  Add runtime evidence to restart notices  ",
  }));

  assert.equal(config.coordination.version, "sha-1234567");
  assert.equal(config.coordination.commitSubject, "Add runtime evidence to restart notices");
});

test("loadConfig accepts joined Slack channel learning controls", () => {
  const config = loadConfig(minimalEnv({
    CEREBRO_SLACK_CHANNEL_LEARNING_ENABLED: "true",
    CEREBRO_SLACK_CHANNEL_LEARNING_EXCLUDED_CHANNEL_IDS: "CHR, CLEGAL",
    CEREBRO_SLACK_CHANNEL_LEARNING_BATCH_SIZE: "20",
    CEREBRO_SLACK_CHANNEL_LEARNING_FLUSH_INTERVAL_MS: "120000",
  }));

  assert.equal(config.learning.channelLearningEnabled, true);
  assert.deepEqual([...config.learning.channelLearningExcludedChannelIds], ["CHR", "CLEGAL"]);
  assert.equal(config.learning.channelLearningBatchSize, 20);
  assert.equal(config.learning.channelLearningFlushIntervalMs, 120_000);
});

test("loadConfig accepts Slack assistant bot handoff policy", () => {
  const config = loadConfig(minimalEnv({
    SLACK_ASSISTANT_BOT_USER_IDS: "BHELPER,UHELPER,AHELPER",
    SLACK_ASSISTANT_BOT_COOLDOWN_SECONDS: "120",
    SLACK_ASSISTANT_BOT_MAX_HANDOFFS_PER_THREAD: "3",
    SLACK_ASSISTANT_BOT_HANDOFF_WINDOW_SECONDS: "900",
    SLACK_ASSISTANT_BOT_HANDOFF_POLICIES_JSON: JSON.stringify([{
      channel_id: "CSEC",
      bot_user_ids: ["BHELPER"],
      cooldown_seconds: 30,
      max_handoffs_per_thread: 1,
      window_seconds: 120,
    }]),
    CEREBRO_TRIAGE_PROMPT_MAX_CHARS: "12000",
    CEREBRO_TRIAGE_PROMPT_COMPACTION_TARGET_CHARS: "9000",
    CEREBRO_WORK_LOOP_DUPLICATE_COOLDOWN_MS: "30000",
  }));

  assert.deepEqual([...config.slack.assistantBotUserIds], ["BHELPER", "UHELPER", "AHELPER"]);
  assert.equal(config.slack.assistantBotCooldownSeconds, 120);
  assert.equal(config.slack.assistantBotMaxHandoffsPerThread, 3);
  assert.equal(config.slack.assistantBotHandoffWindowSeconds, 900);
  assert.equal(config.slack.assistantBotHandoffPolicies[0]?.channelId, "CSEC");
  assert.deepEqual([...(config.slack.assistantBotHandoffPolicies[0]?.botUserIds ?? [])], ["BHELPER"]);
  assert.equal(config.slack.assistantBotHandoffPolicies[0]?.cooldownSeconds, 30);
  assert.equal(config.slack.assistantBotHandoffPolicies[0]?.maxHandoffsPerThread, 1);
  assert.equal(config.slack.assistantBotHandoffPolicies[0]?.windowSeconds, 120);
  assert.equal(config.triage.promptMaxChars, 12_000);
  assert.equal(config.triage.promptCompactionTargetChars, 9_000);
  assert.equal(config.triage.duplicateQuestionCooldownMs, 30_000);
});

test("loadConfig accepts the Flue assistant runtime", () => {
  const config = loadConfig(minimalEnv({
    CEREBRO_ASSISTANT_RUNTIME: "flue",
    PI_EXECUTION_MODEL: "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    PI_EXECUTION_THINKING_LEVEL: "low",
  }));

  assert.equal(config.triage.assistantRuntime, "flue");
  assert.equal(config.triage.pi.executionModel, "us.anthropic.claude-haiku-4-5-20251001-v1:0");
  assert.equal(config.triage.pi.executionThinkingLevel, "low");
});

test("loadConfig requires a queue URL when durable Slack work is enabled", () => {
  assert.throws(
    () => loadConfig(minimalEnv({ CEREBRO_WORK_QUEUE_ENABLED: "true" })),
    /CEREBRO_WORK_QUEUE_URL is required/,
  );
  const config = loadConfig(minimalEnv({
    CEREBRO_WORK_QUEUE_ENABLED: "true",
    CEREBRO_WORK_QUEUE_URL: "https://sqs.us-east-1.amazonaws.com/123/slack-question-work.fifo",
    CEREBRO_WORK_QUEUE_PUBLISHER_INTERVAL_MS: "750",
    CEREBRO_WORK_QUEUE_PUBLISHER_BATCH_SIZE: "25",
    CEREBRO_WORK_QUEUE_CONSUMER_COUNT: "4",
    CEREBRO_WORK_QUEUE_VISIBILITY_TIMEOUT_SECONDS: "120",
  }));
  assert.equal(config.triage.workQueueEnabled, true);
  assert.equal(config.triage.workQueuePublisherIntervalMs, 750);
  assert.equal(config.triage.workQueuePublisherBatchSize, 25);
  assert.equal(config.triage.workQueueConsumerCount, 4);
  assert.equal(config.triage.workQueueVisibilityTimeoutSeconds, 120);
});

test("loadConfig accepts an assistant help mention", () => {
  const config = loadConfig(minimalEnv({
    CEREBRO_ASSISTANT_HELP_MENTION: "<@U0AR7EF2FSP>",
  }));

  assert.equal(config.cerebro.assistantHelpMention, "<@U0AR7EF2FSP>");
});

test("loadConfig accepts Panther MCP configuration", () => {
  const config = loadConfig(minimalEnv({
    PANTHER_MCP_ENABLED: "true",
    PANTHER_MCP_URL: "https://panther-mcp.example.com/mcp/",
    PANTHER_MCP_AUTH_TOKEN: "mcp-auth-token",
    PANTHER_MCP_ALLOWED_TOOLS: "list_alerts,get_alert",
    PANTHER_MCP_ALLOW_MUTATING_TOOLS: "false",
    PANTHER_MCP_TIMEOUT_MS: "20000",
  }));

  assert.equal(config.pantherMcp.enabled, true);
  assert.equal(config.pantherMcp.url, "https://panther-mcp.example.com/mcp");
  assert.equal(config.pantherMcp.authToken, "mcp-auth-token");
  assert.deepEqual([...config.pantherMcp.allowedTools], ["list_alerts", "get_alert"]);
  assert.equal(config.pantherMcp.allowMutatingTools, false);
  assert.equal(config.pantherMcp.timeoutMs, 20_000);
});

test("loadConfig accepts operator users and Slack actor mapping", () => {
  const config = loadConfig(minimalEnv({
    SLACK_OPERATOR_USER_IDS: "UOWNER",
    SLACK_SOURCE_WRITE_USER_IDS: "UOWNER",
    CEREBRO_SLACK_USER_MAP_JSON: JSON.stringify({
      UOWNER: { actor_id: "jonathan.haas@writer.com", display_name: "Jonathan Haas" },
    }),
  }));

  assert.deepEqual([...config.slack.operatorUserIds], ["UOWNER"]);
  assert.deepEqual([...config.slack.sourceWriteUserIds], ["UOWNER"]);
  assert.deepEqual(config.cerebro.slackUsers.get("UOWNER"), {
    actorId: "jonathan.haas@writer.com",
    displayName: "Jonathan Haas",
  });
});

test("loadConfig accepts complete GitHub App runtime PR auth", () => {
  const config = loadConfig(minimalEnv({
    CEREBRO_CODE_GITHUB_APP_ID: "12345",
    CEREBRO_CODE_GITHUB_INSTALLATION_ID: "67890",
    CEREBRO_CODE_GITHUB_PRIVATE_KEY_BASE64: Buffer.from("test-private-key").toString("base64"),
  }));

  assert.deepEqual(config.code.githubApp, {
    appId: "12345",
    installationId: "67890",
    privateKeyBase64: Buffer.from("test-private-key").toString("base64"),
  });
});

test("loadConfig stores autonomy goals in the learning table by default", () => {
  const config = loadConfig(minimalEnv({
    SECURITY_LEARNING_TABLE_NAME: "learning-table",
    SLACK_AUTONOMY_APPROVAL_USER_IDS: "UAPPROVER,UOWNER",
  }));

  assert.equal(config.triage.threadStateTableName, "learning-table");
  assert.equal(config.autonomy.goalsEnabled, true);
  assert.equal(config.autonomy.goalsTableName, "learning-table");
  assert.equal(config.autonomy.legacyGoalsTableName, undefined);
  assert.equal(config.autonomy.maxListedGoals, 10);
  assert.equal(config.autonomy.runnerEnabled, true);
  assert.equal(config.autonomy.runnerPollIntervalMs, 60_000);
  assert.equal(config.autonomy.runnerLeaseMs, 120_000);
  assert.equal(config.autonomy.runnerMaxGoalsPerTick, 1);
  assert.equal(config.autonomy.queueEnabled, false);
  assert.equal(config.autonomy.queueUrl, undefined);
  assert.equal(config.autonomy.queuePublisherIntervalMs, 1_000);
  assert.equal(config.autonomy.queuePublisherBatchSize, 50);
  assert.equal(config.autonomy.queueReconcileIntervalMs, 300_000);
  assert.equal(config.autonomy.queueConsumerCount, 2);
  assert.equal(config.autonomy.queueVisibilityTimeoutSeconds, 900);
  assert.deepEqual([...config.slack.autonomyApprovalUserIds], ["UAPPROVER", "UOWNER"]);
});

test("loadConfig accepts a separate mission table with a legacy migration source", () => {
  const config = loadConfig(minimalEnv({
    CEREBRO_AUTONOMY_GOALS_TABLE_NAME: "mission-table",
    CEREBRO_AUTONOMY_GOALS_LEGACY_TABLE_NAME: "learning-table",
  }));

  assert.equal(config.autonomy.goalsTableName, "mission-table");
  assert.equal(config.autonomy.legacyGoalsTableName, "learning-table");
});

test("loadConfig parses Slack proactive channel policies", () => {
  const config = loadConfig(minimalEnv({
    SLACK_TRIAGE_CHANNEL_IDS: "CSEC,CNOISY,COPS",
    SLACK_TRIAGE_CHANNEL_POLICIES: "CSEC:eager,CNOISY:quiet,COPS:strict,CBAD:loud",
  }));

  assert.deepEqual([...config.slack.triageChannelIds], ["CSEC", "CNOISY", "COPS"]);
  assert.equal(config.slack.triageChannelPolicies.get("CSEC"), "eager");
  assert.equal(config.slack.triageChannelPolicies.get("CNOISY"), "quiet");
  assert.equal(config.slack.triageChannelPolicies.get("COPS"), "strict");
  assert.equal(config.slack.triageChannelPolicies.has("CBAD"), false);
});

test("loadConfig scopes risk attestation to triage channels unless explicitly configured", () => {
  const defaulted = loadConfig(minimalEnv({ SLACK_TRIAGE_CHANNEL_IDS: "CSEC,CIR" }));
  const configured = loadConfig(minimalEnv({
    SLACK_TRIAGE_CHANNEL_IDS: "CSEC,CIR",
    SLACK_RISK_ATTESTATION_CHANNEL_IDS: "CSEC",
    SLACK_RISK_ATTESTATION_TIMEOUT_MS: "2500",
  }));

  assert.deepEqual([...defaulted.slack.riskAttestationChannelIds], ["CSEC", "CIR"]);
  assert.deepEqual([...configured.slack.riskAttestationChannelIds], ["CSEC"]);
  assert.equal(configured.slack.riskAttestationTimeoutMs, 2_500);
});

test("loadConfig rejects partial GitHub App runtime PR auth", () => {
  assert.throws(() => loadConfig(minimalEnv({
    CEREBRO_CODE_GITHUB_APP_ID: "12345",
  })), /GitHub App runtime PR auth needs/);
});

function minimalEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    SLACK_BOT_TOKEN: "xoxb-test",
    SLACK_SOCKET_MODE: "true",
    SLACK_APP_TOKEN: "xapp-test",
    CEREBRO_BASE_URL: "https://cerebro.example.com",
    CEREBRO_TENANT_ID: "writer",
    CEREBRO_READ_API_KEY: "read-key",
    ...overrides,
  };
}
