import type { AppConfig } from "../config/index.js";
import { listSecuritySkills } from "../skills/security-skills.js";
import { commandHelpEntries } from "../slack/command-parser.js";
import { toolPolicyManifest } from "./tool-policy.js";

interface ToolSummary {
  name: string;
  label?: string;
  description?: string;
}

interface SelfContextOptions {
  includeTools?: boolean;
  includeCommands?: boolean;
  includeDebugPlan?: boolean;
}

export function companionSelfContext(
  config: AppConfig,
  tools: ToolSummary[],
  options: SelfContextOptions = {},
): Record<string, unknown> {
  const includeTools = options.includeTools !== false;
  const includeCommands = options.includeCommands !== false;
  const includeDebugPlan = options.includeDebugPlan !== false;
  return {
    identity: {
      service: "cerebro-slack-companion",
      assistant_name: "Cerebro",
      version: config.coordination.version,
      deployment_environment: config.telemetry.deploymentEnvironment,
      node_env: config.nodeEnv,
      tenant_id: config.cerebro.tenantId,
      companion_runtime_id: config.cerebro.companionRuntimeId,
      default_runtime_ids: config.cerebro.defaultRuntimeIds,
      process: {
        node_version: process.version,
        uptime_seconds: Math.round(process.uptime()),
      },
    },
    endpoints: {
      cerebro_api_base_url: config.cerebro.baseUrl,
      cerebro_web_base_url_configured: Boolean(config.cerebro.webBaseUrl),
      evidence_cas_base_url_configured: Boolean(config.evidenceCas.baseUrl),
      infisical_base_url_configured: Boolean(config.infisical.baseUrl),
    },
    redaction_policy: "This self-context reports URLs, ids, feature flags, counts, and configured/missing booleans only. It never returns Slack tokens, API keys, OIDC tokens, or secret values.",
    capabilities: capabilitySummary(config),
    commands: includeCommands ? commandHelpEntries() : { count: commandHelpEntries().length },
    skills: listSecuritySkills().map((skill) => ({
      id: skill.id,
      title: skill.title,
      summary: skill.summary,
      aliases: skill.aliases,
      category: skill.category,
    })),
    self_repair: selfRepairSummary(config),
    agent_tools: includeTools
      ? tools.map((tool) => tool.name).sort((left, right) => left.localeCompare(right))
      : { count: tools.length },
    agent_tool_policy: includeTools
      ? compactToolPolicyManifest(tools)
      : { count: tools.length },
    likely_config_gaps: likelyConfigGaps(config),
    debug_playbook: includeDebugPlan ? debugPlaybook(config) : undefined,
  };
}

function compactToolPolicyManifest(tools: ToolSummary[]): Record<string, unknown> {
  const manifest = toolPolicyManifest(tools.map((tool) => ({ name: tool.name, label: tool.label }))) as {
    default_policy?: unknown;
    write_boundary?: unknown;
    tools?: unknown;
  };
  const rows = Array.isArray(manifest.tools) ? manifest.tools : [];
  const groups = new Map<string, {
    tier: unknown;
    allowed_intents: unknown;
    approval_required: unknown;
    tools: unknown[];
  }>();
  for (const row of rows) {
    if (!row || typeof row !== "object" || !("tier" in row) || row.tier === "read") continue;
    const policy = row as Record<string, unknown>;
    const key = JSON.stringify([policy.tier, policy.allowed_intents, policy.approval_required]);
    const group = groups.get(key) ?? {
      tier: policy.tier,
      allowed_intents: policy.allowed_intents,
      approval_required: policy.approval_required,
      tools: [],
    };
    group.tools.push(policy.name);
    groups.set(key, group);
  }
  return {
    default_policy: manifest.default_policy,
    write_boundary: manifest.write_boundary,
    read_tool_count: rows.length - [...groups.values()].reduce((count, group) => count + group.tools.length, 0),
    policy_exception_groups: [...groups.values()],
  };
}

function selfRepairSummary(config: AppConfig): Record<string, unknown> {
  return {
    mode: "diagnose, learn, and open reviewable repair PRs without merging or deploying",
    enabled: config.selfRepair.enabled,
    draft_pr_escalation_enabled: config.selfRepair.createPr && Boolean(config.code.githubToken || config.code.githubApp),
    escalation_threshold: config.selfRepair.threshold,
    lookback_hours: config.selfRepair.lookbackHours,
    duplicate_cooldown_hours: config.selfRepair.cooldownHours,
    can_do_now: [
      "Identify this Slack companion from configured service, runtime, command, skill, and tool context.",
      "Check Cerebro runtime health, findings, graph routes, Slack research scope, EvidenceCAS status, schedules, working memory, and learning docs.",
      "Update working memory and learning docs with compact non-secret lessons when a bad answer came from stale context or a repeated workflow mistake.",
      "On an explicit request from a configured Slack operator, inspect the actual source and tests at an immutable commit SHA, prepare a bounded change with a focused regression test, and open or update the same draft PR and inspect its checks. The host binds the protected candidate to that exact base; updates also require the exact head SHA from current PR status.",
      "Compose source inspection and validation in Code Mode when the work needs repeated reads or data transformation, while keeping the draft PR as the turn's single side effect.",
      "Create a draft self-repair PR packet after repeated matching answer gaps when runtime GitHub PR creation is configured.",
    ],
    requires_operator_change: [
      "Merging repair PRs, dependency changes, and deploy workflow changes.",
      "Secret, token, Slack app scope, AWS, Pulumi, or IAM changes.",
      "Deletion of durable memory, graph data, findings, infrastructure, or production state.",
    ],
    safety_boundary: "Cerebro can diagnose bad behavior, save non-secret lessons, and open draft repair artifacts. Code merge, deploy, secrets, AWS/Pulumi, Slack scopes, graph deletion, and production changes require the reviewed operator path.",
  };
}

function capabilitySummary(config: AppConfig): Record<string, unknown> {
  return {
    pi_planner_and_assistant: {
      enabled: config.triage.pi.enabled,
      assistant_runtime: config.triage.assistantRuntime,
      provider: config.triage.pi.provider,
      model: config.triage.pi.model,
      thinking_level: config.triage.pi.thinkingLevel,
      timeout_ms: config.triage.timeoutMs,
      max_research_steps: config.triage.maxResearchSteps,
      max_concurrent: config.triage.maxConcurrent,
      prompt_max_chars: config.triage.promptMaxChars,
      duplicate_question_cooldown_ms: config.triage.duplicateQuestionCooldownMs,
    },
    cerebro_api_credentials: {
      read: true,
      findings_write: Boolean(config.cerebro.apiKeys.findings),
      source_write: Boolean(config.cerebro.apiKeys.source),
      runtime_response_write: Boolean(config.cerebro.apiKeys.runtimeResponse),
      graph_actions_write: Boolean(config.cerebro.apiKeys.graphActions),
    },
    slack: {
      socket_mode: config.slack.socketMode,
      bot_token_configured: Boolean(config.slack.botToken),
      app_token_configured: Boolean(config.slack.appToken),
      signing_secret_configured: Boolean(config.slack.signingSecret),
      default_channel_configured: Boolean(config.slack.defaultChannelId),
      allowed_team_count: config.slack.allowedTeamIds.size,
      triage_auto_reply: config.slack.triageAutoReply,
      triage_channel_count: config.slack.triageChannelIds.size,
      risk_attestation_channel_count: config.slack.riskAttestationChannelIds.size,
      risk_attestation_timeout_ms: config.slack.riskAttestationTimeoutMs,
      lifecycle_notices_enabled: config.slack.lifecycleNoticesEnabled,
      lifecycle_channel_count: config.slack.lifecycleChannelIds.size,
      audit_logs_token_configured: Boolean(config.slack.auditLogsToken),
      operator_user_count: config.slack.operatorUserIds.size,
      autonomy_approval_user_count: config.slack.autonomyApprovalUserIds.size,
      mapped_slack_user_count: config.cerebro.slackUsers.size,
      research_max_channels: config.slack.researchMaxChannels,
      research_history_limit: config.slack.researchHistoryLimit,
      assistant_bot_handoff_allowed_id_count: config.slack.assistantBotUserIds.size,
      assistant_bot_handoff_cooldown_seconds: config.slack.assistantBotCooldownSeconds,
      assistant_bot_handoff_max_per_thread: config.slack.assistantBotMaxHandoffsPerThread,
      assistant_bot_handoff_window_seconds: config.slack.assistantBotHandoffWindowSeconds,
      assistant_bot_handoff_channel_policy_count: config.slack.assistantBotHandoffPolicies.length,
    },
    memory: {
      enabled: config.learning.enabled,
      durable_table_configured: Boolean(config.learning.tableName),
      max_search_results: config.learning.maxSearchResults,
      channel_learning_enabled: config.learning.channelLearningEnabled,
      channel_learning_excluded_channel_count: config.learning.channelLearningExcludedChannelIds.size,
      channel_learning_batch_size: config.learning.channelLearningBatchSize,
      channel_learning_flush_interval_ms: config.learning.channelLearningFlushIntervalMs,
      daily_notes_enabled: config.learning.dailyNotesEnabled,
      daily_notes_time_zone: config.learning.dailyNotesTimeZone,
      working_memory_enabled: config.learning.workingMemoryEnabled,
      working_memory_dir_configured: Boolean(config.learning.workingMemoryDir),
      working_memory_char_limit: config.learning.workingMemoryCharLimit,
      team_memory_char_limit: config.learning.teamMemoryCharLimit,
      learning_docs_enabled: config.learning.learningDocsEnabled,
      learning_docs_dir_configured: Boolean(config.learning.learningDocsDir),
      learning_docs_char_limit: config.learning.learningDocsCharLimit,
      learning_doc_targets: ["normal-patterns", "runbook", "investigations", "skill-improvements"],
    },
    runtime_code: {
      enabled: config.code.enabled,
      workspace_dir_configured: Boolean(config.code.workspaceDir),
      github_pr_enabled: Boolean(config.code.githubToken || config.code.githubApp),
      github_read_enabled: Boolean(config.code.githubToken || config.code.githubApp),
      github_auth_mode: config.code.githubToken ? "token" : config.code.githubApp ? "app" : "not_configured",
      default_repo: config.code.defaultRepo,
      github_read_scope: "any_repo",
      write_allowed_orgs: [...config.code.writeAllowedOrgs],
      branch_prefix: config.code.branchPrefix,
      max_file_bytes: config.code.maxFileBytes,
      max_files: config.code.maxFiles,
      shell_enabled: false,
      shell_unavailable_reason: "OS sandbox is not configured.",
      gate: "bounded workspace files and reviewable GitHub changes",
    },
    code_mode: config.codeMode ? {
      enabled: config.codeMode.enabled,
      max_tool_calls: config.codeMode.maxToolCalls,
      max_side_effect_calls: config.codeMode.maxSideEffectCalls,
      timeout_ms: config.codeMode.timeoutMs,
      memory_limit_bytes: config.codeMode.memoryLimitBytes,
      max_script_bytes: config.codeMode.maxScriptBytes,
      max_output_bytes: config.codeMode.maxOutputBytes,
      authority: "nested tools keep their normal host-owned policy and approval checks",
    } : { enabled: false },
    ticketing: {
      jira_drafts_available: true,
      jira_search_available: Boolean(config.ticketing.jira.baseUrl && ticketingJiraAuthPathConfigured(config)),
      jira_create_available_with_args: Boolean(config.ticketing.jira.baseUrl && ticketingJiraAuthPathConfigured(config)),
      jira_create_available_with_defaults: Boolean(config.ticketing.jira.baseUrl && config.ticketing.jira.defaultProjectKey && ticketingJiraAuthPathConfigured(config)),
      jira_base_url_configured: Boolean(config.ticketing.jira.baseUrl),
      jira_default_project_key_configured: Boolean(config.ticketing.jira.defaultProjectKey),
      jira_default_issue_type: config.ticketing.jira.defaultIssueType,
      jira_auth_mode: config.ticketing.jira.authEmail ? "basic" : "bearer",
      jira_auth_email_configured: Boolean(config.ticketing.jira.authEmail),
      jira_api_token_configured: Boolean(config.ticketing.jira.apiToken),
      jira_api_token_infisical_mirror_configured: Boolean(config.ticketing.jira.apiTokenInfisicalSecretName),
      jira_api_token_infisical_secret_name: config.ticketing.jira.apiTokenInfisicalSecretName,
      linear_drafts_available: true,
      linear_create_available_with_args: ticketingLinearAuthPathConfigured(config),
      linear_create_available_with_defaults: Boolean(config.ticketing.linear.defaultTeamId && ticketingLinearAuthPathConfigured(config)),
      linear_default_team_id_configured: Boolean(config.ticketing.linear.defaultTeamId),
      linear_api_key_configured: Boolean(config.ticketing.linear.apiKey),
      linear_api_key_infisical_mirror_configured: Boolean(config.ticketing.linear.apiKeyInfisicalSecretName),
      linear_api_key_infisical_secret_name: config.ticketing.linear.apiKeyInfisicalSecretName,
      max_description_chars: config.ticketing.maxDescriptionChars,
      timeout_ms: config.ticketing.timeoutMs,
      side_effects: "Jira search and draft tools create no external state; create tools write one Jira or Linear issue after an explicit ticket request",
    },
    compliance_context: {
      enabled: config.complianceContext.enabled,
      repo: config.complianceContext.repo,
      ref: config.complianceContext.ref,
      local_dir_configured: Boolean(config.complianceContext.localDir),
      cache_ttl_ms: config.complianceContext.cacheTtlMs,
      fetch_timeout_ms: config.complianceContext.fetchTimeoutMs,
      max_file_bytes: config.complianceContext.maxFileBytes,
      max_total_bytes: config.complianceContext.maxTotalBytes,
      source: config.complianceContext.localDir ? "local checkout" : "github raw content",
      note: "Use cerebro_compliance_context for source context, then cerebro_compliance_packet for control evidence, policy-system maps, audit-safe reports, finding lifecycle, exceptions, triage quality, approved remediation, and continuous monitor packets.",
    },
    autonomy_goals: {
      enabled: config.autonomy.goalsEnabled,
      durable_table_configured: Boolean(config.autonomy.goalsTableName),
      max_listed_goals: config.autonomy.maxListedGoals,
      runner_enabled: config.autonomy.runnerEnabled,
      runner_poll_interval_ms: config.autonomy.runnerPollIntervalMs,
      runner_lease_ms: config.autonomy.runnerLeaseMs,
      runner_max_goals_per_tick: config.autonomy.runnerMaxGoalsPerTick,
    },
    schedules: {
      enabled: config.schedules.enabled,
      durable_table_configured: Boolean(config.schedules.tableName),
      poll_interval_ms: config.schedules.pollIntervalMs,
      max_concurrent: config.schedules.maxConcurrent,
      default_channel_configured: Boolean(config.schedules.defaultChannelId),
      default_time_zone: config.schedules.defaultTimeZone,
    },
    telemetry: {
      enabled: config.telemetry.enabled,
      metrics_enabled: config.telemetry.metricsEnabled,
      metrics_path: config.telemetry.metricsEnabled ? "/metrics" : undefined,
      service_name: config.telemetry.serviceName,
      deployment_environment: config.telemetry.deploymentEnvironment,
      resource_attributes_configured: Boolean(config.telemetry.resourceAttributes),
      wide_events: [
        "slack.event.*",
        "companion.work.slack_question",
        "assistant.answer",
        "assistant.pi.run",
        "assistant.tool.execute",
        "triage.run",
        "slack.alert_triage",
        "schedule.tick",
        "schedule.run",
        "schedule.step.run",
        "cerebro.http.request",
      ],
      redaction: "Slack text, prompts, answers, raw errors, tokens, secrets, cookies, and credentials are redacted from telemetry attributes.",
    },
    evidence_cas: {
      configured: Boolean(config.evidenceCas.baseUrl && (config.evidenceCas.readToken || config.evidenceCas.readTokenInfisicalSecretName)),
      base_url_configured: Boolean(config.evidenceCas.baseUrl),
      read_token_configured: Boolean(config.evidenceCas.readToken),
      read_token_infisical_mirror_configured: Boolean(config.evidenceCas.readTokenInfisicalSecretName),
      read_token_infisical_secret_name: config.evidenceCas.readTokenInfisicalSecretName,
      default_bucket: config.evidenceCas.defaultBucket,
      timeout_ms: config.evidenceCas.timeoutMs,
    },
    infisical: {
      enabled: config.infisical.enabled,
      configured: Boolean(config.infisical.enabled && config.infisical.projectId && config.infisical.identityId),
      auth_method: "aws",
      base_url_configured: Boolean(config.infisical.baseUrl),
      project_id_configured: Boolean(config.infisical.projectId),
      project_slug: config.infisical.projectSlug,
      identity_id_configured: Boolean(config.infisical.identityId),
      environment: config.infisical.environment,
      secret_path: config.infisical.secretPath,
      aws_region: config.infisical.awsRegion,
      raw_secret_values_returned: false,
    },
    coordination: {
      event_dedupe_enabled: config.coordination.eventDedupeEnabled,
      event_dedupe_ttl_seconds: config.coordination.eventDedupeTtlSeconds,
      lifecycle_notice_ttl_seconds: config.coordination.lifecycleNoticeTtlSeconds,
      deployment_fence_enabled: config.coordination.deploymentFenceEnabled,
      deployment_fence_cache_ms: config.coordination.deploymentFenceCacheMs,
      ecs_target_configured: Boolean(config.coordination.ecsClusterName && config.coordination.ecsServiceName),
    },
  };
}

function likelyConfigGaps(config: AppConfig): string[] {
  const gaps: string[] = [];
  if (config.cerebro.defaultRuntimeIds.length === 0) {
    gaps.push("No default Cerebro runtime ids are configured; broad health, finding, and posture checks need explicit runtime ids.");
  }
  if (/\bdev\b|\.dev\.|dev\./i.test(config.cerebro.baseUrl)) {
    gaps.push("Cerebro API base URL points at a dev origin; current-state answers use dev backend data until CEREBRO_BASE_URL is moved to the intended backend.");
  }
  if (!config.triage.pi.enabled) {
    gaps.push("Pi is disabled; assistant answers stop at the route boundary, and schedule planning fails where a planner is required.");
  }
  if (config.slack.socketMode && !config.slack.appToken) {
    gaps.push("Socket Mode is enabled but no Slack app token is configured.");
  }
  if (!config.slack.socketMode && !config.slack.signingSecret) {
    gaps.push("HTTP Slack mode is enabled but no signing secret is configured.");
  }
  if (config.slack.triageChannelIds.size === 0) {
    gaps.push("No proactive triage channels are configured; passive alert triage will stay quiet.");
  }
  if (config.slack.riskAttestationChannelIds.size > 0 && !config.learning.tableName) {
    gaps.push("Risk subject checks are enabled without a durable learning table; pending answers will not survive a restart.");
  }
  if (config.learning.enabled && !config.learning.tableName) {
    gaps.push("Durable security memory table is not configured; memory is process-local unless file-backed docs cover the fact.");
  }
  if (config.schedules.enabled && !config.schedules.tableName) {
    gaps.push("Scheduled checks have no durable table configured; local runs keep schedules in process memory.");
  }
  if (config.autonomy.goalsEnabled && !config.autonomy.goalsTableName) {
    gaps.push("Autonomy goals have no durable table configured; local runs keep goals in process memory.");
  }
  if (config.autonomy.runnerEnabled && config.slack.autonomyApprovalUserIds.size === 0) {
    gaps.push("Autonomy runner is enabled but no Slack autonomy approval users are configured; approval-needed goals cannot be approved from Slack.");
  }
  if (config.slack.operatorUserIds.size === 0) {
    gaps.push("No Slack operator users are configured; /cerebro operator commands cannot run.");
  }
  if (config.evidenceCas.baseUrl && !config.evidenceCas.readToken && !config.evidenceCas.readTokenInfisicalSecretName) {
    gaps.push("EvidenceCAS has a base URL but no env read token or Infisical mirror secret name; protected ref resolution will fail.");
  }
  if (config.evidenceCas.baseUrl && config.evidenceCas.readTokenInfisicalSecretName && (!config.infisical.enabled || !config.infisical.projectId || !config.infisical.identityId)) {
    gaps.push("EvidenceCAS is set to use an Infisical read-token mirror, but Infisical runtime access is not fully configured.");
  }
  if (!config.evidenceCas.baseUrl && !config.evidenceCas.readToken) {
    gaps.push("EvidenceCAS is not configured; artifact manifest and digest verification tools will report unavailable.");
  }
  if (config.infisical.enabled && (!config.infisical.projectId || !config.infisical.identityId)) {
    gaps.push("Infisical runtime access is enabled but missing project or AWS identity id; metadata and fingerprint tools cannot authenticate yet.");
  }
  if (!config.cerebro.apiKeys.source) {
    gaps.push("Source-runtime write credential is not configured; sync, ingest, and finding evaluation slash commands cannot complete.");
  }
  if (config.code.enabled && !config.code.githubToken && !config.code.githubApp) {
    gaps.push("Runtime code workspace writes are enabled, but GitHub PR creation is not configured because no token or GitHub App installation credentials are configured.");
  }
  if (!config.ticketing.jira.defaultProjectKey) {
    gaps.push("Jira issue drafts need a project_key argument because no default Jira project key is configured.");
  }
  if (config.ticketing.jira.baseUrl && !ticketingJiraAuthPathConfigured(config)) {
    gaps.push("Jira issue creation has a base URL but no env API token or configured Infisical mirror access.");
  }
  if (!config.ticketing.linear.defaultTeamId) {
    gaps.push("Linear issue drafts need a team_id argument because no default Linear team id is configured.");
  }
  if (!ticketingLinearAuthPathConfigured(config)) {
    gaps.push("Linear issue creation has no env API key or configured Infisical mirror access.");
  }
  return gaps;
}

function ticketingJiraAuthPathConfigured(config: AppConfig): boolean {
  return Boolean(config.ticketing.jira.apiToken || (config.ticketing.jira.apiTokenInfisicalSecretName && infisicalRuntimeConfigured(config)));
}

function ticketingLinearAuthPathConfigured(config: AppConfig): boolean {
  return Boolean(config.ticketing.linear.apiKey || (config.ticketing.linear.apiKeyInfisicalSecretName && infisicalRuntimeConfigured(config)));
}

function infisicalRuntimeConfigured(config: AppConfig): boolean {
  return Boolean(config.infisical.enabled && config.infisical.projectId && config.infisical.identityId);
}

function debugPlaybook(config: AppConfig): string[] {
  const runtimes = [config.cerebro.companionRuntimeId, ...config.cerebro.defaultRuntimeIds].filter(Boolean);
  return [
    "Start with cerebro_companion_self_context to identify configured feature flags, available commands, skills, and agent tools.",
    runtimes.length > 0
      ? `Check Cerebro runtime health for ${runtimes.join(", ")} with cerebro_runtime_health.`
      : "Ask for or configure runtime ids before making runtime health claims.",
    "For Slack search, thread, channel, or app-install failures, run slack_scope_capabilities and name missing scopes or fallback coverage.",
    "For graph, finding, or evidence questions, use cerebro_graph_cypher_schema, cerebro_graph_cypher_investigate, cerebro_open_findings, or cerebro_finding_evidence based on the failing path.",
    "For EvidenceCAS manifest or digest failures, run evidence_cas_status before evidence_cas_resolve.",
    "For runtime secret, Infisical, rotation, or secret mirror questions, run infisical_status first. Use infisical_secret_metadata or infisical_secret_fingerprint only for named secrets, and never expose raw values.",
    "For memory or repeated-answer issues, read security_working_memory_read, security_learning_docs_read, security_session_recall, and security_memory_intelligence before changing memory.",
    "For self-improvement requested by a configured Slack operator, run cerebro_code_status, inspect the relevant skill, and read the actual source and tests at one immutable commit SHA with cerebro_code_github_source_list and cerebro_code_github_source_read. Use Code Mode for repeated reads or validation, then use its one side effect for cerebro_code_self_improvement_pr with that exact base SHA, the implementation, and a focused regression test. Inspect the draft checks; for a later authorized repair, read current PR status and pass its exact head SHA as expected_head_sha when updating the same PR. Use one skill_improvement write instead when no code change is needed. Never merge or deploy the PR.",
    "For schedule issues, inspect schedule settings here, then use schedule ids from /cerebro schedules or ask an operator for the failing schedule id.",
    "For runtime-debug issues, check telemetry wide events by operation name and use /metrics for low-cardinality counters and durations.",
    "Report what is configured, what was checked, what is missing, and the next concrete operator action. Do not expose secrets.",
  ];
}
