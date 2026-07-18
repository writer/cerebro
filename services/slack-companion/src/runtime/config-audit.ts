import type { AppConfig } from "../config/index.js";

export interface RuntimeConfigAuditCheck {
  id: string;
  status: "ok" | "warn";
  summary: string;
}

export interface RuntimeConfigAudit {
  status: "ok" | "warn";
  issueCount: number;
  checks: RuntimeConfigAuditCheck[];
}

export function auditRuntimeConfig(config: AppConfig): RuntimeConfigAudit {
  const checks: RuntimeConfigAuditCheck[] = [
    check("slack.bot_token", Boolean(config.slack.botToken), "Slack bot token is configured.", "Slack bot token is missing."),
    check("slack.app_token", !config.slack.socketMode || Boolean(config.slack.appToken), "Slack app token is configured for Socket Mode.", "Slack app token is missing for Socket Mode."),
    check("assistant.runtime", config.triage.pi.enabled, `${runtimeLabel(config)} is enabled.`, `${runtimeLabel(config)} is disabled.`),
    check("assistant.prompt_limit", config.triage.promptMaxChars >= 8_000, `Prompt limit is ${config.triage.promptMaxChars} chars.`, "Prompt limit is below the runtime floor."),
    check("assistant.prompt_compaction", config.triage.promptCompactionTargetChars < Math.max(8_000, config.triage.promptMaxChars), `Prompt compaction target is ${config.triage.promptCompactionTargetChars} chars.`, "Prompt compaction target is not below the prompt limit."),
    check("assistant.duplicate_brake", config.triage.duplicateQuestionCooldownMs > 0, `Duplicate question cooldown is ${config.triage.duplicateQuestionCooldownMs} ms.`, "Duplicate question cooldown is disabled."),
    check("assistant.bot_handoff_allowlist", config.slack.assistantBotUserIds.size + config.slack.assistantBotHandoffPolicies.length > 0, botPolicySummary(config), "No assistant bot handoff allowlist or channel policy is configured."),
    check("assistant.bot_handoff_loop_brake", config.slack.assistantBotMaxHandoffsPerThread > 0, `Bot handoff loop limit is ${config.slack.assistantBotMaxHandoffsPerThread} per thread window.`, "Bot handoff loop limit is disabled."),
    check("risk_attestation.channel_scope", config.slack.riskAttestationChannelIds.size > 0, `Risk subject checks are limited to ${config.slack.riskAttestationChannelIds.size} channel(s).`, "No risk subject check channels are configured."),
    check("risk_attestation.durable_state", config.slack.riskAttestationChannelIds.size === 0 || Boolean(config.learning.tableName), "Risk subject checks have a durable state table.", "Risk subject checks are enabled without a durable state table."),
    check("coordination.event_dedupe", !config.coordination.eventDedupeEnabled || Boolean(config.learning.tableName), "Slack event dedupe has a durable claim table.", "Slack event dedupe is enabled without a durable claim table."),
    check("coordination.deployment_fence", !config.coordination.deploymentFenceEnabled || Boolean(config.coordination.ecsClusterName && config.coordination.ecsServiceName), "Deployment fence has ECS service identity.", "Deployment fence is enabled without ECS service identity."),
    check("autonomy.mission_queue", !config.autonomy.queueEnabled || Boolean(config.autonomy.goalsEnabled && config.autonomy.goalsTableName && config.autonomy.queueUrl), "Mission queue has a durable table and queue URL.", "Mission queue is enabled without durable goal storage and a queue URL."),
    check("infisical.identity", !config.infisical.enabled || Boolean(config.infisical.identityId || config.infisical.projectId || config.infisical.projectSlug), "Infisical metadata is configured.", "Infisical is enabled without project or identity metadata."),
    check("telemetry.metrics", config.telemetry.metricsEnabled, "Metrics endpoint is enabled.", "Metrics endpoint is disabled."),
  ];
  const issueCount = checks.filter((item) => item.status !== "ok").length;
  return {
    status: issueCount > 0 ? "warn" : "ok",
    issueCount,
    checks,
  };
}

export function auditSummaryLines(audit: RuntimeConfigAudit): string[] {
  return audit.checks.map((item) => `${item.status === "ok" ? "ok" : "warn"} ${item.id}: ${item.summary}`);
}

function check(id: string, passed: boolean, okSummary: string, warnSummary: string): RuntimeConfigAuditCheck {
  return {
    id,
    status: passed ? "ok" : "warn",
    summary: passed ? okSummary : warnSummary,
  };
}

function runtimeLabel(config: AppConfig): string {
  return config.triage.assistantRuntime === "flue" ? "Flue assistant runtime" : "Pi assistant runtime";
}

function botPolicySummary(config: AppConfig): string {
  const globalCount = config.slack.assistantBotUserIds.size;
  const channelPolicyCount = config.slack.assistantBotHandoffPolicies.length;
  return `Bot handoff policy has ${globalCount} global id(s) and ${channelPolicyCount} channel policy record(s).`;
}
