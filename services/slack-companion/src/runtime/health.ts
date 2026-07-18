import type { AutonomyGoalService, AutonomyGoalServiceStats } from "../autonomy/goal-service.js";
import type { CerebroClient } from "../cerebro/client.js";
import type { AppConfig } from "../config/index.js";
import type { ScheduledJobService, ScheduledJobServiceStats } from "../schedules/scheduled-jobs/index.js";
import type { DeploymentCheckResult, ServiceSnapshot, SlackEventCoordinator } from "../slack/coordination.js";
import { trimForSlack } from "../slack/format.js";
import { recordGauge } from "../telemetry.js";
import type { CompanionWorkLoop, CompanionWorkLoopStats } from "../work/companion-work-loop.js";
import { auditRuntimeConfig, type RuntimeConfigAudit } from "./config-audit.js";

export type RuntimeHealthStatus = "ok" | "warn" | "fail";
export type RuntimeReadinessStatus = "ready" | "degraded" | "not_ready";

export interface RuntimeHealthCheck {
  id: string;
  status: RuntimeHealthStatus;
  summary: string;
}

export interface RuntimeDeploymentHealth {
  enabled: boolean;
  status: RuntimeHealthStatus;
  current: boolean;
  reason: DeploymentCheckResult["reason"];
  detail?: string;
  service?: ServiceSnapshot;
}

export interface RuntimeBacklogHealth {
  work?: CompanionWorkLoopStats;
  schedules?: ScheduledJobServiceStats;
  autonomy?: AutonomyGoalServiceStats;
}

export interface RuntimeHealthSnapshot {
  checkedAt: string;
  status: RuntimeReadinessStatus;
  ready: boolean;
  version: string;
  environment: string;
  configAudit: RuntimeConfigAudit;
  checks: RuntimeHealthCheck[];
  deployment?: RuntimeDeploymentHealth;
  backlog: RuntimeBacklogHealth;
}

export interface RuntimeHealthDeps {
  config: AppConfig;
  cerebro?: Pick<CerebroClient, "getAgentControlPlane">;
  coordinator?: Pick<SlackEventCoordinator, "isCurrentTask" | "serviceSnapshot" | "botHandoffStats">;
  scheduler?: Pick<ScheduledJobService, "stats">;
  goals?: Pick<AutonomyGoalService, "stats">;
  workLoop?: Pick<CompanionWorkLoop, "stats">;
}

const READINESS_BLOCKING_AUDIT_CHECKS = new Set([
  "slack.bot_token",
  "slack.app_token",
  "assistant.runtime",
  "assistant.prompt_limit",
  "assistant.prompt_compaction",
  "coordination.event_dedupe",
  "coordination.deployment_fence",
]);

export async function collectRuntimeHealth(deps: RuntimeHealthDeps): Promise<RuntimeHealthSnapshot> {
  const checkedAt = new Date().toISOString();
  const configAudit = auditRuntimeConfig(deps.config);
  const checks: RuntimeHealthCheck[] = [
    ...configAudit.checks.map((item) => ({
      id: `config.${item.id}`,
      status: item.status === "ok" ? "ok" as const : auditCheckStatus(item.id),
      summary: item.summary,
    })),
    ...staticDependencyChecks(deps.config),
  ];

  const deployment = await deploymentHealth(deps.coordinator, deps.config);
  if (deployment) {
    checks.push({
      id: "deployment.fence",
      status: deployment.status,
      summary: deploymentSummary(deployment),
    });
  }

  const backlog = await backlogHealth(deps, checks);
  const worst = worstStatus(checks);
  return {
    checkedAt,
    status: worst === "fail" ? "not_ready" : worst === "warn" ? "degraded" : "ready",
    ready: worst !== "fail",
    version: deps.config.coordination.version,
    environment: deps.config.telemetry.deploymentEnvironment,
    configAudit,
    checks,
    deployment,
    backlog,
  };
}

export function runtimeHealthHttpStatus(snapshot: RuntimeHealthSnapshot): number {
  return snapshot.ready ? 200 : 503;
}

export function renderRuntimeHealth(snapshot: RuntimeHealthSnapshot): string {
  const lines = [
    `status=${snapshot.status}`,
    `ready=${snapshot.ready ? "true" : "false"}`,
    `version=${snapshot.version}`,
    `environment=${snapshot.environment}`,
    `checked_at=${snapshot.checkedAt}`,
    ...snapshot.checks.map((check) => `check.${safeKey(check.id)}=${check.status} ${check.summary}`),
  ];
  return `${lines.join("\n")}\n`;
}

export function runtimeHealthSlackText(snapshot: RuntimeHealthSnapshot): string {
  const work = snapshot.backlog.work;
  const schedules = snapshot.backlog.schedules;
  const autonomy = snapshot.backlog.autonomy;
  const dependencyProblems = snapshot.checks.filter((check) => check.status !== "ok").slice(0, 8);
  return trimForSlack([
    "Cerebro operator health",
    `Status: ${statusText(snapshot.status)}.`,
    `Version: ${snapshot.version}.`,
    `Environment: ${snapshot.environment}.`,
    `Config audit: ${snapshot.configAudit.status} (${snapshot.configAudit.issueCount} issue${snapshot.configAudit.issueCount === 1 ? "" : "s"}).`,
    work
      ? `Work queue: ${work.queued} queued, ${work.active} active, ${work.activeThreads} active thread${work.activeThreads === 1 ? "" : "s"}, oldest queued ${formatMs(work.oldestQueuedAgeMs)}.`
      : "Work queue: not wired in this process.",
    schedules
      ? `Scheduled checks: ${schedules.total} total, ${schedules.active} active, ${schedules.dueCount} due, oldest due ${formatMs(schedules.oldestDueAgeMs)}, ${schedules.blocked} blocked.`
      : "Scheduled checks: not wired in this process.",
    autonomy
      ? `Autonomy goals: ${autonomy.total} total, ${autonomy.active} active, ${autonomy.dueCount} due, oldest due ${formatMs(autonomy.oldestDueAgeMs)}, ${autonomy.blocked} blocked, ${autonomy.claimed} claimed.`
      : "Autonomy goals: not wired in this process.",
    deploymentLine(snapshot.deployment),
    dependencyProblems.length > 0
      ? `Issues:\n${dependencyProblems.map((check) => `${check.status} ${check.id}: ${check.summary}`).join("\n")}`
      : "Issues: none.",
  ].filter(Boolean).join("\n"), 3000);
}

export function recordRuntimeHealthMetrics(snapshot: RuntimeHealthSnapshot): void {
  recordGauge("cerebro_slack_companion_runtime_ready", {}, snapshot.ready ? 1 : 0);
  recordGauge("cerebro_slack_companion_runtime_status", {}, statusValue(snapshot.status));
  for (const check of snapshot.checks) {
    recordGauge("cerebro_slack_companion_runtime_check_status", { check: check.id }, healthStatusValue(check.status));
  }
  if (snapshot.backlog.work) {
    recordGauge("cerebro_slack_companion_work_queue_depth", { kind: "slack_question" }, snapshot.backlog.work.queued);
    recordGauge("cerebro_slack_companion_work_active", { kind: "slack_question" }, snapshot.backlog.work.active);
    recordGauge("cerebro_slack_companion_work_oldest_queue_age_seconds", { kind: "slack_question" }, snapshot.backlog.work.oldestQueuedAgeMs / 1000);
  }
  if (snapshot.backlog.schedules) {
    const schedules = snapshot.backlog.schedules;
    recordGauge("cerebro_slack_companion_schedule_jobs", { status: "active" }, schedules.active);
    recordGauge("cerebro_slack_companion_schedule_jobs", { status: "paused" }, schedules.paused);
    recordGauge("cerebro_slack_companion_schedule_jobs", { status: "blocked" }, schedules.blocked);
    recordGauge("cerebro_slack_companion_schedule_jobs", { status: "completed" }, schedules.completed);
    recordGauge("cerebro_slack_companion_schedule_due_count", {}, schedules.dueCount);
    recordGauge("cerebro_slack_companion_schedule_oldest_due_age_seconds", {}, schedules.oldestDueAgeMs / 1000);
    recordGauge("cerebro_slack_companion_schedule_active_runs", {}, schedules.activeRuns);
  }
  if (snapshot.backlog.autonomy) {
    const autonomy = snapshot.backlog.autonomy;
    recordGauge("cerebro_slack_companion_autonomy_goals", { status: "active" }, autonomy.active);
    recordGauge("cerebro_slack_companion_autonomy_goals", { status: "waiting" }, autonomy.waiting);
    recordGauge("cerebro_slack_companion_autonomy_goals", { status: "approval_needed" }, autonomy.approvalNeeded);
    recordGauge("cerebro_slack_companion_autonomy_goals", { status: "blocked" }, autonomy.blocked);
    recordGauge("cerebro_slack_companion_autonomy_due_count", {}, autonomy.dueCount);
    recordGauge("cerebro_slack_companion_autonomy_oldest_due_age_seconds", {}, autonomy.oldestDueAgeMs / 1000);
    recordGauge("cerebro_slack_companion_autonomy_claimed", {}, autonomy.claimed);
    recordGauge("cerebro_slack_companion_autonomy_stale_claims", {}, autonomy.staleClaims);
  }
}

function staticDependencyChecks(config: AppConfig): RuntimeHealthCheck[] {
  const checks: RuntimeHealthCheck[] = [
    {
      id: "dependency.slack_transport",
      status: config.slack.socketMode
        ? config.slack.botToken && config.slack.appToken ? "ok" : "fail"
        : config.slack.botToken && config.slack.signingSecret ? "ok" : "fail",
      summary: config.slack.socketMode ? "Slack Socket Mode credentials are configured." : "Slack HTTP signing credentials are configured.",
    },
    {
      id: "dependency.cerebro_read",
      status: config.cerebro.baseUrl && config.cerebro.apiKeys.read ? "ok" : "fail",
      summary: "Cerebro read endpoint and credential are configured.",
    },
    {
      id: "dependency.durable_slack_claims",
      status: config.coordination.eventDedupeEnabled
        ? config.learning.tableName ? "ok" : "fail"
        : "warn",
      summary: config.coordination.eventDedupeEnabled
        ? config.learning.tableName ? "Slack event claims use DynamoDB." : "Slack event claims are enabled without a DynamoDB table."
        : "Slack event claims are disabled.",
    },
    {
      id: "dependency.scheduled_job_store",
      status: !config.schedules.enabled ? "ok" : config.schedules.tableName ? "ok" : "warn",
      summary: !config.schedules.enabled
        ? "Scheduled checks are disabled."
        : config.schedules.tableName ? "Scheduled checks use DynamoDB." : "Scheduled checks use process memory.",
    },
    {
      id: "dependency.autonomy_goal_store",
      status: !config.autonomy.goalsEnabled ? "ok" : config.autonomy.goalsTableName || config.learning.tableName ? "ok" : "warn",
      summary: !config.autonomy.goalsEnabled
        ? "Autonomy goals are disabled."
        : config.autonomy.goalsTableName ? "Autonomy goals use the configured DynamoDB table."
          : config.learning.tableName ? "Autonomy goals use the learning DynamoDB table."
            : "Autonomy goals use process memory.",
    },
  ];
  return checks;
}

async function deploymentHealth(
  coordinator: RuntimeHealthDeps["coordinator"],
  config: AppConfig,
): Promise<RuntimeDeploymentHealth | undefined> {
  if (!coordinator) return undefined;
  const deployment = await coordinator.isCurrentTask().catch((error) => ({
    current: false,
    reason: "check_failed" as const,
    detail: shortError(error),
  }));
  const service = await coordinator.serviceSnapshot?.().catch(() => undefined);
  return {
    enabled: config.coordination.deploymentFenceEnabled,
    status: deployment.current ? deploymentWarnStatus(deployment.reason) : "fail",
    current: deployment.current,
    reason: deployment.reason,
    detail: deployment.detail,
    service,
  };
}

async function backlogHealth(deps: RuntimeHealthDeps, checks: RuntimeHealthCheck[]): Promise<RuntimeBacklogHealth> {
  const backlog: RuntimeBacklogHealth = {};
  backlog.work = deps.workLoop?.stats();
  if (deps.scheduler) {
    backlog.schedules = await deps.scheduler.stats().catch((error) => {
      checks.push({ id: "dependency.scheduled_job_stats", status: "fail", summary: `Scheduled check stats failed: ${shortError(error)}.` });
      return undefined;
    });
  }
  if (deps.goals) {
    backlog.autonomy = await deps.goals.stats().catch((error) => {
      checks.push({ id: "dependency.autonomy_goal_stats", status: "fail", summary: `Autonomy goal stats failed: ${shortError(error)}.` });
      return undefined;
    });
  }
  return backlog;
}

function auditCheckStatus(id: string): RuntimeHealthStatus {
  return READINESS_BLOCKING_AUDIT_CHECKS.has(id) ? "fail" : "warn";
}

function deploymentWarnStatus(reason: DeploymentCheckResult["reason"]): RuntimeHealthStatus {
  if (reason === "current" || reason === "disabled") return "ok";
  if (reason === "replacement_not_running" || reason === "metadata_unavailable" || reason === "check_failed" || reason === "service_unavailable" || reason === "not_configured") {
    return "warn";
  }
  return "ok";
}

function deploymentSummary(deployment: RuntimeDeploymentHealth): string {
  if (!deployment.enabled) return "Deployment fence is disabled.";
  if (!deployment.current) return deployment.detail ?? "This task is fenced by a newer deployment.";
  if (deployment.reason === "current") return "This task matches the ECS primary deployment.";
  return `Deployment fence reported ${deployment.reason}.`;
}

function deploymentLine(deployment: RuntimeDeploymentHealth | undefined): string {
  if (!deployment) return "Deployment fence: not wired in this process.";
  const service = deployment.service
    ? ` desired ${deployment.service.desiredCount}, running ${deployment.service.runningCount}, pending ${deployment.service.pendingCount}`
    : "";
  return `Deployment fence: ${deployment.status}, ${deployment.reason}${service}.`;
}

function worstStatus(checks: RuntimeHealthCheck[]): RuntimeHealthStatus {
  if (checks.some((check) => check.status === "fail")) return "fail";
  if (checks.some((check) => check.status === "warn")) return "warn";
  return "ok";
}

function statusText(status: RuntimeReadinessStatus): string {
  switch (status) {
    case "ready":
      return "ready";
    case "degraded":
      return "degraded";
    case "not_ready":
      return "not ready";
  }
}

function statusValue(status: RuntimeReadinessStatus): number {
  switch (status) {
    case "ready":
      return 0;
    case "degraded":
      return 1;
    case "not_ready":
      return 2;
  }
}

function healthStatusValue(status: RuntimeHealthStatus): number {
  switch (status) {
    case "ok":
      return 0;
    case "warn":
      return 1;
    case "fail":
      return 2;
  }
}

function safeKey(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.-]/g, "_");
}

function formatMs(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0s";
  if (value < 1000) return `${Math.round(value)}ms`;
  return `${Math.round(value / 1000)}s`;
}

function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return trimForSlack(message.replace(/\s+/g, " ").trim(), 240);
}
