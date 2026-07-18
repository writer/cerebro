import "dotenv/config";

import { Authorization } from "./auth.js";
import { AutonomyGoalService } from "./autonomy/goal-service.js";
import { AutonomyRunner } from "./autonomy/runner.js";
import { MissionWorkScheduler } from "./autonomy/mission-work.js";
import { AutonomyToolDispatcher } from "./autonomy/tool-dispatcher.js";
import { createSecurityAgentTools } from "./agent/tools/index.js";
import { loadConfig } from "./config/index.js";
import { CerebroClient } from "./cerebro/client.js";
import { SecurityAssistantService } from "./agent/security-assistant.js";
import { AssistantThreadStateStore } from "./agent/thread-intelligence-store.js";
import { EvidenceGovernanceService } from "./agent/evidence-governance.js";
import { DailyNotesService } from "./learning/daily-notes.js";
import { SecurityMemoryCurator } from "./learning/security-memory-curator.js";
import { SecurityMemoryStore } from "./learning/security-memory/index.js";
import { AssistantFeedbackService } from "./learning/assistant-feedback.js";
import { SlackChannelLearningService } from "./learning/slack-channel-learning.js";
import { CompanyLibraryCompoundingService } from "./learning/company-library-compounding.js";
import { CompanyLibraryCurator } from "./learning/company-library-curator.js";
import { createImprovementControlPlane } from "./improvement/control-plane.js";
import { SlackImprovementHumanAssistancePublisher } from "./improvement/human-assistance.js";
import { logger } from "./logger.js";
import { ScheduledJobService } from "./schedules/scheduled-jobs/index.js";
import { SecuritySkillService } from "./skills/security-skill-service.js";
import { createSlackApp } from "./slack/app.js";
import { SlackEventCoordinator } from "./slack/coordination.js";
import { SlackDeliveryOutbox } from "./slack/delivery-outbox.js";
import { postLifecycleNotice, startReleaseNoticeMonitor } from "./slack/lifecycle.js";
import { auditRuntimeConfig } from "./runtime/config-audit.js";
import { captureTelemetryError, configureTelemetry, telemetryEvent, telemetryOptionsFromConfig } from "./telemetry.js";
import { SlackThreadSessionStateStore } from "./triage/slack-thread-state.js";
import { CompanionWorkLoop } from "./work/companion-work-loop.js";
import { RiskAttestationService } from "./slack/risk-attestation.js";
import { A2AFleetService, DynamoSharedRateLimitStore, InMemorySharedRateLimitStore, SharedRateLimitCoordinator } from "./a2a/index.js";
import { CerebroEnsembleService } from "./agent/cerebro-ensemble.js";
import { CerebroDistributedWorkService } from "./agent/distributed-work.js";
import { verifyProductReleaseRuntime } from "./product-release.js";

async function main(): Promise<void> {
  const startupStartedAt = Date.now();
  const config = loadConfig();
  configureTelemetry(telemetryOptionsFromConfig(config));
  const productRelease = await verifyProductReleaseRuntime();
  const configAudit = auditRuntimeConfig(config);
  telemetryEvent("companion.starting", {
    component: "runtime",
    operation: "startup",
    "startup.started_at": new Date(startupStartedAt).toISOString(),
    "slack.socket_mode": config.slack.socketMode,
    "telemetry.metrics.enabled": config.telemetry.metricsEnabled,
    "config.audit.status": configAudit.status,
    "config.audit.issue_count": configAudit.issueCount,
    "product_release.status": productRelease.status,
    "product_release.version": productRelease.version ?? "",
    "product_release.commit": productRelease.commit ?? "",
  });
  logger.info("product release package verified", {
    status: productRelease.status,
    version: productRelease.version,
    commit: productRelease.commit,
    package: productRelease.package,
  });
  logger.info("runtime config audit", {
    status: configAudit.status,
    issueCount: configAudit.issueCount,
    warnings: configAudit.checks.filter((item) => item.status === "warn").map((item) => item.id),
  });
  const auth = new Authorization(config);
  const cerebro = new CerebroClient(config);
  const memoryCurator = new SecurityMemoryCurator(config);
  const memory = new SecurityMemoryStore(config, { curator: memoryCurator });
  const companyLibrary = new CompanyLibraryCompoundingService(
    config,
    memory,
    memory.companyLibrary,
    new CompanyLibraryCurator(config),
  );
  const channelLearning = new SlackChannelLearningService(config, memory);
  const notes = new DailyNotesService(config, memory);
  const a2a = new A2AFleetService(config);
  const sharedRateStore = config.learning.tableName
    ? new DynamoSharedRateLimitStore(config.learning.tableName, config.cerebro.tenantId)
    : new InMemorySharedRateLimitStore();
  const sharedRateLimits = new SharedRateLimitCoordinator(sharedRateStore, config.a2a.instanceId);
  const distributedWork = new CerebroDistributedWorkService(config, a2a, cerebro, memory, sharedRateLimits);
  const ensemble = new CerebroEnsembleService(config, a2a, { rateLimits: sharedRateLimits });
  a2a.setMessageHandler(async (message) => {
    if (message.kind === "handoff") {
      await distributedWork.handleHandoff(message);
      await notes.record({
        kind: "lifecycle",
        title: "Cerebro peer handoff received",
        summary: `Instance ${config.a2a.instanceId} accepted a shutdown handoff from ${message.from}.`,
        outcome: "accepted",
        tags: ["a2a", "handoff", message.from],
      });
      return;
    }
    const distributedReply = await distributedWork.handleMessage(message);
    return distributedReply ?? ensemble.handleMessage(message);
  });
  const skills = new SecuritySkillService(config, cerebro, memory);
  const scheduler = new ScheduledJobService({ config, cerebro, notes, skills });
  const goals = new AutonomyGoalService(config, { cerebro });
  const assistantThreadState = new AssistantThreadStateStore(config);
  const coordinator = new SlackEventCoordinator(config);
  const threadState = new SlackThreadSessionStateStore(config);
  const deliveryOutbox = new SlackDeliveryOutbox(config, {
    beforeCompletePosted: async ({ delivery, postedTs }) => {
      await threadState.bindAssistantInitiativeReceipt({
        deliveryId: delivery.id,
        channelId: delivery.channelId,
        threadTs: delivery.threadTs ?? postedTs,
        receiptContext: delivery.receiptContext,
      });
    },
  });
  const improvement = createImprovementControlPlane(config, {
    humanAssistance: new SlackImprovementHumanAssistancePublisher(deliveryOutbox),
  });
  const evidenceGovernance = new EvidenceGovernanceService(config);
  const feedback = new AssistantFeedbackService(config, { memory, improvement, evidenceGovernance });
  const riskAttestations = new RiskAttestationService(config);
  const assistant = new SecurityAssistantService(config, cerebro, memory, {
    goals,
    threadState: assistantThreadState,
    feedback,
    evidenceGovernance,
    riskAttestations,
    ensemble,
    distributedWork,
    rateLimits: sharedRateLimits,
  });
  const workLoop = new CompanionWorkLoop({ config, assistant, memory, notes, feedback, improvement, evidenceGovernance });
  const autonomyTools = createSecurityAgentTools({ config, cerebro, memory, autonomyGoals: goals });
  const autonomyRunner = new AutonomyRunner(config, goals, {
    cerebro,
    memory,
    dispatcher: new AutonomyToolDispatcher(autonomyTools, config.triage.timeoutMs),
  });
  const missionWork = config.autonomy.goalsEnabled && config.autonomy.runnerEnabled && config.autonomy.queueEnabled
    ? new MissionWorkScheduler(config, autonomyRunner)
    : undefined;
  try {
    await cerebro.ensureCompanionRuntime();
    telemetryEvent("companion.runtime_bootstrap.completed", {
      component: "startup",
      operation: "ensure_companion_runtime",
    });
  } catch (error) {
    captureTelemetryError("companion.runtime_bootstrap.error", error, { component: "startup", operation: "ensure_companion_runtime" });
    logger.error("companion runtime bootstrap failed", { error: String(error) });
    throw new Error("Cerebro runtime bootstrap failed", { cause: error });
  }

  const app = createSlackApp({ config, auth, cerebro, memory, channelLearning, coordinator, notes, skills, scheduler, goals, threadState, assistant, workLoop, feedback, riskAttestations, a2a, improvement });
  riskAttestations.setSlackClient(app.client);
  await app.start(config.port);
  deliveryOutbox.start(app.client);
  improvement?.start();
  await a2a.start().catch((error) => logger.warn("A2A fleet start failed", { error: String(error) }));
  feedback.start();
  channelLearning.start();
  companyLibrary.start();
  workLoop.start(app.client);
  notes.start();
  scheduler.start(app.client);
  if (missionWork) missionWork.start(app.client);
  else autonomyRunner.start(app.client);
  logger.info("cerebro slack companion started", {
    port: config.port,
    socketMode: config.slack.socketMode,
    cerebroBaseUrl: config.cerebro.baseUrl,
  });
  telemetryEvent("companion.started", {
    component: "runtime",
    operation: "startup",
    "startup.duration_ms": Date.now() - startupStartedAt,
    "server.port": config.port,
    "slack.socket_mode": config.slack.socketMode,
    "a2a.instance_id": config.a2a.instanceId,
    "a2a.label": config.a2a.label,
    "a2a.role": config.a2a.role,
  });

  await postLifecycleNotice(config, coordinator, app.client, { phase: "started" });
  const releaseNoticeMonitor = startReleaseNoticeMonitor(config, coordinator, app.client);
  await notes.record({
    kind: "lifecycle",
    title: "Cerebro started",
    summary: `Cerebro Slack companion started on version ${config.coordination.version}.`,
    outcome: "started",
    tags: ["startup", config.coordination.version],
  }).catch((error) => logger.warn("daily note write failed", { error: String(error), kind: "lifecycle" }));

  let shutdownStarted = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shutdownStarted) return;
    shutdownStarted = true;
    const shutdownStartedAt = Date.now();
    telemetryEvent("companion.shutdown_requested", { component: "runtime", operation: "shutdown", signal });
    logger.info("shutdown requested", { signal });
    notes.stop();
    await improvement?.stop();
    await deliveryOutbox.stop();
    releaseNoticeMonitor.stop();
    scheduler.stop();
    autonomyRunner.stop();
    await missionWork?.stop();
    workLoop.stop();
    const activeGoalIds = await goals.list("active")
      .then((items) => items.map((goal) => goal.id))
      .catch((error) => {
        logger.warn("active goal listing failed during shutdown", { error: String(error), signal });
        return [];
      });
    const noticesStartedAt = Date.now();
    const shutdownResults = await Promise.all([
      a2a.drain(signal, activeGoalIds, distributedWork.activeWorkHandoffs())
        .catch((error) => {
          logger.warn("A2A shutdown handoff failed", { error: String(error), signal });
          return { state: "timed_out" as const, goalIds: activeGoalIds, workPacketIds: distributedWork.activeWorkPacketIds() };
        }),
      withTimeout(channelLearning.stop(), 3_000)
        .catch((error) => logger.warn("channel learning stop failed", { error: String(error), signal })),
      withTimeout(companyLibrary.stop(), 3_000)
        .catch((error) => logger.warn("company library stop failed", { error: String(error), signal })),
      withTimeout(notes.record({
        kind: "lifecycle",
        title: "Cerebro stopping",
        summary: `Cerebro Slack companion received ${signal} on version ${config.coordination.version}.`,
        outcome: "stopping",
        tags: ["shutdown", config.coordination.version],
      }), 2_000).catch((error) => logger.warn("shutdown daily note write failed", { error: String(error), kind: "lifecycle" })),
      withTimeout(postLifecycleNotice(config, coordinator, app.client, { phase: "stopping", signal }), 2_000)
        .catch((error) => logger.warn("shutdown lifecycle notice failed", { error: String(error), signal })),
    ]);
    const a2aShutdown = shutdownResults[0];
    const noticeDurationMs = Date.now() - noticesStartedAt;
    const appStopStartedAt = Date.now();
    let appStopStatus = "completed";
    await withTimeout(app.stop(), 3_000)
      .catch((error) => {
        appStopStatus = "failed";
        logger.warn("slack app stop failed", { error: String(error), signal });
      });
    telemetryEvent("companion.shutdown_completed", {
      component: "runtime",
      operation: "shutdown",
      signal,
      "shutdown.duration_ms": Date.now() - shutdownStartedAt,
      "shutdown.notice_duration_ms": noticeDurationMs,
      "shutdown.app_stop_duration_ms": Date.now() - appStopStartedAt,
      "shutdown.app_stop_status": appStopStatus,
      "shutdown.a2a_handoff_status": a2aShutdown.state,
      "shutdown.a2a_handoff_goal_count": a2aShutdown.goalIds.length,
      "shutdown.a2a_handoff_work_packet_count": a2aShutdown.workPacketIds.length,
    });
    process.exit(0);
  };

  process.once("SIGTERM", () => {
    void shutdown("SIGTERM");
  });
  process.once("SIGINT", () => {
    void shutdown("SIGINT");
  });
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => reject(new Error(`Timed out after ${timeoutMs}ms`)), timeoutMs);
    timeout.unref?.();
  });
  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

main().catch((error) => {
  captureTelemetryError("companion.startup.error", error, { component: "runtime", operation: "startup" });
  logger.error("startup failed", { error: String(error) });
  process.exitCode = 1;
});
