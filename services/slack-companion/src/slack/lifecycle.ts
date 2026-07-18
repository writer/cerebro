import type { AppConfig } from "../config/index.js";
import { logger } from "../logger.js";
import type {
  ServiceSnapshot,
  SlackEventCoordinator,
  StartupObservation,
  StoppedTaskSnapshot,
} from "./coordination.js";
import type { ReleaseReceipt } from "./release-receipt.js";

export type LifecyclePhase = "started" | "stopping";

export interface LifecycleNoticeInput {
  phase: LifecyclePhase;
  signal?: string;
}

export interface LifecycleNoticeMonitor {
  stop(): void;
}

interface SlackClient {
  chat: {
    postMessage(message: any): Promise<any>;
  };
}

export async function postLifecycleNotice(
  config: AppConfig,
  coordinator: SlackEventCoordinator,
  client: SlackClient,
  input: LifecycleNoticeInput,
): Promise<void> {
  if (!config.slack.lifecycleNoticesEnabled) return;
  const channels = [...config.slack.lifecycleChannelIds].filter(Boolean);
  if (channels.length === 0) return;

  const [snapshot, activeRelease] = await Promise.all([
    coordinator.serviceSnapshot().catch((error) => {
      logger.warn("slack lifecycle service snapshot failed", { phase: input.phase, error: String(error) });
      return undefined;
    }),
    coordinator.activeReleaseReceipt().catch((error) => {
      logger.warn("slack lifecycle release receipt read failed", { phase: input.phase, error: String(error) });
      return undefined;
    }),
  ]);

  if (input.phase === "started") {
    const startup = await coordinator.recordStartup().catch((error) => {
      logger.warn("slack lifecycle startup record failed", { error: String(error) });
      return {
        count: 1,
        durable: false,
        loopDetected: false,
        windowMinutes: 15,
        startedAt: new Date().toISOString(),
      } satisfies StartupObservation;
    });
    if (activeRelease?.version === config.coordination.version && activeRelease.status === "deploying") {
      await postReleaseState(config, coordinator, client, activeRelease, channels, snapshot);
      return;
    }
    if (availabilityUnchanged(snapshot)) {
      logger.info("slack lifecycle notice skipped", { phase: input.phase, reason: "worker_scaling_without_availability_change" });
      return;
    }
    const stoppedTask = await recentStoppedTaskWithRetry(coordinator, startup.windowMinutes).catch((error) => {
      logger.warn("slack lifecycle stopped task read failed", { error: String(error) });
      return undefined;
    });
    await postStandaloneNotice(config, coordinator, client, channels, {
      phase: input.phase,
      scope: `${config.coordination.version}#${startup.startedAt}`,
      text: unexpectedRestartText(config, startup, stoppedTask),
    });
    return;
  }

  if (activeRelease?.status === "deploying") {
    await postReleaseTaskStopping(coordinator, client, activeRelease, channels, snapshot);
    return;
  }
  if (availabilityUnchanged(snapshot)) {
    logger.info("slack lifecycle notice skipped", { phase: input.phase, reason: "worker_scaling_without_availability_change" });
    return;
  }
  await postStandaloneNotice(config, coordinator, client, channels, {
    phase: input.phase,
    scope: config.coordination.version,
    text: lifecycleText(config, input, snapshot),
  });
}

export function startReleaseNoticeMonitor(
  config: AppConfig,
  coordinator: SlackEventCoordinator,
  client: SlackClient,
  intervalMs = 10_000,
): LifecycleNoticeMonitor {
  if (!config.slack.lifecycleNoticesEnabled || config.slack.lifecycleChannelIds.size === 0) {
    return { stop() {} };
  }
  let stopped = false;
  let running = false;
  const tick = async (): Promise<void> => {
    if (stopped || running) return;
    running = true;
    try {
      const receipt = await coordinator.activeReleaseReceipt();
      if (!receipt) return;
      if (releaseStateAlreadySent(receipt, [...config.slack.lifecycleChannelIds])) return;
      const snapshot = await coordinator.serviceSnapshot().catch(() => undefined);
      await postReleaseState(config, coordinator, client, receipt, [...config.slack.lifecycleChannelIds], snapshot);
    } catch (error) {
      logger.warn("slack release notice poll failed", { error: String(error) });
    } finally {
      running = false;
    }
  };
  const timer = setInterval(() => void tick(), Math.max(1_000, intervalMs));
  timer.unref?.();
  void tick();
  return {
    stop() {
      stopped = true;
      clearInterval(timer);
    },
  };
}

export function lifecycleText(config: AppConfig, input: LifecycleNoticeInput, snapshot?: ServiceSnapshot): string {
  const deployment = deploymentDetails(config);
  const model = languageModelDetails(config);
  if (input.phase === "started") {
    return `Cerebro restarted outside a recorded deployment. Running ${deployment}. Slack replies are connected. Language model ${model}.`;
  }

  const running = snapshot?.runningCount ?? 1;
  const otherWorkers = Math.max(running - 1, 0);
  if (otherWorkers > 0) {
    return `Cerebro worker is stopping outside a recorded deployment. Other workers running: ${otherWorkers}. Current ${deployment}. Language model ${model}.`;
  }
  return `Cerebro is stopping outside a recorded deployment. Slack replies may pause until a replacement connects. Current ${deployment}. Language model ${model}.`;
}

export function releaseStartedText(receipt: ReleaseReceipt): string {
  const subject = safeLifecycleText(receipt.commitSubject, 160)?.replace(/[.!?]+$/u, "");
  const commit = subject ? `commit ${safeLifecycleText(receipt.version, 80)}: ${subject}` : `version ${safeLifecycleText(receipt.version, 80)}`;
  const mode = receipt.deployMode === "pulumi" ? "infrastructure update" : "ECS application update";
  const components = receipt.components.length > 0
    ? receipt.components.map((item) => safeLifecycleText(item, 80)).filter(Boolean).join(", ")
    : "companion runtime";
  return [
    `Deployment started for ${commit}.`,
    `Mode: ${mode}. Components: ${components}. Changed files: ${receipt.changedFileCount}.`,
    "Checks running: Slack release message, ECS image, runtime configuration, and Cerebro API.",
    releaseLinks(receipt),
  ].filter(Boolean).join("\n");
}

export function releaseTerminalText(receipt: ReleaseReceipt, snapshot?: ServiceSnapshot): string {
  const links = releaseLinks(receipt);
  if (receipt.status === "verified") {
    const workers = snapshot ? ` Workers running: ${snapshot.runningCount}/${snapshot.desiredCount}.` : "";
    return [
      `Deployment verified. Running version ${safeLifecycleText(receipt.runningVersion ?? receipt.version, 80)}.${workers}`,
      "Checks passed: Slack release message, ECS image, runtime configuration, and Cerebro API.",
      links,
    ].filter(Boolean).join("\n");
  }
  if (receipt.status === "superseded") {
    return [
      `Deployment superseded. The service update was skipped. Running version: ${safeLifecycleText(receipt.runningVersion, 80) ?? "unknown"}.`,
      safeLifecycleText(receipt.statusDetail, 300),
      links,
    ].filter(Boolean).join("\n");
  }
  const failed = receipt.failedChecks.length > 0
    ? receipt.failedChecks.map((item) => safeLifecycleText(item, 80)).filter(Boolean).join(", ")
    : "deployment verification";
  if (receipt.status === "rolled_back") {
    return [
      `Deployment rolled back. Restored version ${safeLifecycleText(receipt.runningVersion ?? receipt.previousVersion, 80) ?? "unknown"}.`,
      `Failed checks: ${failed}.`,
      safeLifecycleText(receipt.statusDetail, 300),
      links,
    ].filter(Boolean).join("\n");
  }
  return [
    `Deployment failed verification. Running version: ${safeLifecycleText(receipt.runningVersion, 80) ?? "unknown"}.`,
    `Failed checks: ${failed}.`,
    safeLifecycleText(receipt.statusDetail, 300),
    links,
  ].filter(Boolean).join("\n");
}

function unexpectedRestartText(
  config: AppConfig,
  startup: StartupObservation,
  stoppedTask?: StoppedTaskSnapshot,
): string {
  const loop = startup.loopDetected
    ? `Restart loop detected: ${startup.count} starts in ${startup.windowMinutes} minutes.`
    : `Starts in the last ${startup.windowMinutes} minutes: ${startup.count}.`;
  const stopParts = [
    safeLifecycleText(stoppedTask?.stopCode, 80),
    stoppedTask?.exitCode === undefined ? undefined : `exit code ${stoppedTask.exitCode}`,
    safeLifecycleText(stoppedTask?.stoppedReason ?? stoppedTask?.containerReason, 240),
  ].filter(Boolean);
  const stop = stopParts.length > 0 ? `Last ECS stop: ${stopParts.join(" — ")}.` : "ECS has not reported a recent stop reason.";
  return [
    `Cerebro restarted outside a recorded deployment. Running ${deploymentDetails(config)}.`,
    "Slack replies are connected. Deployment health has not been asserted.",
    loop,
    stop,
  ].join("\n");
}

async function postReleaseState(
  _config: AppConfig,
  coordinator: SlackEventCoordinator,
  client: SlackClient,
  receipt: ReleaseReceipt,
  channels: string[],
  snapshot?: ServiceSnapshot,
): Promise<void> {
  let connectedChannels = 0;
  await Promise.all(channels.map(async (channel) => {
    let threadTs = receipt.threadTsByChannel[channel];
    if (!threadTs) {
      const claim = await coordinator.claimReleaseNotice({ version: receipt.version, channelId: channel, state: "started", leaseSeconds: 15 });
      if (claim.claimed) {
        try {
          const response = await client.chat.postMessage({
            channel,
            text: releaseStartedText(receipt),
            unfurl_links: false,
            unfurl_media: false,
          }) as { ts?: string };
          if (!response?.ts) throw new Error("Slack did not return a message timestamp.");
          threadTs = response.ts;
          await coordinator.completeReleaseNotice({ version: receipt.version, channelId: channel, state: "started", threadTs });
        } catch (error) {
          logger.warn("slack release start notice failed", { version: receipt.version, channel, error: String(error) });
          return;
        }
      }
    }
    if (!threadTs) return;
    connectedChannels += 1;
    if (receipt.status === "deploying") return;
    const claim = await coordinator.claimReleaseNotice({
      version: receipt.version,
      channelId: channel,
      state: receipt.status,
      leaseSeconds: 120,
    });
    if (!claim.claimed) return;
    try {
      await client.chat.postMessage({
        channel,
        thread_ts: threadTs,
        text: releaseTerminalText(receipt, snapshot),
        unfurl_links: false,
        unfurl_media: false,
      });
      await coordinator.completeReleaseNotice({ version: receipt.version, channelId: channel, state: receipt.status });
    } catch (error) {
      logger.warn("slack release terminal notice failed", { version: receipt.version, status: receipt.status, channel, error: String(error) });
    }
  }));
  if (receipt.status === "deploying" && connectedChannels === channels.length && receipt.checks.slack.status !== "passed") {
    await coordinator.markReleaseSlackCheck(
      receipt.version,
      "passed",
      `Release thread created in ${connectedChannels}/${channels.length} configured channel(s).`,
    ).catch((error) => logger.warn("slack release check write failed", { version: receipt.version, error: String(error) }));
  }
}

async function postReleaseTaskStopping(
  coordinator: SlackEventCoordinator,
  client: SlackClient,
  receipt: ReleaseReceipt,
  channels: string[],
  snapshot?: ServiceSnapshot,
): Promise<void> {
  await Promise.all(channels.map(async (channel) => {
    const threadTs = receipt.threadTsByChannel[channel];
    if (!threadTs) return;
    const claim = await coordinator.claimReleaseNotice({ version: receipt.version, channelId: channel, state: "previous_task_stopping" });
    if (!claim.claimed) return;
    const otherWorkers = Math.max((snapshot?.runningCount ?? 1) - 1, 0);
    const text = otherWorkers > 0
      ? `Previous task is stopping. Other workers running: ${otherWorkers}.`
      : "Previous task is stopping. Slack replies may pause until the replacement connects.";
    try {
      await client.chat.postMessage({ channel, thread_ts: threadTs, text });
      await coordinator.completeReleaseNotice({ version: receipt.version, channelId: channel, state: "previous_task_stopping" });
    } catch (error) {
      logger.warn("slack release task stop notice failed", { version: receipt.version, channel, error: String(error) });
    }
  }));
}

async function postStandaloneNotice(
  _config: AppConfig,
  coordinator: SlackEventCoordinator,
  client: SlackClient,
  channels: string[],
  input: { phase: LifecyclePhase; scope: string; text: string },
): Promise<void> {
  const claim = await coordinator.claimLifecycleNotice({ phase: input.phase, scope: input.scope });
  if (!claim.claimed) {
    logger.info("slack lifecycle notice skipped", { phase: input.phase, reason: claim.reason, eventKey: claim.eventKey });
    return;
  }
  await Promise.all(channels.map(async (channel) => {
    try {
      await client.chat.postMessage({ channel, text: input.text, unfurl_links: false, unfurl_media: false });
    } catch (error) {
      logger.warn("slack lifecycle notice failed", { phase: input.phase, channel, error: String(error) });
    }
  }));
}

function availabilityUnchanged(snapshot?: ServiceSnapshot): boolean {
  return Boolean(snapshot && snapshot.desiredCount > 1 && snapshot.runningCount >= snapshot.desiredCount && snapshot.pendingCount === 0);
}

async function recentStoppedTaskWithRetry(
  coordinator: SlackEventCoordinator,
  windowMinutes: number,
): Promise<StoppedTaskSnapshot | undefined> {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const stoppedTask = await coordinator.recentStoppedTask(windowMinutes);
    if (stoppedTask) return stoppedTask;
    if (attempt < 2) await delay(1_500);
  }
  return undefined;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref?.();
  });
}

function releaseStateAlreadySent(receipt: ReleaseReceipt, channels: string[]): boolean {
  if (receipt.status === "deploying") return false;
  return channels.every((channel) => Boolean(receipt.notifications[
    `${cleanNoticeKey(channel, 60)}:${cleanNoticeKey(receipt.status, 50)}`
  ]));
}

function cleanNoticeKey(value: string, maxLength: number): string {
  return value.replace(/[^A-Za-z0-9_.:-]+/g, "_").slice(0, maxLength);
}

function deploymentDetails(config: AppConfig): string {
  const version = safeLifecycleText(config.coordination.version, 80) ?? "unknown";
  const subject = safeLifecycleText(config.coordination.commitSubject, 160)?.replace(/[.!?]+$/u, "");
  return subject ? `commit ${version}: ${subject}` : `version ${version}`;
}

function releaseLinks(receipt: ReleaseReceipt): string {
  return [
    slackLink(receipt.deployRunUrl, "Deploy run"),
    slackLink(receipt.commitUrl, "Commit"),
    slackLink(receipt.pullRequestUrl, "Pull request"),
  ].filter(Boolean).join(" · ");
}

function slackLink(url: string | undefined, label: string): string | undefined {
  if (!url) return undefined;
  return `<${url}|${label}>`;
}

function safeLifecycleText(value: string | undefined, maxLength: number): string | undefined {
  const normalized = value
    ?.replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!normalized) return undefined;
  const bounded = normalized.slice(0, maxLength).trimEnd();
  return bounded
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function languageModelDetails(config: AppConfig): string {
  const { provider, model, thinkingLevel } = config.triage.pi;
  return `${provider}/${model} (thinking ${thinkingLevel})`;
}
