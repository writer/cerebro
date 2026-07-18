import { DescribeServicesCommand, DescribeTasksCommand, ECSClient, ListTasksCommand } from "@aws-sdk/client-ecs";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import type { AppConfig } from "../config/index.js";
import { hashTelemetryId, recordMetric, telemetryEvent } from "../telemetry.js";
import {
  type ReleaseCheckStatus,
  type ReleaseReceipt,
  releasePointerFromItem,
  releaseReceiptFromItem,
} from "./release-receipt.js";

export interface SlackEventClaimInput {
  kind: string;
  channelId?: string;
  ts?: string;
  eventId?: string;
  teamId?: string;
}

export interface SlackEventClaimResult {
  claimed: boolean;
  reason:
    | "claimed"
    | "claimed_local"
    | "missing_event_key"
    | "local_duplicate"
    | "durable_duplicate"
    | "stale_deployment"
    | "claim_store_unavailable";
  eventKey?: string;
  detail?: string;
}

export interface SlackBotHandoffInput {
  channelId?: string;
  threadTs?: string;
  ts?: string;
  botId?: string;
  userId?: string;
  appId?: string;
  subtype?: string;
}

export interface SlackBotHandoffResult {
  accepted: boolean;
  reason:
    | "not_bot"
    | "allowed"
    | "missing_sender"
    | "bot_not_allowed"
    | "cooldown"
    | "loop_limit";
  senderId?: string;
  cooldownSeconds?: number;
  handoffCount?: number;
  maxHandoffsPerThread?: number;
  windowSeconds?: number;
  policyScope?: "global" | "channel";
}

export interface DeploymentCheckResult {
  current: boolean;
  reason:
    | "disabled"
    | "not_configured"
    | "metadata_unavailable"
    | "service_unavailable"
    | "current"
    | "replacement_not_running"
    | "stale_deployment"
    | "check_failed";
  ownTaskDefinitionArn?: string;
  primaryTaskDefinitionArn?: string;
  primaryRunningCount?: number;
  detail?: string;
}

export interface ServiceSnapshot {
  desiredCount: number;
  runningCount: number;
  pendingCount: number;
  primaryTaskDefinitionArn?: string;
  primaryRunningCount?: number;
}

export interface StartupObservation {
  count: number;
  durable: boolean;
  loopDetected: boolean;
  windowMinutes: number;
  startedAt: string;
}

export interface StoppedTaskSnapshot {
  taskArn?: string;
  stoppedAt?: string;
  stopCode?: string;
  stoppedReason?: string;
  containerReason?: string;
  exitCode?: number;
}

export interface ReleaseNoticeClaimResult {
  claimed: boolean;
  reason: "claimed" | "already_sent" | "leased" | "store_unavailable" | "receipt_unavailable";
}

export interface BotHandoffStats {
  globalAllowedIds: number;
  channelPolicies: number;
  cooldownSeconds: number;
  maxHandoffsPerThread: number;
  windowSeconds: number;
  activeWindows: number;
}

export interface LifecycleNoticeClaimInput {
  phase: "started" | "stopping";
  scope?: string;
  ttlSeconds?: number;
}

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

interface TaskIdentity {
  taskDefinitionArn: string;
  taskArn?: string;
}

interface BotHandoffState {
  windowStartedAt: number;
  lastSeenAt: number;
  count: number;
}

interface BotHandoffPolicyMatch {
  senderId: string;
  allowedSenderId: string;
  scope: "global" | "channel";
  cooldownSeconds: number;
  maxHandoffsPerThread: number;
  windowSeconds: number;
}

interface SlackEventCoordinatorOptions {
  dynamo?: CommandSender;
  ecs?: CommandSender;
  now?: () => Date;
  taskIdentityProvider?: () => Promise<TaskIdentity | undefined>;
}

export class SlackEventCoordinator {
  private readonly localEvents = new RecentEventSet(1_000);
  private readonly botHandoffStates = new Map<string, BotHandoffState>();
  private readonly dynamo?: CommandSender;
  private readonly ecs?: CommandSender;
  private readonly partitionKey: string;
  private readonly releasePartitionKey: string;
  private readonly startupPartitionKey: string;
  private readonly now: () => Date;
  private readonly taskIdentityProvider?: () => Promise<TaskIdentity | undefined>;
  private taskIdentityPromise?: Promise<TaskIdentity | undefined>;
  private deploymentCache?: { expiresAt: number; result: DeploymentCheckResult };

  constructor(private readonly config: AppConfig, options: SlackEventCoordinatorOptions = {}) {
    this.partitionKey = `tenant#${config.cerebro.tenantId}#slack-event-claims`;
    this.releasePartitionKey = `tenant#${config.cerebro.tenantId}#release-receipts`;
    this.startupPartitionKey = `tenant#${config.cerebro.tenantId}#companion-startups`;
    this.now = options.now ?? (() => new Date());
    this.taskIdentityProvider = options.taskIdentityProvider;
    if (config.learning.tableName) {
      this.dynamo = options.dynamo ?? DynamoDBDocumentClient.from(new DynamoDBClient({}));
    }
    if (config.coordination.deploymentFenceEnabled && config.coordination.ecsClusterName && config.coordination.ecsServiceName) {
      this.ecs = options.ecs ?? new ECSClient({});
    }
  }

  async claimSlackEvent(input: SlackEventClaimInput): Promise<SlackEventClaimResult> {
    const eventKey = eventKeyFor(input, this.config.cerebro.tenantId);
    if (!eventKey) {
      return { claimed: false, reason: "missing_event_key" };
    }

    if (!this.localEvents.add(eventKey)) {
      return { claimed: false, reason: "local_duplicate", eventKey };
    }

    const deployment = await this.isCurrentTask();
    if (!deployment.current) {
      return { claimed: false, reason: "stale_deployment", eventKey, detail: deployment.detail };
    }

    if (!this.dynamo || !this.config.learning.tableName) {
      return { claimed: true, reason: "claimed_local", eventKey };
    }

    try {
      const now = this.now();
      await this.dynamo.send(new PutCommand({
        TableName: this.config.learning.tableName,
        Item: {
          pk: this.partitionKey,
          sk: `event#${eventKey}`,
          kind: cleanKeyPart(input.kind, 80),
          channelId: input.channelId,
          ts: input.ts,
          eventId: input.eventId,
          teamId: input.teamId,
          companionVersion: this.config.coordination.version,
          claimedAt: now.toISOString(),
          expires_at: Math.floor(now.getTime() / 1000) + this.config.coordination.eventDedupeTtlSeconds,
        },
        ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
      }));
      return { claimed: true, reason: "claimed", eventKey };
    } catch (error) {
      if (isConditionalCheckFailed(error)) {
        return { claimed: false, reason: "durable_duplicate", eventKey };
      }
      return {
        claimed: false,
        reason: "claim_store_unavailable",
        eventKey,
        detail: shortError(error),
      };
    }
  }

  claimBotHandoff(input: SlackBotHandoffInput): SlackBotHandoffResult {
    if (!isBotAuthored(input)) return this.recordBotHandoff(input, { accepted: true, reason: "not_bot" });

    const senderIds = senderIdsForBotHandoff(input);
    const senderId = senderIds[0];
    if (!senderId) return this.recordBotHandoff(input, { accepted: false, reason: "missing_sender" });

    const policy = this.botHandoffPolicy(input, senderIds);
    if (!policy) {
      return this.recordBotHandoff(input, { accepted: false, reason: "bot_not_allowed", senderId });
    }

    const nowMs = this.now().getTime();
    const key = [
      cleanKeyPart(input.channelId ?? "unknown-channel", 80),
      cleanKeyPart(input.threadTs ?? input.ts ?? "unknown-thread", 80),
      cleanKeyPart(policy.allowedSenderId, 120),
    ].join("#");
    const windowMs = Math.max(1, policy.windowSeconds) * 1000;
    const existing = this.botHandoffStates.get(key);
    const state = !existing || nowMs - existing.windowStartedAt >= windowMs
      ? { windowStartedAt: nowMs, lastSeenAt: 0, count: 0 }
      : existing;
    if (policy.cooldownSeconds > 0 && state.lastSeenAt > 0 && nowMs - state.lastSeenAt < policy.cooldownSeconds * 1000) {
      return this.recordBotHandoff(input, {
        accepted: false,
        reason: "cooldown",
        senderId: policy.senderId,
        cooldownSeconds: policy.cooldownSeconds,
        handoffCount: state.count,
        maxHandoffsPerThread: policy.maxHandoffsPerThread,
        windowSeconds: policy.windowSeconds,
        policyScope: policy.scope,
      });
    }
    if (policy.maxHandoffsPerThread > 0 && state.count >= policy.maxHandoffsPerThread) {
      return this.recordBotHandoff(input, {
        accepted: false,
        reason: "loop_limit",
        senderId: policy.senderId,
        cooldownSeconds: policy.cooldownSeconds,
        handoffCount: state.count,
        maxHandoffsPerThread: policy.maxHandoffsPerThread,
        windowSeconds: policy.windowSeconds,
        policyScope: policy.scope,
      });
    }
    state.count += 1;
    state.lastSeenAt = nowMs;
    this.botHandoffStates.set(key, state);
    pruneBotHandoffStates(this.botHandoffStates, nowMs - windowMs);
    return this.recordBotHandoff(input, {
      accepted: true,
      reason: "allowed",
      senderId: policy.senderId,
      cooldownSeconds: policy.cooldownSeconds,
      handoffCount: state.count,
      maxHandoffsPerThread: policy.maxHandoffsPerThread,
      windowSeconds: policy.windowSeconds,
      policyScope: policy.scope,
    });
  }

  botHandoffStats(): BotHandoffStats {
    return {
      globalAllowedIds: this.config.slack.assistantBotUserIds.size,
      channelPolicies: this.config.slack.assistantBotHandoffPolicies.length,
      cooldownSeconds: Math.max(0, this.config.slack.assistantBotCooldownSeconds),
      maxHandoffsPerThread: Math.max(0, this.config.slack.assistantBotMaxHandoffsPerThread),
      windowSeconds: Math.max(1, this.config.slack.assistantBotHandoffWindowSeconds),
      activeWindows: this.botHandoffStates.size,
    };
  }

  async claimLifecycleNotice(input: LifecycleNoticeClaimInput): Promise<SlackEventClaimResult> {
    const scope = input.scope ?? this.config.coordination.version;
    const eventKey = ["lifecycle", cleanKeyPart(input.phase, 40), cleanKeyPart(scope, 160)].join("#");
    return this.claimDurableKey({
      eventKey,
      kind: `lifecycle_${input.phase}`,
      ttlSeconds: input.ttlSeconds ?? this.config.coordination.lifecycleNoticeTtlSeconds,
      checkDeploymentFence: false,
    });
  }

  async isCurrentTask(): Promise<DeploymentCheckResult> {
    if (!this.config.coordination.deploymentFenceEnabled) {
      return { current: true, reason: "disabled" };
    }
    if (!this.ecs || !this.config.coordination.ecsClusterName || !this.config.coordination.ecsServiceName) {
      return { current: true, reason: "not_configured" };
    }

    const nowMs = this.now().getTime();
    if (this.deploymentCache && this.deploymentCache.expiresAt > nowMs) {
      return this.deploymentCache.result;
    }

    const result = await this.checkCurrentTask().catch((error) => ({
      current: true,
      reason: "check_failed" as const,
      detail: shortError(error),
    }));
    this.deploymentCache = {
      expiresAt: nowMs + this.config.coordination.deploymentFenceCacheMs,
      result,
    };
    return result;
  }

  async serviceSnapshot(): Promise<ServiceSnapshot | undefined> {
    const service = await this.describeService();
    if (!service) return undefined;
    const primary = service.deployments?.find((deployment) => deployment.status === "PRIMARY");
    return {
      desiredCount: service.desiredCount ?? 0,
      runningCount: service.runningCount ?? 0,
      pendingCount: service.pendingCount ?? 0,
      primaryTaskDefinitionArn: primary?.taskDefinition,
      primaryRunningCount: primary?.runningCount,
    };
  }

  async activeReleaseReceipt(): Promise<ReleaseReceipt | undefined> {
    if (!this.dynamo || !this.config.learning.tableName) return undefined;
    const pointerResponse = await this.dynamo.send(new GetCommand({
      TableName: this.config.learning.tableName,
      Key: { pk: this.releasePartitionKey, sk: "current" },
      ConsistentRead: true,
    })) as { Item?: unknown };
    const pointer = releasePointerFromItem(pointerResponse.Item);
    return pointer ? this.releaseReceipt(pointer.version) : undefined;
  }

  async releaseReceipt(version: string): Promise<ReleaseReceipt | undefined> {
    if (!this.dynamo || !this.config.learning.tableName) return undefined;
    const response = await this.dynamo.send(new GetCommand({
      TableName: this.config.learning.tableName,
      Key: { pk: this.releasePartitionKey, sk: `release#${cleanKeyPart(version, 80)}` },
      ConsistentRead: true,
    })) as { Item?: unknown };
    return releaseReceiptFromItem(response.Item);
  }

  async claimReleaseNotice(input: {
    version: string;
    channelId: string;
    state: string;
    leaseSeconds?: number;
  }): Promise<ReleaseNoticeClaimResult> {
    if (!this.dynamo || !this.config.learning.tableName) return { claimed: false, reason: "store_unavailable" };
    const noticeKey = releaseNoticeKey(input.channelId, input.state);
    const nowSeconds = Math.floor(this.now().getTime() / 1_000);
    try {
      await this.dynamo.send(new UpdateCommand({
        TableName: this.config.learning.tableName,
        Key: { pk: this.releasePartitionKey, sk: `release#${cleanKeyPart(input.version, 80)}` },
        UpdateExpression: "SET #claims.#notice = :lease",
        ConditionExpression: "attribute_exists(pk) AND attribute_not_exists(#notifications.#notice) AND (attribute_not_exists(#claims.#notice) OR #claims.#notice < :now)",
        ExpressionAttributeNames: {
          "#claims": "notificationClaims",
          "#notifications": "notifications",
          "#notice": noticeKey,
        },
        ExpressionAttributeValues: {
          ":lease": nowSeconds + Math.max(10, input.leaseSeconds ?? 60),
          ":now": nowSeconds,
        },
      }));
      return { claimed: true, reason: "claimed" };
    } catch (error) {
      if (!isConditionalCheckFailed(error)) throw error;
      const receipt = await this.releaseReceipt(input.version);
      if (!receipt) return { claimed: false, reason: "receipt_unavailable" };
      if (receipt.notifications[noticeKey]) return { claimed: false, reason: "already_sent" };
      return { claimed: false, reason: "leased" };
    }
  }

  async completeReleaseNotice(input: {
    version: string;
    channelId: string;
    state: string;
    threadTs?: string;
  }): Promise<void> {
    if (!this.dynamo || !this.config.learning.tableName) return;
    const noticeKey = releaseNoticeKey(input.channelId, input.state);
    const names: Record<string, string> = {
      "#claims": "notificationClaims",
      "#notifications": "notifications",
      "#notice": noticeKey,
    };
    const values: Record<string, unknown> = { ":sentAt": this.now().toISOString() };
    let updateExpression = "SET #notifications.#notice = :sentAt REMOVE #claims.#notice";
    if (input.threadTs) {
      names["#threads"] = "threadTsByChannel";
      names["#channel"] = cleanKeyPart(input.channelId, 120);
      values[":threadTs"] = input.threadTs;
      updateExpression = "SET #notifications.#notice = :sentAt, #threads.#channel = :threadTs REMOVE #claims.#notice";
    }
    await this.dynamo.send(new UpdateCommand({
      TableName: this.config.learning.tableName,
      Key: { pk: this.releasePartitionKey, sk: `release#${cleanKeyPart(input.version, 80)}` },
      UpdateExpression: updateExpression,
      ExpressionAttributeNames: names,
      ExpressionAttributeValues: values,
    }));
  }

  async markReleaseSlackCheck(version: string, status: ReleaseCheckStatus, detail: string): Promise<void> {
    if (!this.dynamo || !this.config.learning.tableName) return;
    await this.dynamo.send(new UpdateCommand({
      TableName: this.config.learning.tableName,
      Key: { pk: this.releasePartitionKey, sk: `release#${cleanKeyPart(version, 80)}` },
      UpdateExpression: "SET #checks.#slack = :check, updatedAt = :updatedAt",
      ExpressionAttributeNames: { "#checks": "checks", "#slack": "slack" },
      ExpressionAttributeValues: {
        ":check": { status, detail: detail.replace(/\s+/g, " ").slice(0, 300) },
        ":updatedAt": this.now().toISOString(),
      },
    }));
  }

  async recordStartup(windowMinutes = 15): Promise<StartupObservation> {
    if (!this.dynamo || !this.config.learning.tableName) {
      return { count: 1, durable: false, loopDetected: false, windowMinutes, startedAt: this.now().toISOString() };
    }
    const now = this.now();
    const identity = await this.taskIdentity().catch(() => undefined);
    const taskKey = cleanKeyPart(identity?.taskArn ?? `${process.pid}-${now.getTime()}`, 180);
    const startedAt = now.toISOString();
    await this.dynamo.send(new PutCommand({
      TableName: this.config.learning.tableName,
      Item: {
        pk: this.startupPartitionKey,
        sk: `started#${startedAt}#${taskKey}`,
        recordType: "companion_startup",
        version: this.config.coordination.version,
        taskArn: identity?.taskArn,
        startedAt,
        expires_at: Math.floor(now.getTime() / 1_000) + (7 * 24 * 60 * 60),
      },
      ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
    }));
    const since = new Date(now.getTime() - (windowMinutes * 60_000)).toISOString();
    const response = await this.dynamo.send(new QueryCommand({
      TableName: this.config.learning.tableName,
      KeyConditionExpression: "pk = :pk AND sk BETWEEN :since AND :until",
      ExpressionAttributeValues: {
        ":pk": this.startupPartitionKey,
        ":since": `started#${since}`,
        ":until": `started#${startedAt}#~`,
      },
      ConsistentRead: true,
    })) as { Items?: unknown[] };
    const count = response.Items?.filter((item) => {
      return typeof item === "object" && item !== null && (item as { version?: unknown }).version === this.config.coordination.version;
    }).length ?? 1;
    return { count, durable: true, loopDetected: count >= 3, windowMinutes, startedAt };
  }

  async recentStoppedTask(windowMinutes = 15): Promise<StoppedTaskSnapshot | undefined> {
    if (!this.ecs || !this.config.coordination.ecsClusterName || !this.config.coordination.ecsServiceName) return undefined;
    const listed = await this.ecs.send(new ListTasksCommand({
      cluster: this.config.coordination.ecsClusterName,
      serviceName: this.config.coordination.ecsServiceName,
      desiredStatus: "STOPPED",
      maxResults: 20,
    })) as { taskArns?: string[] };
    if (!listed.taskArns?.length) return undefined;
    const described = await this.ecs.send(new DescribeTasksCommand({
      cluster: this.config.coordination.ecsClusterName,
      tasks: listed.taskArns.slice(0, 20),
    })) as { tasks?: Array<Record<string, unknown>> };
    const cutoff = this.now().getTime() - (windowMinutes * 60_000);
    const task = described.tasks
      ?.filter((item) => item.stoppedAt instanceof Date && item.stoppedAt.getTime() >= cutoff)
      .sort((left, right) => ((right.stoppedAt as Date).getTime() - (left.stoppedAt as Date).getTime()))[0];
    if (!task) return undefined;
    const containers = Array.isArray(task.containers) ? task.containers as Array<Record<string, unknown>> : [];
    const companion = containers.find((container) => container.name === this.config.coordination.ecsServiceName)
      ?? containers.find((container) => typeof container.exitCode === "number")
      ?? containers[0];
    return {
      taskArn: typeof task.taskArn === "string" ? task.taskArn : undefined,
      stoppedAt: task.stoppedAt instanceof Date ? task.stoppedAt.toISOString() : undefined,
      stopCode: typeof task.stopCode === "string" ? task.stopCode : undefined,
      stoppedReason: typeof task.stoppedReason === "string" ? task.stoppedReason : undefined,
      containerReason: typeof companion?.reason === "string" ? companion.reason : undefined,
      exitCode: typeof companion?.exitCode === "number" ? companion.exitCode : undefined,
    };
  }

  private async claimDurableKey(input: {
    eventKey: string;
    kind: string;
    channelId?: string;
    ts?: string;
    eventId?: string;
    teamId?: string;
    ttlSeconds: number;
    checkDeploymentFence: boolean;
  }): Promise<SlackEventClaimResult> {
    if (!this.localEvents.add(input.eventKey)) {
      return { claimed: false, reason: "local_duplicate", eventKey: input.eventKey };
    }

    if (input.checkDeploymentFence) {
      const deployment = await this.isCurrentTask();
      if (!deployment.current) {
        return { claimed: false, reason: "stale_deployment", eventKey: input.eventKey, detail: deployment.detail };
      }
    }

    if (!this.dynamo || !this.config.learning.tableName) {
      return { claimed: true, reason: "claimed_local", eventKey: input.eventKey };
    }

    try {
      const now = this.now();
      await this.dynamo.send(new PutCommand({
        TableName: this.config.learning.tableName,
        Item: {
          pk: this.partitionKey,
          sk: `event#${input.eventKey}`,
          kind: cleanKeyPart(input.kind, 80),
          channelId: input.channelId,
          ts: input.ts,
          eventId: input.eventId,
          teamId: input.teamId,
          companionVersion: this.config.coordination.version,
          claimedAt: now.toISOString(),
          expires_at: Math.floor(now.getTime() / 1000) + input.ttlSeconds,
        },
        ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
      }));
      return { claimed: true, reason: "claimed", eventKey: input.eventKey };
    } catch (error) {
      if (isConditionalCheckFailed(error)) {
        return { claimed: false, reason: "durable_duplicate", eventKey: input.eventKey };
      }
      return {
        claimed: false,
        reason: "claim_store_unavailable",
        eventKey: input.eventKey,
        detail: shortError(error),
      };
    }
  }

  private async checkCurrentTask(): Promise<DeploymentCheckResult> {
    const identity = await this.taskIdentity();
    if (!identity) {
      return { current: true, reason: "metadata_unavailable" };
    }

    const service = await this.describeService();
    const primary = service?.deployments?.find((deployment) => deployment.status === "PRIMARY");
    if (!primary?.taskDefinition) {
      return { current: true, reason: "service_unavailable", ownTaskDefinitionArn: identity.taskDefinitionArn };
    }
    if (primary.taskDefinition === identity.taskDefinitionArn) {
      return {
        current: true,
        reason: "current",
        ownTaskDefinitionArn: identity.taskDefinitionArn,
        primaryTaskDefinitionArn: primary.taskDefinition,
        primaryRunningCount: primary.runningCount,
      };
    }

    const primaryRunningCount = primary.runningCount ?? 0;
    if (primaryRunningCount <= 0) {
      return {
        current: true,
        reason: "replacement_not_running",
        ownTaskDefinitionArn: identity.taskDefinitionArn,
        primaryTaskDefinitionArn: primary.taskDefinition,
        primaryRunningCount,
      };
    }

    return {
      current: false,
      reason: "stale_deployment",
      ownTaskDefinitionArn: identity.taskDefinitionArn,
      primaryTaskDefinitionArn: primary.taskDefinition,
      primaryRunningCount,
      detail: "A newer primary ECS deployment is running.",
    };
  }

  private async describeService(): Promise<{
    desiredCount?: number;
    runningCount?: number;
    pendingCount?: number;
    deployments?: Array<{
      status?: string;
      taskDefinition?: string;
      runningCount?: number;
      rolloutState?: string;
    }>;
  } | undefined> {
    if (!this.ecs || !this.config.coordination.ecsClusterName || !this.config.coordination.ecsServiceName) {
      return undefined;
    }
    const response = await this.ecs.send(new DescribeServicesCommand({
      cluster: this.config.coordination.ecsClusterName,
      services: [this.config.coordination.ecsServiceName],
    })) as {
      services?: Array<{
        desiredCount?: number;
        runningCount?: number;
        pendingCount?: number;
        deployments?: Array<{
          status?: string;
          taskDefinition?: string;
          runningCount?: number;
          rolloutState?: string;
        }>;
      }>;
    };
    return response.services?.[0];
  }

  private async taskIdentity(): Promise<TaskIdentity | undefined> {
    if (this.taskIdentityProvider) {
      return this.taskIdentityProvider();
    }
    this.taskIdentityPromise ??= taskIdentityFromMetadata();
    return this.taskIdentityPromise;
  }

  private botHandoffPolicy(input: SlackBotHandoffInput, senderIds: string[]): BotHandoffPolicyMatch | undefined {
    const channelPolicy = input.channelId
      ? this.config.slack.assistantBotHandoffPolicies.find((policy) =>
        policy.channelId === input.channelId && senderIds.some((candidate) => hasCaseInsensitive(policy.botUserIds, candidate)))
      : undefined;
    const channelSenderId = channelPolicy
      ? senderIds.find((candidate) => hasCaseInsensitive(channelPolicy.botUserIds, candidate))
      : undefined;
    if (channelPolicy && channelSenderId) {
      return {
        senderId: senderIds[0]!,
        allowedSenderId: channelSenderId,
        scope: "channel",
        cooldownSeconds: Math.max(0, channelPolicy.cooldownSeconds ?? this.config.slack.assistantBotCooldownSeconds),
        maxHandoffsPerThread: Math.max(0, channelPolicy.maxHandoffsPerThread ?? this.config.slack.assistantBotMaxHandoffsPerThread),
        windowSeconds: Math.max(1, channelPolicy.windowSeconds ?? this.config.slack.assistantBotHandoffWindowSeconds),
      };
    }

    const globalSenderId = senderIds.find((candidate) => hasCaseInsensitive(this.config.slack.assistantBotUserIds, candidate));
    if (!globalSenderId) return undefined;
    return {
      senderId: senderIds[0]!,
      allowedSenderId: globalSenderId,
      scope: "global",
      cooldownSeconds: Math.max(0, this.config.slack.assistantBotCooldownSeconds),
      maxHandoffsPerThread: Math.max(0, this.config.slack.assistantBotMaxHandoffsPerThread),
      windowSeconds: Math.max(1, this.config.slack.assistantBotHandoffWindowSeconds),
    };
  }

  private recordBotHandoff(input: SlackBotHandoffInput, result: SlackBotHandoffResult): SlackBotHandoffResult {
    telemetryEvent("slack.bot_handoff.decision", {
      component: "slack-events",
      operation: "bot_handoff",
      "slack.bot_handoff.accepted": result.accepted,
      "slack.bot_handoff.reason": result.reason,
      "slack.bot_handoff.policy_scope": result.policyScope ?? "",
      "slack.bot_handoff.count": result.handoffCount ?? 0,
      "slack.bot_handoff.max_per_thread": result.maxHandoffsPerThread ?? 0,
      "slack.channel_hash": input.channelId ? hashTelemetryId(input.channelId) : "",
      "slack.thread_hash": input.threadTs || input.ts ? hashTelemetryId(input.threadTs ?? input.ts ?? "") : "",
      "slack.sender_hash": result.senderId ? hashTelemetryId(result.senderId) : "",
    });
    recordMetric("cerebro_slack_companion_bot_handoff_total", {
      accepted: result.accepted,
      reason: result.reason,
      scope: result.policyScope ?? "none",
    }, 1);
    return result;
  }
}

class RecentEventSet {
  private readonly items: string[] = [];
  private readonly values = new Set<string>();

  constructor(private readonly maxSize: number) {}

  add(value: string): boolean {
    if (this.values.has(value)) return false;
    this.values.add(value);
    this.items.push(value);
    while (this.items.length > this.maxSize) {
      const next = this.items.shift();
      if (next) this.values.delete(next);
    }
    return true;
  }
}

async function taskIdentityFromMetadata(): Promise<TaskIdentity | undefined> {
  const uri = process.env.ECS_CONTAINER_METADATA_URI_V4;
  if (!uri) return undefined;

  const response = await fetch(`${uri}/task`, { signal: AbortSignal.timeout(1_000) });
  if (!response.ok) {
    throw new Error(`ECS task metadata returned ${response.status}`);
  }
  const body = await response.json() as Record<string, unknown>;
  return taskIdentityFromMetadataBody(body);
}

function taskIdentityFromMetadataBody(body: Record<string, unknown>): TaskIdentity | undefined {
  const taskArn = typeof body.TaskARN === "string" ? body.TaskARN : undefined;
  const family = typeof body.Family === "string" ? body.Family : undefined;
  const revision = typeof body.Revision === "string" || typeof body.Revision === "number" ? String(body.Revision) : undefined;
  if (!taskArn || !family || !revision) return undefined;

  const match = /^arn:([^:]+):ecs:([^:]+):([^:]+):task\//.exec(taskArn);
  if (!match) return undefined;
  const [, partition, region, accountId] = match;
  return {
    taskArn,
    taskDefinitionArn: `arn:${partition}:ecs:${region}:${accountId}:task-definition/${family}:${revision}`,
  };
}

function isBotAuthored(input: SlackBotHandoffInput): boolean {
  return Boolean(input.botId || input.appId || input.subtype === "bot_message");
}

function senderIdsForBotHandoff(input: SlackBotHandoffInput): string[] {
  return [input.botId, input.userId, input.appId]
    .map((value) => value?.trim())
    .filter((value): value is string => Boolean(value));
}

function pruneBotHandoffStates(states: Map<string, BotHandoffState>, staleBeforeMs: number): void {
  if (states.size <= 5_000) return;
  for (const [key, state] of states) {
    if (state.lastSeenAt < staleBeforeMs) states.delete(key);
  }
  if (states.size <= 5_000) return;
  for (const key of [...states.keys()].slice(0, 2_500)) {
    states.delete(key);
  }
}

function hasCaseInsensitive(values: Set<string>, candidate: string): boolean {
  const normalized = candidate.trim().toLowerCase();
  for (const value of values) {
    if (value.trim().toLowerCase() === normalized) return true;
  }
  return false;
}

function eventKeyFor(input: SlackEventClaimInput, tenantId: string): string | undefined {
  const uniqueId = input.eventId ?? (input.channelId && input.ts ? `${input.channelId}:${input.ts}` : input.ts);
  if (!uniqueId) return undefined;
  return [
    "v1",
    cleanKeyPart(input.kind, 80),
    cleanKeyPart(input.teamId ?? tenantId, 80),
    cleanKeyPart(uniqueId, 220),
  ].join("#");
}

function cleanKeyPart(value: string, maxLength: number): string {
  return value.replace(/[^A-Za-z0-9_.:-]+/g, "_").slice(0, maxLength);
}

function releaseNoticeKey(channelId: string, state: string): string {
  return `${cleanKeyPart(channelId, 60)}:${cleanKeyPart(state, 50)}`;
}

function isConditionalCheckFailed(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { name?: string }).name === "ConditionalCheckFailedException";
}

function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/\s+/g, " ").slice(0, 240);
}
