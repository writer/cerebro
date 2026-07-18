import { randomUUID } from "node:crypto";
import type { AppConfig } from "../config/index.js";
import { logger } from "../logger.js";
import { captureTelemetryError, telemetryEvent } from "../telemetry.js";
import { redactSecurityText } from "../security/redaction.js";
import { DynamoA2AFleetStore, type A2AFleetStore } from "./store.js";
import type { A2AAgentCard, A2AInstance, A2AMessage, A2AMessageHandler, A2AMessageKind, A2APart, A2AShutdownResult, A2AWorkHandoff } from "./types.js";

interface A2AFleetOptions {
  store?: A2AFleetStore;
  now?: () => Date;
  sleep?: (milliseconds: number) => Promise<void>;
  onMessage?: A2AMessageHandler;
}

interface PendingRequest {
  expectedSender: string;
  contextId: string;
  isTerminal: (message: A2AMessage) => boolean;
  onProgress?: (message: A2AMessage) => Promise<void> | void;
  resolve: (message: A2AMessage | undefined) => void;
  timeout: NodeJS.Timeout;
}

export class A2AFleetService {
  private readonly store?: A2AFleetStore;
  private readonly now: () => Date;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private onMessage?: A2AMessageHandler;
  private readonly pendingRequests = new Map<string, PendingRequest>();
  private readonly startedAt: string;
  private state: A2AInstance["state"] = "active";
  private heartbeatTimer?: NodeJS.Timeout;
  private inboxTimer?: NodeJS.Timeout;
  private inboxRunning = false;

  constructor(private readonly config: AppConfig, options: A2AFleetOptions = {}) {
    this.now = options.now ?? (() => new Date());
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.onMessage = options.onMessage;
    this.startedAt = this.now().toISOString();
    if (config.a2a.enabled && config.learning.tableName) {
      this.store = options.store ?? new DynamoA2AFleetStore(config.learning.tableName, config.cerebro.tenantId);
    }
  }

  async start(): Promise<void> {
    if (!this.store || this.heartbeatTimer) return;
    await this.register("active");
    this.heartbeatTimer = setInterval(() => {
      void this.register(this.state).catch((error) => this.recordFailure("heartbeat", error));
    }, this.config.a2a.heartbeatIntervalMs);
    this.heartbeatTimer.unref?.();
    this.inboxTimer = setInterval(() => {
      void this.pollInbox().catch((error) => this.recordFailure("inbox_poll", error));
    }, this.config.a2a.inboxPollIntervalMs);
    this.inboxTimer.unref?.();
    void this.pollInbox().catch((error) => this.recordFailure("initial_inbox_poll", error));
    telemetryEvent("companion.a2a.started", this.telemetryFields());
  }

  async listInstances(): Promise<A2AInstance[]> {
    if (!this.store) return [this.instance(this.state)];
    const instances = await this.store.listInstances(this.nowEpochSeconds());
    return instances.sort((left, right) => right.heartbeatAt.localeCompare(left.heartbeatAt));
  }

  setMessageHandler(handler: A2AMessageHandler): void {
    this.onMessage = handler;
  }

  async send(input: {
    to: string;
    kind: A2AMessageKind;
    contextId?: string;
    taskId?: string;
    parts: A2APart[];
    ttlSeconds?: number;
  }): Promise<A2AMessage> {
    if (!this.store) throw new Error("A2A fleet messaging is not configured.");
    const now = this.now();
    const parts = sanitizeParts(input.parts);
    if (Buffer.byteLength(JSON.stringify(parts), "utf8") > 32_000) {
      throw new Error("A2A message parts exceed the 32 KB mailbox limit.");
    }
    const message: A2AMessage = {
      messageId: randomUUID(),
      contextId: cleanText(input.contextId || randomUUID(), 160),
      taskId: input.taskId ? cleanText(input.taskId, 160) : undefined,
      kind: input.kind,
      from: this.config.a2a.instanceId,
      to: cleanText(input.to, 160),
      parts,
      createdAt: now.toISOString(),
      expiresAt: Math.floor(now.getTime() / 1000) + Math.min(Math.max(input.ttlSeconds ?? 300, 30), 3_600),
    };
    await this.store.putMessage(message);
    telemetryEvent("companion.a2a.message_sent", {
      ...this.telemetryFields(),
      "a2a.message.kind": message.kind,
      "a2a.recipient": message.to,
    });
    return message;
  }

  async request(input: {
    to: string;
    contextId?: string;
    parts: A2APart[];
    timeoutMs: number;
    ttlSeconds?: number;
    isTerminal?: (message: A2AMessage) => boolean;
    onProgress?: (message: A2AMessage) => Promise<void> | void;
  }): Promise<A2AMessage | undefined> {
    if (!this.store) return undefined;
    const taskId = randomUUID();
    const contextId = cleanText(input.contextId || randomUUID(), 160);
    const timeoutMs = Math.min(Math.max(Math.floor(input.timeoutMs), 250), 120_000);
    return new Promise<A2AMessage | undefined>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(taskId);
        resolve(undefined);
      }, timeoutMs);
      this.pendingRequests.set(taskId, {
        expectedSender: cleanText(input.to, 160),
        contextId,
        isTerminal: input.isTerminal ?? (() => true),
        onProgress: input.onProgress,
        resolve,
        timeout,
      });
      void this.send({
        to: input.to,
        kind: "task",
        contextId,
        taskId,
        parts: input.parts,
        ttlSeconds: input.ttlSeconds,
      }).catch((error) => {
        clearTimeout(timeout);
        this.pendingRequests.delete(taskId);
        reject(error);
      });
    });
  }

  async drain(signal: string, goalIds: string[], workPackets: A2AWorkHandoff[] = []): Promise<A2AShutdownResult> {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = undefined;
    this.state = "draining";
    if (!this.store) return { state: "disabled", goalIds: [], workPacketIds: [] };

    await this.register("draining");
    const boundedGoalIds = [...new Set(goalIds.map((id) => cleanText(id, 160)).filter(Boolean))].slice(0, 50);
    const boundedWorkPackets = boundWorkHandoffs(workPackets);
    const boundedWorkPacketIds = [...new Set(workPackets.map((item) => cleanText(item.packet_id, 160)).filter(Boolean))].slice(0, 50);
    const peer = await this.selectHandoffPeer(boundedGoalIds.length > 0, boundedWorkPackets.length > 0);
    if (!peer) {
      await this.markStopped();
      return { state: "no_peer", goalIds: boundedGoalIds, workPacketIds: boundedWorkPacketIds };
    }

    const message = await this.send({
      to: peer.instanceId,
      kind: "handoff",
      contextId: `shutdown:${this.config.a2a.instanceId}`,
      parts: [{
        kind: "data",
        data: {
          signal: cleanText(signal, 40),
          source: {
            instance_id: this.config.a2a.instanceId,
            label: this.config.a2a.label,
            role: this.config.a2a.role,
            commit: this.config.coordination.version,
          },
          active_goal_ids: boundedGoalIds,
          active_work_packet_ids: boundedWorkPacketIds,
          active_work_packets: boundedWorkPackets,
          instruction: "Resume shared active goals after their current lease expires. Reassign unfinished work packets from the original coordinator.",
        },
      }],
      ttlSeconds: 300,
    });
    const acknowledged = await this.waitForAcknowledgement(peer.instanceId, message, this.config.a2a.drainTimeoutMs);
    await this.markStopped();
    const result: A2AShutdownResult = {
      state: acknowledged ? "acknowledged" : "timed_out",
      peerId: peer.instanceId,
      messageId: message.messageId,
      goalIds: boundedGoalIds,
      workPacketIds: boundedWorkPacketIds,
    };
    telemetryEvent("companion.a2a.shutdown_handoff", {
      ...this.telemetryFields(),
      "a2a.handoff.state": result.state,
      "a2a.handoff.peer": peer.instanceId,
      "a2a.handoff.goal_count": boundedGoalIds.length,
      "a2a.handoff.work_packet_count": boundedWorkPacketIds.length,
    });
    return result;
  }

  stop(): void {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    if (this.inboxTimer) clearInterval(this.inboxTimer);
    this.heartbeatTimer = undefined;
    this.inboxTimer = undefined;
    for (const [taskId, pending] of this.pendingRequests) {
      clearTimeout(pending.timeout);
      pending.resolve(undefined);
      this.pendingRequests.delete(taskId);
    }
  }

  agentCard(): A2AAgentCard {
    return {
      protocolVersion: "0.3.0",
      name: `Cerebro ${this.config.a2a.label}`,
      description: `${this.config.a2a.role} Cerebro instance ${this.config.a2a.instanceId}`,
      version: this.config.coordination.version,
      capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: true },
      skills: this.config.a2a.capabilities.map((capability) => ({
        id: capability,
        name: capability,
        description: `Handles ${capability} work.`,
        tags: [this.config.a2a.role, capability],
      })),
    };
  }

  private async pollInbox(): Promise<void> {
    if (!this.store || this.inboxRunning || this.state === "stopped") return;
    this.inboxRunning = true;
    try {
      const messages = await this.store.listInbox(this.config.a2a.instanceId, this.nowEpochSeconds());
      for (const message of messages) {
        const processedAt = this.now().toISOString();
        if (!await this.store.claimMessage(this.config.a2a.instanceId, message, processedAt)) continue;
        try {
          if (message.kind === "status" && await this.resolvePendingRequest(message)) {
            // Correlated replies are consumed by the waiting request.
          } else {
            const response = await this.onMessage?.(message);
            if (message.kind === "task" && message.taskId && response?.length) {
              await this.send({
                to: message.from,
                kind: "status",
                contextId: message.contextId,
                taskId: message.taskId,
                parts: response,
                ttlSeconds: Math.max(30, message.expiresAt - this.nowEpochSeconds()),
              });
            }
          }
          await this.store.acknowledgeMessage(this.config.a2a.instanceId, message, this.now().toISOString());
          telemetryEvent("companion.a2a.message_acknowledged", {
            ...this.telemetryFields(),
            "a2a.message.kind": message.kind,
            "a2a.sender": message.from,
          });
        } catch (error) {
          this.recordFailure("message_handler", error);
          await this.store.releaseMessage(this.config.a2a.instanceId, message, processedAt)
            .catch((releaseError) => this.recordFailure("message_release", releaseError));
        }
      }
    } finally {
      this.inboxRunning = false;
    }
  }

  private async resolvePendingRequest(message: A2AMessage): Promise<boolean> {
    if (!message.taskId) return false;
    const pending = this.pendingRequests.get(message.taskId);
    if (!pending || pending.expectedSender !== message.from || pending.contextId !== message.contextId) return false;
    if (!pending.isTerminal(message)) {
      await pending.onProgress?.(message);
      return true;
    }
    clearTimeout(pending.timeout);
    this.pendingRequests.delete(message.taskId);
    pending.resolve(message);
    return true;
  }

  private async selectHandoffPeer(needsGoals: boolean, needsResearch: boolean): Promise<A2AInstance | undefined> {
    const peers = (await this.listInstances()).filter((instance) =>
      instance.instanceId !== this.config.a2a.instanceId
      && instance.state === "active"
      && (!needsGoals || instance.capabilities.includes("goals"))
      && (!needsResearch || instance.capabilities.includes("research")));
    return peers.sort((left, right) => {
      const leftRole = left.role === this.config.a2a.role ? 1 : 0;
      const rightRole = right.role === this.config.a2a.role ? 1 : 0;
      return rightRole - leftRole || right.heartbeatAt.localeCompare(left.heartbeatAt);
    })[0];
  }

  private async waitForAcknowledgement(recipientId: string, message: A2AMessage, timeoutMs: number): Promise<boolean> {
    if (!this.store) return false;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const current = await this.store.getMessage(recipientId, message);
      if (current?.acknowledgedAt) return true;
      await this.sleep(Math.min(200, Math.max(1, deadline - Date.now())));
    }
    return false;
  }

  private async register(state: A2AInstance["state"]): Promise<void> {
    if (!this.store) return;
    await this.store.putInstance(this.instance(state));
  }

  private async markStopped(): Promise<void> {
    this.state = "stopped";
    await this.register("stopped");
    this.stop();
  }

  private instance(state: A2AInstance["state"]): A2AInstance {
    const now = this.now();
    return {
      instanceId: this.config.a2a.instanceId,
      label: this.config.a2a.label,
      role: this.config.a2a.role,
      commit: this.config.coordination.version,
      commitSubject: this.config.coordination.commitSubject,
      capabilities: [...this.config.a2a.capabilities],
      state,
      startedAt: this.startedAt,
      heartbeatAt: now.toISOString(),
      expiresAt: Math.floor(now.getTime() / 1000) + (state === "stopped" ? 3_600 : this.config.a2a.instanceTtlSeconds),
    };
  }

  private nowEpochSeconds(): number {
    return Math.floor(this.now().getTime() / 1000);
  }

  private telemetryFields(): Record<string, string> {
    return {
      component: "a2a",
      operation: "fleet",
      "a2a.instance_id": this.config.a2a.instanceId,
      "a2a.label": this.config.a2a.label,
      "a2a.role": this.config.a2a.role,
      "a2a.commit": this.config.coordination.version,
    };
  }

  private recordFailure(operation: string, error: unknown): void {
    captureTelemetryError("companion.a2a.error", error, { ...this.telemetryFields(), operation });
    logger.warn("A2A fleet operation failed", { operation, error: String(error), instanceId: this.config.a2a.instanceId });
  }
}

function sanitizeParts(parts: A2APart[]): A2APart[] {
  return parts.slice(0, 12).map((part) => part.kind === "text"
    ? { kind: "text", text: cleanText(part.text ?? "", 4_000) }
    : { kind: "data", data: sanitizeData(part.data ?? {}) });
}

function boundWorkHandoffs(items: A2AWorkHandoff[]): A2AWorkHandoff[] {
  const result: A2AWorkHandoff[] = [];
  for (const item of items.slice(0, 8)) {
    const candidate = [...result, item];
    if (Buffer.byteLength(JSON.stringify(candidate), "utf8") > 20_000) break;
    result.push(item);
  }
  return result;
}

function sanitizeData(data: Record<string, unknown>): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data).slice(0, 50)) {
    if (/token|secret|password|credential|private.?key/i.test(key)) {
      output[key] = "[redacted]";
      continue;
    }
    output[key] = sanitizeValue(value, 0);
  }
  return output;
}

function sanitizeValue(value: unknown, depth: number): unknown {
  if (depth >= 8) return "[truncated]";
  if (typeof value === "string") return cleanText(value, 2_000);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => sanitizeValue(item, depth + 1));
  if (!value || typeof value !== "object") return undefined;
  const output: Record<string, unknown> = {};
  for (const [key, nested] of Object.entries(value).slice(0, 50)) {
    output[key] = /token|secret|password|credential|private.?key/i.test(key)
      ? "[redacted]"
      : sanitizeValue(nested, depth + 1);
  }
  return output;
}

function cleanText(value: string, maxLength: number): string {
  return redactSecurityText(value).replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, maxLength);
}
