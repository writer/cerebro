import { createHash } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import type { AppConfig, ProactiveSlackChannelPolicy } from "../config/index.js";
import { redactSecurityText } from "../security/redaction.js";
import type { SlackDeliveryReceiptContext } from "../slack/delivery-outbox-store.js";
import { trimForSlack } from "../slack/format.js";
import type { TriageClassification, TriageTopic } from "./alert-triage-types.js";

export type ProactiveTriageOutcome = "observed" | "drafted" | "posted" | "suggested" | "suppressed" | "blocked";
export type ProactiveMonitorSuggestionStatus = "pending" | "accepted" | "dismissed";
export type ProactiveSuggestionStatus = "pending" | "accepted" | "dismissed";
export type AssistantInitiativeThreadStatus = "open" | "closed";
export type AssistantInitiativeCloseReason = "completed" | "cancelled" | "expired";

export interface AssistantInitiativeThreadBinding {
  initiativeId: string;
  deliveryId: string;
  channelId: string;
  threadTs: string;
  intendedUserId: string;
  status: AssistantInitiativeThreadStatus;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
  goalId?: string;
  closedAt?: string;
  closeReason?: AssistantInitiativeCloseReason;
}

export interface ProactiveTriageOutcomeRecord {
  id: string;
  channelId: string;
  threadTs: string;
  sourceTs: string;
  outcome: ProactiveTriageOutcome;
  topic?: TriageTopic;
  classification?: TriageClassification;
  confidence?: number;
  summary: string;
  reason?: string;
  research: string[];
  createdAt: string;
}

export interface ProactiveMonitorSuggestionRecord {
  id: string;
  title: string;
  description: string;
  scheduleText: string;
  dedupKey: string;
  sourceTs: string;
  status: ProactiveMonitorSuggestionStatus;
  createdAt: string;
  resolvedAt?: string;
}

export interface ProactiveSuggestionRecord {
  id: string;
  title: string;
  description: string;
  goalText: string;
  dedupKey: string;
  sourceTs: string;
  status: ProactiveSuggestionStatus;
  createdAt: string;
  resolvedAt?: string;
  goalId?: string;
}

export interface SlackThreadSessionState {
  channelId: string;
  threadTs: string;
  channelPolicy: ProactiveSlackChannelPolicy;
  createdAt: string;
  updatedAt: string;
  lastReviewedTs?: string;
  lastPostedTs?: string;
  lastContextFetchedAt?: string;
  contextMessageCount?: number;
  latestSummary?: string;
  outcomes: ProactiveTriageOutcomeRecord[];
  suggestions: ProactiveMonitorSuggestionRecord[];
  proactiveSuggestions: ProactiveSuggestionRecord[];
}

export interface SlackThreadStateStoreOptions {
  dynamo?: { send(command: unknown): Promise<unknown> };
  now?: () => Date;
}

export class SlackThreadSessionStateStore {
  private readonly dynamo?: { send(command: unknown): Promise<unknown> };
  private readonly now: () => Date;
  private readonly memory = new Map<string, SlackThreadSessionState>();
  private readonly initiativeMemory = new Map<string, AssistantInitiativeThreadBinding>();

  constructor(
    private readonly config: AppConfig,
    options: SlackThreadStateStoreOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    if (config.triage.enabled && config.triage.threadStateTableName) {
      this.dynamo = options.dynamo ?? DynamoDBDocumentClient.from(new DynamoDBClient({}));
    }
  }

  async get(channelId: string, threadTs: string): Promise<SlackThreadSessionState | undefined> {
    const key = stateKey(channelId, threadTs);
    if (this.dynamo && this.config.triage.threadStateTableName) {
      const response = await this.dynamo.send(new QueryCommand({
        TableName: this.config.triage.threadStateTableName,
        KeyConditionExpression: "pk = :pk AND sk = :sk",
        ExpressionAttributeValues: {
          ":pk": partitionKey(this.config),
          ":sk": `thread#${key}`,
        },
        Limit: 1,
      })) as { Items?: Record<string, unknown>[] };
      return toThreadState(response.Items?.[0]);
    }
    return cloneState(this.memory.get(key));
  }

  async getOrCreate(input: {
    channelId: string;
    threadTs: string;
    channelPolicy: ProactiveSlackChannelPolicy;
  }): Promise<SlackThreadSessionState> {
    const existing = await this.get(input.channelId, input.threadTs);
    if (existing) {
      if (existing.channelPolicy !== input.channelPolicy) {
        const updated = { ...existing, channelPolicy: input.channelPolicy, updatedAt: this.now().toISOString() };
        await this.put(updated);
        return updated;
      }
      return existing;
    }
    const now = this.now().toISOString();
    const state: SlackThreadSessionState = {
      channelId: cleanId(input.channelId),
      threadTs: cleanId(input.threadTs),
      channelPolicy: input.channelPolicy,
      createdAt: now,
      updatedAt: now,
      outcomes: [],
      suggestions: [],
      proactiveSuggestions: [],
    };
    await this.put(state);
    return state;
  }

  async markContextFetched(input: {
    channelId: string;
    threadTs: string;
    channelPolicy: ProactiveSlackChannelPolicy;
    messageCount: number;
  }): Promise<SlackThreadSessionState> {
    const current = await this.getOrCreate(input);
    const updated: SlackThreadSessionState = {
      ...current,
      lastContextFetchedAt: this.now().toISOString(),
      contextMessageCount: Math.max(0, Math.min(50, Math.floor(input.messageCount))),
      updatedAt: this.now().toISOString(),
    };
    await this.put(updated);
    return updated;
  }

  async recordOutcome(input: {
    channelId: string;
    threadTs: string;
    sourceTs: string;
    channelPolicy: ProactiveSlackChannelPolicy;
    outcome: ProactiveTriageOutcome;
    topic?: TriageTopic;
    classification?: TriageClassification;
    confidence?: number;
    summary: string;
    reason?: string;
    research?: string[];
  }): Promise<SlackThreadSessionState> {
    const current = await this.getOrCreate(input);
    const now = this.now().toISOString();
    const record: ProactiveTriageOutcomeRecord = {
      id: stableId(["outcome", input.channelId, input.threadTs, input.sourceTs, input.outcome]),
      channelId: cleanId(input.channelId),
      threadTs: cleanId(input.threadTs),
      sourceTs: cleanId(input.sourceTs),
      outcome: input.outcome,
      topic: input.topic,
      classification: input.classification,
      confidence: typeof input.confidence === "number" ? Math.max(0, Math.min(1, input.confidence)) : undefined,
      summary: cleanText(input.summary, 420),
      reason: input.reason ? cleanText(input.reason, 420) : undefined,
      research: (input.research ?? []).map((item) => cleanText(item, 160)).filter(Boolean).slice(0, 8),
      createdAt: now,
    };
    const outcomes = [record, ...current.outcomes.filter((item) => item.id !== record.id)].slice(0, 20);
    const updated: SlackThreadSessionState = {
      ...current,
      channelPolicy: input.channelPolicy,
      updatedAt: now,
      lastReviewedTs: cleanId(input.sourceTs),
      lastPostedTs: input.outcome === "posted" || input.outcome === "suggested" ? cleanId(input.sourceTs) : current.lastPostedTs,
      latestSummary: record.summary || current.latestSummary,
      outcomes,
    };
    await this.put(updated);
    return updated;
  }

  async addSuggestion(input: {
    channelId: string;
    threadTs: string;
    channelPolicy: ProactiveSlackChannelPolicy;
    title: string;
    description: string;
    scheduleText: string;
    dedupKey: string;
    sourceTs: string;
  }): Promise<{ state: SlackThreadSessionState; suggestion?: ProactiveMonitorSuggestionRecord; existing?: ProactiveMonitorSuggestionRecord }> {
    const current = await this.getOrCreate(input);
    const dedupKey = cleanText(input.dedupKey, 160);
    const existing = current.suggestions.find((suggestion) => suggestion.dedupKey === dedupKey);
    if (existing) return { state: current, existing };
    const now = this.now().toISOString();
    const suggestion: ProactiveMonitorSuggestionRecord = {
      id: stableId(["suggestion", input.channelId, input.threadTs, dedupKey]).slice(0, 16),
      title: cleanText(input.title, 100),
      description: cleanText(input.description, 320),
      scheduleText: cleanText(input.scheduleText, 800),
      dedupKey,
      sourceTs: cleanId(input.sourceTs),
      status: "pending",
      createdAt: now,
    };
    const updated: SlackThreadSessionState = {
      ...current,
      updatedAt: now,
      suggestions: [suggestion, ...current.suggestions].slice(0, 8),
    };
    await this.put(updated);
    return { state: updated, suggestion };
  }

  async resolveSuggestion(input: {
    channelId: string;
    threadTs: string;
    suggestionId: string;
    status: "accepted" | "dismissed";
  }): Promise<{ state: SlackThreadSessionState; suggestion?: ProactiveMonitorSuggestionRecord }> {
    const current = await this.get(input.channelId, input.threadTs);
    if (!current) throw new Error("Thread session state was not found.");
    const now = this.now().toISOString();
    let resolved: ProactiveMonitorSuggestionRecord | undefined;
    const suggestions = current.suggestions.map((suggestion) => {
      if (suggestion.id !== input.suggestionId) return suggestion;
      resolved = { ...suggestion, status: input.status, resolvedAt: now };
      return resolved;
    });
    if (!resolved) throw new Error("Monitor suggestion was not found.");
    const updated = { ...current, suggestions, updatedAt: now };
    await this.put(updated);
    return { state: updated, suggestion: resolved };
  }

  async addProactiveSuggestion(input: {
    channelId: string;
    threadTs: string;
    channelPolicy: ProactiveSlackChannelPolicy;
    title: string;
    description: string;
    goalText: string;
    dedupKey: string;
    sourceTs: string;
  }): Promise<{ state: SlackThreadSessionState; suggestion?: ProactiveSuggestionRecord; existing?: ProactiveSuggestionRecord }> {
    const current = await this.getOrCreate(input);
    const dedupKey = cleanText(input.dedupKey, 180);
    const existing = current.proactiveSuggestions.find((suggestion) => suggestion.dedupKey === dedupKey);
    if (existing) return { state: current, existing };
    const now = this.now().toISOString();
    const suggestion: ProactiveSuggestionRecord = {
      id: stableId(["proactive-suggestion", input.channelId, input.threadTs, dedupKey]).slice(0, 16),
      title: cleanText(input.title, 100),
      description: cleanText(input.description, 320),
      goalText: cleanText(input.goalText, 1200),
      dedupKey,
      sourceTs: cleanId(input.sourceTs),
      status: "pending",
      createdAt: now,
    };
    const updated: SlackThreadSessionState = {
      ...current,
      updatedAt: now,
      proactiveSuggestions: [suggestion, ...current.proactiveSuggestions].slice(0, 8),
    };
    await this.put(updated);
    return { state: updated, suggestion };
  }

  async resolveProactiveSuggestion(input: {
    channelId: string;
    threadTs: string;
    suggestionId: string;
    status: "accepted" | "dismissed";
    goalId?: string;
  }): Promise<{ state: SlackThreadSessionState; suggestion?: ProactiveSuggestionRecord }> {
    const current = await this.get(input.channelId, input.threadTs);
    if (!current) throw new Error("Thread session state was not found.");
    const now = this.now().toISOString();
    let resolved: ProactiveSuggestionRecord | undefined;
    const proactiveSuggestions = current.proactiveSuggestions.map((suggestion) => {
      if (suggestion.id !== input.suggestionId) return suggestion;
      resolved = { ...suggestion, status: input.status, resolvedAt: now, goalId: input.goalId };
      return resolved;
    });
    if (!resolved) throw new Error("Proactive suggestion was not found.");
    const updated = { ...current, proactiveSuggestions, updatedAt: now };
    await this.put(updated);
    return { state: updated, suggestion: resolved };
  }

  async bindAssistantInitiativeReceipt(input: {
    deliveryId: string;
    channelId: string;
    threadTs: string;
    receiptContext?: SlackDeliveryReceiptContext;
  }): Promise<AssistantInitiativeThreadBinding | undefined> {
    if (!input.receiptContext || input.receiptContext.kind !== "assistant_initiative") return undefined;
    if (!input.receiptContext.assistantInitiative) {
      throw new Error("Assistant initiative receipt context is missing its intended user.");
    }
    const now = this.now();
    const binding: AssistantInitiativeThreadBinding = {
      initiativeId: requiredBindingText(input.receiptContext.refId, "initiative id", 300),
      deliveryId: requiredBindingText(input.deliveryId, "delivery id", 120),
      channelId: requiredSlackChannelId(input.channelId),
      threadTs: requiredSlackTimestamp(input.threadTs),
      intendedUserId: requiredSlackUserId(input.receiptContext.assistantInitiative.intendedUserId),
      status: "open",
      expiresAt: initiativeExpiry(input.receiptContext.assistantInitiative.expiresAt, now),
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      goalId: input.receiptContext.assistantInitiative.goalId
        ? requiredBindingText(input.receiptContext.assistantInitiative.goalId, "goal id", 300)
        : undefined,
    };
    const key = initiativeStateKey(binding.channelId, binding.threadTs);
    if (this.dynamo && this.config.triage.threadStateTableName) {
      const assignments = [
        "initiativeId = if_not_exists(initiativeId, :initiativeId)",
        "deliveryId = if_not_exists(deliveryId, :deliveryId)",
        "channelId = if_not_exists(channelId, :channelId)",
        "threadTs = if_not_exists(threadTs, :threadTs)",
        "intendedUserId = if_not_exists(intendedUserId, :intendedUserId)",
        "#status = if_not_exists(#status, :open)",
        "expiresAt = if_not_exists(expiresAt, :expiresAt)",
        "createdAt = if_not_exists(createdAt, :createdAt)",
        "updatedAt = :updatedAt",
        "expires_at = if_not_exists(expires_at, :expiresAtEpoch)",
      ];
      const values: Record<string, unknown> = {
        ":initiativeId": binding.initiativeId,
        ":deliveryId": binding.deliveryId,
        ":channelId": binding.channelId,
        ":threadTs": binding.threadTs,
        ":intendedUserId": binding.intendedUserId,
        ":open": "open",
        ":expiresAt": binding.expiresAt,
        ":createdAt": binding.createdAt,
        ":updatedAt": binding.updatedAt,
        ":expiresAtEpoch": Math.floor(new Date(binding.expiresAt).getTime() / 1_000),
      };
      if (binding.goalId) {
        assignments.push("goalId = if_not_exists(goalId, :goalId)");
        values[":goalId"] = binding.goalId;
      }
      const response = await this.dynamo.send(new UpdateCommand({
        TableName: this.config.triage.threadStateTableName,
        Key: { pk: partitionKey(this.config), sk: `assistant-initiative#${key}` },
        UpdateExpression: `SET ${assignments.join(", ")}`,
        ConditionExpression: "attribute_not_exists(initiativeId) OR (initiativeId = :initiativeId AND deliveryId = :deliveryId AND channelId = :channelId AND threadTs = :threadTs AND intendedUserId = :intendedUserId)",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: values,
        ReturnValues: "ALL_NEW",
      })) as { Attributes?: Record<string, unknown> };
      const saved = toAssistantInitiativeBinding(response.Attributes);
      if (!saved) throw new Error("Assistant initiative binding write returned no record.");
      return saved;
    }
    const existing = this.initiativeMemory.get(key);
    if (existing) {
      assertSameAssistantInitiative(existing, binding);
      return cloneAssistantInitiative(existing);
    }
    this.initiativeMemory.set(key, binding);
    return cloneAssistantInitiative(binding);
  }

  async getAssistantInitiativeBinding(channelId: string, threadTs: string): Promise<AssistantInitiativeThreadBinding | undefined> {
    const key = initiativeStateKey(channelId, threadTs);
    if (this.dynamo && this.config.triage.threadStateTableName) {
      const response = await this.dynamo.send(new GetCommand({
        TableName: this.config.triage.threadStateTableName,
        Key: { pk: partitionKey(this.config), sk: `assistant-initiative#${key}` },
        ConsistentRead: true,
      })) as { Item?: Record<string, unknown> };
      return toAssistantInitiativeBinding(response.Item);
    }
    return cloneAssistantInitiative(this.initiativeMemory.get(key));
  }

  async matchAssistantInitiativeReply(input: {
    channelId: string;
    threadTs: string;
    userId: string;
  }): Promise<AssistantInitiativeThreadBinding | undefined> {
    const binding = await this.getAssistantInitiativeBinding(input.channelId, input.threadTs);
    if (!binding || binding.status !== "open") return undefined;
    if (binding.expiresAt <= this.now().toISOString()) {
      await this.closeAssistantInitiative({
        channelId: binding.channelId,
        threadTs: binding.threadTs,
        initiativeId: binding.initiativeId,
        reason: "expired",
      });
      return undefined;
    }
    return binding.intendedUserId === cleanId(input.userId) ? binding : undefined;
  }

  async closeAssistantInitiative(input: {
    channelId: string;
    threadTs: string;
    initiativeId: string;
    reason: AssistantInitiativeCloseReason;
  }): Promise<AssistantInitiativeThreadBinding | undefined> {
    const key = initiativeStateKey(input.channelId, input.threadTs);
    const initiativeId = requiredBindingText(input.initiativeId, "initiative id", 300);
    const now = this.now().toISOString();
    if (this.dynamo && this.config.triage.threadStateTableName) {
      try {
        const response = await this.dynamo.send(new UpdateCommand({
          TableName: this.config.triage.threadStateTableName,
          Key: { pk: partitionKey(this.config), sk: `assistant-initiative#${key}` },
          UpdateExpression: "SET #status = :closed, closeReason = :reason, closedAt = :now, updatedAt = :now",
          ConditionExpression: "initiativeId = :initiativeId AND #status = :open",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":initiativeId": initiativeId,
            ":open": "open",
            ":closed": "closed",
            ":reason": input.reason,
            ":now": now,
          },
          ReturnValues: "ALL_NEW",
        })) as { Attributes?: Record<string, unknown> };
        return toAssistantInitiativeBinding(response.Attributes);
      } catch (error) {
        if (!conditionalCheckFailed(error)) throw error;
        return this.getAssistantInitiativeBinding(input.channelId, input.threadTs);
      }
    }
    const current = this.initiativeMemory.get(key);
    if (!current || current.initiativeId !== initiativeId) return cloneAssistantInitiative(current);
    if (current.status === "closed") return cloneAssistantInitiative(current);
    const closed: AssistantInitiativeThreadBinding = {
      ...current,
      status: "closed",
      closeReason: input.reason,
      closedAt: now,
      updatedAt: now,
    };
    this.initiativeMemory.set(key, closed);
    return cloneAssistantInitiative(closed);
  }

  private async put(state: SlackThreadSessionState): Promise<void> {
    const normalized = normalizeState(state, this.now());
    if (this.dynamo && this.config.triage.threadStateTableName) {
      await this.dynamo.send(new PutCommand({
        TableName: this.config.triage.threadStateTableName,
        Item: {
          pk: partitionKey(this.config),
          sk: `thread#${stateKey(normalized.channelId, normalized.threadTs)}`,
          ...normalized,
        },
      }));
      return;
    }
    this.memory.set(stateKey(normalized.channelId, normalized.threadTs), normalized);
  }
}

export function slackThreadStateKey(channelId: string, threadTs: string): string {
  return stateKey(channelId, threadTs);
}

function partitionKey(config: AppConfig): string {
  return `tenant#${config.cerebro.tenantId}#slack-thread-sessions`;
}

function stateKey(channelId: string, threadTs: string): string {
  return `${cleanId(channelId)}#${cleanId(threadTs)}`;
}

function initiativeStateKey(channelId: string, threadTs: string): string {
  return `${requiredSlackChannelId(channelId)}#${requiredSlackTimestamp(threadTs)}`;
}

function normalizeState(state: SlackThreadSessionState, now: Date): SlackThreadSessionState {
  return {
    channelId: cleanId(state.channelId),
    threadTs: cleanId(state.threadTs),
    channelPolicy: isPolicy(state.channelPolicy) ? state.channelPolicy : "watch",
    createdAt: state.createdAt || now.toISOString(),
    updatedAt: state.updatedAt || now.toISOString(),
    lastReviewedTs: state.lastReviewedTs ? cleanId(state.lastReviewedTs) : undefined,
    lastPostedTs: state.lastPostedTs ? cleanId(state.lastPostedTs) : undefined,
    lastContextFetchedAt: state.lastContextFetchedAt,
    contextMessageCount: typeof state.contextMessageCount === "number" ? Math.max(0, Math.min(50, Math.floor(state.contextMessageCount))) : undefined,
    latestSummary: state.latestSummary ? cleanText(state.latestSummary, 420) : undefined,
    outcomes: state.outcomes.slice(0, 20),
    suggestions: state.suggestions.slice(0, 8),
    proactiveSuggestions: (state.proactiveSuggestions ?? []).slice(0, 8),
  };
}

function toThreadState(item: Record<string, unknown> | undefined): SlackThreadSessionState | undefined {
  if (!item || typeof item.channelId !== "string" || typeof item.threadTs !== "string" || typeof item.createdAt !== "string" || typeof item.updatedAt !== "string") {
    return undefined;
  }
  return normalizeState({
    channelId: item.channelId,
    threadTs: item.threadTs,
    channelPolicy: isPolicy(item.channelPolicy) ? item.channelPolicy : "watch",
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    lastReviewedTs: typeof item.lastReviewedTs === "string" ? item.lastReviewedTs : undefined,
    lastPostedTs: typeof item.lastPostedTs === "string" ? item.lastPostedTs : undefined,
    lastContextFetchedAt: typeof item.lastContextFetchedAt === "string" ? item.lastContextFetchedAt : undefined,
    contextMessageCount: typeof item.contextMessageCount === "number" ? item.contextMessageCount : undefined,
    latestSummary: typeof item.latestSummary === "string" ? item.latestSummary : undefined,
    outcomes: Array.isArray(item.outcomes) ? item.outcomes.map(toOutcome).filter(Boolean) as ProactiveTriageOutcomeRecord[] : [],
    suggestions: Array.isArray(item.suggestions) ? item.suggestions.map(toSuggestion).filter(Boolean) as ProactiveMonitorSuggestionRecord[] : [],
    proactiveSuggestions: Array.isArray(item.proactiveSuggestions) ? item.proactiveSuggestions.map(toProactiveSuggestion).filter(Boolean) as ProactiveSuggestionRecord[] : [],
  }, new Date());
}

function toOutcome(value: unknown): ProactiveTriageOutcomeRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const item = value as Record<string, unknown>;
  if (typeof item.id !== "string" || typeof item.channelId !== "string" || typeof item.threadTs !== "string" || typeof item.sourceTs !== "string" || typeof item.summary !== "string" || typeof item.createdAt !== "string") return undefined;
  if (!isOutcome(item.outcome)) return undefined;
  return {
    id: item.id,
    channelId: item.channelId,
    threadTs: item.threadTs,
    sourceTs: item.sourceTs,
    outcome: item.outcome,
    topic: isTopic(item.topic) ? item.topic : undefined,
    classification: isClassification(item.classification) ? item.classification : undefined,
    confidence: typeof item.confidence === "number" ? item.confidence : undefined,
    summary: item.summary,
    reason: typeof item.reason === "string" ? item.reason : undefined,
    research: Array.isArray(item.research) ? item.research.map(String) : [],
    createdAt: item.createdAt,
  };
}

function toSuggestion(value: unknown): ProactiveMonitorSuggestionRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const item = value as Record<string, unknown>;
  if (typeof item.id !== "string" || typeof item.title !== "string" || typeof item.description !== "string" || typeof item.scheduleText !== "string" || typeof item.dedupKey !== "string" || typeof item.sourceTs !== "string" || typeof item.createdAt !== "string") return undefined;
  if (item.status !== "pending" && item.status !== "accepted" && item.status !== "dismissed") return undefined;
  return {
    id: item.id,
    title: item.title,
    description: item.description,
    scheduleText: item.scheduleText,
    dedupKey: item.dedupKey,
    sourceTs: item.sourceTs,
    status: item.status,
    createdAt: item.createdAt,
    resolvedAt: typeof item.resolvedAt === "string" ? item.resolvedAt : undefined,
  };
}

function toProactiveSuggestion(value: unknown): ProactiveSuggestionRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const item = value as Record<string, unknown>;
  if (typeof item.id !== "string" || typeof item.title !== "string" || typeof item.description !== "string" || typeof item.goalText !== "string" || typeof item.dedupKey !== "string" || typeof item.sourceTs !== "string" || typeof item.createdAt !== "string") return undefined;
  if (item.status !== "pending" && item.status !== "accepted" && item.status !== "dismissed") return undefined;
  return {
    id: item.id,
    title: item.title,
    description: item.description,
    goalText: item.goalText,
    dedupKey: item.dedupKey,
    sourceTs: item.sourceTs,
    status: item.status,
    createdAt: item.createdAt,
    resolvedAt: typeof item.resolvedAt === "string" ? item.resolvedAt : undefined,
    goalId: typeof item.goalId === "string" ? item.goalId : undefined,
  };
}

function toAssistantInitiativeBinding(item: Record<string, unknown> | undefined): AssistantInitiativeThreadBinding | undefined {
  if (
    !item
    || typeof item.initiativeId !== "string"
    || typeof item.deliveryId !== "string"
    || typeof item.channelId !== "string"
    || typeof item.threadTs !== "string"
    || typeof item.intendedUserId !== "string"
    || (item.status !== "open" && item.status !== "closed")
    || typeof item.expiresAt !== "string"
    || typeof item.createdAt !== "string"
    || typeof item.updatedAt !== "string"
  ) return undefined;
  return {
    initiativeId: item.initiativeId,
    deliveryId: item.deliveryId,
    channelId: item.channelId,
    threadTs: item.threadTs,
    intendedUserId: item.intendedUserId,
    status: item.status,
    expiresAt: item.expiresAt,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    goalId: typeof item.goalId === "string" ? item.goalId : undefined,
    closedAt: typeof item.closedAt === "string" ? item.closedAt : undefined,
    closeReason: isAssistantInitiativeCloseReason(item.closeReason) ? item.closeReason : undefined,
  };
}

function cloneAssistantInitiative(binding: AssistantInitiativeThreadBinding | undefined): AssistantInitiativeThreadBinding | undefined {
  return binding ? { ...binding } : undefined;
}

function assertSameAssistantInitiative(existing: AssistantInitiativeThreadBinding, proposed: AssistantInitiativeThreadBinding): void {
  if (
    existing.initiativeId !== proposed.initiativeId
    || existing.deliveryId !== proposed.deliveryId
    || existing.channelId !== proposed.channelId
    || existing.threadTs !== proposed.threadTs
    || existing.intendedUserId !== proposed.intendedUserId
  ) {
    throw new Error(`Assistant initiative binding conflict for ${proposed.channelId} ${proposed.threadTs}.`);
  }
}

function initiativeExpiry(value: string | undefined, now: Date): string {
  if (!value) return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1_000).toISOString();
  const expiry = new Date(requiredBindingText(value, "assistant initiative expiry", 80));
  if (!Number.isFinite(expiry.getTime())) throw new Error("Assistant initiative expiry must be an ISO-8601 timestamp.");
  return expiry.toISOString();
}

function requiredSlackChannelId(value: string): string {
  const cleaned = requiredBindingText(value, "Slack channel id", 120);
  if (!/^[CDG][A-Z0-9]+$/i.test(cleaned)) throw new Error("Assistant initiative requires a Slack channel id.");
  return cleaned;
}

function requiredSlackUserId(value: string): string {
  const cleaned = requiredBindingText(value, "Slack user id", 120);
  if (!/^[UW][A-Z0-9]+$/i.test(cleaned)) throw new Error("Assistant initiative requires a Slack user id.");
  return cleaned;
}

function requiredSlackTimestamp(value: string): string {
  const cleaned = requiredBindingText(value, "Slack thread timestamp", 80);
  if (!/^\d+\.\d+$/.test(cleaned)) throw new Error("Assistant initiative requires a Slack thread timestamp.");
  return cleaned;
}

function requiredBindingText(value: string, label: string, max: number): string {
  const cleaned = String(value ?? "").replace(/[\r\n]/g, " ").trim();
  if (!cleaned) throw new Error(`${label} is required.`);
  if (cleaned.length > max) throw new Error(`${label} exceeds ${max} characters.`);
  return cleaned;
}

function isAssistantInitiativeCloseReason(value: unknown): value is AssistantInitiativeCloseReason {
  return value === "completed" || value === "cancelled" || value === "expired";
}

function conditionalCheckFailed(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { name?: string }).name === "ConditionalCheckFailedException";
}

function cloneState(value: SlackThreadSessionState | undefined): SlackThreadSessionState | undefined {
  if (!value) return undefined;
  return {
    ...value,
    outcomes: value.outcomes.map((item) => ({ ...item, research: [...item.research] })),
    suggestions: value.suggestions.map((item) => ({ ...item })),
    proactiveSuggestions: value.proactiveSuggestions.map((item) => ({ ...item })),
  };
}

function cleanId(value: string): string {
  return String(value ?? "").replace(/[\r\n]/g, " ").trim().slice(0, 120);
}

function cleanText(value: string, max: number): string {
  return trimForSlack(redactSecurityText(String(value ?? "").replace(/\s+/g, " ").trim()), max);
}

function stableId(parts: string[]): string {
  return createHash("sha256").update(parts.join("\u0000")).digest("hex");
}

function isPolicy(value: unknown): value is ProactiveSlackChannelPolicy {
  return value === "strict" || value === "quiet" || value === "watch" || value === "eager";
}

function isOutcome(value: unknown): value is ProactiveTriageOutcome {
  return value === "observed" || value === "drafted" || value === "posted" || value === "suggested" || value === "suppressed" || value === "blocked";
}

function isClassification(value: unknown): value is TriageClassification {
  return value === "likely_security_issue" || value === "needs_context" || value === "likely_noise";
}

function isTopic(value: unknown): value is TriageTopic {
  return value === "security_alert" || value === "assistant_follow_up" || value === "operational_update" || value === "other";
}
