import { Agent, type ThinkingLevel } from "@earendil-works/pi-agent-core";
import { builtinModels } from "@earendil-works/pi-ai/providers/all";
import type { AppConfig } from "../config/index.js";
import type {
  SecurityMemoryKind,
  SecurityMemoryPromotionState,
  SecurityMemoryRecord,
  SecurityMemorySourceKind,
  SecurityMemoryStalenessPolicy,
  SecurityMemoryWriteInput,
} from "./memory-types.js";

export interface SecurityMemoryCuratorCompleteInput {
  systemPrompt: string;
  userPrompt: string;
  operation: "write" | "recall" | "hygiene";
  modelLane?: "orchestrator" | "execution";
}

export interface SecurityMemoryCuratorOptions {
  complete?: (input: SecurityMemoryCuratorCompleteInput) => Promise<string>;
}

export interface CuratedMemoryWriteDecision {
  shouldStore: boolean;
  reason: string;
  kind?: SecurityMemoryKind;
  topic?: string;
  summary?: string;
  details?: string;
  tags?: string[];
  classification?: string;
  confidence?: number;
  sourceKind?: SecurityMemorySourceKind;
  entities?: string[];
  expiresAt?: string;
  scope?: string;
  verifiedBy?: string[];
  verifiedAt?: string;
  sourceArtifacts?: string[];
  stalenessPolicy?: SecurityMemoryStalenessPolicy;
  promotionState?: SecurityMemoryPromotionState;
}

export type CuratedMemoryBatchRejectionCategory =
  | "social_chatter"
  | "transient_status"
  | "unsupported_or_speculative"
  | "no_reusable_knowledge"
  | "duplicate_only"
  | "other";

export interface CuratedMemoryWriteBatchDecision {
  reason: string;
  memories: CuratedMemoryWriteDecision[];
  rejectionCategory?: CuratedMemoryBatchRejectionCategory;
}

export interface CuratedMemoryRecallSelection {
  id: string;
  relevance: number;
  reason: string;
}

export interface CuratedMemoryRecallDecision {
  queryIntent: string;
  selections: CuratedMemoryRecallSelection[];
  rejected: Array<{ id: string; reason: string }>;
}

export interface CuratedMemoryHygieneDecision {
  expire: Array<{ id: string; reason: string }>;
  keep: Array<{ id: string; reason: string }>;
}

export class SecurityMemoryCurator {
  private readonly models = builtinModels();

  constructor(
    private readonly config: AppConfig,
    private readonly options: SecurityMemoryCuratorOptions = {},
  ) {}

  async curateWrite(input: {
    candidate: SecurityMemoryWriteInput;
    now: Date;
    recent: SecurityMemoryRecord[];
  }): Promise<CuratedMemoryWriteDecision> {
    if (input.candidate.sourceKind === "slack_channel" && !this.config.triage.pi.model.toLowerCase().includes("opus")) {
      throw new Error("Joined-channel learning requires a configured Opus model.");
    }
    const raw = await this.complete({
      operation: "write",
      modelLane: "orchestrator",
      systemPrompt: curatorSystemPrompt(),
      userPrompt: [
        "Decide whether this candidate should become memory.",
        "Return the JSON shape from the system prompt.",
        JSON.stringify({
          now: input.now.toISOString(),
          candidate: compactWriteInput(input.candidate),
          recent_memory: input.recent.map(compactRecord),
        }, null, 2),
      ].join("\n\n"),
    });
    return parseCuratedMemoryWriteDecision(raw);
  }

  async curateSlackChannelBatch(input: {
    candidate: SecurityMemoryWriteInput;
    now: Date;
    recent: SecurityMemoryRecord[];
  }): Promise<CuratedMemoryWriteBatchDecision> {
    if (input.candidate.sourceKind !== "slack_channel") {
      throw new Error("Batch memory curation only accepts Slack channel candidates.");
    }
    if (!this.config.triage.pi.model.toLowerCase().includes("opus")) {
      throw new Error("Joined-channel learning requires a configured Opus model.");
    }
    const raw = await this.complete({
      operation: "write",
      modelLane: "orchestrator",
      systemPrompt: curatorSystemPrompt(),
      userPrompt: [
        "Extract every distinct reusable operating fact supported by this passive human Slack batch.",
        "Use the slack_channel batch write decision shape from the system prompt.",
        "Return at most six memories. Keep separate facts separate; do not combine unrelated topics to force one memory.",
        JSON.stringify({
          now: input.now.toISOString(),
          candidate: compactWriteInput(input.candidate),
          recent_memory: input.recent.map(compactRecord),
        }, null, 2),
      ].join("\n\n"),
    });
    return parseCuratedMemoryWriteBatchDecision(raw);
  }

  async curateRecall(input: {
    query?: string;
    candidates: SecurityMemoryRecord[];
    limit: number;
    now: Date;
  }): Promise<CuratedMemoryRecallDecision> {
    const raw = await this.complete({
      operation: "recall",
      systemPrompt: curatorSystemPrompt(),
      userPrompt: [
        "Select only the memories that are useful context for this query.",
        "Return the JSON shape from the system prompt.",
        JSON.stringify({
          now: input.now.toISOString(),
          query: input.query ?? "",
          limit: input.limit,
          candidates: input.candidates.map(compactRecord),
        }, null, 2),
      ].join("\n\n"),
    });
    return parseCuratedMemoryRecallDecision(raw, input.limit);
  }

  async curateHygiene(input: {
    records: SecurityMemoryRecord[];
    now: Date;
  }): Promise<CuratedMemoryHygieneDecision> {
    const raw = await this.complete({
      operation: "hygiene",
      systemPrompt: curatorSystemPrompt(),
      userPrompt: [
        "Decide which memories should expire from active recall.",
        "Return the JSON shape from the system prompt.",
        JSON.stringify({
          now: input.now.toISOString(),
          records: input.records.map((record) => ({
            ...compactRecord(record),
            age_days: ageDays(record.createdAt, input.now),
          })),
        }, null, 2),
      ].join("\n\n"),
    });
    return parseCuratedMemoryHygieneDecision(raw);
  }

  private async complete(input: SecurityMemoryCuratorCompleteInput): Promise<string> {
    if (this.options.complete) return this.options.complete(input);
    if (!this.config.triage.pi.enabled) {
      throw new Error("Pi memory curator is disabled by configuration.");
    }
    const execution = input.modelLane === "execution";
    const modelName = execution ? this.config.triage.pi.executionModel : this.config.triage.pi.model;
    const thinkingLevel = execution ? this.config.triage.pi.executionThinkingLevel : this.config.triage.pi.thinkingLevel;
    const model = this.models.getModel(this.config.triage.pi.provider, modelName);
    if (!model) {
      throw new Error(`Pi model ${this.config.triage.pi.provider}/${modelName} is not available`);
    }

    const agent = new Agent({
      initialState: {
        systemPrompt: input.systemPrompt,
        model,
        thinkingLevel: thinkingLevel as ThinkingLevel,
        tools: [],
      },
      streamFn: (requestModel, context, options) => this.models.streamSimple(requestModel, context, options),
    });

    const timeout = setTimeout(() => agent.abort(), this.config.triage.timeoutMs);
    timeout.unref?.();
    try {
      await agent.prompt(input.userPrompt);
    } finally {
      clearTimeout(timeout);
    }
    if (agent.state.errorMessage) {
      throw new Error(agent.state.errorMessage);
    }
    return latestAssistantText(agent.state.messages);
  }
}

export function parseCuratedMemoryWriteDecision(raw: string): CuratedMemoryWriteDecision {
  const decoded = parseJsonObject(raw, "memory write decision");
  return parseCuratedMemoryWriteDecisionObject(decoded);
}

export function parseCuratedMemoryWriteBatchDecision(raw: string): CuratedMemoryWriteBatchDecision {
  const decoded = parseJsonObject(raw, "memory write batch decision");
  const reason = stringField(decoded, "reason", true)!;
  const memories = arrayField(decoded, "memories")
    .slice(0, 6)
    .map((value) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Pi memory curator field memories must contain objects.");
      }
      return parseCuratedMemoryWriteDecisionObject(value as Record<string, unknown>);
    })
    .filter((decision) => decision.shouldStore);
  const rejectionCategory = batchRejectionCategoryField(decoded, "rejection_category");
  if (memories.length === 0 && !rejectionCategory) {
    throw new Error("Pi memory curator field rejection_category is required when no memories are returned.");
  }
  return { reason, memories, rejectionCategory };
}

function parseCuratedMemoryWriteDecisionObject(decoded: Record<string, unknown>): CuratedMemoryWriteDecision {
  const shouldStore = booleanField(decoded, "should_store");
  const reason = stringField(decoded, "reason", true) ?? "";
  if (!shouldStore) return { shouldStore, reason };
  return {
    shouldStore,
    reason,
    kind: memoryKindField(decoded, "kind"),
    topic: stringField(decoded, "topic", true),
    summary: stringField(decoded, "summary", true),
    details: stringField(decoded, "details", false),
    tags: stringArrayField(decoded, "tags"),
    classification: stringField(decoded, "classification", false),
    confidence: numberField(decoded, "confidence", false),
    sourceKind: sourceKindField(decoded, "source_kind", false),
    entities: stringArrayField(decoded, "entities"),
    expiresAt: stringField(decoded, "expires_at", false),
    scope: stringField(decoded, "scope", false),
    verifiedBy: stringArrayField(decoded, "verified_by"),
    verifiedAt: stringField(decoded, "verified_at", false),
    sourceArtifacts: stringArrayField(decoded, "source_artifacts"),
    stalenessPolicy: stalenessPolicyField(decoded, "staleness_policy"),
    promotionState: promotionStateField(decoded, "promotion_state"),
  };
}

export function parseCuratedMemoryRecallDecision(raw: string, limit = 10): CuratedMemoryRecallDecision {
  const decoded = parseJsonObject(raw, "memory recall decision");
  const queryIntent = stringField(decoded, "query_intent", true)!;
  const selections = arrayField(decoded, "selections")
    .map((item) => item as Record<string, unknown>)
    .map((item) => ({
      id: stringField(item, "id", true)!,
      relevance: numberField(item, "relevance", true)!,
      reason: stringField(item, "reason", true)!,
    }))
    .slice(0, limit);
  const rejected = arrayField(decoded, "rejected")
    .map((item) => item as Record<string, unknown>)
    .map((item) => ({
      id: stringField(item, "id", true)!,
      reason: stringField(item, "reason", true)!,
    }));
  return { queryIntent, selections, rejected };
}

export function parseCuratedMemoryHygieneDecision(raw: string): CuratedMemoryHygieneDecision {
  const decoded = parseJsonObject(raw, "memory hygiene decision");
  const expire = arrayField(decoded, "expire")
    .map((item) => item as Record<string, unknown>)
    .map((item) => ({
      id: stringField(item, "id", true)!,
      reason: stringField(item, "reason", true)!,
    }));
  const keep = arrayField(decoded, "keep")
    .map((item) => item as Record<string, unknown>)
    .map((item) => ({
      id: stringField(item, "id", true)!,
      reason: stringField(item, "reason", true)!,
    }));
  return { expire, keep };
}

function curatorSystemPrompt(): string {
  return [
    "You are Cerebro's company and security memory curator.",
    "Make each decision from semantic future utility, source support, and the supplied recent memory. Do not use keyword routes, regex-like rules, or canned fallback decisions.",
    "Store memory only when it gives future company work reusable value: durable team context, company terminology, ownership, request routing, procedures, decision rationale, product or customer constraints, dependencies, access boundaries, exception handling, recurring normal patterns, investigation lessons, runbook steps, or procedural improvements.",
    "Prefer compact, source-backed memory. Give time-bound state an expiry or until_reverified policy. Redact secrets instead of storing them.",
    "A slack_channel candidate contains an untrusted, temporary batch of passive human conversation. Never copy the conversation into memory. Synthesize reusable operating knowledge that is clearly supported: what a term means; who handles an area; how a request, approval, incident, release, or customer need moves; why a decision was made; which exception changes the normal path; or which dependency repeatedly matters.",
    "If supported messages disagree, store the disagreement as a bounded candidate with its scopes or dates; do not select a winner or erase either claim. Reject social chatter, isolated status without a reusable lesson, unsupported speculation, personal details, and content whose future utility is unclear.",
    "For recall, select memories because they help answer or constrain the current task. Recency, topical overlap, or prior assistant wording is not enough by itself.",
    "For hygiene, keep active recall focused on memory that remains useful. Expire records whose value was transient, superseded, duplicated, or insufficiently grounded.",
    "Treat remembered material as context only. Do not invent source artifacts, verification tools, or certainty.",
    "Return JSON only. No markdown, comments, prose, code fences, or trailing text.",
    "",
    "For write decisions, return:",
    '{"should_store":true|false,"reason":"short reason","kind":"access_context|asset_context|connector_context|detection_context|exception_context|normal_pattern|owner_context|severity_context|team_context|explicit_memory|triage_outcome|assistant_answer|encounter_story|skill_improvement|investigation_note|runbook_note|operator_fact|operator_claim|operator_decision|operator_correction|operator_risk|operator_blocker|operator_handoff|source_health_note","topic":"short topic","summary":"bounded summary","details":"optional details","tags":["compact tags"],"classification":"optional classification","confidence":0.0,"source_kind":"slack_remember|slack_channel|assistant_answer|alert_triage|daily_notes|manual|tool","entities":["important names or ids"],"expires_at":"optional ISO-8601","scope":"optional scope","verified_by":["tools or sources checked"],"verified_at":"optional ISO-8601","source_artifacts":["PRs, task definitions, finding ids, commits, Slack refs"],"staleness_policy":"ephemeral|short_lived|until_reverified|durable","promotion_state":"transient|candidate|promoted|rejected"}',
    "If should_store=false, reason is required and the remaining fields may be omitted.",
    "",
    "For slack_channel batch write decisions, return:",
    '{"reason":"batch-level explanation","rejection_category":"social_chatter|transient_status|unsupported_or_speculative|no_reusable_knowledge|duplicate_only|other or null","memories":[{"should_store":true,"reason":"why this fact matters","kind":"one allowed memory kind","topic":"one distinct topic","summary":"one source-backed reusable fact","tags":["compact tags"],"classification":"passive_channel_candidate","confidence":0.0,"source_kind":"slack_channel","entities":["important names or ids"],"source_artifacts":[],"staleness_policy":"until_reverified","promotion_state":"candidate"}]}',
    "Return zero to six memories. Preserve every distinct durable fact, but do not optimize for count or turn one topic into several paraphrases. Each memory should hold one coherent fact, procedure, decision, exception, ownership rule, or dependency.",
    "Do not return knowledge already represented in recent_memory unless this batch materially refines or contradicts it. If the entire batch is already represented, return no memories with duplicate_only.",
    "Use rejection_category only when memories is empty. Never copy conversation text, personal details, or secrets.",
    "",
    "For recall decisions, return:",
    '{"query_intent":"plain language intent","selections":[{"id":"memory id","relevance":0.0,"reason":"why this helps"}],"rejected":[{"id":"memory id","reason":"why this does not help"}]}',
    "",
    "For hygiene decisions, return:",
    '{"expire":[{"id":"memory id","reason":"why active recall should stop using it"}],"keep":[{"id":"memory id","reason":"why it remains useful"}]}',
  ].join("\n");
}

function compactWriteInput(input: SecurityMemoryWriteInput): Record<string, unknown> {
  return {
    kind: input.kind,
    topic: input.topic,
    summary: input.summary,
    details: input.details,
    tags: input.tags,
    channel_id: input.channelId,
    source_ts: input.sourceTs,
    classification: input.classification,
    confidence: input.confidence,
    source_kind: input.sourceKind,
    entities: input.entities,
    expires_at: input.expiresAt,
    scope: input.scope,
    verified_by: input.verifiedBy,
    verified_at: input.verifiedAt,
    source_artifacts: input.sourceArtifacts,
    staleness_policy: input.stalenessPolicy,
    promotion_state: input.promotionState,
  };
}

function compactRecord(record: SecurityMemoryRecord): Record<string, unknown> {
  return {
    id: record.id,
    kind: record.kind,
    topic: record.topic,
    summary: record.summary,
    details: record.details,
    tags: record.tags,
    channel_id: record.channelId,
    source_ts: record.sourceTs,
    classification: record.classification,
    confidence: record.confidence,
    source_kind: record.sourceKind,
    entities: record.entities,
    expires_at: record.expiresAt,
    scope: record.scope,
    verified_by: record.verifiedBy,
    verified_at: record.verifiedAt,
    source_artifacts: record.sourceArtifacts,
    staleness_policy: record.stalenessPolicy,
    promotion_state: record.promotionState,
    created_at: record.createdAt,
  };
}

function parseJsonObject(raw: string, label: string): Record<string, unknown> {
  const text = raw.trim();
  let decoded: unknown;
  try {
    decoded = JSON.parse(text) as unknown;
  } catch {
    throw new Error(`Pi memory curator did not return valid ${label} JSON.`);
  }
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new Error(`Pi memory curator returned non-object ${label} JSON.`);
  }
  return decoded as Record<string, unknown>;
}

function booleanField(record: Record<string, unknown>, field: string): boolean {
  const value = record[field];
  if (typeof value !== "boolean") throw new Error(`Pi memory curator field ${field} must be boolean.`);
  return value;
}

function stringField(record: Record<string, unknown>, field: string, required: boolean): string | undefined {
  const value = record[field];
  if (value === undefined || value === null || value === "") {
    if (required) throw new Error(`Pi memory curator field ${field} is required.`);
    return undefined;
  }
  if (typeof value !== "string") throw new Error(`Pi memory curator field ${field} must be a string.`);
  const trimmed = value.trim();
  if (!trimmed) {
    if (required) throw new Error(`Pi memory curator field ${field} is required.`);
    return undefined;
  }
  return trimmed;
}

function numberField(record: Record<string, unknown>, field: string, required: boolean): number | undefined {
  const value = record[field];
  if (value === undefined || value === null) {
    if (required) throw new Error(`Pi memory curator field ${field} is required.`);
    return undefined;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`Pi memory curator field ${field} must be a finite number.`);
  }
  if (value < 0 || value > 1) {
    throw new Error(`Pi memory curator field ${field} must be between 0 and 1.`);
  }
  return value;
}

function arrayField(record: Record<string, unknown>, field: string): unknown[] {
  const value = record[field];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new Error(`Pi memory curator field ${field} must be an array.`);
  return value;
}

function stringArrayField(record: Record<string, unknown>, field: string): string[] | undefined {
  const values = arrayField(record, field).map((value) => {
    if (typeof value !== "string") throw new Error(`Pi memory curator field ${field} must contain strings.`);
    return value.trim();
  }).filter(Boolean);
  return values.length > 0 ? values : undefined;
}

function batchRejectionCategoryField(
  record: Record<string, unknown>,
  field: string,
): CuratedMemoryBatchRejectionCategory | undefined {
  const value = stringField(record, field, false);
  if (!value) return undefined;
  if (value === "social_chatter" || value === "transient_status" || value === "unsupported_or_speculative" || value === "no_reusable_knowledge" || value === "duplicate_only" || value === "other") {
    return value;
  }
  throw new Error(`Pi memory curator field ${field} has unknown rejection category.`);
}

function memoryKindField(record: Record<string, unknown>, field: string): SecurityMemoryKind {
  const value = stringField(record, field, true);
  if (value === "access_context" || value === "asset_context" || value === "connector_context" || value === "detection_context" || value === "exception_context" || value === "normal_pattern" || value === "owner_context" || value === "severity_context" || value === "team_context" || value === "explicit_memory" || value === "triage_outcome" || value === "assistant_answer" || value === "encounter_story" || value === "skill_improvement" || value === "investigation_note" || value === "runbook_note" || value === "operator_fact" || value === "operator_claim" || value === "operator_decision" || value === "operator_correction" || value === "operator_risk" || value === "operator_blocker" || value === "operator_handoff" || value === "source_health_note") {
    return value;
  }
  throw new Error(`Pi memory curator field ${field} has unknown memory kind.`);
}

function sourceKindField(record: Record<string, unknown>, field: string, required: boolean): SecurityMemorySourceKind | undefined {
  const value = stringField(record, field, required);
  if (!value) return undefined;
  if (value === "slack_remember" || value === "slack_channel" || value === "assistant_answer" || value === "alert_triage" || value === "daily_notes" || value === "manual" || value === "tool") {
    return value;
  }
  throw new Error(`Pi memory curator field ${field} has unknown source kind.`);
}

function promotionStateField(record: Record<string, unknown>, field: string): SecurityMemoryPromotionState {
  const value = stringField(record, field, true);
  if (value === "transient" || value === "candidate" || value === "promoted" || value === "rejected") return value;
  throw new Error(`Pi memory curator field ${field} has unknown promotion state.`);
}

function stalenessPolicyField(record: Record<string, unknown>, field: string): SecurityMemoryStalenessPolicy {
  const value = stringField(record, field, true);
  if (value === "ephemeral" || value === "short_lived" || value === "until_reverified" || value === "durable") return value;
  throw new Error(`Pi memory curator field ${field} has unknown staleness policy.`);
}

function latestAssistantText(messages: unknown[]): string {
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index] as { role?: string; content?: unknown };
    if (message?.role !== "assistant" || !Array.isArray(message.content)) continue;
    return message.content
      .flatMap((part) => {
        const item = part as { type?: string; text?: unknown };
        return item.type === "text" && typeof item.text === "string" ? [item.text] : [];
      })
      .join("\n")
      .trim();
  }
  return "";
}

function ageDays(createdAt: string, now: Date): number {
  const parsed = Date.parse(createdAt);
  if (!Number.isFinite(parsed)) return 0;
  return Math.round(Math.max(0, (now.getTime() - parsed) / 86_400_000) * 100) / 100;
}
