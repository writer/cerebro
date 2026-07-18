import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { z } from "zod";
import type { AppConfig } from "../config/index.js";
import { redactSecurityText } from "../security/redaction.js";
import type {
  AssistantExecutionLane,
  AttentionDecision,
  InvestigationHypothesis,
  OperationalDecision,
  OperationalWorkflow,
  OperationalWorldFact,
  SecurityDomainLens,
} from "./operational-intelligence.js";
import type { SecurityAssistantAnswer, SecurityAssistantInput } from "./security-assistant-types.js";
import {
  advanceAssistantMission,
  parseAssistantMission,
  shouldResumeAssistantMission,
  withMissionDelivery,
  type AssistantMissionState,
} from "./mission-kernel.js";
import {
  emptyAssistantTeammateState,
  mergeAssistantTeammateState,
  parseAssistantTeammateState,
  teammateStatePromptValue,
  type AssistantTeammateState,
} from "./teammate-state.js";

const MAX_FACTS = 24;
const MAX_TURNS = 12;

const worldFactSchema = z.object({
  id: z.string(), statement: z.string(), state: z.enum(["observed", "inferred", "expected", "desired"]), confidence: z.number(),
  source_tool: z.string().optional(), evidence_receipt: z.string().optional(), observed_at: z.string().optional(), freshness: z.string().optional(),
  source_refs: z.array(z.string()).default([]), scope: z.string().optional(), valid_until: z.string().optional(), verified: z.boolean(),
});
const hypothesisSchema = z.object({
  id: z.string(), statement: z.string(), status: z.enum(["open", "supported", "contradicted", "eliminated"]), confidence: z.number(),
  supporting_receipts: z.array(z.string()), counterevidence_receipts: z.array(z.string()), falsifier: z.string().optional(), next_check: z.string().optional(),
});
const decisionSchema = z.object({
  id: z.string(), decision: z.string(), rationale: z.string(), owner: z.string().optional(), status: z.enum(["proposed", "approved", "executed", "superseded"]),
  review_at: z.string().optional(), evidence_receipts: z.array(z.string()), source_refs: z.array(z.string()).default([]), verified: z.boolean(),
});
const workflowStepSchema = z.object({
  id: z.string(), kind: z.enum(["observe", "compare", "verify", "decide", "act", "monitor", "rollback"]), title: z.string(), depends_on: z.array(z.string()),
  tool: z.string().optional(), tool_arguments: z.record(z.string(), z.unknown()).default({}), approval_required: z.boolean(), idempotency_key: z.string().optional(),
  verification: z.string().optional(), verification_tool: z.string().optional(), verification_arguments: z.record(z.string(), z.unknown()).default({}), rollback: z.string().optional(),
  max_attempts: z.number().int().min(1).max(3).default(1), acceptance_criteria_ids: z.array(z.string()).default([]),
});
const workflowSchema = z.object({
  objective: z.string(), owner: z.string().optional(), steps: z.array(workflowStepSchema), completion_condition: z.string(), valid: z.boolean(), issues: z.array(z.string()),
});
const attentionSchema = z.object({
  signal: z.string(), dedup_key: z.string(), novelty: z.number(), materiality: z.number(), urgency: z.number(), actionability: z.number(), confidence: z.number(),
  decision_needed: z.boolean(), score: z.number(), recommendation: z.enum(["speak", "suppress"]), reason: z.string(),
});
const investigationSchema = z.object({
  decision: z.string(), status: z.enum(["open", "ready", "blocked"]), claimCoverage: z.number(), remainingGaps: z.array(z.string()), updatedAt: z.string(),
});
const threadEvidencePacketSchema = z.object({
  claimId: z.string(), claimText: z.string(), temporalScope: z.enum(["historical", "current"]),
  verification: z.enum(["verified", "historical_only", "contradicted", "unverified", "blocked"]),
  evidenceIds: z.array(z.string()).default([]), sourceTools: z.array(z.string()).default([]),
});
const turnSchema = z.object({
  sourceTs: z.string(), question: z.string(), answer: z.string(), executionLane: z.enum(["ignore", "converse", "continue", "lookup", "investigate", "act"]), toolCount: z.number(),
  evidencePackets: z.array(threadEvidencePacketSchema).default([]), createdAt: z.string(),
});
const stateSchema = z.object({
  channelId: z.string(), threadTs: z.string(), userId: z.string().optional(), createdAt: z.string(), updatedAt: z.string(), entities: z.array(z.string()).default([]),
  domainLenses: z.array(z.enum(["identity", "delivery", "cloud", "detection", "compliance", "incident", "self", "general"])).default([]),
  reportedFacts: z.array(z.string()).default([]), worldFacts: z.array(worldFactSchema).default([]), hypotheses: z.array(hypothesisSchema).default([]),
  decisions: z.array(decisionSchema).default([]), workflow: workflowSchema.optional(), attention: attentionSchema.optional(), attentionHistory: z.array(attentionSchema).default([]),
  activeInvestigation: investigationSchema.optional(), turns: z.array(turnSchema).default([]),
  teammate: z.unknown().optional(),
  mission: z.unknown().optional(),
});

export interface AssistantThreadTurn {
  sourceTs: string;
  question: string;
  answer: string;
  executionLane: AssistantExecutionLane;
  toolCount: number;
  evidencePackets: AssistantThreadEvidencePacket[];
  createdAt: string;
}

export interface AssistantThreadEvidencePacket {
  claimId: string;
  claimText: string;
  temporalScope: "historical" | "current";
  verification: "verified" | "historical_only" | "contradicted" | "unverified" | "blocked";
  evidenceIds: string[];
  sourceTools: string[];
}

export interface AssistantThreadInvestigation {
  decision: string;
  status: "open" | "ready" | "blocked";
  claimCoverage: number;
  remainingGaps: string[];
  updatedAt: string;
}

export interface AssistantThreadState {
  channelId: string;
  threadTs: string;
  userId?: string;
  createdAt: string;
  updatedAt: string;
  entities: string[];
  domainLenses: SecurityDomainLens[];
  reportedFacts: string[];
  worldFacts: OperationalWorldFact[];
  hypotheses: InvestigationHypothesis[];
  decisions: OperationalDecision[];
  workflow?: OperationalWorkflow;
  attention?: AttentionDecision;
  attentionHistory: AttentionDecision[];
  activeInvestigation?: AssistantThreadInvestigation;
  turns: AssistantThreadTurn[];
  teammate: AssistantTeammateState;
  mission?: AssistantMissionState;
}

export interface AssistantThreadIntelligenceUpdate {
  decision?: string;
  executionLane?: AssistantExecutionLane;
  domainLenses?: SecurityDomainLens[];
  entities?: string[];
  claimCoverage?: number;
  answerReady?: boolean;
  remainingGaps?: string[];
  toolCount?: number;
  worldFacts?: OperationalWorldFact[];
  hypotheses?: InvestigationHypothesis[];
  decisions?: OperationalDecision[];
  workflow?: OperationalWorkflow;
  attention?: AttentionDecision;
}

export interface AssistantThreadStateStoreOptions {
  dynamo?: { send(command: unknown): Promise<unknown> };
  now?: () => Date;
}

export class AssistantThreadStateStore {
  private readonly dynamo?: { send(command: unknown): Promise<unknown> };
  private readonly now: () => Date;
  private readonly memory = new Map<string, AssistantThreadState>();

  constructor(
    private readonly config: AppConfig,
    options: AssistantThreadStateStoreOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    if (config.learning.enabled && config.triage.threadStateTableName) {
      this.dynamo = options.dynamo ?? DynamoDBDocumentClient.from(new DynamoDBClient({}), { marshallOptions: { removeUndefinedValues: true } });
    }
  }

  async get(channelId: string, threadTs: string): Promise<AssistantThreadState | undefined> {
    const key = stateKey(channelId, threadTs);
    return this.getByStorageKey(`assistant-thread#${key}`, key);
  }

  async getForQuestion(question: SecurityAssistantInput): Promise<AssistantThreadState | undefined> {
    const threadTs = question.threadTs ?? question.ts;
    const exact = await this.get(question.channelId, threadTs);
    if (exact || !question.userId) return exact;
    const activeKey = activeMissionKey(question.channelId, question.userId);
    const active = await this.getByStorageKey(`assistant-active#${activeKey}`, activeKey);
    return shouldResumeAssistantMission(question.question, active?.mission) ? active : undefined;
  }

  private async getByStorageKey(storageKey: string, memoryKey: string): Promise<AssistantThreadState | undefined> {
    if (this.dynamo && this.config.triage.threadStateTableName) {
      const response = await this.dynamo.send(new QueryCommand({
        TableName: this.config.triage.threadStateTableName,
        KeyConditionExpression: "pk = :pk AND sk = :sk",
        ExpressionAttributeValues: {
          ":pk": partitionKey(this.config),
          ":sk": storageKey,
        },
        Limit: 1,
      })) as { Items?: Record<string, unknown>[] };
      return parseState(response.Items?.[0]);
    }
    return clone(this.memory.get(memoryKey));
  }

  async recordTurn(input: {
    question: SecurityAssistantInput;
    answer: SecurityAssistantAnswer;
    intelligence: AssistantThreadIntelligenceUpdate;
  }): Promise<AssistantThreadState> {
    const threadTs = input.question.threadTs ?? input.question.ts;
    const current = await this.getForQuestion(input.question);
    const now = this.now().toISOString();
    const update = input.intelligence;
    const turn: AssistantThreadTurn = {
      sourceTs: cleanId(input.question.ts),
      question: cleanText(input.question.question, 800),
      answer: cleanText(input.answer.answer, 1200),
      executionLane: update.executionLane ?? input.answer.executionLane ?? "investigate",
      toolCount: boundedInteger(update.toolCount, 0, 100),
      evidencePackets: (input.answer.claimEvidence ?? []).slice(0, 12).map((packet) => ({
        claimId: cleanId(packet.claimId),
        claimText: cleanText(packet.claimText, 1_200),
        temporalScope: packet.temporalScope,
        verification: packet.verification,
        evidenceIds: unique(packet.evidence.map((evidence) => evidence.id), 12),
        sourceTools: unique(packet.sourceTools, 12),
      })),
      createdAt: now,
    };
    const worldFacts = mergeById(current?.worldFacts ?? [], update.worldFacts ?? [], MAX_FACTS);
    const state: AssistantThreadState = normalizeState({
      channelId: input.question.channelId,
      threadTs,
      userId: cleanId(input.question.userId ?? "") || current?.userId,
      createdAt: current?.createdAt ?? now,
      updatedAt: now,
      entities: unique([...(current?.entities ?? []), ...(update.entities ?? [])], 24),
      domainLenses: uniqueLenses([...(current?.domainLenses ?? []), ...(update.domainLenses ?? [])]),
      reportedFacts: unique([...(input.answer.keyPoints ?? []), ...(input.answer.evidence ?? []), ...(current?.reportedFacts ?? [])], MAX_FACTS),
      worldFacts,
      hypotheses: update.hypotheses?.length ? update.hypotheses.slice(0, 16) : current?.hypotheses ?? [],
      decisions: mergeById(current?.decisions ?? [], update.decisions ?? [], 16),
      workflow: update.workflow ?? current?.workflow,
      attention: update.attention ?? current?.attention,
      attentionHistory: mergeAttention(current?.attentionHistory ?? [], update.attention),
      activeInvestigation: investigationState(update, current?.activeInvestigation, now),
      turns: [turn, ...(current?.turns ?? []).filter((item) => item.sourceTs !== turn.sourceTs)].slice(0, MAX_TURNS),
      teammate: mergeAssistantTeammateState(current?.teammate, input.answer.teammate, update.decision, now),
      mission: advanceAssistantMission({ current: current?.mission, ...input, now }),
    });
    await this.put(state);
    await this.putActive(state);
    return state;
  }

  async recordDelivery(
    question: SecurityAssistantInput,
    delivery: { plannedMessages: number; postedMessages: number; complete: boolean; answerTs?: string },
  ): Promise<void> {
    const threadTs = question.threadTs ?? question.ts;
    const state = await this.get(question.channelId, threadTs) ?? await this.getForQuestion(question);
    if (!state?.mission) return;
    const updated = normalizeState({
      ...state,
      threadTs,
      updatedAt: this.now().toISOString(),
      mission: withMissionDelivery(state.mission, delivery, this.now().toISOString()),
    });
    await this.put(updated);
    await this.putActive(updated);
  }

  private async put(state: AssistantThreadState): Promise<void> {
    if (this.dynamo && this.config.triage.threadStateTableName) {
      await this.dynamo.send(new PutCommand({
        TableName: this.config.triage.threadStateTableName,
        Item: {
          pk: partitionKey(this.config),
          sk: `assistant-thread#${stateKey(state.channelId, state.threadTs)}`,
          ...state,
        },
      }));
      return;
    }
    this.memory.set(stateKey(state.channelId, state.threadTs), clone(state) as AssistantThreadState);
  }

  private async putActive(state: AssistantThreadState): Promise<void> {
    if (!state.userId || !state.mission) return;
    const key = activeMissionKey(state.channelId, state.userId);
    if (this.dynamo && this.config.triage.threadStateTableName) {
      await this.dynamo.send(new PutCommand({
        TableName: this.config.triage.threadStateTableName,
        Item: {
          pk: partitionKey(this.config),
          sk: `assistant-active#${key}`,
          ...state,
        },
      }));
      return;
    }
    this.memory.set(key, clone(state) as AssistantThreadState);
  }
}

export function assistantThreadStatePromptBlock(state: AssistantThreadState | undefined): string {
  if (!state) return "";
  return [
    "Durable assistant thread state:",
    "Use this state to resolve pronouns, follow-ups, already-reported facts, and resumable work. It is continuity context, not proof that current external state is unchanged.",
    JSON.stringify({
      entities: state.entities,
      domain_lenses: state.domainLenses,
      mission: state.mission,
      teammate: teammateStatePromptValue(state.teammate),
      already_reported_facts: state.reportedFacts.slice(0, 12),
      world_facts: state.worldFacts.slice(0, 12).map((fact) => ({
        id: fact.id,
        statement: fact.statement,
        state: fact.state,
        confidence: fact.confidence,
        scope: fact.scope,
        observed_at: fact.observed_at,
        valid_until: fact.valid_until,
        source_refs: fact.source_refs,
        verified: fact.verified,
      })),
      hypotheses: state.hypotheses.slice(0, 8),
      decisions: state.decisions.slice(0, 8),
      workflow: state.workflow,
      active_investigation: state.activeInvestigation,
      recent_attention: state.attentionHistory.slice(0, 8),
      recent_turns: state.turns.slice(0, 6).map((turn) => ({
        source_ts: turn.sourceTs,
        question: turn.question,
        answer: turn.answer,
        execution_lane: turn.executionLane,
        evidence_packets: turn.evidencePackets,
      })),
    }, null, 2),
  ].join("\n");
}

function investigationState(
  update: AssistantThreadIntelligenceUpdate,
  current: AssistantThreadInvestigation | undefined,
  now: string,
): AssistantThreadInvestigation | undefined {
  const decision = cleanText(update.decision, 800) || current?.decision;
  if (!decision) return current;
  const coverage = boundedNumber(update.claimCoverage, current?.claimCoverage ?? 0);
  const remainingGaps = unique(update.remainingGaps ?? current?.remainingGaps ?? [], 12);
  return {
    decision,
    status: update.answerReady ? "ready" : remainingGaps.length > 0 ? "blocked" : "open",
    claimCoverage: coverage,
    remainingGaps,
    updatedAt: now,
  };
}

function normalizeState(state: AssistantThreadState): AssistantThreadState {
  return {
    ...state,
    channelId: cleanId(state.channelId),
    threadTs: cleanId(state.threadTs),
    entities: unique(state.entities, 24),
    domainLenses: uniqueLenses(state.domainLenses),
    reportedFacts: unique(state.reportedFacts, MAX_FACTS),
    worldFacts: state.worldFacts.slice(0, MAX_FACTS),
    hypotheses: state.hypotheses.slice(0, 16),
    decisions: state.decisions.slice(0, 16),
    attentionHistory: (state.attentionHistory ?? []).slice(0, 12),
    turns: state.turns.slice(0, MAX_TURNS),
    teammate: parseAssistantTeammateState(state.teammate) ?? emptyAssistantTeammateState(),
    mission: parseAssistantMission(state.mission),
  };
}

function parseState(item: Record<string, unknown> | undefined): AssistantThreadState | undefined {
  if (!item) return undefined;
  const parsed = stateSchema.safeParse(item);
  if (!parsed.success) return undefined;
  const teammate = parseAssistantTeammateState(parsed.data.teammate) ?? emptyAssistantTeammateState();
  return normalizeState({ ...parsed.data, teammate, mission: parseAssistantMission(parsed.data.mission) });
}

function partitionKey(config: AppConfig): string {
  return `tenant#${config.cerebro.tenantId}#assistant-thread-intelligence`;
}

function stateKey(channelId: string, threadTs: string): string {
  return `${cleanId(channelId)}#${cleanId(threadTs)}`;
}

function activeMissionKey(channelId: string, userId: string): string {
  return `${cleanId(channelId)}#${cleanId(userId)}`;
}

function cleanId(value: string): string {
  return value.replace(/[^A-Za-z0-9_.:-]/g, "").slice(0, 160);
}

function cleanText(value: unknown, max = 800): string {
  return typeof value === "string" ? redactSecurityText(value).replace(/\s+/g, " ").trim().slice(0, max) : "";
}

function unique(values: string[], limit: number): string[] {
  return [...new Set(values.map((value) => cleanText(value)).filter(Boolean))].slice(0, limit);
}

function uniqueLenses(values: SecurityDomainLens[]): SecurityDomainLens[] {
  const allowed = values.filter((value) => value === "identity" || value === "delivery" || value === "cloud" || value === "detection" || value === "compliance" || value === "incident" || value === "self" || value === "general");
  return [...new Set(allowed)].slice(0, 8);
}

function mergeById<T extends { id: string }>(current: T[], updates: T[], limit: number): T[] {
  const merged = new Map(current.map((item) => [item.id, item]));
  for (const item of updates) merged.set(item.id, item);
  return [...updates.map((item) => item.id), ...current.map((item) => item.id)]
    .filter((id, index, values) => values.indexOf(id) === index)
    .flatMap((id) => merged.get(id) ?? [])
    .slice(0, limit);
}

function mergeAttention(current: AttentionDecision[], update: AttentionDecision | undefined): AttentionDecision[] {
  if (!update) return current.slice(0, 12);
  return [update, ...current.filter((item) => item.dedup_key !== update.dedup_key)].slice(0, 12);
}

function boundedNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : fallback;
}

function boundedInteger(value: unknown, min: number, max: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(min, Math.min(max, Math.floor(value))) : min;
}

function clone<T>(value: T | undefined): T | undefined {
  return value === undefined ? undefined : structuredClone(value);
}
