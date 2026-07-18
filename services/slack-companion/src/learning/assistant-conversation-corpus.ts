import { GetObjectCommand, ListObjectsV2Command, S3Client } from "@aws-sdk/client-s3";
import { redactSecurityText } from "../security/redaction.js";
import type { SecurityAssistantAnswer } from "../agent/security-assistant-types.js";
import {
  improvementFeedbackOutcomeSchema,
  improvementInteractionSchema,
  type ImprovementFeedbackOutcome,
  type ImprovementInteraction,
} from "../improvement/types.js";
import { assistantHardCorpusCaseSchema, type AssistantHardCorpusCase } from "./assistant-hillclimb.js";

const LIVE_CASE_LATENCY_BUDGET_MS = 90_000;
const LIVE_CASE_LIMIT = 500;
const LIVE_CASE_LOOKBACK_DAYS = 30;
const MAX_PAGES_PER_DAY = 5;
const MAX_INTERACTION_PAGES = 5;

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

export interface PriorConversationTurn {
  question: string;
  answer: string;
}

export function buildConversationCorpusCase(input: {
  interactionId: string;
  question: string;
  answer: SecurityAssistantAnswer;
  prior?: PriorConversationTurn;
}): AssistantHardCorpusCase | undefined {
  if (input.answer.source === "blocked") return undefined;
  const packets = (input.answer.claimEvidence ?? []).filter((packet) =>
    packet.evidence.length > 0
    && packet.evidence.every((evidence) => evidence.access === "allowed"));
  if (!packets.some((packet) => packet.evidence.some((evidence) => evidence.kind === "live_source"))) return undefined;

  const evidence = packets.map((packet) => {
    const verified = packet.verification === "verified" || packet.verification === "contradicted";
    const receipt = packet.evidenceReceipts[0] ?? packet.evidence[0]?.id ?? `claim:${packet.claimId}`;
    return {
      source: packet.sourceTools.join("+") || packet.evidence[0]?.sourceTool || "live-source",
      receipt,
      status: verified ? "completed" as const : "partial" as const,
      facts: [bounded(packet.claimText, 2_000)],
      subjects: unique(packet.evidence.flatMap((item) => item.subjectId ?? item.sourceRef ?? item.id)).slice(0, 24),
    };
  });
  const completed = packets.filter((packet) => packet.verification === "verified" || packet.verification === "contradicted");
  const requiredSubjectBindings = completed.flatMap((packet) => packet.evidence.flatMap((item) => {
    const subject = item.subjectId ?? item.sourceRef;
    return subject ? [{ claim: bounded(packet.claimText, 1_000), subject: bounded(subject, 500) }] : [];
  }));
  const threadContext = input.prior ? [
    `Human: ${bounded(input.prior.question, 3_900)}`,
    `Cerebro: ${bounded(input.prior.answer, 3_900)}`,
  ] : [];
  return assistantHardCorpusCaseSchema.parse({
    schemaVersion: 1,
    id: `live-${boundedToken(input.interactionId)}`,
    partition: "train",
    challenge: input.prior ? "live-human-follow-up-with-verified-sources" : "live-human-request-with-verified-sources",
    difficulty: 5,
    senderKind: "human",
    question: bounded(input.question, 4_000),
    threadContext,
    evidence,
    assignedRoles: [],
    expectations: {
      outcome: "respond",
      requiredFactGroups: completed.map((packet) => [bounded(packet.claimText, 240)]),
      forbiddenFacts: [
        "claim ledger not closed",
        "current_claim_not_live_verified",
        "private work receipt is missing",
        "Flue assistant",
        "LLM error",
      ],
      requiredReceipts: unique(evidence.filter((packet) => packet.status === "completed").map((packet) => packet.receipt)),
      requiredActionGroups: [],
      requireCoverageBoundary: evidence.some((packet) => packet.status !== "completed"),
      requireRecommendation: false,
      forbidClarifyingQuestion: Boolean(input.prior),
      requiredSubjectBindings: dedupeBindings(requiredSubjectBindings).slice(0, 24),
      maxLatencyMs: LIVE_CASE_LATENCY_BUDGET_MS,
      maxHumanFollowUps: 0,
    },
  });
}

export function buildInteractionReplayCase(input: {
  interaction: ImprovementInteraction;
  feedback?: ImprovementFeedbackOutcome;
  prior?: ImprovementInteraction;
}): AssistantHardCorpusCase | undefined {
  const weak = input.interaction.answerSource === "blocked" || input.feedback?.vote === "down" || !input.interaction.deliveryComplete;
  if (!weak) return undefined;
  const prior = input.prior ? [
    `Human: ${bounded(input.prior.question, 3_900)}`,
    `Cerebro: ${bounded(input.prior.answer, 3_900)}`,
  ] : [];
  const reason = input.feedback?.reason.toLowerCase() ?? "";
  return assistantHardCorpusCaseSchema.parse({
    schemaVersion: 1,
    id: `traffic-${boundedToken(input.interaction.interactionId)}`,
    partition: "train",
    challenge: input.interaction.answerSource === "blocked" ? "live-human-blocked-answer-replay" : "live-human-needs-work-replay",
    difficulty: 5,
    senderKind: "human",
    question: bounded(input.interaction.question, 4_000),
    threadContext: prior,
    evidence: [],
    assignedRoles: [],
    expectations: {
      outcome: "respond",
      requiredFactGroups: [],
      forbiddenFacts: [
        "LLM error",
        "model request failed",
        "evidence contract",
        "citation_claim_not_visible",
        "current_claim_not_live_verified",
        "claim ledger not closed",
        "Flue assistant",
        "No memory, Slack, or graph substitute ran",
      ],
      requiredReceipts: [],
      requiredActionGroups: [],
      requireCoverageBoundary: false,
      requireRecommendation: /did.not.act|missed.request|incomplete.action|no.action/.test(reason),
      forbidClarifyingQuestion: Boolean(input.prior),
      requiredSubjectBindings: [],
      maxLatencyMs: LIVE_CASE_LATENCY_BUDGET_MS,
      maxHumanFollowUps: 0,
    },
  });
}

export async function loadConversationCorpusCases(input: {
  bucket: string;
  limit?: number;
  client?: CommandSender;
  now?: Date;
}): Promise<AssistantHardCorpusCase[]> {
  const client = input.client ?? new S3Client({});
  const limit = Math.max(1, Math.min(LIVE_CASE_LIMIT, Math.floor(input.limit ?? 100)));
  const objects: Array<{ Key: string; LastModified?: Date }> = [];
  const now = input.now ?? new Date();
  for (let daysAgo = 0; daysAgo < LIVE_CASE_LOOKBACK_DAYS && objects.length < limit; daysAgo += 1) {
    const day = new Date(now.getTime() - daysAgo * 86_400_000).toISOString().slice(0, 10);
    let continuationToken: string | undefined;
    for (let page = 0; page < MAX_PAGES_PER_DAY; page += 1) {
      const response = await client.send(new ListObjectsV2Command({
        Bucket: input.bucket,
        Prefix: `runs/conversation-${day}-`,
        MaxKeys: 1_000,
        ContinuationToken: continuationToken,
      })) as { Contents?: Array<{ Key?: string; LastModified?: Date }>; NextContinuationToken?: string; IsTruncated?: boolean };
      for (const item of response.Contents ?? []) {
        if (item.Key?.includes("/corpus/")) objects.push({ Key: item.Key, LastModified: item.LastModified });
      }
      continuationToken = response.NextContinuationToken;
      if (!response.IsTruncated || !continuationToken) break;
    }
  }
  const selected = objects
    .sort((left, right) => (right.LastModified?.getTime() ?? 0) - (left.LastModified?.getTime() ?? 0))
    .slice(0, limit);
  const cases = await mapLimit(selected, 8, async (item) => {
    try {
      const response = await client.send(new GetObjectCommand({ Bucket: input.bucket, Key: item.Key })) as {
        Body?: { transformToString(): Promise<string> };
      };
      if (!response.Body) return undefined;
      const parsed = assistantHardCorpusCaseSchema.safeParse(JSON.parse(await response.Body.transformToString()) as unknown);
      if (!parsed.success || parsed.data.partition !== "train") return undefined;
      return parsed.data;
    } catch {
      return undefined;
    }
  });
  const interactionObjects: Array<{ Key: string; LastModified?: Date }> = [];
  let continuationToken: string | undefined;
  for (let page = 0; page < MAX_INTERACTION_PAGES; page += 1) {
    const response = await client.send(new ListObjectsV2Command({
      Bucket: input.bucket,
      Prefix: "runs/interaction-",
      MaxKeys: 1_000,
      ContinuationToken: continuationToken,
    })) as { Contents?: Array<{ Key?: string; LastModified?: Date }>; NextContinuationToken?: string; IsTruncated?: boolean };
    for (const item of response.Contents ?? []) {
      if (item.Key && (/\/interaction\//.test(item.Key) || /\/feedback\//.test(item.Key))) {
        interactionObjects.push({ Key: item.Key, LastModified: item.LastModified });
      }
    }
    continuationToken = response.NextContinuationToken;
    if (!response.IsTruncated || !continuationToken) break;
  }
  const cutoff = now.getTime() - LIVE_CASE_LOOKBACK_DAYS * 86_400_000;
  const interactionArtifacts = await mapLimit(interactionObjects
    .filter((item) => !item.LastModified || item.LastModified.getTime() >= cutoff)
    .sort((left, right) => (right.LastModified?.getTime() ?? 0) - (left.LastModified?.getTime() ?? 0))
    .slice(0, limit * 3), 8, async (item) => {
      try {
        const response = await client.send(new GetObjectCommand({ Bucket: input.bucket, Key: item.Key })) as { Body?: { transformToString(): Promise<string> } };
        if (!response.Body) return undefined;
        const value = JSON.parse(await response.Body.transformToString()) as unknown;
        if (/\/interaction\//.test(item.Key)) {
          const parsed = improvementInteractionSchema.safeParse(value);
          return parsed.success ? { kind: "interaction" as const, value: parsed.data } : undefined;
        }
        const parsed = improvementFeedbackOutcomeSchema.safeParse(value);
        return parsed.success ? { kind: "feedback" as const, value: parsed.data } : undefined;
      } catch {
        return undefined;
      }
    });
  const interactions = new Map(interactionArtifacts.flatMap((item) => item?.kind === "interaction" ? [[item.value.interactionId, item.value] as const] : []));
  const feedback = new Map<string, ImprovementFeedbackOutcome>();
  for (const item of interactionArtifacts) {
    if (item?.kind !== "feedback") continue;
    const existing = feedback.get(item.value.interactionId);
    if (!existing || existing.occurredAt < item.value.occurredAt) feedback.set(item.value.interactionId, item.value);
  }
  const replayCases = [...interactions.values()]
    .sort((left, right) => right.occurredAt.localeCompare(left.occurredAt))
    .flatMap((interaction) => {
      const prior = interaction.followsInteractionId
        ? interactions.get(interaction.followsInteractionId)
        : nearestPriorInteraction(interaction, interactions.values());
      const replay = buildInteractionReplayCase({
        interaction,
        feedback: feedback.get(interaction.interactionId),
        prior,
      });
      return replay ? [replay] : [];
    });
  const byId = new Map(cases.flatMap((item) => item ? [[item.id, item] as const] : []));
  for (const item of replayCases) {
    if (byId.has(`live-${item.id.slice("traffic-".length)}`)) continue;
    if (!byId.has(item.id)) byId.set(item.id, item);
    if (byId.size >= limit) break;
  }
  return [...byId.values()];
}

function nearestPriorInteraction(
  interaction: ImprovementInteraction,
  candidates: Iterable<ImprovementInteraction>,
): ImprovementInteraction | undefined {
  return [...candidates]
    .filter((candidate) => candidate.interactionId !== interaction.interactionId
      && candidate.threadHash === interaction.threadHash
      && candidate.occurredAt < interaction.occurredAt
      && (!interaction.requester?.slackUserId || !candidate.requester?.slackUserId
        || interaction.requester.slackUserId === candidate.requester.slackUserId))
    .sort((left, right) => right.occurredAt.localeCompare(left.occurredAt))[0];
}

function bounded(value: string, max: number): string {
  return redactSecurityText(value)
    .replace(/<@[A-Z0-9]+>/gi, "[person]")
    .replace(/<#[A-Z0-9]+(?:\|[^>]+)?>/gi, "[channel]")
    .replace(/https:\/\/[A-Za-z0-9.-]+\.slack\.com\/archives\/[A-Z0-9]+\/p\d+(?:\?[^\s)]*)?/gi, "[slack_message]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

function boundedToken(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.-]/g, "-").slice(0, 120) || "interaction";
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

function dedupeBindings(values: Array<{ claim: string; subject: string }>): Array<{ claim: string; subject: string }> {
  const byKey = new Map(values.map((value) => [`${value.claim}\0${value.subject}`, value]));
  return [...byKey.values()];
}

async function mapLimit<T, U>(values: readonly T[], limit: number, worker: (value: T) => Promise<U>): Promise<U[]> {
  const results = new Array<U>(values.length);
  let cursor = 0;
  async function run(): Promise<void> {
    while (cursor < values.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(values[index] as T);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, () => run()));
  return results;
}
