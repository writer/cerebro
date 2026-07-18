import { createHash } from "node:crypto";
import { z } from "zod";
import { redactSecurityText } from "../security/redaction.js";
import type { SecurityAssistantAnswer, SecurityAssistantInput } from "./security-assistant-types.js";
import type { AssistantThreadIntelligenceUpdate } from "./thread-intelligence-store.js";

export type AssistantMissionStatus = "active" | "waiting" | "approval_needed" | "blocked" | "completed" | "cancelled";

export interface AssistantMissionSubject {
  id: string;
  kind: string;
  label: string;
  sourceTool?: string;
  sourceRef?: string;
  url?: string;
  observedAt?: string;
}

export interface AssistantMissionState {
  id: string;
  status: AssistantMissionStatus;
  objective: string;
  desiredOutcome?: string;
  subjects: AssistantMissionSubject[];
  acceptanceCriteria: string[];
  openLoopIds: string[];
  lastUserIntent: string;
  turnCount: number;
  lastAnswerId?: string;
  delivery?: {
    status: "complete" | "partial" | "failed";
    plannedMessages: number;
    postedMessages: number;
    answerTs?: string;
    updatedAt: string;
  };
  updatedAt: string;
}

const subjectSchema = z.object({
  id: z.string(),
  kind: z.string(),
  label: z.string(),
  sourceTool: z.string().optional(),
  sourceRef: z.string().optional(),
  url: z.string().optional(),
  observedAt: z.string().optional(),
});

const missionSchema = z.object({
  id: z.string(),
  status: z.enum(["active", "waiting", "approval_needed", "blocked", "completed", "cancelled"]),
  objective: z.string(),
  desiredOutcome: z.string().optional(),
  subjects: z.array(subjectSchema).default([]),
  acceptanceCriteria: z.array(z.string()).default([]),
  openLoopIds: z.array(z.string()).default([]),
  lastUserIntent: z.string(),
  turnCount: z.number().int().min(1),
  lastAnswerId: z.string().optional(),
  delivery: z.object({
    status: z.enum(["complete", "partial", "failed"]),
    plannedMessages: z.number().int().min(0),
    postedMessages: z.number().int().min(0),
    answerTs: z.string().optional(),
    updatedAt: z.string(),
  }).optional(),
  updatedAt: z.string(),
});

export function parseAssistantMission(value: unknown): AssistantMissionState | undefined {
  const parsed = missionSchema.safeParse(value);
  return parsed.success ? parsed.data : undefined;
}

export function advanceAssistantMission(input: {
  current?: AssistantMissionState;
  question: SecurityAssistantInput;
  answer: SecurityAssistantAnswer;
  intelligence: AssistantThreadIntelligenceUpdate;
  now: string;
}): AssistantMissionState {
  const current = input.current;
  const teammate = input.answer.teammate;
  const objective = cleanText(teammate?.objective)
    || cleanText(input.intelligence.decision)
    || current?.objective
    || cleanText(input.question.question);
  const desiredOutcome = cleanText(teammate?.desiredOutcome) || current?.desiredOutcome;
  const subjects = mergeSubjects(subjectsFromAnswer(input.answer), current?.subjects ?? []);
  const commitments = teammate?.commitments ?? [];
  const openLoops = teammate?.openLoops ?? [];
  const acceptanceCriteria = unique([
    ...commitments.flatMap((commitment) => commitment.acceptanceCriteria ?? []),
    ...(current?.acceptanceCriteria ?? []),
  ], 24, 500);
  const status = missionStatus(input.answer, current);
  const missionId = current?.id ?? stableMissionId(input.question);
  return {
    id: missionId,
    status,
    objective,
    desiredOutcome,
    subjects,
    acceptanceCriteria,
    openLoopIds: unique([
      ...openLoops.map((loop) => loop.id),
      ...commitments.filter((item) => item.status === "planned" || item.status === "in_progress" || item.status === "blocked").map((item) => item.id),
    ], 24, 160),
    lastUserIntent: cleanText(input.question.question),
    turnCount: Math.max(1, (current?.turnCount ?? 0) + 1),
    lastAnswerId: cleanId(input.question.interactionId ?? input.question.ts),
    delivery: current?.delivery,
    updatedAt: input.now,
  };
}

export function shouldResumeAssistantMission(question: string, mission: AssistantMissionState | undefined): boolean {
  if (!mission) return false;
  const value = cleanText(question, 1_200).toLowerCase();
  if (!value) return false;
  if (/^(\^+|again\b|continue\b|keep going\b|go on\b|retry\b|try again\b|do better\b|anything else\b)/i.test(value)) return true;
  if (/\b(that|this|those|these|them|it|they|prior|previous|above|same|better query|detailed link|grounded citation|source|receipt)\b/i.test(value)) return true;
  if (value.length <= 80 && mission.status !== "completed" && mission.status !== "cancelled") return true;
  return false;
}

export function withMissionDelivery(
  mission: AssistantMissionState,
  delivery: { plannedMessages: number; postedMessages: number; complete: boolean; answerTs?: string },
  now: string,
): AssistantMissionState {
  return {
    ...mission,
    delivery: {
      status: delivery.complete ? "complete" : delivery.postedMessages > 0 ? "partial" : "failed",
      plannedMessages: Math.max(0, Math.floor(delivery.plannedMessages)),
      postedMessages: Math.max(0, Math.floor(delivery.postedMessages)),
      answerTs: cleanId(delivery.answerTs ?? "") || undefined,
      updatedAt: now,
    },
    updatedAt: now,
  };
}

function missionStatus(answer: SecurityAssistantAnswer, current: AssistantMissionState | undefined): AssistantMissionStatus {
  if (answer.source === "blocked") return "blocked";
  const teammate = answer.teammate;
  if (teammate?.userDecision?.required) return "approval_needed";
  const statuses = teammate?.commitments.map((item) => item.goalStatus ?? item.status) ?? [];
  if (statuses.includes("blocked")) return "blocked";
  if (statuses.includes("waiting")) return "waiting";
  if (statuses.some((status) => status === "planned" || status === "in_progress" || status === "active" || status === "paused")) return "active";
  if ((teammate?.openLoops.length ?? 0) > 0) return "active";
  if (statuses.length > 0 && statuses.every((status) => status === "completed" || status === "cancelled")) {
    return statuses.includes("completed") ? "completed" : "cancelled";
  }
  return current?.status === "cancelled" ? "cancelled" : "completed";
}

function subjectsFromAnswer(answer: SecurityAssistantAnswer): AssistantMissionSubject[] {
  const evidenceSubjects = (answer.claimEvidence ?? []).flatMap((packet) => packet.evidence).flatMap((evidence) => {
    const sourceRef = cleanText(evidence.sourceRef, 500) || undefined;
    const id = cleanId(evidence.subjectId ?? sourceRef ?? evidence.id);
    if (!id) return [];
    return [{
      id,
      kind: cleanId(evidence.subjectKind ?? evidence.kind) || "source",
      label: cleanText(evidence.subjectLabel ?? evidence.title, 500) || id,
      sourceTool: cleanId(evidence.sourceTool ?? "") || undefined,
      sourceRef,
      url: safeUrl(evidence.permalink),
      observedAt: cleanText(evidence.verifiedAt ?? evidence.createdAt, 80) || undefined,
    }];
  });
  const scopeSubjects = (answer.teammate?.resolvedScope ?? []).flatMap((scope) => {
    const label = cleanText(scope, 500);
    if (!label) return [];
    const [kind] = label.split(":", 1);
    return [{ id: cleanId(label), kind: cleanId(kind ?? "scope") || "scope", label }];
  });
  return mergeSubjects(evidenceSubjects, scopeSubjects);
}

function mergeSubjects(primary: AssistantMissionSubject[], secondary: AssistantMissionSubject[]): AssistantMissionSubject[] {
  const merged = new Map<string, AssistantMissionSubject>();
  for (const subject of [...secondary, ...primary]) merged.set(subject.id, subject);
  return [...primary.map((item) => item.id), ...secondary.map((item) => item.id)]
    .filter((id, index, ids) => ids.indexOf(id) === index)
    .flatMap((id) => merged.get(id) ?? [])
    .slice(0, 24);
}

function stableMissionId(question: SecurityAssistantInput): string {
  const digest = createHash("sha256")
    .update(question.channelId)
    .update("\0")
    .update(question.userId ?? "unknown")
    .update("\0")
    .update(question.threadTs ?? question.ts)
    .digest("hex")
    .slice(0, 20);
  return `mission:${digest}`;
}

function cleanId(value: string): string {
  return value.replace(/[^A-Za-z0-9_.:-]/g, "").slice(0, 200);
}

function cleanText(value: unknown, max = 800): string {
  return typeof value === "string" ? redactSecurityText(value).replace(/\s+/g, " ").trim().slice(0, max) : "";
}

function unique(values: string[], limit: number, max: number): string[] {
  return [...new Set(values.map((value) => cleanText(value, max)).filter(Boolean))].slice(0, limit);
}

function safeUrl(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try {
    const url = new URL(value);
    return url.protocol === "https:" ? url.toString() : undefined;
  } catch {
    return undefined;
  }
}
