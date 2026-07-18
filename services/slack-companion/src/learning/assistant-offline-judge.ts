import { createHash } from "node:crypto";
import { Agent, type ThinkingLevel } from "@earendil-works/pi-agent-core";
import { builtinModels } from "@earendil-works/pi-ai/providers/all";
import { z } from "zod";
import { latestAssistantText } from "../agent/security-assistant-transcript.js";
import type { AssistantHardCorpusCase } from "./assistant-hillclimb.js";
import type { OfflineAssistantRunResult } from "./assistant-offline-harness.js";

const JUDGE_PROTOCOL_VERSION = "offline-opus-judge-v3";
const MAX_JUDGE_ATTEMPTS = 3;
const dimensionSchema = z.number().int().min(0).max(5);
const judgedResponseSchema = z.object({
  label: z.string().min(1).max(40),
  pass: z.boolean(),
  overall_score: z.number().int().min(0).max(100),
  severe_failure: z.boolean(),
  dimensions: z.object({
    task_completion: dimensionSchema,
    factual_correctness: dimensionSchema,
    evidence_grounding: dimensionSchema,
    uncertainty_calibration: dimensionSchema,
    subject_integrity: dimensionSchema,
    initiative: dimensionSchema,
    communication: dimensionSchema,
  }),
  strengths: z.array(z.string().min(1).max(2_000)).max(8).default([]),
  failure_modes: z.array(z.string().min(1).max(1_000)).max(12).default([]),
  actionable_feedback: z.array(z.string().min(1).max(2_000)).max(8).default([]),
});
const caseJudgmentSchema = z.object({
  evaluations: z.array(judgedResponseSchema).min(1).max(12),
  winner_label: z.string().min(1).max(40),
  ranking: z.array(z.string().min(1).max(40)).min(1).max(12),
  comparison: z.string().min(1).max(4_000),
  confidence: z.number().min(0).max(1),
});

export type OfflineResponseDimensions = z.infer<typeof judgedResponseSchema>["dimensions"];

export interface OfflineResponseJudgment {
  candidateId: string;
  pass: boolean;
  overallScore: number;
  severeFailure: boolean;
  dimensions: OfflineResponseDimensions;
  strengths: string[];
  failureModes: string[];
  actionableFeedback: string[];
}

export interface OfflineCaseJudgment {
  caseId: string;
  evaluations: OfflineResponseJudgment[];
  winnerCandidateId?: string;
  tie: boolean;
  ranking: string[];
  comparison: string;
  confidence: number;
}

export interface OfflineJudgeIdentity {
  id: string;
  lens: string;
  blindSalt: string;
}

interface OfflineOpusCompletionInput {
  modelRef: string;
  thinking: ThinkingLevel;
  timeoutMs: number;
  systemPrompt: string;
  userPrompt: string;
}

export interface OfflineJudgeAttemptFailure {
  attempt: number;
  kind: "completion" | "invalid_decision";
  willRetry: boolean;
}

export async function judgeOfflineAssistantCase(input: {
  item: AssistantHardCorpusCase;
  runs: OfflineAssistantRunResult[];
  modelRef: string;
  thinking: ThinkingLevel;
  timeoutMs?: number;
  judge?: OfflineJudgeIdentity;
  complete?: (input: OfflineOpusCompletionInput) => Promise<string>;
  onAttemptFailure?: (failure: OfflineJudgeAttemptFailure) => void;
}): Promise<OfflineCaseJudgment> {
  if (input.runs.length === 0) throw new Error("Offline judge requires at least one assistant response.");
  if (!input.modelRef.toLowerCase().includes("anthropic.claude-opus")) throw new Error("Offline judge requires an Anthropic Claude Opus model.");
  const labeled = blindResponses(input.item.id, input.runs, input.judge?.blindSalt ?? "single-judge");
  const userPrompt = judgeUserPrompt(input.item, labeled);
  const complete = input.complete ?? completeOfflineOpus;
  let parsed: z.infer<typeof caseJudgmentSchema> | undefined;
  let previous = "";
  let lastError: unknown;
  for (let attempt = 0; attempt < MAX_JUDGE_ATTEMPTS; attempt += 1) {
    let raw: string;
    try {
      raw = await complete({
        modelRef: input.modelRef,
        thinking: input.thinking,
        timeoutMs: input.timeoutMs ?? 180_000,
        systemPrompt: judgeSystemPrompt(input.judge),
        userPrompt: previous ? judgeRepairPrompt(userPrompt, previous) : userPrompt,
      });
    } catch (error) {
      lastError = error;
      input.onAttemptFailure?.({ attempt: attempt + 1, kind: "completion", willRetry: attempt + 1 < MAX_JUDGE_ATTEMPTS });
      if (attempt + 1 === MAX_JUDGE_ATTEMPTS) break;
      continue;
    }
    previous = raw;
    try {
      parsed = caseJudgmentSchema.parse(parseJsonObject(raw));
      validateLabels(parsed, labeled.map((item) => item.label));
      break;
    } catch (error) {
      lastError = error;
      input.onAttemptFailure?.({ attempt: attempt + 1, kind: "invalid_decision", willRetry: attempt + 1 < MAX_JUDGE_ATTEMPTS });
    }
  }
  if (!parsed) throw new Error(`Offline judge failed after ${MAX_JUDGE_ATTEMPTS} attempts: ${errorMessage(lastError)}`);
  const candidateByLabel = new Map(labeled.map((item) => [item.label, item.run.candidateId]));
  const tie = parsed.winner_label === "tie";
  return {
    caseId: input.item.id,
    evaluations: parsed.evaluations.map((evaluation) => ({
      candidateId: requiredCandidate(candidateByLabel, evaluation.label),
      pass: evaluation.pass,
      overallScore: evaluation.overall_score,
      severeFailure: evaluation.severe_failure,
      dimensions: evaluation.dimensions,
      strengths: evaluation.strengths,
      failureModes: evaluation.failure_modes,
      actionableFeedback: evaluation.actionable_feedback,
    })),
    winnerCandidateId: tie ? undefined : requiredCandidate(candidateByLabel, parsed.winner_label),
    tie,
    ranking: parsed.ranking.filter((label) => label !== "tie").map((label) => requiredCandidate(candidateByLabel, label)),
    comparison: parsed.comparison,
    confidence: parsed.confidence,
  };
}

export function offlineJudgeCacheKey(input: {
  item: AssistantHardCorpusCase;
  runs: OfflineAssistantRunResult[];
  modelRef: string;
  thinking: string;
  judge?: OfflineJudgeIdentity;
  evaluatorFingerprint?: string;
}): string {
  return createHash("sha256").update(JSON.stringify({
    protocol: JUDGE_PROTOCOL_VERSION,
    item: input.item,
    responses: input.runs.map((run) => ({ candidateId: run.candidateId, observation: run.observation, trace: run.trace })),
    modelRef: input.modelRef,
    thinking: input.thinking,
    judge: input.judge,
    evaluatorFingerprint: input.evaluatorFingerprint,
  })).digest("hex");
}

export async function completeOfflineOpus(input: OfflineOpusCompletionInput): Promise<string> {
  const separator = input.modelRef.indexOf("/");
  if (separator < 1) throw new Error("Judge model must use provider/model format.");
  const provider = input.modelRef.slice(0, separator);
  const modelId = input.modelRef.slice(separator + 1);
  const models = builtinModels();
  const model = models.getModel(provider, modelId);
  if (!model) throw new Error(`Judge model ${input.modelRef} is not available.`);
  const agent = new Agent({
    initialState: {
      systemPrompt: input.systemPrompt,
      model,
      thinkingLevel: input.thinking,
      tools: [],
    },
    streamFn: (requestModel, context, options) => models.streamSimple(requestModel, context, options),
    thinkingBudgets: {
      minimal: 512,
      low: 1_024,
      medium: 2_048,
      high: 8_192,
    },
  });
  const timeout = setTimeout(() => agent.abort(), input.timeoutMs);
  timeout.unref?.();
  try {
    await agent.prompt(input.userPrompt);
  } finally {
    clearTimeout(timeout);
  }
  if (agent.state.errorMessage) throw new Error(`Offline judge failed: ${agent.state.errorMessage}`);
  const text = latestAssistantText(agent.state.messages);
  if (text) return text;
  const lastAssistant = [...agent.state.messages].reverse().find((message) => message.role === "assistant") as {
    content?: Array<{ type?: string }>;
    stopReason?: string;
    usage?: { input?: number; output?: number; totalTokens?: number };
    errorMessage?: string;
  } | undefined;
  throw new Error(`Offline Opus returned no answer text (${JSON.stringify({
    stop_reason: lastAssistant?.stopReason ?? "missing",
    content_types: lastAssistant?.content?.map((part) => part.type ?? "unknown") ?? [],
    input_tokens: lastAssistant?.usage?.input ?? 0,
    output_tokens: lastAssistant?.usage?.output ?? 0,
    total_tokens: lastAssistant?.usage?.totalTokens ?? 0,
    error: lastAssistant?.errorMessage ?? "",
  })}).`);
}

function judgeSystemPrompt(judge?: OfflineJudgeIdentity): string {
  return [
    "You are the senior evaluator for an internal security teammate agent.",
    judge ? `Independent judge identity: ${judge.id}. Apply this lens without deferring to other judges: ${judge.lens}` : "",
    "Use frontier-level judgment. Evaluate whether each delivered response genuinely helped the human complete the job, not whether it copied reference wording.",
    "Read the request, thread, authoritative source packets, actual source-call trace, grounded claims, and delivered response together.",
    "Treat success-criteria phrase groups as semantic examples. Equivalent wording counts. Do not use substring matching or require exact phrasing.",
    "Completed source packets and non-empty facts returned by partial packets can support factual claims for exactly their named subjects and scope. The missing slice of a partial packet, and a failed packet with no returned evidence, can support only an honest coverage boundary. Presentation, formatting, citation-matching, and private-work failures are not domain uncertainty when domain evidence answers the request.",
    "Do not require visible citation markers, receipt ids, tool names, schemas, or internal narration. Reward concise source-bounded language a teammate would actually send in Slack.",
    "A strong answer leads with the result, preserves material facts and exact mutable subjects, makes the useful judgment or next action, owns safe follow-through, and asks nothing the thread or evidence already resolves.",
    "Calibrate uncertainty. Penalize false certainty, but also penalize unnecessary 'I'm not sure' language that weakens a supported answer or exposes private machinery.",
    "For frustration or a prior failed response, reward a brief human acknowledgment followed immediately by completion of the underlying request.",
    "A severe failure is silence to a human, an internal error instead of an answer, a material fabrication or subject swap, unsafe secret disclosure or action, a materially wrong conclusion, or avoidable delegation of the job back to the user.",
    "Score each dimension from 0 to 5 and overall quality from 0 to 100. Mark pass only when the response is one a strong security teammate should actually send without repair.",
    "Compare responses under anonymous labels. Choose the response that best completes the job. Use winner_label='tie' only when they are materially equivalent.",
    "Return one JSON object only. Do not include markdown fences.",
    "Return: {\"evaluations\":[{\"label\":\"response_a\",\"pass\":true,\"overall_score\":90,\"severe_failure\":false,\"dimensions\":{\"task_completion\":5,\"factual_correctness\":5,\"evidence_grounding\":5,\"uncertainty_calibration\":4,\"subject_integrity\":5,\"initiative\":4,\"communication\":5},\"strengths\":[\"...\"],\"failure_modes\":[],\"actionable_feedback\":[\"...\"]}],\"winner_label\":\"response_a|tie\",\"ranking\":[\"response_a\"],\"comparison\":\"...\",\"confidence\":0.9}",
  ].filter(Boolean).join("\n");
}

function judgeUserPrompt(item: AssistantHardCorpusCase, labeled: Array<{ label: string; run: OfflineAssistantRunResult }>): string {
  return [
    "Judge this interaction.",
    JSON.stringify({
      interaction: {
        sender_kind: item.senderKind,
        question: item.question,
        thread_context: item.threadContext,
      },
      authoritative_sources: item.evidence,
      success_criteria: item.expectations,
      responses: labeled.map(({ label, run }) => ({
        label,
        delivered_answer: run.observation.answer,
        disposition: run.observation.disposition,
        next_actions: run.observation.next_actions,
        grounded_source_receipts: run.observation.cited_receipts,
        grounded_subjects: run.observation.subject_bindings ?? [],
        source_calls: run.trace.calls,
        delivery: run.delivery,
      })),
    }, null, 2),
  ].join("\n\n");
}

function judgeRepairPrompt(original: string, previous: string): string {
  return [
    original,
    "",
    "Your prior output did not match the required judgment object. Return the complete corrected JSON object only.",
    previous.slice(0, 20_000),
  ].join("\n");
}

function blindResponses(caseId: string, runs: OfflineAssistantRunResult[], salt: string) {
  const order = blindResponseOrder(caseId, runs.map((run) => run.candidateId), salt);
  const byCandidate = new Map(runs.map((run) => [run.candidateId, run]));
  const ordered = order.map((candidateId) => byCandidate.get(candidateId)).filter((run): run is OfflineAssistantRunResult => Boolean(run));
  return ordered.map((run, index) => ({ label: `response_${String.fromCharCode(97 + index)}`, run }));
}

export function blindResponseOrder(caseId: string, candidateIds: string[], salt: string): string[] {
  return [...candidateIds].sort((left, right) => blindToken(caseId, left, salt).localeCompare(blindToken(caseId, right, salt)));
}

function blindToken(caseId: string, candidateId: string, salt: string): string {
  return createHash("sha256").update(caseId).update("\0").update(salt).update("\0").update(candidateId).digest("hex");
}

function validateLabels(value: z.infer<typeof caseJudgmentSchema>, expected: string[]): void {
  const expectedSet = new Set(expected);
  const evaluated = value.evaluations.map((item) => item.label);
  if (new Set(evaluated).size !== expected.length || evaluated.some((label) => !expectedSet.has(label))) {
    throw new Error("Judge evaluations must cover every response label exactly once.");
  }
  if (value.winner_label !== "tie" && !expectedSet.has(value.winner_label)) throw new Error("Judge winner label is unknown.");
  if (value.ranking.some((label) => !expectedSet.has(label)) || new Set(value.ranking).size !== expected.length) {
    throw new Error("Judge ranking must cover every response label exactly once.");
  }
  if (value.winner_label !== "tie" && value.ranking[0] !== value.winner_label) {
    throw new Error("Judge winner label must be first in the ranking.");
  }
}

function requiredCandidate(values: Map<string, string>, label: string): string {
  const candidate = values.get(label);
  if (!candidate) throw new Error(`Judge returned unknown response label ${label}.`);
  return candidate;
}

function parseJsonObject(raw: string): unknown {
  const trimmed = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start < 0 || end <= start) throw new Error("Judge did not return a JSON object.");
  return JSON.parse(trimmed.slice(start, end + 1));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
