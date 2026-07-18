import { createHash } from "node:crypto";
import { completeWithFlueSecurityAssistant, type FlueSecurityAssistantCompleteOutput } from "../agent/flue-security-assistant.js";
import { SecurityAssistantService } from "../agent/security-assistant.js";
import { CerebroEnsembleService } from "../agent/cerebro-ensemble.js";
import { CerebroDistributedWorkService } from "../agent/distributed-work.js";
import { InMemorySharedRateLimitStore, SharedRateLimitCoordinator } from "../a2a/index.js";
import type { SecurityAssistantAnswer, SecurityAssistantInput } from "../agent/security-assistant-types.js";
import { AssistantThreadStateStore } from "../agent/thread-intelligence-store.js";
import type { CerebroClient } from "../cerebro/client.js";
import type { AppConfig } from "../config/index.js";
import { SecurityMemoryStore } from "./security-memory/index.js";
import {
  ASSISTANT_POLICY_CANDIDATES,
  type AssistantHardCorpusCase,
  type AssistantHillClimbObservation,
  type AssistantPolicyCandidate,
} from "./assistant-hillclimb.js";
import {
  createOfflineFixtureToolFactory,
  createOfflineFixtureTrace,
  type OfflineFixtureSource,
  type OfflineFixtureTrace,
} from "./assistant-offline-fixtures.js";

export const OFFLINE_PRODUCTION_CANDIDATE: AssistantPolicyCandidate = {
  id: "production",
  mutation: "Current production assistant policy.",
  instructions: [],
};

export const OFFLINE_ENSEMBLE_CANDIDATE: AssistantPolicyCandidate = {
  id: "ensemble-production",
  parentId: "production",
  mutation: "Use two independent read-only Cerebro peers and an Opus chair before delivering difficult human requests.",
  instructions: [],
  ensembleReviewerCount: 2,
};

export const OFFLINE_DISTRIBUTED_CANDIDATE: AssistantPolicyCandidate = {
  id: "distributed-production",
  parentId: "ensemble-production",
  mutation: "Use Opus decomposition and three parallel read-only Cerebro workers before the primary research synthesis.",
  instructions: [],
  ensembleReviewerCount: 2,
  distributedWorkerCount: 3,
};

export const OFFLINE_ASSISTANT_POLICY_CANDIDATES: readonly AssistantPolicyCandidate[] = [
  OFFLINE_PRODUCTION_CANDIDATE,
  OFFLINE_ENSEMBLE_CANDIDATE,
  OFFLINE_DISTRIBUTED_CANDIDATE,
  ...ASSISTANT_POLICY_CANDIDATES.slice(1),
];

export interface OfflineAssistantRunResult {
  caseId: string;
  candidateId: string;
  answer: SecurityAssistantAnswer;
  observation: AssistantHillClimbObservation;
  trace: OfflineFixtureTrace;
  specialistWork: FlueSecurityAssistantCompleteOutput["data"]["specialist_work"];
  delivery: { plannedMessages: number; postedMessages: number; complete: boolean };
}

export async function runOfflineAssistantCase(input: {
  config: AppConfig;
  item: AssistantHardCorpusCase;
  candidate: AssistantPolicyCandidate;
  ensembleReviewerCount?: number;
  flueComplete?: typeof completeWithFlueSecurityAssistant;
}): Promise<OfflineAssistantRunResult> {
  assertOfflineConfig(input.config);
  const trace = createOfflineFixtureTrace();
  const threadState = new AssistantThreadStateStore(input.config);
  const question = offlineQuestion(input.item);
  await seedThreadContext(threadState, question, input.item.threadContext);
  const toolFactory = createOfflineFixtureToolFactory(input.item, trace);
  const additionalReadOnlyToolNames = new Set(trace.sources.map((source) => source.toolName));
  let flueOutput: FlueSecurityAssistantCompleteOutput | undefined;
  const ensembleReviewerCount = input.ensembleReviewerCount ?? input.candidate.ensembleReviewerCount;
  const ensemble = ensembleReviewerCount
    ? new CerebroEnsembleService(input.config)
    : undefined;
  const distributedWorkerCount = input.candidate.distributedWorkerCount;
  const distributed = distributedWorkerCount
    ? new CerebroDistributedWorkService(
        input.config,
        offlineFleet(),
        {} as CerebroClient,
        new SecurityMemoryStore(input.config),
        new SharedRateLimitCoordinator(new InMemorySharedRateLimitStore(), `offline-${input.item.id}`),
        {
          toolFactory,
          isReadOnlyTool: (toolName) => trace.sources.some((source) => source.toolName === toolName),
        },
      )
    : undefined;
  const service = new SecurityAssistantService(
    input.config,
    {} as CerebroClient,
    new SecurityMemoryStore(input.config),
    {
      threadState,
      toolFactory,
      additionalReadOnlyToolNames,
      evaluationInstructions: input.candidate.instructions,
      ensemble: ensemble ? {
        refine: (questionInput, answer) => ensemble.refineWithLocalReviews(questionInput, answer, ensembleReviewerCount),
      } : undefined,
      distributedWork: distributed ? {
        coordinate: (questionInput, plan) => distributed.coordinateLocally(questionInput, plan, distributedWorkerCount),
      } : undefined,
      flueComplete: async (request) => {
        flueOutput = await (input.flueComplete ?? completeWithFlueSecurityAssistant)(request);
        return flueOutput;
      },
    },
  );
  const startedAt = Date.now();
  const answer = await service.answer(question);
  const latencyMs = Date.now() - startedAt;
  const delivery = deliveryFor(answer);
  await service.recordDelivery(question, delivery);
  const observation = offlineObservation({ answer, flueOutput, trace, latencyMs });
  return {
    caseId: input.item.id,
    candidateId: input.candidate.id,
    answer,
    observation,
    trace,
    specialistWork: flueOutput?.data.specialist_work ?? [],
    delivery,
  };
}

function offlineFleet() {
  return {
    async listInstances() { return []; },
    async request() { return undefined; },
    async send() { throw new Error("Offline distributed work does not use A2A transport."); },
  } as never;
}

export function offlineObservation(input: {
  answer: SecurityAssistantAnswer;
  flueOutput?: FlueSecurityAssistantCompleteOutput;
  trace: OfflineFixtureTrace;
  latencyMs: number;
}): AssistantHillClimbObservation {
  const sourceByTool = new Map(input.trace.sources.map((source) => [source.toolName, source]));
  const claimEvidence = input.answer.claimEvidence ?? [];
  const citedReceipts = unique(claimEvidence.flatMap((claim) => claim.sourceTools.flatMap((tool) => {
    const source = sourceByTool.get(tool);
    return source?.status === "completed" ? [source.receipt] : [];
  })));
  const dynamicReceipts = dynamicReceiptMap(claimEvidence, sourceByTool);
  const specialistWork = (input.flueOutput?.data.specialist_work ?? []).map((work) => ({
    role: work.role,
    status: work.status,
    findings: work.findings,
    recommendations: work.recommendations,
    actions: work.actions,
    checks: work.checks,
    blockers: work.blockers,
    evidence_receipts: unique(work.evidence_receipts.flatMap((receipt) => dynamicReceipts.get(receipt) ?? [])),
  }));
  const answer = input.answer.messages.length > 0 ? input.answer.messages.join("\n") : input.answer.answer;
  return {
    answer,
    disposition: input.answer.delivery === "suppress" ? "ignore" : "respond",
    cited_receipts: citedReceipts,
    next_actions: input.answer.nextActions,
    specialist_work: specialistWork,
    subject_bindings: uniqueSubjectBindings(claimEvidence),
    latency_ms: Math.max(0, Math.floor(input.latencyMs)),
    human_follow_ups: clarifyingQuestionCount(answer),
  };
}

export function offlineHarnessCacheKey(input: {
  runtimeFingerprint: string;
  model: string;
  thinking: string;
  executionModel: string;
  executionThinking: string;
  protocolPrompt: string;
  candidate: AssistantPolicyCandidate;
  item: AssistantHardCorpusCase;
}): string {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}

export function selectOfflineCases(input: {
  cases: AssistantHardCorpusCase[];
  heldOut: boolean;
  caseIds?: Set<string>;
  limit?: number;
}): AssistantHardCorpusCase[] {
  const partitioned = input.cases.filter((item) => input.heldOut ? item.partition === "held_out" : item.partition !== "held_out");
  const selected = input.caseIds?.size ? partitioned.filter((item) => input.caseIds?.has(item.id)) : partitioned;
  return selected.slice(0, input.limit ?? selected.length);
}

function offlineQuestion(item: AssistantHardCorpusCase): SecurityAssistantInput {
  const suffix = Number.parseInt(createHash("sha256").update(item.id).digest("hex").slice(0, 6), 16) % 1_000_000;
  return {
    interactionId: `offline-${item.id}`.slice(0, 160),
    channelId: "COFFLINE",
    userId: "UOFFLINE",
    senderKind: item.senderKind,
    question: item.question,
    ts: `1700000000.${String(suffix).padStart(6, "0")}`,
  };
}

async function seedThreadContext(
  state: AssistantThreadStateStore,
  question: SecurityAssistantInput,
  context: string[],
): Promise<void> {
  if (context.length === 0) return;
  const priorQuestion: SecurityAssistantInput = {
    ...question,
    interactionId: `${question.interactionId}-context`,
    question: "Earlier conversation in this thread",
    ts: `${question.ts}-context`,
    threadTs: question.ts,
  };
  await state.recordTurn({
    question: priorQuestion,
    answer: {
      answer: context.join("\n"),
      messages: context,
      keyPoints: context,
      evidence: [],
      actionsTaken: [],
      nextActions: [],
      research: ["offline_thread_context: supplied"],
      memoryUpdates: [],
      source: "flue",
      executionLane: "continue",
      delivery: "respond",
    },
    intelligence: { executionLane: "continue", toolCount: 0 },
  });
}

function dynamicReceiptMap(
  claims: NonNullable<SecurityAssistantAnswer["claimEvidence"]>,
  sourceByTool: Map<string, OfflineFixtureSource>,
): Map<string, string[]> {
  const result = new Map<string, string[]>();
  for (const claim of claims) {
    const staticReceipts = claim.sourceTools.flatMap((tool) => {
      const source = sourceByTool.get(tool);
      return source?.status === "completed" ? [source.receipt] : [];
    });
    for (const receipt of claim.evidenceReceipts) {
      result.set(receipt, unique([...(result.get(receipt) ?? []), ...staticReceipts]));
    }
  }
  return result;
}

function uniqueSubjectBindings(claims: NonNullable<SecurityAssistantAnswer["claimEvidence"]>) {
  const seen = new Set<string>();
  return claims.flatMap((claim) => claim.evidence.flatMap((evidence) => {
    const subject = evidence.subjectId ?? evidence.sourceRef;
    if (!subject) return [];
    const key = `${claim.claimText}\0${subject}`;
    if (seen.has(key)) return [];
    seen.add(key);
    return [{ claim: claim.claimText, subject }];
  }));
}

function deliveryFor(answer: SecurityAssistantAnswer) {
  const plannedMessages = answer.delivery === "suppress" ? 0 : answer.messages.length;
  return { plannedMessages, postedMessages: plannedMessages, complete: true };
}

function clarifyingQuestionCount(answer: string): number {
  return /\b(?:which|what)\s+(?:repository|repo|ticket|project|owner|runtime|source|scope)\b[^?]*\?/i.test(answer)
    || /\b(?:provide|share|send)\b[^?]{0,100}\b(?:scope|details|context|identifier)\b[^?]*\?/i.test(answer) ? 1 : 0;
}

function assertOfflineConfig(config: AppConfig): void {
  if (config.triage.assistantRuntime !== "flue") throw new Error("Offline assistant evaluation requires the Flue runtime.");
  if (!config.triage.pi.model.toLowerCase().includes("anthropic.claude-opus")) throw new Error("Offline assistant evaluation requires an Anthropic Claude Opus model.");
  if (!config.triage.pi.executionModel.toLowerCase().includes("anthropic.claude-opus")) throw new Error("Offline assistant execution requires an Anthropic Claude Opus model.");
  if (!config.a2a.workFleetEnabled) throw new Error("Offline assistant evaluation requires the distributed work candidate to remain available.");
  if (config.learning.enabled) throw new Error("Offline assistant evaluation requires SECURITY_LEARNING_ENABLED=false.");
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
