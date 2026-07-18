import type { AppConfig } from "../config/index.js";
import type { SecurityMemoryStore } from "../learning/security-memory/index.js";
import { evaluateAssistantReplayTurn } from "../learning/assistant-replay-eval.js";
import { SlackResearchClient } from "../slack/research/index.js";
import { annotateMain, recordMetric } from "../telemetry.js";
import { shortError } from "./security-assistant-errors.js";
import { formatThreadContext } from "./security-assistant-thread.js";
import type { SecurityAssistantAnswer, SecurityAssistantInput } from "./security-assistant-types.js";
import type { SecurityResearchState } from "./research-state.js";
import { assistantThreadStatePromptBlock, type AssistantThreadStateStore } from "./thread-intelligence-store.js";
import type { AutonomousGoalRecord } from "../autonomy/goals.js";
import { verifiedTeammateGoalPromptBlock } from "./teammate-goals.js";
import type { AssistantFeedbackService } from "../learning/assistant-feedback.js";
import type { EvidenceGovernanceService } from "./evidence-governance.js";

export async function assistantLearningPromptBlock(input: {
  memoryPromptBlock: string;
  feedback?: Pick<AssistantFeedbackService, "promptBlockFor">;
  userId?: string;
  interactionId?: string;
  channelId: string;
  threadTs: string;
  question: string;
  research: string[];
}): Promise<string> {
  const feedback = await input.feedback?.promptBlockFor({
    interactionId: input.interactionId ?? "0000000000000000",
    requesterUserId: input.userId,
    channelId: input.channelId,
    threadTs: input.threadTs,
    question: input.question,
  }).catch((error) => {
    input.research.push(`assistant_feedback: failed (${shortError(error)})`);
    return "";
  }) ?? "";
  if (feedback) input.research.push("assistant_feedback: checked");
  return [input.memoryPromptBlock, feedback].filter(Boolean).join("\n\n");
}

export async function assistantConversationContext(input: {
  config: AppConfig;
  stateStore: AssistantThreadStateStore;
  question: SecurityAssistantInput;
  research: string[];
  goals?: { get(goalId: string): Promise<AutonomousGoalRecord | undefined> };
  evidenceGovernance?: Pick<EvidenceGovernanceService, "promptBlockForThread">;
}): Promise<string> {
  const threadTs = input.question.threadTs ?? input.question.ts;
  const [durable, visible, invalidatedEvidence] = await Promise.all([
    input.stateStore.getForQuestion(input.question).catch((error) => {
      input.research.push(`assistant_thread_state: failed (${shortError(error)})`);
      return undefined;
    }),
    input.question.threadTs
      ? new SlackResearchClient(input.config).threadContext(input.question.channelId, input.question.threadTs, 12)
        .then((thread) => {
          input.research.push("slack_thread_context: checked");
          return formatThreadContext(thread.messages);
        })
        .catch((error) => {
          input.research.push(`slack_thread_context: failed (${shortError(error)})`);
          return "";
        })
      : Promise.resolve(""),
    input.evidenceGovernance?.promptBlockForThread(input.question.channelId, threadTs).catch((error) => {
      input.research.push(`evidence_governance: failed (${shortError(error)})`);
      return "";
    }) ?? Promise.resolve(""),
  ]);
  if (durable) input.research.push("assistant_thread_state: checked");
  if (invalidatedEvidence) input.research.push("evidence_governance: checked");
  const verifiedGoals = await verifiedTeammateGoalPromptBlock({
    state: durable?.teammate,
    goals: input.goals,
    channelId: input.question.channelId,
    threadTs,
  }).catch((error) => {
    input.research.push(`assistant_goal_state: failed (${shortError(error)})`);
    return "";
  });
  if (verifiedGoals) input.research.push("assistant_goal_state: checked");
  return [visible, assistantThreadStatePromptBlock(durable), invalidatedEvidence, verifiedGoals].filter(Boolean).join("\n\n");
}

export async function persistAssistantIntelligence(input: {
  stateStore: AssistantThreadStateStore;
  memory: SecurityMemoryStore;
  question: SecurityAssistantInput;
  answer: SecurityAssistantAnswer;
  researchState: SecurityResearchState;
}): Promise<void> {
  const intelligence = input.researchState.threadIntelligenceUpdate();
  await input.stateStore.recordTurn({
    question: input.question,
    answer: input.answer,
    intelligence,
  });
  const operational = input.researchState.operationalSnapshot();
  const quality = evaluateAssistantReplayTurn({
    question: input.question.question,
    answer: input.answer,
    toolCount: intelligence.toolCount ?? 0,
    claimCoverage: intelligence.claimCoverage,
    threadStateUsed: input.answer.research.some((item) => item.startsWith("assistant_thread_state: checked")),
  });
  annotateMain({
    "assistant.eval.passed": quality.passed,
    "assistant.eval.score": quality.score,
    "assistant.eval.reference_continuity": quality.referenceContinuity,
    "assistant.eval.claim_grounding": quality.claimGrounding,
    "assistant.eval.coverage_honesty": quality.coverageHonesty,
    "assistant.eval.execution_efficiency": quality.executionEfficiency,
    "assistant.eval.action_closure": quality.actionClosure,
    "assistant.eval.goal_understanding": quality.goalUnderstanding,
    "assistant.eval.teammate_ownership": quality.teammateOwnership,
    "assistant.eval.burden_reduction": quality.burdenReduction,
    "assistant.eval.communication_quality": quality.communicationQuality,
    "assistant.eval.citation_precision": quality.citationPrecision,
    "assistant.eval.citation_access": quality.citationAccess,
    "assistant.eval.current_state_verification": quality.currentStateVerification,
    "assistant.eval.source_subject_binding": quality.sourceSubjectBinding,
    "assistant.eval.latency_budget": quality.latencyBudget,
    "assistant.eval.human_burden": quality.humanBurden,
    "assistant.eval.outcome_closure": quality.outcomeClosure,
    "assistant.eval.conflict_disclosure": quality.conflictDisclosure,
    "assistant.eval.blocker_count": quality.blockers.length,
  });
  recordMetric("cerebro_slack_companion_assistant_eval_total", { passed: quality.passed }, 1);
  const memoryWrites = [
    ...operational.world_facts.filter((fact) => fact.verified).map((fact) => input.memory.remember({
      kind: "operator_fact" as const,
      topic: fact.id,
      summary: fact.statement,
      tags: ["world-state", fact.state],
      channelId: input.question.channelId,
      sourceTs: input.question.ts,
      classification: "observed_fact",
      confidence: fact.confidence,
      sourceKind: "tool" as const,
      scope: fact.scope,
      verifiedBy: fact.source_tool ? [fact.source_tool] : undefined,
      verifiedAt: fact.observed_at ?? new Date().toISOString(),
      sourceArtifacts: fact.source_refs.length > 0 ? fact.source_refs : fact.evidence_receipt ? [fact.evidence_receipt] : undefined,
      stalenessPolicy: fact.valid_until ? "until_reverified" as const : "short_lived" as const,
      promotionState: "candidate" as const,
      expiresAt: fact.valid_until ?? new Date(Date.now() + 7 * 86_400_000).toISOString(),
    })),
    ...operational.decisions.filter((decision) => decision.verified).map((decision) => input.memory.remember({
      kind: "operator_decision" as const,
      topic: decision.decision,
      summary: decision.decision,
      details: [
        `Rationale: ${decision.rationale}`,
        decision.owner ? `Owner: ${decision.owner}` : "",
        decision.review_at ? `Review at: ${decision.review_at}` : "",
      ].filter(Boolean).join("\n"),
      tags: ["decision", decision.status],
      channelId: input.question.channelId,
      sourceTs: input.question.ts,
      classification: "decision_record",
      confidence: decision.verified ? 0.9 : 0.65,
      sourceKind: "tool" as const,
      verifiedBy: decision.verified ? ["operator_decision_ledger"] : undefined,
      verifiedAt: decision.verified ? new Date().toISOString() : undefined,
      sourceArtifacts: [...decision.source_refs, ...decision.evidence_receipts].slice(0, 16),
      stalenessPolicy: "durable" as const,
      promotionState: decision.verified ? "candidate" as const : "transient" as const,
      expiresAt: decision.review_at,
    })),
  ];
  if (!quality.passed && input.answer.source !== "blocked" && input.answer.delivery !== "suppress") {
    memoryWrites.push(input.memory.remember({
      kind: "skill_improvement",
      topic: `Assistant replay gap: ${quality.blockers[0] ?? "quality"}`,
      summary: `The completed turn scored ${quality.score}; replay should improve ${quality.blockers.join(", ") || "answer quality"}.`,
      details: [
        `Question: ${input.question.question}`,
        `Execution lane: ${input.answer.executionLane ?? "unknown"}`,
        `Tool count: ${intelligence.toolCount ?? 0}`,
        `Claim coverage: ${intelligence.claimCoverage ?? 0}`,
      ].join("\n"),
      tags: ["assistant-replay", ...quality.blockers].slice(0, 12),
      channelId: input.question.channelId,
      sourceTs: input.question.ts,
      classification: "assistant_replay_gap",
      confidence: 0.8,
      sourceKind: "tool",
      stalenessPolicy: "short_lived",
      promotionState: "transient",
      expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
    }));
  }
  await Promise.all(memoryWrites.map((write) => write.catch(() => undefined)));
}
