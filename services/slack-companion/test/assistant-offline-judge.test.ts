import assert from "node:assert/strict";
import test from "node:test";
import { judgeOfflineAssistantCase, type OfflineJudgeAttemptFailure } from "../src/learning/assistant-offline-judge.js";
import type { OfflineAssistantRunResult } from "../src/learning/assistant-offline-harness.js";
import { parseAssistantHardCorpusLine } from "../src/learning/assistant-hillclimb.js";

const item = parseAssistantHardCorpusLine({
  schemaVersion: 1,
  id: "judge-retry",
  partition: "train",
  challenge: "transient-evaluator-failure",
  difficulty: 5,
  senderKind: "human",
  question: "Is finding F-17 a legitimate risk?",
  threadContext: [],
  evidence: [],
  assignedRoles: [],
  expectations: { outcome: "respond" },
});

const run = {
  caseId: item.id,
  candidateId: "production",
  answer: {
    answer: "F-17 needs validation.",
    messages: ["F-17 needs validation."],
    keyPoints: ["F-17 needs validation."],
    evidence: [],
    actionsTaken: [],
    nextActions: ["Ask the finding owner to confirm the activity."],
    research: [],
    memoryUpdates: [],
    source: "flue",
  },
  observation: {
    answer: "F-17 needs validation.",
    disposition: "respond",
    cited_receipts: [],
    next_actions: ["Ask the finding owner to confirm the activity."],
    specialist_work: [],
  },
  trace: { sources: [], calls: [] },
  specialistWork: [],
  delivery: { plannedMessages: 1, postedMessages: 1, complete: true },
} satisfies OfflineAssistantRunResult;

const validDecision = JSON.stringify({
  evaluations: [{
    label: "response_a",
    pass: true,
    overall_score: 88,
    severe_failure: false,
    dimensions: {
      task_completion: 4,
      factual_correctness: 5,
      evidence_grounding: 4,
      uncertainty_calibration: 5,
      subject_integrity: 5,
      initiative: 4,
      communication: 5,
    },
    strengths: ["Calibrated next action."],
    failure_modes: [],
    actionable_feedback: [],
  }],
  winner_label: "response_a",
  ranking: ["response_a"],
  comparison: "The response is useful and calibrated.",
  confidence: 0.9,
});

test("offline judge retries transient completion failures without changing the sealed comparison", async () => {
  const prompts: string[] = [];
  const failures: OfflineJudgeAttemptFailure[] = [];
  const judgment = await judgeOfflineAssistantCase({
    item,
    runs: [run],
    modelRef: "amazon-bedrock/us.anthropic.claude-opus-4-8",
    thinking: "high",
    complete: async (input) => {
      prompts.push(input.userPrompt);
      if (prompts.length === 1) throw new Error("transient Bedrock failure");
      return validDecision;
    },
    onAttemptFailure: (failure) => failures.push(failure),
  });

  assert.equal(judgment.winnerCandidateId, "production");
  assert.deepEqual(prompts, [prompts[0], prompts[0]]);
  assert.deepEqual(failures, [{ attempt: 1, kind: "completion", willRetry: true }]);
});

test("offline judge repairs malformed decisions and preserves the original blinded evidence", async () => {
  const prompts: string[] = [];
  const judgment = await judgeOfflineAssistantCase({
    item,
    runs: [run],
    modelRef: "amazon-bedrock/us.anthropic.claude-opus-4-8",
    thinking: "high",
    complete: async (input) => {
      prompts.push(input.userPrompt);
      return prompts.length === 1 ? "{\"evaluations\":[]}" : validDecision;
    },
  });

  assert.equal(judgment.winnerCandidateId, "production");
  assert.match(prompts[1]!, /Your prior output did not match/);
  assert.match(prompts[0]!, /Is finding F-17 a legitimate risk\?/);
  assert.match(prompts[1]!, /Is finding F-17 a legitimate risk\?/);
  assert.match(prompts[1]!, /F-17 needs validation/);
});
