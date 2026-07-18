import assert from "node:assert/strict";
import test from "node:test";
import {
  ASSISTANT_POLICY_CANDIDATES,
  assistantHillClimbObservationKey,
  hardCorpusDigest,
  heldOutPromotionReady,
  parseAssistantHardCorpusLine,
  parseAssistantHillClimbObservation,
  scoreAssistantHardCase,
  selectAssistantHillClimbWinner,
  summarizeAssistantCandidate,
  type AssistantCandidateScore,
  type AssistantHardCaseReceipt,
} from "../src/learning/assistant-hillclimb.js";

const hardCase = parseAssistantHardCorpusLine({
  schemaVersion: 1,
  id: "hard-case",
  partition: "train",
  challenge: "partial-evidence-with-private-gap",
  difficulty: 5,
  senderKind: "human",
  question: "do a better query then",
  threadContext: ["The first query found zero results but some sources failed."],
  evidence: [
    { source: "graph", receipt: "receipt-ok", status: "completed", facts: ["two sources completed", "three failed"] },
    { source: "catalog", receipt: "receipt-failed", status: "failed", facts: ["catalog unavailable"] },
  ],
  assignedRoles: ["researcher", "triage"],
  expectations: {
    outcome: "respond",
    requiredFactGroups: [["two sources"], ["three failed"]],
    forbiddenFacts: ["all sources were clean"],
    requiredReceipts: ["receipt-ok"],
    requiredActionGroups: [["retry", "broaden", "query"]],
    requireCoverageBoundary: true,
    requireRecommendation: true,
    forbidClarifyingQuestion: true,
  },
});

test("hard corpus digest is stable across input order", () => {
  const second = parseAssistantHardCorpusLine({ ...hardCase, id: "second", challenge: "second" });
  assert.equal(hardCorpusDigest([hardCase, second]), hardCorpusDigest([second, hardCase]));
});

test("hillclimb observation cache changes when the shared protocol changes", () => {
  const candidate = ASSISTANT_POLICY_CANDIDATES[0];
  assert.ok(candidate);
  const base = { model: "amazon-bedrock/us.anthropic.claude-opus-4-8", thinking: "high", candidate, item: hardCase };
  const first = assistantHillClimbObservationKey({ ...base, protocolPrompt: "Humans always receive a reply." });
  const second = assistantHillClimbObservationKey({ ...base, protocolPrompt: "Humans may be ignored." });
  assert.notEqual(first, second);
});

test("grounded useful answer passes when private specialist coverage is incomplete", () => {
  const receipt = scoreAssistantHardCase(hardCase, "candidate", {
    answer: "The checked graph sources show two sources completed and three failed. I recommend broadening the query, then retrying the failed catalog source.",
    disposition: "respond",
    cited_receipts: ["receipt-ok"],
    next_actions: ["Broaden the query and retry the failed source."],
    specialist_work: [],
  });
  assert.equal(receipt.passed, true);
  assert.equal(receipt.specialistCoverage, 0);
  assert.deepEqual(receipt.blockers, []);
});

test("internal failure text and invented receipts are hard blockers", () => {
  const receipt = scoreAssistantHardCase(hardCase, "candidate", {
    answer: "LLM error: specialist work contract is incomplete. Retry the query.",
    disposition: "respond",
    cited_receipts: ["receipt-made-up"],
    next_actions: [],
    specialist_work: [],
  });
  assert.equal(receipt.passed, false);
  assert.ok(receipt.blockers.includes("internal_failure_leaked"));
  assert.ok(receipt.blockers.includes("invented_receipt"));
});

test("hillclimb scores incomplete specialist status instead of aborting the run", () => {
  const observation = parseAssistantHillClimbObservation({
    answer: "The completed source returned one supported result.",
    disposition: "respond",
    cited_receipts: ["receipt-ok"],
    next_actions: [],
    specialist_work: [{ role: "researcher", status: "partial" }],
  });

  assert.equal(observation.specialist_work[0]?.status, "blocked");
});

test("uncertain cases require an explicit I'm not sure disclosure", () => {
  const item = parseAssistantHardCorpusLine({
    ...hardCase,
    id: "uncertainty-disclosure",
    expectations: {
      ...hardCase.expectations,
      requireUncertaintyDisclosure: true,
    },
  });
  const missing = scoreAssistantHardCase(item, "candidate", {
    answer: "The checked graph sources show two sources completed and three failed. Broaden the query and retry the catalog source.",
    disposition: "respond",
    cited_receipts: ["receipt-ok"],
    next_actions: ["Broaden the query and retry the catalog source."],
    specialist_work: [],
  });
  const disclosed = scoreAssistantHardCase(item, "candidate", {
    answer: "The checked graph sources show two sources completed and three failed. I'm not sure what the unavailable catalog contains. Broaden the query and retry that source.",
    disposition: "respond",
    cited_receipts: ["receipt-ok"],
    next_actions: ["Broaden the query and retry the catalog source."],
    specialist_work: [],
  });

  assert.equal(missing.blockers.includes("uncertainty_disclosure_missing"), true);
  assert.equal(disclosed.blockers.includes("uncertainty_disclosure_missing"), false);
});

test("subject binding accepts a paraphrased claim only for the exact subject", () => {
  const item = parseAssistantHardCorpusLine({
    ...hardCase,
    id: "subject-binding",
    expectations: {
      ...hardCase.expectations,
      requiredSubjectBindings: [{ claim: "F-701 is critical and internet reachable", subject: "finding:F-701" }],
    },
  });
  const grounded = scoreAssistantHardCase(item, "candidate", {
    answer: "F-701 is critical, internet reachable, and open. Two sources completed and three failed; broaden the query and retry.",
    disposition: "respond",
    cited_receipts: ["receipt-ok"],
    next_actions: ["Broaden the query and retry."],
    subject_bindings: [{ claim: "Critical and internet reachable", subject: "finding:F-701" }],
    specialist_work: [],
  });
  const swapped = scoreAssistantHardCase(item, "candidate", {
    answer: "F-701 is critical, internet reachable, and open. Two sources completed and three failed; broaden the query and retry.",
    disposition: "respond",
    cited_receipts: ["receipt-ok"],
    next_actions: ["Broaden the query and retry."],
    subject_bindings: [{ claim: "Critical and internet reachable", subject: "finding:F-702" }],
    specialist_work: [],
  });
  assert.equal(grounded.blockers.includes("source_subject_mismatch"), false);
  assert.equal(swapped.blockers.includes("source_subject_mismatch"), true);
});

test("hillclimb selection uses train and validation scores only", () => {
  const candidates = ASSISTANT_POLICY_CANDIDATES.slice(0, 2);
  const scores = [
    candidateScore(candidates[0]!.id, "train", 0.7, 4),
    candidateScore(candidates[0]!.id, "validation", 0.7, 4),
    candidateScore(candidates[1]!.id, "train", 0.8, 2),
    candidateScore(candidates[1]!.id, "validation", 0.7, 3),
    candidateScore(candidates[0]!.id, "held_out", 0.95, 0),
    candidateScore(candidates[1]!.id, "held_out", 0.1, 20),
  ];
  assert.equal(selectAssistantHillClimbWinner(candidates, scores).winnerId, candidates[1]!.id);
});

test("hillclimb prefers fewer hard failures over score noise within one point", () => {
  const candidates = ASSISTANT_POLICY_CANDIDATES.slice(0, 2);
  const scores = [
    candidateScore(candidates[0]!.id, "train", 0.907, 14, 0.4),
    candidateScore(candidates[0]!.id, "validation", 0.954, 5, 0.5, 10),
    candidateScore(candidates[1]!.id, "train", 0.942, 13, 0.55),
    candidateScore(candidates[1]!.id, "validation", 0.952, 4, 0.6, 10),
  ];
  assert.equal(selectAssistantHillClimbWinner(candidates, scores).winnerId, candidates[1]!.id);
});

test("held-out promotion requires a strict score gain and fewer blockers", () => {
  const baseline = candidateScore("baseline", "held_out", 0.72, 12, 0.5, 10);
  const winner = candidateScore("winner", "held_out", 0.81, 5, 0.7, 10);
  assert.equal(heldOutPromotionReady({ baseline, winner }), true);
  assert.equal(heldOutPromotionReady({ baseline, winner: { ...winner, averageScore: baseline.averageScore } }), false);
  assert.equal(heldOutPromotionReady({ baseline, winner: { ...winner, hardBlockerCount: baseline.hardBlockerCount } }), false);
});

test("candidate summary reports stable blocker counts", () => {
  const receipts: AssistantHardCaseReceipt[] = [
    hardReceipt("a", ["required_fact_missing", "invented_receipt"]),
    hardReceipt("b", ["required_fact_missing"]),
  ];
  const summary = summarizeAssistantCandidate("candidate", "train", receipts);
  assert.equal(summary.caseCount, 2);
  assert.equal(summary.hardBlockerCount, 3);
  assert.deepEqual(summary.blockerCounts, { required_fact_missing: 2, invented_receipt: 1 });
});

function candidateScore(candidateId: string, partition: AssistantCandidateScore["partition"], averageScore: number, hardBlockerCount: number, passRate = 0.5, caseCount = 20): AssistantCandidateScore {
  return { candidateId, partition, averageScore, hardBlockerCount, passRate, caseCount, passed: Math.round(passRate * caseCount), blockerCounts: {} };
}

function hardReceipt(caseId: string, blockers: string[]): AssistantHardCaseReceipt {
  return { caseId, candidateId: "candidate", partition: "train", passed: false, score: 0.5, correctness: 0, grounding: 0, coverage: 1, resilience: 1, usefulness: 0, specialistCoverage: 1, blockers };
}
