import assert from "node:assert/strict";
import test from "node:test";
import { blindResponseOrder } from "../src/learning/assistant-offline-judge.js";
import {
  frontierDeliberationPolicyContext,
  frontierPromotionEligibleCandidateIds,
  selectDiverseFrontierCases,
} from "../src/learning/assistant-frontier-eval.js";
import { parseAssistantHardCorpusLine, type AssistantHardCorpusCase } from "../src/learning/assistant-hillclimb.js";

function corpusCase(id: string, partition: AssistantHardCorpusCase["partition"] = "train") {
  return parseAssistantHardCorpusLine({
    schemaVersion: 1,
    id,
    partition,
    challenge: id,
    difficulty: 5,
    senderKind: "human",
    question: `Handle ${id}`,
    threadContext: [],
    evidence: [],
    assignedRoles: [],
    expectations: { outcome: "respond" },
  });
}

test("frontier selection interleaves live, adversarial, and static cases", () => {
  const cases = [
    corpusCase("live-one"), corpusCase("live-two"),
    corpusCase("adversarial-train-one"), corpusCase("adversarial-train-two"),
    corpusCase("static-one"), corpusCase("static-two"),
  ];
  const selected = selectDiverseFrontierCases(cases, 6, "round-one");
  assert.equal(selected.length, 6);
  assert.match(selected[0]!.id, /^live-/);
  assert.match(selected[1]!.id, /^adversarial-/);
  assert.match(selected[2]!.id, /^static-/);
});

test("independent judge salts rotate anonymous response order", () => {
  const candidates = ["production", "policy-one", "policy-two", "policy-three"];
  const first = blindResponseOrder("case-1", candidates, "security-principal-v1");
  const second = blindResponseOrder("case-1", candidates, "teammate-operator-v1");
  assert.deepEqual(new Set(first), new Set(candidates));
  assert.deepEqual(new Set(second), new Set(candidates));
  assert.notDeepEqual(first, second);
});

test("diverse development selection never pulls from a caller-excluded held-out set", () => {
  const development = [corpusCase("train-one", "train"), corpusCase("validation-one", "validation")];
  const heldOut = corpusCase("held-out-secret", "held_out");
  const selected = selectDiverseFrontierCases(development, 20, "sealed");
  assert.equal(selected.some((item) => item.id === heldOut.id), false);
  assert.deepEqual(selected.map((item) => item.partition).sort(), ["train", "validation"]);
});

test("held-out deliberation identifies the anonymous incumbent and eligible challengers", () => {
  const context = frontierDeliberationPolicyContext("held_out", ["challenger-two", "production", "challenger-one"]);
  assert.equal(context.incumbentLabel, context.labelByCandidate.production);
  assert.deepEqual(new Set(context.challengerLabels), new Set([
    context.labelByCandidate["challenger-one"],
    context.labelByCandidate["challenger-two"],
  ]));
  assert.equal(context.challengerLabels.includes(context.incumbentLabel ?? ""), false);
});

test("promotion requires static and shadow agreement or a shadow-tested repair", () => {
  assert.deepEqual(frontierPromotionEligibleCandidateIds({
    staticPromotionReady: true,
    validationFinalistId: "validation-finalist",
    repairCandidateIds: ["repair-one"],
  }), ["validation-finalist"]);
  assert.deepEqual(frontierPromotionEligibleCandidateIds({
    staticPromotionReady: false,
    validationFinalistId: "validation-finalist",
    repairCandidateIds: ["repair-one", "repair-two", "repair-one"],
  }), ["repair-one", "repair-two"]);
  assert.deepEqual(frontierPromotionEligibleCandidateIds({
    staticPromotionReady: true,
    validationFinalistId: "production",
    repairCandidateIds: [],
  }), []);
});
