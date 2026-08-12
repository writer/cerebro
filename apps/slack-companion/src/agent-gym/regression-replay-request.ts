import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRegressionCorpusAugmentation, type AgentGymRegressionCorpusAugmentationV1 } from "./regression-corpus-augmentation.js";
import { validateAgentGymRegressionFixtureReceipt, type AgentGymRegressionFixtureReceiptV1 } from "./regression-fixture.js";
import { validateAgentGymRegressionLearningCandidate, type AgentGymRegressionLearningCandidateV1 } from "./regression-learning-candidate.js";

export interface AgentGymRegressionReplayRequestV1 {
  readonly augmentation_digest: string;
  readonly baseline_candidate_ref: string;
  readonly case_digest: string;
  readonly case_ref: string;
  readonly challenger_candidate_ref: string;
  readonly fixture_receipt_digest: string;
  readonly maximum_model_calls: number;
  readonly planned_at: string;
  readonly request_digest: string;
  readonly request_ref: string;
  readonly schema_version: "agent-gym-regression-replay-request/v1";
}

/** Requests paired replay after a regression is safely appended to training data. */
export function requestAgentGymRegressionReplay(
  candidateValue: AgentGymRegressionLearningCandidateV1,
  fixtureReceiptValue: AgentGymRegressionFixtureReceiptV1,
  augmentationValue: AgentGymRegressionCorpusAugmentationV1,
  input: Pick<AgentGymRegressionReplayRequestV1,
    "challenger_candidate_ref" | "maximum_model_calls" | "planned_at" | "request_ref">,
): AgentGymRegressionReplayRequestV1 {
  const candidate = validateAgentGymRegressionLearningCandidate(candidateValue);
  const receipt = validateAgentGymRegressionFixtureReceipt(fixtureReceiptValue);
  const augmentation = validateAgentGymRegressionCorpusAugmentation(augmentationValue);
  reference(input.challenger_candidate_ref); reference(input.request_ref); timestamp(input.planned_at);
  if (!Number.isSafeInteger(input.maximum_model_calls) || input.maximum_model_calls < 2 || input.maximum_model_calls > 10_000
    || input.challenger_candidate_ref === candidate.expected_candidate_ref
    || receipt.candidate_digest !== candidate.candidate_digest
    || augmentation.fixture_receipt_digest !== receipt.receipt_digest
    || augmentation.added_case_digest !== receipt.fixture_digest
    || augmentation.added_case_ref !== receipt.fixture.case_ref) invalid();
  const body = {
    augmentation_digest: augmentation.augmentation_digest,
    baseline_candidate_ref: candidate.expected_candidate_ref,
    case_digest: receipt.fixture_digest,
    case_ref: receipt.fixture.case_ref,
    challenger_candidate_ref: input.challenger_candidate_ref,
    fixture_receipt_digest: receipt.receipt_digest,
    maximum_model_calls: input.maximum_model_calls,
    planned_at: input.planned_at,
    request_ref: input.request_ref,
    schema_version: "agent-gym-regression-replay-request/v1" as const,
  };
  return Object.freeze({ ...body, request_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionReplayRequest(value: AgentGymRegressionReplayRequestV1): AgentGymRegressionReplayRequestV1 {
  if (value.schema_version !== "agent-gym-regression-replay-request/v1") invalid();
  for (const ref of [value.baseline_candidate_ref, value.case_ref, value.challenger_candidate_ref, value.request_ref]) reference(ref);
  for (const item of [value.augmentation_digest, value.case_digest, value.fixture_receipt_digest, value.request_digest]) digest(item);
  timestamp(value.planned_at);
  if (value.baseline_candidate_ref === value.challenger_candidate_ref || !Number.isSafeInteger(value.maximum_model_calls)
    || value.maximum_model_calls < 2 || value.maximum_model_calls > 10_000) invalid();
  const { request_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.request_digest) invalid();
  return Object.freeze({ ...value });
}

function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression replay request is invalid."); }
