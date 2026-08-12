import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymCorpusQualityReceiptV1 } from "./corpus-quality.js";
import { createAgentGymCorpusManifest } from "./corpus-manifest.js";
import type { AgentGymEvaluatorAdmissionDecisionV1 } from "./evaluator-admission.js";
import type { AgentGymFixtureCaseV1 } from "./fixture-case.js";

export type AgentGymEvaluationPartition = "held_out" | "shadow";

export interface AgentGymEvaluationSuiteCaseV1 {
  readonly case_digest: string;
  readonly case_ref: string;
  readonly labels: readonly string[];
  readonly partition: AgentGymEvaluationPartition;
}

export interface AgentGymEvaluationSuiteV1 {
  readonly case_count: number;
  readonly case_set_digest: string;
  readonly cases: readonly AgentGymEvaluationSuiteCaseV1[];
  readonly corpus_digest: string;
  readonly corpus_quality_receipt_digest: string;
  readonly evaluator_admission_decision_digest: string;
  readonly evaluator_digests: readonly string[];
  readonly partitions: readonly AgentGymEvaluationPartition[];
  readonly rubric_digest: string;
  readonly schema_version: "agent-gym-evaluation-suite/v1";
  readonly suite_digest: string;
  readonly suite_ref: string;
}

/** Seals the non-training cases and admitted evaluators used by a comparison. */
export function defineAgentGymEvaluationSuite(
  fixtures: readonly AgentGymFixtureCaseV1[],
  quality: AgentGymCorpusQualityReceiptV1,
  evaluatorAdmission: AgentGymEvaluatorAdmissionDecisionV1,
  input: {
    readonly partitions: readonly AgentGymEvaluationPartition[];
    readonly suite_ref: string;
  },
): AgentGymEvaluationSuiteV1 {
  reference(input.suite_ref);
  validateQuality(quality);
  validateEvaluatorAdmission(evaluatorAdmission);
  if (!quality.admitted || !evaluatorAdmission.admitted) invalid();
  if (!Array.isArray(input.partitions) || input.partitions.length === 0
    || input.partitions.length > 2 || new Set(input.partitions).size !== input.partitions.length
    || input.partitions.some((value) => !["held_out", "shadow"].includes(value))) invalid();
  const manifest = createAgentGymCorpusManifest(fixtures);
  if (manifest.corpus_digest !== quality.corpus_digest
    || evaluatorAdmission.rubric_digest.length === 0) invalid();
  const partitions = [...input.partitions].sort();
  const cases = manifest.cases.filter((entry): entry is typeof entry & {
    readonly partition: AgentGymEvaluationPartition;
  } => partitions.includes(entry.partition as AgentGymEvaluationPartition)).map((entry) => Object.freeze({
    case_digest: entry.case_digest,
    case_ref: entry.case_ref,
    labels: Object.freeze([...entry.labels]),
    partition: entry.partition,
  }));
  if (cases.length === 0
    || partitions.some((partition) => !cases.some((entry) => entry.partition === partition))) invalid();
  const caseSetBody = cases.map((entry) => ({
    case_digest: entry.case_digest,
    case_ref: entry.case_ref,
    labels: [...entry.labels],
    partition: entry.partition,
  }));
  const body = {
    case_count: cases.length,
    case_set_digest: digestAgentGymJson(caseSetBody),
    cases: caseSetBody,
    corpus_digest: manifest.corpus_digest,
    corpus_quality_receipt_digest: quality.receipt_digest,
    evaluator_admission_decision_digest: evaluatorAdmission.decision_digest,
    evaluator_digests: [...evaluatorAdmission.evaluator_digests],
    partitions,
    rubric_digest: evaluatorAdmission.rubric_digest,
    schema_version: "agent-gym-evaluation-suite/v1" as const,
    suite_ref: input.suite_ref,
  };
  return Object.freeze({
    ...body,
    cases: Object.freeze(cases),
    evaluator_digests: Object.freeze(body.evaluator_digests),
    partitions: Object.freeze(partitions),
    suite_digest: digestAgentGymJson(body),
  });
}

function validateQuality(value: AgentGymCorpusQualityReceiptV1): void {
  if (value.schema_version !== "agent-gym-corpus-quality-receipt/v1") invalid();
  const body = {
    admitted: value.admitted,
    admission_decision_digest: value.admission_decision_digest,
    blocker_codes: value.blocker_codes,
    build_receipt_digest: value.build_receipt_digest,
    corpus_digest: value.corpus_digest,
    evaluated_at: value.evaluated_at,
    evaluation_ref: value.evaluation_ref,
    schema_version: value.schema_version,
  };
  if (digestAgentGymJson(body) !== value.receipt_digest) invalid();
}

function validateEvaluatorAdmission(value: AgentGymEvaluatorAdmissionDecisionV1): void {
  if (value.schema_version !== "agent-gym-evaluator-admission-decision/v1") invalid();
  const body = {
    admitted: value.admitted,
    blocker_codes: value.blocker_codes,
    calibration_digests: value.calibration_digests,
    decided_at: value.decided_at,
    evaluator_digests: value.evaluator_digests,
    policy_ref: value.policy_ref,
    rubric_digest: value.rubric_digest,
    schema_version: value.schema_version,
  };
  if (digestAgentGymJson(body) !== value.decision_digest) invalid();
}

function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym evaluation suite is invalid.");
}
