import { AgentGymContractError } from "./contract-error.js";

export interface AgentGymRegressionReplayEvaluatorInputV1 {
  readonly binding_digest: string;
  readonly candidate_ref: string;
  readonly case_ref: string;
  readonly evaluator_digests: readonly string[];
  readonly output_text: string;
  readonly response_digest: string;
  readonly rubric_digest: string;
  readonly schema_version: "agent-gym-regression-replay-evaluator-input/v1";
}

export interface AgentGymRegressionReplayEvaluatorOutputV1 {
  readonly binding_digest: string;
  readonly blocker_codes: readonly string[];
  readonly candidate_ref: string;
  readonly evidence_digest: string;
  readonly safety_passed: boolean;
  readonly schema_version: "agent-gym-regression-replay-evaluator-output/v1";
  readonly score: number;
}

export interface AgentGymRegressionReplayEvaluatorPort {
  evaluate(input: AgentGymRegressionReplayEvaluatorInputV1): Promise<AgentGymRegressionReplayEvaluatorOutputV1>;
}

/** Validates one transient candidate answer before evaluator execution. */
export function validateAgentGymRegressionReplayEvaluatorInput(value: AgentGymRegressionReplayEvaluatorInputV1): AgentGymRegressionReplayEvaluatorInputV1 {
  if (value.schema_version !== "agent-gym-regression-replay-evaluator-input/v1") invalidInput();
  reference(value.candidate_ref, invalidInput); reference(value.case_ref, invalidInput);
  digest(value.binding_digest, invalidInput); digest(value.response_digest, invalidInput); digest(value.rubric_digest, invalidInput);
  if (!Array.isArray(value.evaluator_digests) || value.evaluator_digests.length < 1 || value.evaluator_digests.length > 2
    || new Set(value.evaluator_digests).size !== value.evaluator_digests.length) invalidInput();
  value.evaluator_digests.forEach((item) => digest(item, invalidInput));
  if (typeof value.output_text !== "string" || !value.output_text.trim() || value.output_text.length > 256_000
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value.output_text)) invalidInput();
  return Object.freeze({ ...value, evaluator_digests: Object.freeze([...value.evaluator_digests]) });
}

/** Fails malformed or internally inconsistent evaluator output closed. */
export function validateAgentGymRegressionReplayEvaluatorOutput(value: AgentGymRegressionReplayEvaluatorOutputV1): AgentGymRegressionReplayEvaluatorOutputV1 {
  if (value.schema_version !== "agent-gym-regression-replay-evaluator-output/v1") invalidOutput();
  reference(value.candidate_ref, invalidOutput); digest(value.binding_digest, invalidOutput); digest(value.evidence_digest, invalidOutput);
  if (!Number.isFinite(value.score) || value.score < 0 || value.score > 1 || typeof value.safety_passed !== "boolean"
    || !Array.isArray(value.blocker_codes) || value.blocker_codes.length > 100
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || value.blocker_codes.some((code) => !/^[a-z][a-z0-9_.-]{0,79}$/u.test(code))
    || value.safety_passed !== (value.blocker_codes.length === 0)) invalidOutput();
  return Object.freeze({ ...value, blocker_codes: Object.freeze([...value.blocker_codes].sort()) });
}

function reference(value: string, invalid: () => never): void { if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid(); }
function digest(value: string, invalid: () => never): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalidInput(): never { throw new AgentGymContractError("Agent gym regression replay evaluator input is invalid."); }
function invalidOutput(): never { throw new AgentGymContractError("Agent gym regression replay evaluator output is invalid."); }
