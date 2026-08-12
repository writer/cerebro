import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymModelResponse } from "./model-runtime.js";
import { validateAgentGymRegressionReplayEvaluatorBinding, type AgentGymRegressionReplayEvaluatorBindingV1 } from "./regression-replay-evaluator-binding.js";
import { validateAgentGymRegressionReplayEvaluatorInput, type AgentGymRegressionReplayEvaluatorInputV1 } from "./regression-replay-evaluator-port.js";
import type { AgentGymRegressionReplayExecutionV1 } from "./regression-replay-execution.js";
import { validateAgentGymRegressionReplayResult, type AgentGymRegressionReplayResultV1 } from "./regression-replay-result.js";

/** Projects exact transient model answers into evaluator inputs without persisting text. */
export function buildAgentGymRegressionReplayEvaluatorInputs(
  bindingValue: AgentGymRegressionReplayEvaluatorBindingV1,
  resultValue: AgentGymRegressionReplayResultV1,
  execution: AgentGymRegressionReplayExecutionV1,
): readonly [AgentGymRegressionReplayEvaluatorInputV1, AgentGymRegressionReplayEvaluatorInputV1] {
  const binding = validateAgentGymRegressionReplayEvaluatorBinding(bindingValue);
  const result = validateAgentGymRegressionReplayResult(resultValue);
  if (binding.replay_result_digest !== result.result_digest
    || execution.schema_version !== "agent-gym-regression-replay-execution/v1"
    || !execution.aggregate_budget.allowed || execution.batch.results.length !== 2) invalid();
  const inputs = execution.batch.results.map((invocation, index) => {
    const expected = index === 0 ? result.baseline : result.challenger;
    const response = validateAgentGymModelResponse(invocation.response);
    if (invocation.receipt.candidate_ref !== expected.candidate_ref
      || invocation.receipt.invocation_ref !== expected.invocation_ref
      || invocation.receipt.response_digest !== expected.response_digest
      || response.invocation_ref !== invocation.receipt.invocation_ref) invalid();
    return validateAgentGymRegressionReplayEvaluatorInput({
      binding_digest: binding.binding_digest, candidate_ref: expected.candidate_ref, case_ref: result.case_ref,
      evaluator_digests: binding.evaluator_digests, output_text: response.output_text,
      response_digest: expected.response_digest, rubric_digest: binding.rubric_digest,
      schema_version: "agent-gym-regression-replay-evaluator-input/v1",
    });
  });
  return Object.freeze([inputs[0]!, inputs[1]!] as const);
}

function invalid(): never { throw new AgentGymContractError("Agent gym regression replay evaluator inputs are invalid."); }
