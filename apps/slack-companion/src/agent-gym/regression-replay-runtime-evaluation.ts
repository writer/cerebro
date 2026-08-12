import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRegressionReplayEvaluation, evaluateAgentGymRegressionReplay,
  type AgentGymRegressionReplayEvaluationV1 } from "./regression-replay-evaluation.js";
import { validateAgentGymRegressionReplayEvaluatorBinding, type AgentGymRegressionReplayEvaluatorBindingV1 } from "./regression-replay-evaluator-binding.js";
import type { AgentGymRegressionReplayEvaluatorExecutionV1 } from "./regression-replay-evaluator-execution.js";
import { validateAgentGymRegressionReplayEvaluatorOutput } from "./regression-replay-evaluator-port.js";
import { validateAgentGymRegressionReplayResult, type AgentGymRegressionReplayResultV1 } from "./regression-replay-result.js";

/** Seals validated paired evaluator output as text-free durable comparison evidence. */
export function recordExecutedAgentGymRegressionReplayEvaluation(
  resultValue: AgentGymRegressionReplayResultV1,
  bindingValue: AgentGymRegressionReplayEvaluatorBindingV1,
  execution: AgentGymRegressionReplayEvaluatorExecutionV1,
  input: Pick<AgentGymRegressionReplayEvaluationV1, "evaluated_at" | "evaluation_ref">,
): AgentGymRegressionReplayEvaluationV1 {
  const result = validateAgentGymRegressionReplayResult(resultValue);
  const binding = validateAgentGymRegressionReplayEvaluatorBinding(bindingValue);
  if (binding.replay_result_digest !== result.result_digest
    || execution.schema_version !== "agent-gym-regression-replay-evaluator-execution/v1"
    || execution.binding_digest !== binding.binding_digest || execution.outputs.length !== 2) invalid();
  const baseline = validateAgentGymRegressionReplayEvaluatorOutput(execution.outputs[0]);
  const challenger = validateAgentGymRegressionReplayEvaluatorOutput(execution.outputs[1]);
  if (baseline.candidate_ref !== result.baseline.candidate_ref
    || challenger.candidate_ref !== result.challenger.candidate_ref
    || baseline.binding_digest !== binding.binding_digest || challenger.binding_digest !== binding.binding_digest) invalid();
  return validateAgentGymRegressionReplayEvaluation(evaluateAgentGymRegressionReplay(result, {
    baseline: candidateEvaluation(baseline), challenger: candidateEvaluation(challenger),
    evaluated_at: input.evaluated_at, evaluation_ref: input.evaluation_ref,
  }));
}

function candidateEvaluation(output: ReturnType<typeof validateAgentGymRegressionReplayEvaluatorOutput>) {
  return { blocker_codes: output.blocker_codes, candidate_ref: output.candidate_ref,
    evidence_digest: output.evidence_digest, safety_passed: output.safety_passed, score: output.score };
}

function invalid(): never { throw new AgentGymContractError("Agent gym executed regression replay evaluation is invalid."); }
