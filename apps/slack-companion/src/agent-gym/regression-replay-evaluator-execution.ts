import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRegressionReplayEvaluatorInput, validateAgentGymRegressionReplayEvaluatorOutput,
  type AgentGymRegressionReplayEvaluatorInputV1, type AgentGymRegressionReplayEvaluatorOutputV1,
  type AgentGymRegressionReplayEvaluatorPort } from "./regression-replay-evaluator-port.js";

export interface AgentGymRegressionReplayEvaluatorExecutionV1 {
  readonly binding_digest: string;
  readonly outputs: readonly [AgentGymRegressionReplayEvaluatorOutputV1, AgentGymRegressionReplayEvaluatorOutputV1];
  readonly schema_version: "agent-gym-regression-replay-evaluator-execution/v1";
}

/** Evaluates baseline then challenger through the same admitted evaluator port. */
export async function executeAgentGymRegressionReplayEvaluators(
  inputValues: readonly [AgentGymRegressionReplayEvaluatorInputV1, AgentGymRegressionReplayEvaluatorInputV1],
  evaluator: AgentGymRegressionReplayEvaluatorPort,
): Promise<AgentGymRegressionReplayEvaluatorExecutionV1> {
  if (!Array.isArray(inputValues) || inputValues.length !== 2) invalid();
  const inputs = inputValues.map(validateAgentGymRegressionReplayEvaluatorInput);
  if (inputs[0]!.binding_digest !== inputs[1]!.binding_digest
    || inputs[0]!.candidate_ref === inputs[1]!.candidate_ref) invalid();
  const outputs: AgentGymRegressionReplayEvaluatorOutputV1[] = [];
  for (const input of inputs) {
    const output = validateAgentGymRegressionReplayEvaluatorOutput(await evaluator.evaluate(input));
    if (output.binding_digest !== input.binding_digest || output.candidate_ref !== input.candidate_ref) invalid();
    outputs.push(output);
  }
  return Object.freeze({ binding_digest: inputs[0]!.binding_digest,
    outputs: Object.freeze([outputs[0]!, outputs[1]!] as const),
    schema_version: "agent-gym-regression-replay-evaluator-execution/v1" });
}

function invalid(): never { throw new AgentGymContractError("Agent gym regression replay evaluator execution is invalid."); }
