import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";

export interface AgentGymEvaluatorModelBindingV1 {
  readonly inference_config_digest: string;
  readonly model_ref: string;
}

export interface AgentGymEvaluatorManifestV1 {
  readonly evaluator_digest: string;
  readonly evaluator_kind: "deterministic" | "model_judge";
  readonly evaluator_ref: string;
  readonly implementation_digest: string;
  readonly model?: AgentGymEvaluatorModelBindingV1;
  readonly output_schema_digest: string;
  readonly rubric_digest: string;
  readonly schema_version: "agent-gym-evaluator-manifest/v1";
}

export type AgentGymEvaluatorManifestInputV1 = Omit<AgentGymEvaluatorManifestV1, "evaluator_digest">;

/** Seals evaluator code, output schema, rubric, and optional model configuration. */
export function defineAgentGymEvaluatorManifest(
  input: AgentGymEvaluatorManifestInputV1,
): AgentGymEvaluatorManifestV1 {
  if (input.schema_version !== "agent-gym-evaluator-manifest/v1"
    || !["deterministic", "model_judge"].includes(input.evaluator_kind)) invalid();
  reference(input.evaluator_ref);
  for (const value of [input.implementation_digest, input.output_schema_digest, input.rubric_digest]) digest(value);
  if ((input.evaluator_kind === "model_judge") !== (input.model !== undefined)) invalid();
  const model = input.model === undefined ? undefined : validateModel(input.model);
  const modelBody = model === undefined ? undefined : {
    inference_config_digest: model.inference_config_digest,
    model_ref: model.model_ref,
  };
  const body = {
    evaluator_kind: input.evaluator_kind,
    evaluator_ref: input.evaluator_ref,
    implementation_digest: input.implementation_digest,
    ...(modelBody === undefined ? {} : { model: modelBody }),
    output_schema_digest: input.output_schema_digest,
    rubric_digest: input.rubric_digest,
    schema_version: input.schema_version,
  };
  return Object.freeze({
    ...body,
    ...(modelBody === undefined ? {} : { model: Object.freeze(modelBody) }),
    evaluator_digest: digestAgentGymJson(body),
  });
}

function validateModel(value: AgentGymEvaluatorModelBindingV1): AgentGymEvaluatorModelBindingV1 {
  reference(value.model_ref);
  digest(value.inference_config_digest);
  return { ...value };
}

function digest(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym evaluator manifest is invalid.");
}
