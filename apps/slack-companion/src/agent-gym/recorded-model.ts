import { AgentGymContractError } from "./contract-error.js";
import {
  agentGymModelRequestDigest,
  type AgentGymModelInvocationRequestV1,
  type AgentGymModelPort,
  type AgentGymModelResponseV1,
  type AgentGymRecordedModelResponseV1,
  validateAgentGymModelRequest,
  validateAgentGymModelResponse,
  validateAgentGymRecordedModelResponse,
} from "./model-runtime.js";

/** Serves exact recorded outputs through the same provider-neutral model port. */
export class RecordedAgentGymModel implements AgentGymModelPort {
  readonly #responses: ReadonlyMap<string, AgentGymRecordedModelResponseV1>;

  constructor(responses: readonly AgentGymRecordedModelResponseV1[]) {
    if (!Array.isArray(responses) || responses.length < 1 || responses.length > 10_000) {
      invalidFixtures();
    }
    const byDigest = new Map<string, AgentGymRecordedModelResponseV1>();
    for (const rawResponse of responses) {
      const response = validateAgentGymRecordedModelResponse(rawResponse);
      if (byDigest.has(response.request_digest)) invalidFixtures();
      byDigest.set(response.request_digest, response);
    }
    this.#responses = byDigest;
  }

  async invoke(
    rawRequest: AgentGymModelInvocationRequestV1,
  ): Promise<AgentGymModelResponseV1> {
    const request = validateAgentGymModelRequest(rawRequest);
    const requestDigest = agentGymModelRequestDigest(request);
    const recorded = this.#responses.get(requestDigest);
    if (recorded === undefined) missingFixture();
    if (recorded.invocation_ref !== request.invocation_ref
      || recorded.model_id !== request.model_id) invalidBinding();
    return validateAgentGymModelResponse({
      ...recorded,
      response_source: "recorded",
      schema_version: "agent-gym-model-response/v1",
    });
  }
}

function invalidFixtures(): never {
  throw new AgentGymContractError("Agent gym recorded model fixtures are invalid.");
}

function missingFixture(): never {
  throw new AgentGymContractError("Agent gym recorded model fixture is missing.");
}

function invalidBinding(): never {
  throw new AgentGymContractError("Agent gym recorded model binding is invalid.");
}
