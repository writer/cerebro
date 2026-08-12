import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  agentGymFixtureCaseDigest,
  validateAgentGymFixtureCase,
  type AgentGymFixtureCaseV1,
} from "./fixture-case.js";

export interface AgentGymCorpusManifestCaseV1 {
  readonly case_digest: string;
  readonly case_ref: string;
  readonly labels: readonly string[];
  readonly partition: AgentGymFixtureCaseV1["partition"];
}

export interface AgentGymCorpusManifestV1 {
  readonly case_count: number;
  readonly cases: readonly AgentGymCorpusManifestCaseV1[];
  readonly corpus_digest: string;
  readonly schema_version: "agent-gym-corpus-manifest/v1";
}

/** Builds an order-independent manifest for one validated evaluation corpus. */
export function createAgentGymCorpusManifest(
  fixtures: readonly AgentGymFixtureCaseV1[],
): AgentGymCorpusManifestV1 {
  if (fixtures.length === 0 || fixtures.length > 100_000) invalid();
  const cases = fixtures.map((fixture) => {
    const value = validateAgentGymFixtureCase(fixture);
    return Object.freeze({
      case_digest: agentGymFixtureCaseDigest(value),
      case_ref: value.case_ref,
      labels: Object.freeze([...value.labels].sort()),
      partition: value.partition,
    });
  }).sort((left, right) => left.case_ref.localeCompare(right.case_ref));
  if (new Set(cases.map((entry) => entry.case_ref)).size !== cases.length) invalid();
  const body = {
    case_count: cases.length,
    cases,
    schema_version: "agent-gym-corpus-manifest/v1" as const,
  };
  return Object.freeze({
    ...body,
    cases: Object.freeze(cases),
    corpus_digest: digestAgentGymJson(body),
  });
}

function invalid(): never {
  throw new AgentGymContractError("Agent gym corpus manifest is invalid.");
}
