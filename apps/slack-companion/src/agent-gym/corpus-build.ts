import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { createAgentGymCorpusInventory } from "./corpus-inventory.js";
import { createAgentGymCorpusManifest } from "./corpus-manifest.js";
import type { AgentGymFixtureCaseV1 } from "./fixture-case.js";

export interface AgentGymCorpusBuildInputV1 {
  readonly build_ref: string;
  readonly built_at: string;
  readonly source_revision: string;
}

export interface AgentGymCorpusBuildReceiptV1 {
  readonly build_ref: string;
  readonly built_at: string;
  readonly case_count: number;
  readonly corpus_digest: string;
  readonly inventory_digest: string;
  readonly receipt_digest: string;
  readonly schema_version: "agent-gym-corpus-build-receipt/v1";
  readonly source_revision: string;
}

/** Produces a durable receipt for the exact corpus assembled from source. */
export function buildAgentGymCorpus(
  fixtures: readonly AgentGymFixtureCaseV1[],
  input: AgentGymCorpusBuildInputV1,
): AgentGymCorpusBuildReceiptV1 {
  reference(input.build_ref, "build reference");
  reference(input.source_revision, "source revision");
  timestamp(input.built_at);
  const manifest = createAgentGymCorpusManifest(fixtures);
  const inventory = createAgentGymCorpusInventory(fixtures);
  const inventoryDigest = digestAgentGymJson({
    case_count: inventory.case_count,
    corpus_digest: inventory.corpus_digest,
    labels: inventory.labels.map((entry) => ({
      case_count: entry.case_count,
      label: entry.label,
    })),
    partitions: inventory.partitions,
    schema_version: inventory.schema_version,
  });
  const body = {
    build_ref: input.build_ref,
    built_at: input.built_at,
    case_count: manifest.case_count,
    corpus_digest: manifest.corpus_digest,
    inventory_digest: inventoryDigest,
    schema_version: "agent-gym-corpus-build-receipt/v1" as const,
    source_revision: input.source_revision,
  };
  return Object.freeze({ ...body, receipt_digest: digestAgentGymJson(body) });
}

function reference(value: string, field: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) {
    throw new AgentGymContractError(`Agent gym corpus ${field} is invalid.`);
  }
}

function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new AgentGymContractError("Agent gym corpus build timestamp is invalid.");
  }
}
