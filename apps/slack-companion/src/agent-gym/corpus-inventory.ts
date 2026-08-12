import {
  createAgentGymCorpusManifest,
  type AgentGymCorpusManifestV1,
} from "./corpus-manifest.js";
import type { AgentGymFixtureCaseV1 } from "./fixture-case.js";

export interface AgentGymCorpusInventoryV1 {
  readonly case_count: number;
  readonly corpus_digest: string;
  readonly labels: readonly {
    readonly case_count: number;
    readonly label: string;
  }[];
  readonly partitions: Readonly<Record<AgentGymFixtureCaseV1["partition"], number>>;
  readonly schema_version: "agent-gym-corpus-inventory/v1";
}

/** Counts the exact partitions and labels represented by a corpus. */
export function createAgentGymCorpusInventory(
  fixtures: readonly AgentGymFixtureCaseV1[],
): AgentGymCorpusInventoryV1 {
  return inventory(createAgentGymCorpusManifest(fixtures));
}

function inventory(manifest: AgentGymCorpusManifestV1): AgentGymCorpusInventoryV1 {
  const partitions = { held_out: 0, shadow: 0, train: 0 };
  const labels = new Map<string, number>();
  for (const entry of manifest.cases) {
    partitions[entry.partition] += 1;
    for (const label of entry.labels) labels.set(label, (labels.get(label) ?? 0) + 1);
  }
  return Object.freeze({
    case_count: manifest.case_count,
    corpus_digest: manifest.corpus_digest,
    labels: Object.freeze([...labels].sort(([left], [right]) => left.localeCompare(right))
      .map(([label, case_count]) => Object.freeze({ case_count, label }))),
    partitions: Object.freeze(partitions),
    schema_version: "agent-gym-corpus-inventory/v1",
  });
}
