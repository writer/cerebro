import { createAgentGymCorpusManifest } from "./corpus-manifest.js";
import {
  agentGymFixtureScenarioDigest,
  validateAgentGymFixtureCase,
  type AgentGymFixtureCaseV1,
} from "./fixture-case.js";

export interface AgentGymCorpusLeakageFindingV1 {
  readonly case_refs: readonly string[];
  readonly finding_code: "corpus.duplicate_scenario" | "corpus.partition_leakage";
  readonly partitions: readonly AgentGymFixtureCaseV1["partition"][];
  readonly scenario_digest: string;
}

export interface AgentGymCorpusLeakageReportV1 {
  readonly corpus_digest: string;
  readonly findings: readonly AgentGymCorpusLeakageFindingV1[];
  readonly passed: boolean;
  readonly schema_version: "agent-gym-corpus-leakage-report/v1";
}

/** Finds repeated scenarios, including train-to-evaluation partition leakage. */
export function auditAgentGymCorpusLeakage(
  fixtures: readonly AgentGymFixtureCaseV1[],
): AgentGymCorpusLeakageReportV1 {
  const manifest = createAgentGymCorpusManifest(fixtures);
  const scenarios = new Map<string, { case_ref: string; partition: AgentGymFixtureCaseV1["partition"] }[]>();
  for (const fixture of fixtures) {
    const value = validateAgentGymFixtureCase(fixture);
    const digest = agentGymFixtureScenarioDigest(value);
    const entries = scenarios.get(digest) ?? [];
    entries.push({ case_ref: value.case_ref, partition: value.partition });
    scenarios.set(digest, entries);
  }
  const findings = [...scenarios.entries()]
    .filter(([, entries]) => entries.length > 1)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([scenario_digest, entries]) => {
      const partitions = [...new Set(entries.map((entry) => entry.partition))].sort();
      return Object.freeze({
        case_refs: Object.freeze(entries.map((entry) => entry.case_ref).sort()),
        finding_code: partitions.length > 1
          ? "corpus.partition_leakage" as const
          : "corpus.duplicate_scenario" as const,
        partitions: Object.freeze(partitions),
        scenario_digest,
      });
    });
  return Object.freeze({
    corpus_digest: manifest.corpus_digest,
    findings: Object.freeze(findings),
    passed: findings.length === 0,
    schema_version: "agent-gym-corpus-leakage-report/v1",
  });
}
