import { AgentGymContractError } from "./contract-error.js";
import { createAgentGymCorpusManifest } from "./corpus-manifest.js";
import { validateAgentGymFixtureCase, type AgentGymFixtureCaseV1 } from "./fixture-case.js";

type Partition = AgentGymFixtureCaseV1["partition"];

export interface AgentGymCorpusCoveragePolicyV1 {
  readonly minimum_partition_cases: Readonly<Record<Partition, number>>;
  readonly policy_ref: string;
  readonly required_slices: readonly {
    readonly label: string;
    readonly minimum_case_count: number;
    readonly partition: Partition;
  }[];
  readonly schema_version: "agent-gym-corpus-coverage-policy/v1";
}

export interface AgentGymCorpusCoverageGapV1 {
  readonly actual_case_count: number;
  readonly gap_code: "corpus.partition_underfilled" | "corpus.slice_underfilled";
  readonly label?: string;
  readonly minimum_case_count: number;
  readonly partition: Partition;
}

export interface AgentGymCorpusCoverageReportV1 {
  readonly corpus_digest: string;
  readonly gaps: readonly AgentGymCorpusCoverageGapV1[];
  readonly passed: boolean;
  readonly policy_ref: string;
  readonly schema_version: "agent-gym-corpus-coverage-report/v1";
}

/** Evaluates explicit partition and label-slice coverage requirements. */
export function evaluateAgentGymCorpusCoverage(
  fixtures: readonly AgentGymFixtureCaseV1[],
  policy: AgentGymCorpusCoveragePolicyV1,
): AgentGymCorpusCoverageReportV1 {
  validatePolicy(policy);
  const manifest = createAgentGymCorpusManifest(fixtures);
  const values = fixtures.map(validateAgentGymFixtureCase);
  const gaps: AgentGymCorpusCoverageGapV1[] = [];
  for (const partition of ["held_out", "shadow", "train"] as const) {
    const actual = values.filter((fixture) => fixture.partition === partition).length;
    const minimum = policy.minimum_partition_cases[partition];
    if (actual < minimum) gaps.push({
      actual_case_count: actual,
      gap_code: "corpus.partition_underfilled",
      minimum_case_count: minimum,
      partition,
    });
  }
  for (const slice of policy.required_slices) {
    const actual = values.filter((fixture) =>
      fixture.partition === slice.partition && fixture.labels.includes(slice.label)
    ).length;
    if (actual < slice.minimum_case_count) gaps.push({
      actual_case_count: actual,
      gap_code: "corpus.slice_underfilled",
      label: slice.label,
      minimum_case_count: slice.minimum_case_count,
      partition: slice.partition,
    });
  }
  return Object.freeze({
    corpus_digest: manifest.corpus_digest,
    gaps: Object.freeze(gaps.map((gap) => Object.freeze(gap))),
    passed: gaps.length === 0,
    policy_ref: policy.policy_ref,
    schema_version: "agent-gym-corpus-coverage-report/v1",
  });
}

function validatePolicy(policy: AgentGymCorpusCoveragePolicyV1): void {
  if (policy.schema_version !== "agent-gym-corpus-coverage-policy/v1"
    || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(policy.policy_ref)
    || policy.policy_ref.length > 240
    || policy.required_slices.length > 256) invalid();
  for (const partition of ["held_out", "shadow", "train"] as const) {
    count(policy.minimum_partition_cases[partition], true);
  }
  const identities = new Set<string>();
  for (const slice of policy.required_slices) {
    if (!["held_out", "shadow", "train"].includes(slice.partition)
      || !slice.label.trim() || slice.label.length > 160
      || /[\u0000-\u001f\u007f]/u.test(slice.label)) invalid();
    count(slice.minimum_case_count, false);
    const identity = `${slice.partition}\0${slice.label}`;
    if (identities.has(identity)) invalid();
    identities.add(identity);
  }
}

function count(value: number, allowZero: boolean): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > 100_000) invalid();
}

function invalid(): never {
  throw new AgentGymContractError("Agent gym corpus coverage policy is invalid.");
}
