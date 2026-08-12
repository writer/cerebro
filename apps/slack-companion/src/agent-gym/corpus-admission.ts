import { digestAgentGymJson } from "./canonical-json.js";
import {
  evaluateAgentGymCorpusCoverage,
  type AgentGymCorpusCoveragePolicyV1,
} from "./corpus-coverage.js";
import { auditAgentGymCorpusLeakage } from "./corpus-leakage.js";
import type { AgentGymFixtureCaseV1 } from "./fixture-case.js";

export type AgentGymCorpusAdmissionBlockerCode =
  | "corpus.duplicate_scenario"
  | "corpus.partition_leakage"
  | "corpus.partition_underfilled"
  | "corpus.slice_underfilled";

export interface AgentGymCorpusAdmissionDecisionV1 {
  readonly admitted: boolean;
  readonly blocker_codes: readonly AgentGymCorpusAdmissionBlockerCode[];
  readonly corpus_digest: string;
  readonly coverage_gap_count: number;
  readonly coverage_policy_ref: string;
  readonly decision_digest: string;
  readonly leakage_finding_count: number;
  readonly schema_version: "agent-gym-corpus-admission-decision/v1";
}

/** Fails corpus admission closed on coverage gaps or repeated scenarios. */
export function decideAgentGymCorpusAdmission(
  fixtures: readonly AgentGymFixtureCaseV1[],
  policy: AgentGymCorpusCoveragePolicyV1,
): AgentGymCorpusAdmissionDecisionV1 {
  const coverage = evaluateAgentGymCorpusCoverage(fixtures, policy);
  const leakage = auditAgentGymCorpusLeakage(fixtures);
  const blockerCodes = [...new Set<AgentGymCorpusAdmissionBlockerCode>([
    ...coverage.gaps.map((gap) => gap.gap_code),
    ...leakage.findings.map((finding) => finding.finding_code),
  ])].sort();
  const body = {
    admitted: blockerCodes.length === 0,
    blocker_codes: blockerCodes,
    corpus_digest: coverage.corpus_digest,
    coverage_gap_count: coverage.gaps.length,
    coverage_policy_ref: coverage.policy_ref,
    leakage_finding_count: leakage.findings.length,
    schema_version: "agent-gym-corpus-admission-decision/v1" as const,
  };
  return Object.freeze({
    ...body,
    blocker_codes: Object.freeze(blockerCodes),
    decision_digest: digestAgentGymJson(body),
  });
}
