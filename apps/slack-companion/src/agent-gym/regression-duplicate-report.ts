import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { agentGymFixtureScenarioDigest, validateAgentGymFixtureCase, type AgentGymFixtureCaseV1 } from "./fixture-case.js";
import { validateAgentGymRegressionSanitization, type AgentGymRegressionSanitizationV1 } from "./regression-sanitization.js";

export interface AgentGymRegressionDuplicateReportV1 {
  readonly admissible: boolean;
  readonly duplicate_case_refs: readonly string[];
  readonly inspected_case_count: number;
  readonly report_digest: string;
  readonly report_ref: string;
  readonly sanitized_scenario_digest: string;
  readonly sanitization_verification_digest: string;
  readonly schema_version: "agent-gym-regression-duplicate-report/v1";
}

/** Detects scenario leakage before a sanitized regression enters any corpus. */
export function inspectAgentGymRegressionDuplicates(
  sanitizationValue: AgentGymRegressionSanitizationV1,
  fixturesValue: readonly AgentGymFixtureCaseV1[],
  reportRef: string,
): AgentGymRegressionDuplicateReportV1 {
  const sanitization = validateAgentGymRegressionSanitization(sanitizationValue);
  reference(reportRef);
  if (fixturesValue.length > 100_000) invalid();
  const fixtures = fixturesValue.map(validateAgentGymFixtureCase);
  if (new Set(fixtures.map((fixture) => fixture.case_ref)).size !== fixtures.length) invalid();
  const duplicates = fixtures.filter((fixture) => agentGymFixtureScenarioDigest(fixture) === sanitization.sanitized_scenario_digest)
    .map((fixture) => fixture.case_ref).sort();
  const body = {
    admissible: duplicates.length === 0,
    duplicate_case_refs: duplicates,
    inspected_case_count: fixtures.length,
    report_ref: reportRef,
    sanitized_scenario_digest: sanitization.sanitized_scenario_digest,
    sanitization_verification_digest: sanitization.verification_digest,
    schema_version: "agent-gym-regression-duplicate-report/v1" as const,
  };
  return freeze({ ...body, report_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionDuplicateReport(value: AgentGymRegressionDuplicateReportV1): AgentGymRegressionDuplicateReportV1 {
  if (value.schema_version !== "agent-gym-regression-duplicate-report/v1") invalid();
  reference(value.report_ref); digest(value.sanitized_scenario_digest); digest(value.sanitization_verification_digest); digest(value.report_digest);
  if (!Number.isSafeInteger(value.inspected_case_count) || value.inspected_case_count < 0 || value.inspected_case_count > 100_000
    || !Array.isArray(value.duplicate_case_refs) || value.duplicate_case_refs.length > value.inspected_case_count
    || new Set(value.duplicate_case_refs).size !== value.duplicate_case_refs.length
    || value.duplicate_case_refs.some((ref, index) => (reference(ref), index > 0 && ref < (value.duplicate_case_refs[index - 1] ?? "")))
    || value.admissible !== (value.duplicate_case_refs.length === 0)) invalid();
  const { report_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.report_digest) invalid();
  return freeze(value);
}

function freeze(value: AgentGymRegressionDuplicateReportV1): AgentGymRegressionDuplicateReportV1 {
  return Object.freeze({ ...value, duplicate_case_refs: Object.freeze([...value.duplicate_case_refs]) });
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression duplicate report is invalid."); }
