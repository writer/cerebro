import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { agentGymFixtureCaseDigest, agentGymFixtureScenarioDigest, validateAgentGymFixtureCase, type AgentGymFixtureCaseV1 } from "./fixture-case.js";
import { validateAgentGymRegressionDuplicateReport, type AgentGymRegressionDuplicateReportV1 } from "./regression-duplicate-report.js";
import { validateAgentGymRegressionLearningCandidate, type AgentGymRegressionLearningCandidateV1 } from "./regression-learning-candidate.js";
import { validateAgentGymRegressionSanitization, type AgentGymRegressionSanitizationV1 } from "./regression-sanitization.js";

export interface AgentGymRegressionFixtureReceiptV1 {
  readonly candidate_digest: string;
  readonly duplicate_report_digest: string;
  readonly fixture: AgentGymFixtureCaseV1;
  readonly fixture_digest: string;
  readonly receipt_digest: string;
  readonly receipt_ref: string;
  readonly sanitization_verification_digest: string;
  readonly schema_version: "agent-gym-regression-fixture-receipt/v1";
}

/** Builds a training fixture only after sanitization and duplicate admission. */
export function buildAgentGymRegressionFixture(
  candidateValue: AgentGymRegressionLearningCandidateV1,
  sanitizationValue: AgentGymRegressionSanitizationV1,
  reportValue: AgentGymRegressionDuplicateReportV1,
  fixtureValue: AgentGymFixtureCaseV1,
  receiptRef: string,
): AgentGymRegressionFixtureReceiptV1 {
  const candidate = validateAgentGymRegressionLearningCandidate(candidateValue);
  const sanitization = validateAgentGymRegressionSanitization(sanitizationValue);
  const report = validateAgentGymRegressionDuplicateReport(reportValue);
  const fixture = validateAgentGymFixtureCase(fixtureValue);
  reference(receiptRef);
  if (!report.admissible || sanitization.candidate_digest !== candidate.candidate_digest
    || report.sanitization_verification_digest !== sanitization.verification_digest
    || fixture.partition !== "train" || agentGymFixtureScenarioDigest(fixture) !== sanitization.sanitized_scenario_digest
    || candidate.failure_labels.some((label) => !fixture.labels.includes(label))) invalid();
  const fixtureDigest = agentGymFixtureCaseDigest(fixture);
  const body = {
    candidate_digest: candidate.candidate_digest,
    duplicate_report_digest: report.report_digest,
    fixture: fixtureBody(fixture),
    fixture_digest: fixtureDigest,
    receipt_ref: receiptRef,
    sanitization_verification_digest: sanitization.verification_digest,
    schema_version: "agent-gym-regression-fixture-receipt/v1" as const,
  };
  return Object.freeze({ ...body, receipt_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionFixtureReceipt(value: AgentGymRegressionFixtureReceiptV1): AgentGymRegressionFixtureReceiptV1 {
  if (value.schema_version !== "agent-gym-regression-fixture-receipt/v1") invalid();
  reference(value.receipt_ref);
  for (const item of [value.candidate_digest, value.duplicate_report_digest, value.fixture_digest,
    value.sanitization_verification_digest, value.receipt_digest]) digest(item);
  const fixture = validateAgentGymFixtureCase(value.fixture);
  if (fixture.partition !== "train" || agentGymFixtureCaseDigest(fixture) !== value.fixture_digest) invalid();
  const body = {
    candidate_digest: value.candidate_digest, duplicate_report_digest: value.duplicate_report_digest,
    fixture: fixtureBody(fixture), fixture_digest: value.fixture_digest, receipt_ref: value.receipt_ref,
    sanitization_verification_digest: value.sanitization_verification_digest, schema_version: value.schema_version,
  };
  if (digestAgentGymJson(body) !== value.receipt_digest) invalid();
  return Object.freeze({ ...value, fixture });
}

function fixtureBody(value: AgentGymFixtureCaseV1) {
  return {
    case_ref: value.case_ref,
    expected_invariants: [...value.expected_invariants],
    labels: [...value.labels],
    partition: value.partition,
    schema_version: value.schema_version,
    slack_events: value.slack_events.map((event) => ({
      event_ref: event.event_ref, kind: event.kind, occurred_at: event.occurred_at, payload: event.payload,
    })),
    tool_fixtures: value.tool_fixtures.map((tool) => ({
      call_ref: tool.call_ref, ...(tool.error_code === undefined ? {} : { error_code: tool.error_code }),
      input: tool.input, outcome: tool.outcome, ...(tool.output === undefined ? {} : { output: tool.output }), tool_id: tool.tool_id,
    })),
  };
}

function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression fixture receipt is invalid."); }
