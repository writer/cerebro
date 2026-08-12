import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRollbackIncident, type AgentGymRollbackIncidentV1 } from "./rollback-incident.js";

export interface AgentGymRegressionLearningCandidateV1 {
  readonly candidate_digest: string;
  readonly candidate_ref: string;
  readonly evidence_refs: readonly string[];
  readonly expected_candidate_ref: string;
  readonly failure_labels: readonly string[];
  readonly proposed_at: string;
  readonly rollback_incident_digest: string;
  readonly schema_version: "agent-gym-regression-learning-candidate/v1";
  readonly source_case_ref: string;
  readonly target_ref: string;
}

/** Proposes a replay candidate only from a mitigated, evidence-complete regression. */
export function proposeAgentGymRegressionLearningCandidate(
  incidentValue: AgentGymRollbackIncidentV1,
  input: Pick<AgentGymRegressionLearningCandidateV1,
    "candidate_ref" | "evidence_refs" | "proposed_at" | "source_case_ref">,
): AgentGymRegressionLearningCandidateV1 {
  const incident = validateAgentGymRollbackIncident(incidentValue);
  reference(input.candidate_ref); reference(input.source_case_ref); references(input.evidence_refs); timestamp(input.proposed_at);
  if (incident.status !== "mitigated" || Date.parse(input.proposed_at) < Date.parse(incident.recorded_at)) invalid();
  const body = {
    candidate_ref: input.candidate_ref,
    evidence_refs: [...input.evidence_refs],
    expected_candidate_ref: incident.fallback_candidate_ref,
    failure_labels: [...incident.blocker_codes].sort(),
    proposed_at: input.proposed_at,
    rollback_incident_digest: incident.incident_digest,
    schema_version: "agent-gym-regression-learning-candidate/v1" as const,
    source_case_ref: input.source_case_ref,
    target_ref: incident.target_ref,
  };
  return freeze({ ...body, candidate_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionLearningCandidate(
  value: AgentGymRegressionLearningCandidateV1,
): AgentGymRegressionLearningCandidateV1 {
  if (value.schema_version !== "agent-gym-regression-learning-candidate/v1") invalid();
  for (const ref of [value.candidate_ref, value.expected_candidate_ref, value.source_case_ref, value.target_ref]) reference(ref);
  references(value.evidence_refs); timestamp(value.proposed_at);
  if (!Array.isArray(value.failure_labels) || value.failure_labels.length === 0 || value.failure_labels.length > 256
    || new Set(value.failure_labels).size !== value.failure_labels.length
    || value.failure_labels.some((label) => typeof label !== "string" || !label.trim() || label.length > 160)
    || value.failure_labels.some((label, index) => index > 0 && label < (value.failure_labels[index - 1] ?? ""))) invalid();
  digest(value.rollback_incident_digest); digest(value.candidate_digest);
  const { candidate_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.candidate_digest) invalid();
  return freeze(value);
}

function freeze(value: AgentGymRegressionLearningCandidateV1): AgentGymRegressionLearningCandidateV1 {
  return Object.freeze({ ...value, evidence_refs: Object.freeze([...value.evidence_refs]),
    failure_labels: Object.freeze([...value.failure_labels]) });
}
function references(values: readonly string[]): void {
  if (!Array.isArray(values) || values.length === 0 || values.length > 128 || new Set(values).size !== values.length) invalid();
  for (const value of values) reference(value);
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression learning candidate is invalid."); }
