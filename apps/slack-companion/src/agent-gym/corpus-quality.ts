import { digestAgentGymJson } from "./canonical-json.js";
import type { AgentGymCorpusAdmissionDecisionV1 } from "./corpus-admission.js";
import type { AgentGymCorpusBuildReceiptV1 } from "./corpus-build.js";
import { AgentGymContractError } from "./contract-error.js";

export interface AgentGymCorpusQualityReceiptV1 {
  readonly admitted: boolean;
  readonly admission_decision_digest: string;
  readonly blocker_codes: AgentGymCorpusAdmissionDecisionV1["blocker_codes"];
  readonly build_receipt_digest: string;
  readonly corpus_digest: string;
  readonly evaluated_at: string;
  readonly evaluation_ref: string;
  readonly receipt_digest: string;
  readonly schema_version: "agent-gym-corpus-quality-receipt/v1";
}

/** Binds a source build to the exact deterministic corpus admission result. */
export function recordAgentGymCorpusQuality(
  build: AgentGymCorpusBuildReceiptV1,
  decision: AgentGymCorpusAdmissionDecisionV1,
  input: { readonly evaluated_at: string; readonly evaluation_ref: string },
): AgentGymCorpusQualityReceiptV1 {
  reference(input.evaluation_ref);
  timestamp(input.evaluated_at);
  if (build.schema_version !== "agent-gym-corpus-build-receipt/v1"
    || decision.schema_version !== "agent-gym-corpus-admission-decision/v1"
    || build.corpus_digest !== decision.corpus_digest
    || build.receipt_digest !== digestAgentGymJson(buildBody(build))
    || decision.decision_digest !== digestAgentGymJson(decisionBody(decision))) invalid();
  const body = {
    admitted: decision.admitted,
    admission_decision_digest: decision.decision_digest,
    blocker_codes: decision.blocker_codes,
    build_receipt_digest: build.receipt_digest,
    corpus_digest: build.corpus_digest,
    evaluated_at: input.evaluated_at,
    evaluation_ref: input.evaluation_ref,
    schema_version: "agent-gym-corpus-quality-receipt/v1" as const,
  };
  return Object.freeze({
    ...body,
    blocker_codes: Object.freeze([...decision.blocker_codes]),
    receipt_digest: digestAgentGymJson(body),
  });
}

function buildBody(value: AgentGymCorpusBuildReceiptV1) {
  return {
    build_ref: value.build_ref,
    built_at: value.built_at,
    case_count: value.case_count,
    corpus_digest: value.corpus_digest,
    inventory_digest: value.inventory_digest,
    schema_version: value.schema_version,
    source_revision: value.source_revision,
  };
}

function decisionBody(value: AgentGymCorpusAdmissionDecisionV1) {
  return {
    admitted: value.admitted,
    blocker_codes: value.blocker_codes,
    corpus_digest: value.corpus_digest,
    coverage_gap_count: value.coverage_gap_count,
    coverage_policy_ref: value.coverage_policy_ref,
    leakage_finding_count: value.leakage_finding_count,
    schema_version: value.schema_version,
  };
}

function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}

function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}

function invalid(): never {
  throw new AgentGymContractError("Agent gym corpus quality receipt is invalid.");
}
