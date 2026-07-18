import type { CapabilityRequirement } from "@writer/cerebro-sdk";

export const SLACK_RESEARCH_LIMITS = {
  capabilities: 32,
  ref_utf8_bytes: 2_048,
  request_key_utf8_bytes: 256,
  results: 64,
  summary_items: 16,
  summary_utf8_bytes: 4_096,
} as const;

export interface SlackResearchRequestV1 {
  readonly capabilities: readonly CapabilityRequirement[];
  readonly request_key: string;
  readonly schema_version: "slack-research-request/v1";
  readonly subject_ref: string;
}

export type SlackResearchCapabilityStatusV1 =
  | "supported"
  | "degraded"
  | "blocked";

export interface SlackResearchCapabilityDecisionV1 {
  readonly decision_id: string;
  readonly missing_optional: readonly CapabilityRequirement[];
  readonly missing_required: readonly CapabilityRequirement[];
  readonly request_digest: string;
  readonly research_id: string;
  readonly schema_version: "slack-research-capability-decision/v1";
  readonly status: SlackResearchCapabilityStatusV1;
}

export type SlackResearchResultStateV1 =
  | "pending"
  | "succeeded"
  | "unavailable"
  | "failed";

export interface SlackResearchResultV1 {
  readonly capability_id: string;
  readonly capability_version: string;
  readonly research_id: string;
  readonly result_digest?: string;
  readonly result_ref?: string;
  readonly schema_version: "slack-research-result/v1";
  readonly state: SlackResearchResultStateV1;
}

export interface SlackResearchSummaryPolicyInputV1 {
  readonly capability_decision: SlackResearchCapabilityDecisionV1;
  readonly max_summary_items?: number;
  readonly max_summary_utf8_bytes?: number;
  readonly request: SlackResearchRequestV1;
  readonly results: readonly SlackResearchResultV1[];
  readonly schema_version: "slack-research-summary-policy-input/v1";
}

export type SlackResearchSummaryPlanV1 =
  | {
      readonly completeness: "complete" | "partial";
      readonly disposition: "summarize";
      readonly max_summary_utf8_bytes: number;
      readonly result_refs: readonly string[];
      readonly schema_version: "slack-research-summary-plan/v1";
      readonly summary_id: string;
    }
  | {
      readonly completeness: "pending";
      readonly disposition: "wait";
      readonly reason_code: "results_pending";
      readonly schema_version: "slack-research-summary-plan/v1";
      readonly summary_id: string;
    }
  | {
      readonly completeness: "none";
      readonly disposition: "unavailable";
      readonly reason_code: "missing_required_capability" | "no_successful_results";
      readonly schema_version: "slack-research-summary-plan/v1";
      readonly summary_id: string;
    };
