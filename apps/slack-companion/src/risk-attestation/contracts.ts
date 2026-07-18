export const RISK_ATTESTATION_LIMITS = {
  decision_key_utf8_bytes: 256,
  ref_utf8_bytes: 2_048,
  request_key_utf8_bytes: 256,
} as const;

export const RISK_ATTESTATION_STATES = [
  "pending",
  "accepted",
  "rejected",
  "expired",
  "withdrawn",
] as const;

export type RiskAttestationStateV1 =
  (typeof RISK_ATTESTATION_STATES)[number];

export const RISK_ATTESTATION_DECISIONS = [
  "accept",
  "reject",
  "expire",
  "withdraw",
] as const;

export type RiskAttestationDecisionKindV1 =
  (typeof RISK_ATTESTATION_DECISIONS)[number];

export interface RiskAttestationV1 {
  readonly attestation_id: string;
  readonly created_at: string;
  readonly last_decision_id?: string;
  readonly request_key: string;
  readonly revision: number;
  readonly schema_version: "risk-attestation/v1";
  readonly state: RiskAttestationStateV1;
  readonly state_sequence: number;
  readonly subject_ref: string;
  readonly updated_at: string;
}

export interface CreateRiskAttestationInputV1 {
  readonly created_at: string;
  readonly request_key: string;
  readonly schema_version: "create-risk-attestation-input/v1";
  readonly subject_ref: string;
}

export interface RiskAttestationDecisionRequestV1 {
  readonly actor_ref: string;
  readonly decided_at: string;
  readonly decision: RiskAttestationDecisionKindV1;
  readonly decision_key: string;
  readonly expected_revision: number;
  readonly rationale_ref: string;
  readonly schema_version: "risk-attestation-decision-request/v1";
}

export interface RiskAttestationDecisionReceiptV1 {
  readonly attestation: RiskAttestationV1;
  readonly decision: RiskAttestationDecisionKindV1;
  readonly decision_id: string;
  readonly decision_key: string;
  readonly from_state: RiskAttestationStateV1;
  readonly receipt_digest: string;
  readonly receipt_id: string;
  readonly request_digest: string;
  readonly schema_version: "risk-attestation-decision-receipt/v1";
  readonly to_state: RiskAttestationStateV1;
}

/** A host resolves this receipt lookup before applying the pure policy. */
export type RiskAttestationDecisionReceiptLookupV1 =
  | {
      readonly found: false;
      readonly receipt_id: string;
      readonly schema_version: "risk-attestation-decision-receipt-lookup/v1";
    }
  | {
      readonly found: true;
      readonly receipt: RiskAttestationDecisionReceiptV1;
      readonly schema_version: "risk-attestation-decision-receipt-lookup/v1";
    };

export type RiskAttestationDecisionResultV1 =
  | {
      readonly applied: true;
      readonly receipt: RiskAttestationDecisionReceiptV1;
      readonly replayed: boolean;
      readonly schema_version: "risk-attestation-decision-result/v1";
    }
  | {
      readonly applied: false;
      readonly reason_code: "idempotency_conflict";
      readonly receipt_ref: string;
      readonly replayed: false;
      readonly schema_version: "risk-attestation-decision-result/v1";
    };
