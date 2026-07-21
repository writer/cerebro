export type SlackArtifactMimeTypeV1 = "application/pdf" | "image/png" | "text/csv";

export interface SlackArtifactV1 {
  readonly alt_text: string;
  readonly artifact_id: string;
  readonly content_digest: string;
  readonly content_ref: string;
  readonly created_at: string;
  readonly evidence_refs: readonly string[];
  readonly mime_type: SlackArtifactMimeTypeV1;
  readonly schema_version: "slack-artifact/v1";
  readonly size_bytes: number;
  readonly title: string;
}

export interface SlackArtifactDeliveryPolicyInputV1 {
  readonly artifacts: readonly SlackArtifactV1[];
  readonly destination_ref: string;
  readonly evidence_refs: readonly string[];
  readonly message_ref: string;
  readonly schema_version: "slack-artifact-delivery-policy-input/v1";
}

export type SlackArtifactDeliveryPlanV1 =
  | {
      readonly artifact_refs: readonly string[];
      readonly delivery_id: string;
      readonly destination_ref: string;
      readonly disposition: "upload";
      readonly message_ref: string;
      readonly schema_version: "slack-artifact-delivery-plan/v1";
    }
  | {
      readonly delivery_id: string;
      readonly disposition: "unavailable";
      readonly reason_code: "no_artifacts" | "missing_evidence";
      readonly schema_version: "slack-artifact-delivery-plan/v1";
    };
