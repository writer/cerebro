export const SLACK_HISTORY_LIMITS = {
  default_items: 20,
  max_items: 100,
  ref_utf8_bytes: 2_048,
  request_key_utf8_bytes: 256,
} as const;

export type SlackHistoryAnchorV1 =
  | { readonly high_water_sequence: number; readonly kind: "snapshot" }
  | { readonly before_sequence: number; readonly kind: "before" };

export interface SlackHistoryRetrievalRequestV1 {
  readonly anchor: SlackHistoryAnchorV1;
  readonly request_key: string;
  readonly requested_items?: number;
  readonly schema_version: "slack-history-retrieval-request/v1";
  readonly thread_ref: string;
}

export interface SlackHistoryWindowPolicyV1 {
  readonly default_items: number;
  readonly max_items: number;
  readonly schema_version: "slack-history-window-policy/v1";
}

export interface SlackHistoryWindowV1 {
  readonly anchor: SlackHistoryAnchorV1;
  readonly item_limit: number;
  readonly retrieval_id: string;
  readonly schema_version: "slack-history-window/v1";
  readonly thread_ref: string;
}

export interface SlackHistoryRetrievalReceiptV1 {
  readonly receipt_digest: string;
  readonly receipt_id: string;
  readonly request_digest: string;
  readonly request_key: string;
  readonly retrieval_id: string;
  readonly schema_version: "slack-history-retrieval-receipt/v1";
  readonly window: SlackHistoryWindowV1;
}

/** A host resolves this receipt lookup before applying the pure policy. */
export type SlackHistoryRetrievalReceiptLookupV1 =
  | {
      readonly found: false;
      readonly receipt_id: string;
      readonly schema_version: "slack-history-retrieval-receipt-lookup/v1";
    }
  | {
      readonly found: true;
      readonly receipt: SlackHistoryRetrievalReceiptV1;
      readonly schema_version: "slack-history-retrieval-receipt-lookup/v1";
    };

export type SlackHistoryRetrievalDecisionV1 =
  | {
      readonly created: true;
      readonly disposition: "retrieve";
      readonly receipt: SlackHistoryRetrievalReceiptV1;
      readonly schema_version: "slack-history-retrieval-decision/v1";
    }
  | {
      readonly created: false;
      readonly disposition: "replay";
      readonly receipt: SlackHistoryRetrievalReceiptV1;
      readonly schema_version: "slack-history-retrieval-decision/v1";
    }
  | {
      readonly disposition: "reject";
      readonly reason_code: "idempotency_conflict";
      readonly receipt_ref: string;
      readonly schema_version: "slack-history-retrieval-decision/v1";
    };
