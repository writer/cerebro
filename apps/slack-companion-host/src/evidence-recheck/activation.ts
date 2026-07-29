import type { EvidenceRecheckRouteRegistrationPort } from "./contracts.js";

export const PUBLIC_CEREBRO_COMMIT = "42f88076c66aedc9540901d000f6d32ef9f2bec6";
export const PUBLIC_SLACK_COMPANION_TREE = "cfe554498a07dbbe5da8ce6d0eed3ab3b422089b";

const REQUIRED_EVIDENCE_KEYS = [
  "atomic_admission",
  "binding_lookup",
  "checkpoint_recovery",
  "public_source_lock",
  "queue_recovery",
  "route_probe",
  "status_outbox",
] as const;

export interface EvidenceRecheckHostRuntimeEvidenceV1 {
  generation: number;
  observed_at: string;
  public_commit: typeof PUBLIC_CEREBRO_COMMIT;
  public_slack_companion_tree: typeof PUBLIC_SLACK_COMPANION_TREE;
  receipt_refs: Record<(typeof REQUIRED_EVIDENCE_KEYS)[number], string>;
  schema_version: "private-evidence-recheck-runtime-evidence/v1";
}

export interface EvidenceRecheckHostActivationReceiptV1 {
  activated_at: string;
  generation: number;
  public_commit: typeof PUBLIC_CEREBRO_COMMIT;
  public_slack_companion_tree: typeof PUBLIC_SLACK_COMPANION_TREE;
  registration_receipt_ref: string;
  schema_version: "private-evidence-recheck-activation-receipt/v1";
}

export interface EvidenceRecheckHostBehaviorReceiptV1 {
  behavior: (typeof REQUIRED_EVIDENCE_KEYS)[number];
  evidence_digest: string;
  generation: number;
  observed_at: string;
  producer_ref: string;
  public_commit: typeof PUBLIC_CEREBRO_COMMIT;
  public_slack_companion_tree: typeof PUBLIC_SLACK_COMPANION_TREE;
  receipt_ref: string;
  schema_version: "private-evidence-recheck-behavior-receipt/v1";
  status: "verified";
}

/** Trusted durable lookup; callers cannot supply resolved receipt bodies. */
export interface EvidenceRecheckHostBehaviorReceiptPort {
  resolve(receiptRef: string): Promise<EvidenceRecheckHostBehaviorReceiptV1 | undefined>;
}

const ACTION_ID = "evidence_recheck";
const ROUTE_ID = "evidence-recheck";

/**
 * Registers the fixed private route only after durable behavior evidence has
 * been produced for the exact portable-contract source lock.
 */
export async function installEvidenceRecheckHost(
  evidence: EvidenceRecheckHostRuntimeEvidenceV1,
  behaviorReceipts: EvidenceRecheckHostBehaviorReceiptPort,
  routes: EvidenceRecheckRouteRegistrationPort,
): Promise<EvidenceRecheckHostActivationReceiptV1> {
  validateRuntimeEvidence(evidence);
  let producerRef: string | undefined;
  for (const behavior of REQUIRED_EVIDENCE_KEYS) {
    const receiptRef = evidence.receipt_refs[behavior];
    const receipt = await behaviorReceipts.resolve(receiptRef);
    validateBehaviorReceipt(receipt, receiptRef, behavior, evidence);
    if (producerRef === undefined) producerRef = receipt.producer_ref;
    if (receipt.producer_ref !== producerRef) {
      throw new Error("Evidence recheck activation receipts have different producers.");
    }
  }
  const registration = await routes.register({
    action_id: ACTION_ID,
    generation: evidence.generation,
    route_id: ROUTE_ID,
  });
  requireRef(registration.registration_receipt_ref, "registration_receipt_ref");
  return {
    activated_at: evidence.observed_at,
    generation: evidence.generation,
    public_commit: evidence.public_commit,
    public_slack_companion_tree: evidence.public_slack_companion_tree,
    registration_receipt_ref: registration.registration_receipt_ref,
    schema_version: "private-evidence-recheck-activation-receipt/v1",
  };
}

function validateBehaviorReceipt(
  receipt: EvidenceRecheckHostBehaviorReceiptV1 | undefined,
  receiptRef: string,
  behavior: (typeof REQUIRED_EVIDENCE_KEYS)[number],
  evidence: EvidenceRecheckHostRuntimeEvidenceV1,
): asserts receipt is EvidenceRecheckHostBehaviorReceiptV1 {
  if (
    receipt === undefined ||
    receipt.schema_version !== "private-evidence-recheck-behavior-receipt/v1" ||
    receipt.status !== "verified" ||
    receipt.receipt_ref !== receiptRef ||
    receipt.behavior !== behavior ||
    receipt.generation !== evidence.generation ||
    receipt.public_commit !== evidence.public_commit ||
    receipt.public_slack_companion_tree !== evidence.public_slack_companion_tree ||
    !isCanonicalTimestamp(receipt.observed_at) ||
    Date.parse(receipt.observed_at) > Date.parse(evidence.observed_at) ||
    !/^sha256:[a-f0-9]{64}$/.test(receipt.evidence_digest)
  ) {
    throw new Error("Evidence recheck host behavior receipt is invalid.");
  }
  requireRef(receipt.producer_ref, "producer_ref");
}

export function validateRuntimeEvidence(
  evidence: EvidenceRecheckHostRuntimeEvidenceV1,
): void {
  if (
    evidence.schema_version !== "private-evidence-recheck-runtime-evidence/v1" ||
    evidence.public_commit !== PUBLIC_CEREBRO_COMMIT ||
    evidence.public_slack_companion_tree !== PUBLIC_SLACK_COMPANION_TREE ||
    !Number.isSafeInteger(evidence.generation) ||
    evidence.generation < 1 ||
    !isCanonicalTimestamp(evidence.observed_at) ||
    evidence.receipt_refs === null ||
    typeof evidence.receipt_refs !== "object" ||
    JSON.stringify(Object.keys(evidence.receipt_refs).sort()) !==
      JSON.stringify([...REQUIRED_EVIDENCE_KEYS].sort())
  ) {
    throw new Error("Evidence recheck host activation evidence is invalid.");
  }
  for (const key of REQUIRED_EVIDENCE_KEYS) {
    requireRef(evidence.receipt_refs[key], `${key} receipt`);
  }
}

function isCanonicalTimestamp(value: string): boolean {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(Date.parse(value)).toISOString() === value
  );
}

function requireRef(value: string, field: string): void {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 2_048 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error(`${field} must be a bounded opaque reference.`);
  }
}
