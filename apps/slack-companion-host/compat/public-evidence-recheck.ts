import {
  admitEvidenceRecheck,
  bindDeliveredAnswerEvidence,
  evidenceRecheckAdmissionReceiptIdentity,
  evidenceRecheckIdentity,
  projectEvidenceRecheckStatus,
  validateDeliveredAnswerEvidenceBinding,
  validateEvidenceRecheck,
  type DeliveredAnswerEvidenceBindingV1 as PublicBindingV1,
  type DurableEvidenceRecheckAdmissionPort as PublicAdmissionPort,
  type EvidenceRecheckV1 as PublicRecheckV1,
} from "@writer/cerebro-slack-companion";
import type {
  DeliveredAnswerEvidenceBindingV1,
  DurableEvidenceRecheckAdmissionPort,
  EvidenceRecheckV1,
  PortableEvidenceRecheckContract,
} from "../src/evidence-recheck/contracts.js";

// These assignments fail compilation if the pinned public package and the
// private host port drift in either direction.
export const exactPublicEvidenceRecheckContract: PortableEvidenceRecheckContract = {
  admitEvidenceRecheck,
  bindDeliveredAnswerEvidence,
  evidenceRecheckAdmissionReceiptIdentity,
  evidenceRecheckIdentity,
  projectEvidenceRecheckStatus,
  validateDeliveredAnswerEvidenceBinding,
  validateEvidenceRecheck,
};

export function privateAdmissionPortAsPublic(
  port: DurableEvidenceRecheckAdmissionPort,
): PublicAdmissionPort {
  return port;
}

export function publicAdmissionPortAsPrivate(
  port: PublicAdmissionPort,
): DurableEvidenceRecheckAdmissionPort {
  return port;
}

export function privateBindingAsPublic(
  binding: DeliveredAnswerEvidenceBindingV1,
): PublicBindingV1 {
  return binding;
}

export function publicBindingAsPrivate(
  binding: PublicBindingV1,
): DeliveredAnswerEvidenceBindingV1 {
  return binding;
}

export function privateRecheckAsPublic(recheck: EvidenceRecheckV1): PublicRecheckV1 {
  return recheck;
}

export function publicRecheckAsPrivate(recheck: PublicRecheckV1): EvidenceRecheckV1 {
  return recheck;
}
