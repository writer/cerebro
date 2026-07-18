import type { WorkLeaseV1 } from "../execution/model.js";
import type {
  ImprovementAuthorCompletion,
  ImprovementAuthorInspection,
  ImprovementAuthorReservation,
  ImprovementAuthorReservationResult,
  ImprovementAuthorResult,
  ImprovementAuthorVerification,
  ImprovementAuthoringIntent,
  ImprovementCandidateCommit,
  ImprovementCandidateCommitResult,
  ImprovementCandidateV1,
  ImprovementDraftSnapshot,
  ImprovementEvidenceCompletion,
  ImprovementEvidenceInvalidationReceipt,
  ImprovementEvidenceInvalidationRequest,
  ImprovementEvidenceRecord,
  ImprovementEvidenceSnapshot,
} from "./contracts.js";

export interface ImprovementClockPort {
  now(): Date;
}

/**
 * Candidate CAS metadata. This port consumes an existing WorkLeaseV1 proof; it
 * does not acquire or renew leases and must reject an older generation/fence.
 */
export interface DurableImprovementCandidatePort {
  completeAuthoring(
    completion: ImprovementAuthorCompletion,
  ): Promise<ImprovementCandidateV1>;
  markEvidenceReady(
    completion: ImprovementEvidenceCompletion,
  ): Promise<ImprovementCandidateV1>;
  putIfAbsent(
    commit: ImprovementCandidateCommit,
  ): Promise<ImprovementCandidateCommitResult>;
  read(candidateId: string): Promise<ImprovementCandidateV1 | undefined>;
  reserveAuthor(
    reservation: ImprovementAuthorReservation,
  ): Promise<ImprovementAuthorReservationResult>;
}

/** Mutates only the exact already-open draft supplied in the intent. */
export interface ImprovementAuthorPort {
  apply(
    intent: ImprovementAuthoringIntent,
    lease: WorkLeaseV1,
  ): Promise<ImprovementAuthorResult>;
  inspect(
    intent: ImprovementAuthoringIntent,
    lease: WorkLeaseV1,
  ): Promise<ImprovementAuthorInspection>;
  inspectDraft(draftRef: string): Promise<ImprovementDraftSnapshot | undefined>;
  readResult(resultRef: string): Promise<ImprovementAuthorResult | undefined>;
  resume(
    intent: ImprovementAuthoringIntent,
    resumeToken: string,
    lease: WorkLeaseV1,
  ): Promise<ImprovementAuthorResult>;
}

/** Independent verification of the exact existing draft after authoring. */
export interface ImprovementVerificationPort {
  verify(
    intent: ImprovementAuthoringIntent,
    result: ImprovementAuthorResult,
    lease: WorkLeaseV1,
  ): Promise<ImprovementAuthorVerification>;
}

/**
 * Evidence remains invalidated until every required exact-head receipt is fresh.
 * `recordFresh` uses the immutable `(candidate_id, author_generation, kind)` tuple
 * as its identity. An exact replay must return the stored snapshot. A replay that
 * changes the head, evidence digest, or evidence reference must reject as a
 * conflict instead of replacing the stored receipt.
 */
export interface ImprovementEvidencePort {
  invalidate(
    request: ImprovementEvidenceInvalidationRequest,
    lease: WorkLeaseV1,
  ): Promise<ImprovementEvidenceInvalidationReceipt>;
  read(
    candidateId: string,
    authorGeneration: number,
  ): Promise<ImprovementEvidenceSnapshot | undefined>;
  recordFresh(input: ImprovementEvidenceRecord): Promise<ImprovementEvidenceSnapshot>;
}
