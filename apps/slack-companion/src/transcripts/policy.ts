import { createHash } from "node:crypto";

import type {
  TranscriptActionDraftV1,
  TranscriptActionPlanV1,
  TranscriptActionPolicyInputV1,
  TranscriptEvidenceLocationV1,
} from "./contracts.js";

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const REF = /^[a-z][a-z0-9_.-]*:[^\s\u0000-\u001f]{1,500}$/;

export class TranscriptActionPolicyError extends Error {}

/** Produces ticket write intents only after an explicit approval record. */
export function planTranscriptActions(
  input: TranscriptActionPolicyInputV1,
): TranscriptActionPlanV1 {
  if (input.schema_version !== "transcript-action-policy-input/v1") {
    throw new TranscriptActionPolicyError("The transcript action policy version is unsupported.");
  }
  if (input.source.schema_version !== "transcript-source/v1") {
    throw new TranscriptActionPolicyError("The transcript source version is unsupported.");
  }
  reference(input.source.transcript_ref, "transcript_ref");
  if (!SHA256.test(input.source.transcript_digest)) {
    throw new TranscriptActionPolicyError("The transcript source requires a lowercase SHA-256 digest.");
  }
  timestamp(input.source.captured_at, "captured_at");
  const drafts = canonicalDrafts(input.drafts, input.source.transcript_ref);
  if (drafts.length === 0 || drafts.length > 50) {
    throw new TranscriptActionPolicyError("Transcript action plans require between 1 and 50 drafts.");
  }
  const planId = `transcript-action-plan:${hash([
    input.source.transcript_digest,
    ...drafts.map((draft) => JSON.stringify(draft)),
  ]).slice(7, 39)}`;
  if (input.approval === undefined) {
    return Object.freeze({
      action_ids: Object.freeze(drafts.map((draft) => draft.action_id)),
      disposition: "await_approval",
      plan_id: planId,
      schema_version: "transcript-action-plan/v1",
    });
  }
  const approval = input.approval;
  if (approval.schema_version !== "transcript-action-approval/v1") {
    throw new TranscriptActionPolicyError("The transcript action approval version is unsupported.");
  }
  token(approval.approval_id, "approval_id");
  reference(approval.approved_by_ref, "approved_by_ref");
  timestamp(approval.approved_at, "approved_at");
  const approvedIds = [...new Set(approval.approved_action_ids)].sort();
  if (approvedIds.length === 0 || approvedIds.some((id) => !drafts.some((draft) => draft.action_id === id))) {
    throw new TranscriptActionPolicyError("Approval must name at least one known action draft.");
  }
  const selected = drafts.filter((draft) => approvedIds.includes(draft.action_id));
  return Object.freeze({
    disposition: "write_tickets",
    intents: Object.freeze(selected.map((draft) => Object.freeze({
      action_id: draft.action_id,
      description: draft.description,
      due_at: draft.due_at,
      evidence: draft.evidence,
      idempotency_key: hash([
        input.source.transcript_digest,
        approval.approval_id,
        draft.action_id,
      ]),
      owner_ref: draft.owner_ref,
      schema_version: "transcript-ticket-write-intent/v1" as const,
      ticket_system: draft.ticket_system,
      title: draft.title,
    }))),
    plan_id: planId,
    schema_version: "transcript-action-plan/v1",
  });
}

function canonicalDrafts(
  values: readonly TranscriptActionDraftV1[],
  transcriptRef: string,
): readonly TranscriptActionDraftV1[] {
  const ids = new Set<string>();
  return Object.freeze(values.map((draft) => {
    if (draft.schema_version !== "transcript-action-draft/v1" || draft.state !== "draft") {
      throw new TranscriptActionPolicyError("Every transcript action must be a v1 draft.");
    }
    const id = token(draft.action_id, "action_id");
    if (ids.has(id)) throw new TranscriptActionPolicyError("Transcript action ids must be unique.");
    ids.add(id);
    if (draft.due_at !== undefined) timestamp(draft.due_at, "due_at");
    const evidence = canonicalEvidence(draft.evidence, transcriptRef);
    if (evidence.length === 0) throw new TranscriptActionPolicyError("Every transcript action requires evidence.");
    return Object.freeze({
      ...draft,
      action_id: id,
      description: boundedText(draft.description, "description", 4_000),
      evidence,
      owner_ref: draft.owner_ref === undefined ? undefined : reference(draft.owner_ref, "owner_ref"),
      title: boundedText(draft.title, "title", 300),
    });
  }).sort((left, right) => left.action_id.localeCompare(right.action_id)));
}

function canonicalEvidence(
  values: readonly TranscriptEvidenceLocationV1[],
  transcriptRef: string,
): readonly TranscriptEvidenceLocationV1[] {
  return Object.freeze(values.map((evidence) => {
    reference(evidence.transcript_ref, "evidence transcript_ref");
    if (evidence.transcript_ref !== transcriptRef) {
      throw new TranscriptActionPolicyError("Action evidence must cite the current transcript.");
    }
    return Object.freeze({
      locator: boundedText(evidence.locator, "evidence locator", 500),
      transcript_ref: evidence.transcript_ref,
    });
  }));
}

function reference(value: string, field: string): string {
  if (!REF.test(value)) throw new TranscriptActionPolicyError(`${field} is invalid.`);
  return value;
}

function token(value: string, field: string): string {
  if (!/^[a-z][a-z0-9_.-]{0,95}$/.test(value)) throw new TranscriptActionPolicyError(`${field} is invalid.`);
  return value;
}

function boundedText(value: string, field: string, max: number): string {
  const normalized = value.trim();
  if (normalized.length === 0 || Buffer.byteLength(normalized, "utf8") > max || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new TranscriptActionPolicyError(`${field} is invalid.`);
  }
  return normalized;
}

function timestamp(value: string, field: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new TranscriptActionPolicyError(`${field} is invalid.`);
  return new Date(parsed).toISOString();
}

function hash(values: readonly unknown[]): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(values)).digest("hex")}`;
}
