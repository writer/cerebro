import { createHash } from "node:crypto";

import type {
  SlackArtifactDeliveryPlanV1,
  SlackArtifactDeliveryPolicyInputV1,
  SlackArtifactV1,
} from "./contracts.js";

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const REF = /^[a-z][a-z0-9_.-]*:[^\s\u0000-\u001f]{1,500}$/;
const MIME_TYPES = new Set(["application/pdf", "image/png", "text/csv"]);

export class SlackArtifactPolicyError extends Error {}

/** Plans bounded uploads. The host resolves content refs and performs Slack writes. */
export function planSlackArtifactDelivery(
  input: SlackArtifactDeliveryPolicyInputV1,
): SlackArtifactDeliveryPlanV1 {
  if (input.schema_version !== "slack-artifact-delivery-policy-input/v1") {
    throw new SlackArtifactPolicyError("The artifact delivery policy version is unsupported.");
  }
  reference(input.destination_ref, "destination_ref");
  reference(input.message_ref, "message_ref");
  const evidence = canonicalRefs(input.evidence_refs, "evidence_refs");
  const artifacts = canonicalArtifacts(input.artifacts);
  const deliveryId = `slack-artifact-delivery:${hash([
    input.destination_ref,
    input.message_ref,
    ...evidence,
    ...artifacts.map((artifact) => `${artifact.artifact_id}|${artifact.content_digest}`),
  ]).slice(7, 39)}`;
  if (artifacts.length === 0) {
    return Object.freeze({
      delivery_id: deliveryId,
      disposition: "unavailable",
      reason_code: "no_artifacts",
      schema_version: "slack-artifact-delivery-plan/v1",
    });
  }
  if (evidence.length === 0 || artifacts.some((artifact) => artifact.evidence_refs.some((ref) => !evidence.includes(ref)))) {
    return Object.freeze({
      delivery_id: deliveryId,
      disposition: "unavailable",
      reason_code: "missing_evidence",
      schema_version: "slack-artifact-delivery-plan/v1",
    });
  }
  return Object.freeze({
    artifact_refs: Object.freeze(artifacts.map((artifact) => artifact.content_ref)),
    delivery_id: deliveryId,
    destination_ref: input.destination_ref,
    disposition: "upload",
    message_ref: input.message_ref,
    schema_version: "slack-artifact-delivery-plan/v1",
  });
}

function canonicalArtifacts(values: readonly SlackArtifactV1[]): readonly SlackArtifactV1[] {
  if (values.length > 8) throw new SlackArtifactPolicyError("A delivery cannot contain more than 8 artifacts.");
  const ids = new Set<string>();
  return Object.freeze(values.map((artifact) => {
    if (artifact.schema_version !== "slack-artifact/v1") throw new SlackArtifactPolicyError("The artifact version is unsupported.");
    const id = token(artifact.artifact_id, "artifact_id");
    if (ids.has(id)) throw new SlackArtifactPolicyError("Artifact ids must be unique.");
    ids.add(id);
    if (!SHA256.test(artifact.content_digest)) throw new SlackArtifactPolicyError("An artifact requires a lowercase SHA-256 digest.");
    reference(artifact.content_ref, "content_ref");
    if (!MIME_TYPES.has(artifact.mime_type)) throw new SlackArtifactPolicyError("The artifact MIME type is unsupported.");
    if (!Number.isSafeInteger(artifact.size_bytes) || artifact.size_bytes < 1 || artifact.size_bytes > 20_000_000) {
      throw new SlackArtifactPolicyError("Artifact size must be between 1 and 20000000 bytes.");
    }
    if (!Number.isFinite(Date.parse(artifact.created_at))) throw new SlackArtifactPolicyError("created_at is invalid.");
    const evidenceRefs = canonicalRefs(artifact.evidence_refs, "artifact evidence_refs");
    if (evidenceRefs.length === 0) throw new SlackArtifactPolicyError("An artifact requires evidence references.");
    return Object.freeze({
      ...artifact,
      alt_text: boundedText(artifact.alt_text, "alt_text", 2_000),
      artifact_id: id,
      evidence_refs: evidenceRefs,
      title: boundedText(artifact.title, "title", 300),
    });
  }).sort((left, right) => left.artifact_id.localeCompare(right.artifact_id)));
}

function canonicalRefs(values: readonly string[], field: string): readonly string[] {
  return Object.freeze([...new Set(values.map((value) => reference(value, field)))].sort());
}

function reference(value: string, field: string): string {
  if (!REF.test(value)) throw new SlackArtifactPolicyError(`${field} contains an invalid reference.`);
  return value;
}

function token(value: string, field: string): string {
  if (!/^[a-z][a-z0-9_.-]{0,95}$/.test(value)) throw new SlackArtifactPolicyError(`${field} is invalid.`);
  return value;
}

function boundedText(value: string, field: string, max: number): string {
  const normalized = value.trim();
  if (normalized.length === 0 || Buffer.byteLength(normalized, "utf8") > max || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new SlackArtifactPolicyError(`${field} is invalid.`);
  }
  return normalized;
}

function hash(values: readonly unknown[]): string {
  return createHash("sha256").update(JSON.stringify(values)).digest("hex");
}
