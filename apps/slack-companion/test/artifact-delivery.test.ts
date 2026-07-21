import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  planSlackArtifactDelivery,
  SlackArtifactPolicyError,
} from "../src/artifacts/policy.js";
import type { SlackArtifactV1 } from "../src/artifacts/contracts.js";

const evidenceRef = "result:security-board-2030-01-02";
const artifactSpecs = [{
  artifact_id: "security_work_age",
  format: "png" as const,
  purpose: "status_chart" as const,
  title: "Security work age",
}];

function artifact(overrides: Partial<SlackArtifactV1> = {}): SlackArtifactV1 {
  return {
    alt_text: "Open and blocked security work by age.",
    artifact_id: "security_work_age",
    content_digest: `sha256:${"b".repeat(64)}`,
    content_ref: "blob:security-work-age.png",
    created_at: "2030-01-02T03:04:05.000Z",
    evidence_refs: [evidenceRef],
    mime_type: "image/png",
    schema_version: "slack-artifact/v1",
    size_bytes: 42_000,
    title: "Security work age",
    ...overrides,
  };
}

describe("Slack artifact delivery policy", () => {
  test("plans evidence-bound uploads without resolving provider content", () => {
    const plan = planSlackArtifactDelivery({
      artifact_specs: artifactSpecs,
      artifacts: [artifact()],
      destination_ref: "slack-channel:security-team",
      evidence_refs: [evidenceRef],
      message_ref: "digest:security-board-2030-01-02",
      schema_version: "slack-artifact-delivery-policy-input/v1",
    });
    assert.equal(plan.disposition, "upload");
    if (plan.disposition !== "upload") assert.fail("expected upload");
    assert.deepEqual(plan.artifact_refs, ["blob:security-work-age.png"]);
  });

  test("does not upload an artifact whose evidence is absent", () => {
    const plan = planSlackArtifactDelivery({
      artifact_specs: artifactSpecs,
      artifacts: [artifact()],
      destination_ref: "slack-channel:security-team",
      evidence_refs: ["result:other-run"],
      message_ref: "digest:security-board-2030-01-02",
      schema_version: "slack-artifact-delivery-policy-input/v1",
    });
    assert.equal(plan.disposition, "unavailable");
    if (plan.disposition !== "unavailable") assert.fail("expected unavailable");
    assert.equal(plan.reason_code, "missing_evidence");
  });

  test("rejects artifact content without a digest", () => {
    assert.throws(() => planSlackArtifactDelivery({
      artifact_specs: artifactSpecs,
      artifacts: [artifact({ content_digest: "missing" })],
      destination_ref: "slack-channel:security-team",
      evidence_refs: [evidenceRef],
      message_ref: "digest:security-board-2030-01-02",
      schema_version: "slack-artifact-delivery-policy-input/v1",
    }), SlackArtifactPolicyError);
  });

  test("does not upload partial or off-contract render output", () => {
    const missing = planSlackArtifactDelivery({
      artifact_specs: [...artifactSpecs, {
        artifact_id: "security_queue",
        format: "csv",
        purpose: "operator_queue",
        title: "Security queue",
      }],
      artifacts: [artifact()],
      destination_ref: "slack-channel:security-team",
      evidence_refs: [evidenceRef],
      message_ref: "digest:security-board-2030-01-02",
      schema_version: "slack-artifact-delivery-policy-input/v1",
    });
    assert.equal(missing.disposition, "unavailable");
    if (missing.disposition !== "unavailable") assert.fail("expected unavailable");
    assert.equal(missing.reason_code, "missing_artifact");
  });
});
