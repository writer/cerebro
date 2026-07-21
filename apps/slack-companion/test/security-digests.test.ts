import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  planSecurityDigest,
  SecurityDigestPolicyError,
  type SecurityDigestPolicyInputV1,
} from "../src/operations/security-digests.js";

const sourceDigest = `sha256:${"a".repeat(64)}`;

function input(
  overrides: Partial<SecurityDigestPolicyInputV1> = {},
): SecurityDigestPolicyInputV1 {
  return {
    generated_at: "2030-01-02T03:04:05.000Z",
    kind: "security_board",
    run_key: "weekday-2030-01-02",
    schema_version: "security-digest-policy-input/v1",
    sections: [{
      items: [{
        detail: "Waiting for the service owner to restore the scanner.",
        item_id: "finding-17",
        owner_ref: "user:owner-1",
        priority: "high",
        source_ids: ["tickets"],
        state: "blocked",
        title: "Scanner remediation is blocked",
      }],
      section_id: "blocked_work",
      title: "Blocked work",
    }],
    sources: [{
      observed_at: "2030-01-02T03:00:00.000Z",
      required: true,
      result_digest: sourceDigest,
      result_ref: "result:tickets-2030-01-02",
      source_id: "tickets",
      state: "succeeded",
    }],
    ...overrides,
  };
}

describe("security digest policy", () => {
  test("publishes a complete source-backed board digest", () => {
    const plan = planSecurityDigest(input());
    assert.equal(plan.disposition, "publish");
    if (plan.disposition !== "publish") assert.fail("expected publish");
    assert.equal(plan.completeness, "complete");
    assert.deepEqual(plan.source_refs, ["result:tickets-2030-01-02"]);
    assert.match(plan.content_digest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(Object.isFrozen(plan.sections), true);
  });

  test("suppresses an unchanged digest", () => {
    const first = planSecurityDigest(input());
    assert.equal(first.disposition, "publish");
    if (first.disposition !== "publish") assert.fail("expected publish");
    const repeated = planSecurityDigest(input({
      generated_at: "2030-01-03T03:04:05.000Z",
      previous_content_digest: first.content_digest,
      run_key: "weekday-2030-01-03",
    }));
    assert.equal(repeated.disposition, "suppress");
    if (repeated.disposition !== "suppress") assert.fail("expected suppression");
    assert.equal(repeated.reason_code, "unchanged");
  });

  test("stops when a required source is unavailable", () => {
    const plan = planSecurityDigest(input({
      sources: [{
        observed_at: "2030-01-02T03:00:00.000Z",
        required: true,
        source_id: "tickets",
        state: "unavailable",
      }],
    }));
    assert.equal(plan.disposition, "unavailable");
    if (plan.disposition !== "unavailable") assert.fail("expected unavailable");
    assert.equal(plan.reason_code, "required_source_unavailable");
  });

  test("does not publish an item backed only by an unavailable optional source", () => {
    const plan = planSecurityDigest(input({
      sections: [{
        items: [{
          detail: "The repository scan did not complete.",
          item_id: "repo-1",
          priority: "medium",
          source_ids: ["repositories"],
          state: "unknown",
          title: "Repository state is unavailable",
        }],
        section_id: "repositories",
        title: "Repositories",
      }],
      sources: [
        ...input().sources,
        {
          observed_at: "2030-01-02T03:00:00.000Z",
          required: false,
          source_id: "repositories",
          state: "unavailable",
        },
      ],
    }));
    assert.equal(plan.disposition, "unavailable");
    if (plan.disposition !== "unavailable") assert.fail("expected unavailable");
    assert.equal(plan.reason_code, "item_source_unavailable");
  });

  test("rejects uncited digest items", () => {
    assert.throws(() => planSecurityDigest(input({
      sections: [{
        items: [{
          detail: "No receipt exists.",
          item_id: "finding-18",
          priority: "low",
          source_ids: ["unknown"],
          state: "open",
          title: "Uncited item",
        }],
        section_id: "open_work",
        title: "Open work",
      }],
    })), SecurityDigestPolicyError);
  });
});
