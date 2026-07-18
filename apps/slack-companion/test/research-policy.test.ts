import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { CapabilityRequirement } from "@writer/cerebro-sdk";

import type {
  SlackResearchRequestV1,
  SlackResearchResultV1,
} from "../src/research/contracts.js";
import { SLACK_RESEARCH_LIMITS } from "../src/research/contracts.js";
import {
  decideSlackResearchCapabilities,
  planSlackResearchSummary,
} from "../src/research/policy.js";

const digest = `sha256:${"a".repeat(64)}`;
const capabilities: readonly CapabilityRequirement[] = [
  { capability_id: "research.fetch", level: "required", version: "v1" },
  { capability_id: "research.context", level: "optional", version: "v2" },
];

function request(overrides: Partial<SlackResearchRequestV1> = {}): SlackResearchRequestV1 {
  return {
    capabilities,
    request_key: "research-request-1",
    schema_version: "slack-research-request/v1",
    subject_ref: "subject:sample-1",
    ...overrides,
  };
}

function result(
  researchId: string,
  capabilityId: string,
  version: string,
  state: SlackResearchResultV1["state"] = "succeeded",
): SlackResearchResultV1 {
  return {
    capability_id: capabilityId,
    capability_version: version,
    research_id: researchId,
    ...(state === "succeeded" ? { result_digest: digest, result_ref: `result:${capabilityId}` } : {}),
    schema_version: "slack-research-result/v1",
    state,
  };
}

describe("Slack research capability and summary policy", () => {
  test("makes deterministic version-aware supported, degraded, and blocked decisions", () => {
    const supported = decideSlackResearchCapabilities(request(), [...capabilities].reverse());
    const repeated = decideSlackResearchCapabilities(request(), capabilities);
    assert.deepEqual(repeated, supported);
    assert.equal(supported.status, "supported");
    assert.equal(Object.isFrozen(supported.missing_required), true);

    const degraded = decideSlackResearchCapabilities(request(), [capabilities[0]!]);
    assert.equal(degraded.status, "degraded");
    assert.deepEqual(degraded.missing_optional, [capabilities[1]]);

    const blocked = decideSlackResearchCapabilities(request(), [
      { ...capabilities[0]!, version: "v2" },
      capabilities[1]!,
    ]);
    assert.equal(blocked.status, "blocked");
    assert.deepEqual(blocked.missing_required, [capabilities[0]]);
  });

  test("selects a bounded complete or partial summary without reading result content", () => {
    const decision = decideSlackResearchCapabilities(request(), capabilities);
    const results = [
      result(decision.research_id, "research.fetch", "v1"),
      result(decision.research_id, "research.context", "v2"),
    ];
    const complete = planSlackResearchSummary({
      capability_decision: decision,
      request: request(),
      results: [...results].reverse(),
      schema_version: "slack-research-summary-policy-input/v1",
    });
    assert.equal(complete.disposition, "summarize");
    if (complete.disposition !== "summarize") assert.fail("expected summary");
    assert.equal(complete.completeness, "complete");
    assert.deepEqual(complete.result_refs, ["result:research.context", "result:research.fetch"]);
    assert.equal(complete.max_summary_utf8_bytes, SLACK_RESEARCH_LIMITS.summary_utf8_bytes);
    assert.equal(Object.isFrozen(complete.result_refs), true);

    const partial = planSlackResearchSummary({
      capability_decision: decision,
      max_summary_items: 1,
      max_summary_utf8_bytes: 512,
      request: request(),
      results,
      schema_version: "slack-research-summary-policy-input/v1",
    });
    assert.equal(partial.disposition, "summarize");
    if (partial.disposition !== "summarize") assert.fail("expected partial summary");
    assert.equal(partial.completeness, "partial");
    assert.equal(partial.result_refs.length, 1);
    assert.equal(partial.max_summary_utf8_bytes, 512);
  });

  test("waits for pending results and stops when required capability is missing", () => {
    const supported = decideSlackResearchCapabilities(request(), capabilities);
    assert.equal(planSlackResearchSummary({
      capability_decision: supported,
      request: request(),
      results: [result(supported.research_id, "research.fetch", "v1", "pending")],
      schema_version: "slack-research-summary-policy-input/v1",
    }).disposition, "wait");

    const blocked = decideSlackResearchCapabilities(request(), [capabilities[1]!]);
    const unavailable = planSlackResearchSummary({
      capability_decision: blocked,
      request: request(),
      results: [],
      schema_version: "slack-research-summary-policy-input/v1",
    });
    assert.deepEqual(unavailable, {
      completeness: "none",
      disposition: "unavailable",
      reason_code: "missing_required_capability",
      schema_version: "slack-research-summary-plan/v1",
      summary_id: unavailable.summary_id,
    });
  });

  test("rejects changed requests, duplicate results, invalid outputs, and UTF-8 overflow", () => {
    const decision = decideSlackResearchCapabilities(request(), capabilities);
    const input = {
      capability_decision: decision,
      request: request(),
      results: [result(decision.research_id, "research.fetch", "v1")],
      schema_version: "slack-research-summary-policy-input/v1" as const,
    };
    assert.throws(() => planSlackResearchSummary({
      ...input,
      request: request({ subject_ref: "subject:changed" }),
    }), /request changed/);
    assert.throws(() => planSlackResearchSummary({
      ...input,
      results: [...input.results, ...input.results],
    }), /duplicated/);
    assert.throws(() => planSlackResearchSummary({
      ...input,
      results: [{ ...input.results[0]!, result_digest: undefined }],
    }), /requires a digest/);
    assert.throws(() => planSlackResearchSummary({
      ...input,
      capability_decision: { ...decision, decision_id: "decision:forged" },
    }), /decision identity is invalid/);
    assert.throws(() => decideSlackResearchCapabilities(
      request({ request_key: "é".repeat(SLACK_RESEARCH_LIMITS.request_key_utf8_bytes / 2 + 1) }),
      capabilities,
    ), /request key is invalid/);
  });
});
