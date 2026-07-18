import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type {
  CapabilityManifestV1,
  CapabilityRequirement,
} from "@writer/cerebro-sdk";

import type {
  SlackResearchCapabilityDecisionV1,
  SlackResearchRequestV1,
  SlackResearchResultV1,
} from "../src/research/contracts.js";
import { SLACK_RESEARCH_LIMITS } from "../src/research/contracts.js";
import {
  decideSlackResearchCapabilities,
  planSlackResearchSummary,
  SlackResearchPolicyError,
} from "../src/research/policy.js";

const digest = `sha256:${"a".repeat(64)}`;
const capabilities: readonly CapabilityRequirement[] = [
  { capability_id: "research.fetch", level: "required", version: "v1" },
  { capability_id: "research.context", level: "optional", version: "v2" },
];

function request(overrides: Partial<SlackResearchRequestV1> = {}): SlackResearchRequestV1 {
  return {
    capabilities,
    contract_version: "v1",
    request_key: "research-request-1",
    schema_version: "slack-research-request/v1",
    subject_ref: "subject:sample-1",
    ...overrides,
  };
}

function manifest(
  overrides: Partial<CapabilityManifestV1> = {},
): CapabilityManifestV1 {
  return {
    capabilities: [...capabilities],
    contract_versions: ["v1"],
    digest: "sha256:manifest-1",
    generation: 7,
    produced_at: "2030-01-02T03:04:05.000Z",
    schema_version: "capability-manifest/v1",
    service_id: "cerebro-core",
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
    ...(state === "succeeded"
      ? { result_digest: digest, result_ref: `result:${capabilityId}` }
      : {}),
    schema_version: "slack-research-result/v1",
    state,
  };
}

function summaryInput(
  decision: SlackResearchCapabilityDecisionV1,
  capabilityManifest: CapabilityManifestV1,
  results: readonly SlackResearchResultV1[],
) {
  return {
    capability_decision: decision,
    capability_manifest: capabilityManifest,
    request: request(),
    results,
    schema_version: "slack-research-summary-policy-input/v1" as const,
  };
}

describe("Slack research capability and summary policy", () => {
  test("binds version-aware decisions to an immutable capability manifest", () => {
    const offered = manifest({ capabilities: [...capabilities].reverse() });
    const supported = decideSlackResearchCapabilities(request(), offered);
    const repeated = decideSlackResearchCapabilities(request(), manifest());
    assert.deepEqual(repeated, supported);
    assert.equal(supported.status, "supported");
    assert.equal(supported.capability_manifest_service_id, "cerebro-core");
    assert.equal(supported.capability_manifest_generation, 7);
    assert.equal(supported.capability_manifest_digest, "sha256:manifest-1");
    assert.equal(supported.contract_version, "v1");
    assert.equal(Object.isFrozen(supported.missing_required), true);

    const newer = decideSlackResearchCapabilities(request(), manifest({ generation: 8 }));
    assert.notEqual(newer.decision_id, supported.decision_id);

    const degradedManifest = manifest({ capabilities: [capabilities[0]!] });
    const degraded = decideSlackResearchCapabilities(request(), degradedManifest);
    assert.equal(degraded.status, "degraded");
    assert.deepEqual(degraded.missing_optional, [capabilities[1]]);

    const blocked = decideSlackResearchCapabilities(request(), manifest({
      capabilities: [
        { ...capabilities[0]!, version: "v2" },
        capabilities[1]!,
      ],
    }));
    assert.equal(blocked.status, "blocked");
    assert.deepEqual(blocked.missing_required, [capabilities[0]]);

    const incompatible = decideSlackResearchCapabilities(
      request(),
      manifest({ contract_versions: ["v2"] }),
    );
    assert.equal(incompatible.status, "incompatible");
  });

  test("marks a summary complete only when every requested result succeeded", () => {
    const capabilityManifest = manifest();
    const decision = decideSlackResearchCapabilities(request(), capabilityManifest);
    const results = [
      result(decision.research_id, "research.fetch", "v1"),
      result(decision.research_id, "research.context", "v2"),
    ];
    const complete = planSlackResearchSummary(
      summaryInput(decision, capabilityManifest, [...results].reverse()),
    );
    assert.equal(complete.disposition, "summarize");
    if (complete.disposition !== "summarize") assert.fail("expected summary");
    assert.equal(complete.completeness, "complete");
    assert.deepEqual(complete.result_refs, [
      "result:research.context",
      "result:research.fetch",
    ]);
    assert.equal(complete.max_summary_utf8_bytes, SLACK_RESEARCH_LIMITS.summary_utf8_bytes);

    const partial = planSlackResearchSummary({
      ...summaryInput(decision, capabilityManifest, results),
      max_summary_items: 1,
      max_summary_utf8_bytes: 512,
    });
    assert.equal(partial.disposition, "summarize");
    if (partial.disposition !== "summarize") assert.fail("expected partial summary");
    assert.equal(partial.completeness, "partial");
    assert.equal(partial.result_refs.length, 1);
    assert.equal(partial.max_summary_utf8_bytes, 512);
  });

  test("waits while any requested result record is absent or pending", () => {
    const capabilityManifest = manifest();
    const decision = decideSlackResearchCapabilities(request(), capabilityManifest);
    const oneResult = [result(decision.research_id, "research.fetch", "v1")];
    assert.equal(
      planSlackResearchSummary(summaryInput(decision, capabilityManifest, oneResult)).disposition,
      "wait",
    );
    assert.equal(
      planSlackResearchSummary(summaryInput(decision, capabilityManifest, [])).disposition,
      "wait",
    );
    assert.equal(planSlackResearchSummary(summaryInput(decision, capabilityManifest, [
      result(decision.research_id, "research.fetch", "v1"),
      result(decision.research_id, "research.context", "v2", "pending"),
    ])).disposition, "wait");
  });

  test("fails unavailable required results and preserves optional failures as partial", () => {
    const capabilityManifest = manifest();
    const decision = decideSlackResearchCapabilities(request(), capabilityManifest);
    const requiredFailure = planSlackResearchSummary(summaryInput(
      decision,
      capabilityManifest,
      [
        result(decision.research_id, "research.fetch", "v1", "failed"),
        result(decision.research_id, "research.context", "v2"),
      ],
    ));
    assert.deepEqual(requiredFailure, {
      completeness: "none",
      disposition: "unavailable",
      reason_code: "required_result_unavailable",
      schema_version: "slack-research-summary-plan/v1",
      summary_id: requiredFailure.summary_id,
    });

    const optionalFailure = planSlackResearchSummary(summaryInput(
      decision,
      capabilityManifest,
      [
        result(decision.research_id, "research.fetch", "v1"),
        result(decision.research_id, "research.context", "v2", "unavailable"),
      ],
    ));
    assert.equal(optionalFailure.disposition, "summarize");
    if (optionalFailure.disposition !== "summarize") assert.fail("expected partial summary");
    assert.equal(optionalFailure.completeness, "partial");
    assert.deepEqual(optionalFailure.result_refs, ["result:research.fetch"]);

    const optionalRequest = request({
      capabilities: [{ capability_id: "research.context", level: "optional", version: "v2" }],
    });
    const optionalManifest = manifest({
      capabilities: [{ capability_id: "research.context", level: "optional", version: "v2" }],
    });
    const optionalDecision = decideSlackResearchCapabilities(optionalRequest, optionalManifest);
    const optionalOnly = planSlackResearchSummary({
      capability_decision: optionalDecision,
      capability_manifest: optionalManifest,
      request: optionalRequest,
      results: [result(optionalDecision.research_id, "research.context", "v2", "failed")],
      schema_version: "slack-research-summary-policy-input/v1",
    });
    assert.equal(optionalOnly.disposition, "summarize");
    if (optionalOnly.disposition !== "summarize") assert.fail("expected partial summary");
    assert.equal(optionalOnly.completeness, "partial");
    assert.deepEqual(optionalOnly.result_refs, []);
  });

  test("stops on missing required capability or incompatible core contract", () => {
    const blockedManifest = manifest({ capabilities: [capabilities[1]!] });
    const blocked = decideSlackResearchCapabilities(request(), blockedManifest);
    const unavailable = planSlackResearchSummary(summaryInput(blocked, blockedManifest, []));
    assert.equal(unavailable.disposition, "unavailable");
    if (unavailable.disposition !== "unavailable") assert.fail("expected unavailable");
    assert.equal(unavailable.reason_code, "missing_required_capability");

    const incompatibleManifest = manifest({ contract_versions: ["v2"] });
    const incompatible = decideSlackResearchCapabilities(request(), incompatibleManifest);
    const incompatiblePlan = planSlackResearchSummary(
      summaryInput(incompatible, incompatibleManifest, []),
    );
    assert.equal(incompatiblePlan.disposition, "unavailable");
    if (incompatiblePlan.disposition !== "unavailable") assert.fail("expected unavailable");
    assert.equal(incompatiblePlan.reason_code, "incompatible_contract");
  });

  test("rejects duplicate, unknown, malformed, and manifest-stale result sets", () => {
    const capabilityManifest = manifest();
    const decision = decideSlackResearchCapabilities(request(), capabilityManifest);
    const valid = result(decision.research_id, "research.fetch", "v1");
    const input = summaryInput(decision, capabilityManifest, [valid]);
    assert.throws(() => planSlackResearchSummary({
      ...input,
      results: [valid, valid],
    }), /duplicated/);
    assert.throws(() => planSlackResearchSummary({
      ...input,
      results: [result(decision.research_id, "research.unknown", "v1")],
    }), /not requested/);
    assert.throws(() => planSlackResearchSummary({
      ...input,
      results: [{ ...valid, result_digest: undefined }],
    }), /requires a digest/);
    assert.throws(() => planSlackResearchSummary({
      ...input,
      capability_decision: { ...decision, decision_id: "decision:forged" },
    }), /inconsistent with its manifest/);
    assert.throws(() => planSlackResearchSummary({
      ...input,
      capability_manifest: manifest({ generation: capabilityManifest.generation + 1 }),
    }), /inconsistent with its manifest/);
    assert.throws(() => decideSlackResearchCapabilities(
      request({
        request_key: "é".repeat(SLACK_RESEARCH_LIMITS.request_key_utf8_bytes / 2 + 1),
      }),
      capabilityManifest,
    ), /request key is invalid/);
  });

  test("rejects every non-plain top-level and nested record", () => {
    const invalidRecords = [null, [], 7, () => undefined, new Date()];
    const capabilityManifest = manifest();
    const decision = decideSlackResearchCapabilities(request(), capabilityManifest);
    for (const invalid of invalidRecords) {
      assert.throws(
        () => decideSlackResearchCapabilities(invalid as never, capabilityManifest),
        SlackResearchPolicyError,
      );
      assert.throws(
        () => decideSlackResearchCapabilities(request(), invalid as never),
        SlackResearchPolicyError,
      );
      assert.throws(
        () => decideSlackResearchCapabilities(
          request({ capabilities: [invalid as never] }),
          capabilityManifest,
        ),
        SlackResearchPolicyError,
      );
      assert.throws(
        () => planSlackResearchSummary({
          ...summaryInput(decision, capabilityManifest, []),
          results: [invalid as never],
        }),
        SlackResearchPolicyError,
      );
    }
  });
});
