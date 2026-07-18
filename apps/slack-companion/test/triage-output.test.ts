import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { parseTriageAgentOutput } from "../src/index.js";

describe("portable triage output boundary", () => {
  test("normalizes fenced output, aliases, and fallback research", () => {
    const result = parseTriageAgentOutput(
      `\`\`\`json
{
  "topic": "assistant_follow_up",
  "classification": "likely_security_issue",
  "severity": "info",
  "confidence": "0.82",
  "shouldRespond": "yes",
  "responseReason": "The current evidence needs an owner response.",
  "summary": "A privileged change needs an accountable owner.",
  "evidence": "The change has no recorded owner.",
  "actionsTaken": ["Checked the evidence receipt."],
  "recommendedActions": ["Confirm the accountable owner."],
  "research": []
}
\`\`\``,
      { research_trail: ["evidence://sample/current"] },
    );

    assert.equal(result.disposition, "accepted");
    if (result.disposition !== "accepted") assert.fail("expected accepted output");
    assert.deepEqual(result.output, {
      actions_taken: ["Checked the evidence receipt."],
      classification: "actionable",
      confidence: 0.82,
      evidence: ["The change has no recorded owner."],
      recommended_actions: ["Confirm the accountable owner."],
      redaction_state: "redacted",
      research: ["evidence://sample/current"],
      response_reason: "The current evidence needs an owner response.",
      schema_version: "triage-agent-output/v1",
      severity: "informational",
      should_respond: true,
      summary: "A privileged change needs an accountable owner.",
      topic: "assistant_follow_up",
    });
  });

  test("redacts every returned text surface before accepting output", () => {
    const tokenLike = ["xoxb", "synthetic", "fixture"].join("-");
    const accessKeyLike = ["AK", "IA", "A".repeat(16)].join("");
    const assignmentLike = ["password", "=", "synthetic-fixture"].join("");
    const result = parseTriageAgentOutput(JSON.stringify({
      actions_taken: [`Removed ${assignmentLike}`],
      classification: "needs_context",
      confidence: 0.6,
      evidence: [`Observed ${tokenLike}`],
      recommended_actions: [`Rotate ${accessKeyLike}`],
      research: [`reference ${assignmentLike}`],
      response_reason: `Review ${tokenLike}`,
      summary: `Potential exposure: ${tokenLike}`,
    }));

    assert.equal(result.disposition, "accepted");
    if (result.disposition !== "accepted") assert.fail("expected accepted output");
    assert.equal(result.output.redaction_state, "redacted");
    assert.doesNotMatch(JSON.stringify(result.output), /synthetic-fixture|xoxb-/);
    assert.match(result.output.summary, /\[redacted_token\]/);
    assert.match(result.output.actions_taken[0] ?? "", /password=\[redacted_secret\]/);
    assert.match(result.output.recommended_actions[0] ?? "", /\[redacted_access_key\]/);
  });

  test("bounds output collections and each text field", () => {
    const result = parseTriageAgentOutput(JSON.stringify({
      actions_taken: Array.from({ length: 9 }, (_, index) => `action-${index}-${"a".repeat(500)}`),
      classification: "actionable",
      confidence: 1,
      evidence: Array.from({ length: 9 }, (_, index) => `evidence-${index}`),
      recommended_actions: Array.from({ length: 9 }, (_, index) => `recommendation-${index}`),
      research: Array.from({ length: 12 }, (_, index) => `research-${index}`),
      response_reason: "r".repeat(500),
      summary: "s".repeat(1_000),
    }));

    assert.equal(result.disposition, "accepted");
    if (result.disposition !== "accepted") assert.fail("expected accepted output");
    assert.equal(result.output.actions_taken.length, 6);
    assert.equal(result.output.evidence.length, 6);
    assert.equal(result.output.recommended_actions.length, 6);
    assert.equal(result.output.research.length, 8);
    assert.equal(result.output.actions_taken[0]?.length, 400);
    assert.equal(result.output.response_reason?.length, 400);
    assert.equal(result.output.summary.length, 900);
  });

  test("defaults response policy without overriding explicit false", () => {
    const actionable = parseTriageAgentOutput(JSON.stringify({
      classification: "actionable",
      confidence: 0.75,
      evidence: ["Current evidence exists."],
      summary: "Review the current evidence.",
    }));
    const explicitFalse = parseTriageAgentOutput(JSON.stringify({
      classification: "actionable",
      confidence: 0.75,
      evidence: ["Current evidence exists."],
      should_respond: false,
      summary: "Do not post this result.",
    }));
    const noise = parseTriageAgentOutput(JSON.stringify({
      classification: "likely_noise",
      confidence: 0.9,
      evidence: ["The event matches the expected baseline."],
      summary: "No action is needed.",
    }));

    assert.equal(
      actionable.disposition === "accepted" && actionable.output.should_respond,
      true,
    );
    assert.equal(
      explicitFalse.disposition === "accepted" && explicitFalse.output.should_respond,
      false,
    );
    assert.equal(
      noise.disposition === "accepted" && noise.output.should_respond,
      false,
    );
  });

  test("rejects oversized, ambiguous, malformed, and schema-invalid output", () => {
    assert.deepEqual(parseTriageAgentOutput("x".repeat(65_537)), {
      disposition: "rejected",
      reason_code: "input_too_large",
      schema_version: "triage-output-parse-result/v1",
    });
    assert.equal(
      parseTriageAgentOutput("preface {\"classification\":\"actionable\"}").disposition,
      "rejected",
    );
    assert.equal(parseTriageAgentOutput("{not-json}").disposition, "rejected");
    assert.equal(
      parseTriageAgentOutput(JSON.stringify({
        classification: "actionable",
        confidence: 2,
        evidence: [{}],
        summary: "Invalid output.",
      })).disposition,
      "rejected",
    );
  });
});
