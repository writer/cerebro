import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  actionsFromResearch,
  graphSummary,
  heuristicTriage,
  shortError,
} from "../src/triage/alert-triage-fallback.js";

describe("deterministic alert-triage fallback", () => {
  test("returns the fixed non-actionable result for every explicit test marker", () => {
    const markers = [
      "canary",
      "test-only",
      "pipeline test",
      "test alert",
      "no action needed",
    ];
    for (const marker of markers) {
      const research = ["source_query: checked"];
      const result = heuristicTriage({ text: `CRITICAL ${marker.toUpperCase()}` }, research);

      assert.deepEqual(result, {
        classification: "non_actionable",
        severity: "informational",
        confidence: 0.7,
        shouldRespond: false,
        responseReason: "The message is an explicit canary/test signal and does not need Cerebro to interrupt the thread.",
        summary: "The alert text is explicitly marked as a canary or test and says no action is needed. Cerebro graph reasoning was unavailable, so no graph evidence was verified.",
        evidence: ["Alert text contains a test or canary marker.", "Cerebro graph reasoning was unavailable during fallback."],
        actionsTaken: ["source query"],
        recommendedActions: ["No response action is needed for the canary alert.", "Retry Cerebro graph reasoning if this was not intended as a test."],
        research,
        source: "cerebro_fallback",
      }, marker);
      assert.equal(result.research, research);
    }
  });

  test("checks test markers before security terms and preserves word boundaries", () => {
    assert.equal(
      heuristicTriage({ text: "Critical credential canary" }, []).classification,
      "non_actionable",
    );
    assert.deepEqual(
      fallbackDecision("The canarying service passed contest alerts."),
      { classification: "needs_context", confidence: 0.3, severity: "informational" },
    );
  });

  test("returns the fixed unverified result for security terms", () => {
    const research = ["identity_lookup: checked", "ignored note"];
    const result = heuristicTriage({ text: "Suspicious credential exposure" }, research);

    assert.deepEqual(result, {
      classification: "needs_context",
      severity: "medium",
      confidence: 0.4,
      shouldRespond: false,
      responseReason: "Fallback did not verify enough signal to interrupt the thread.",
      summary: "The alert text contains security-relevant terms, but Cerebro graph reasoning was unavailable. Treat this as unverified until the affected identity, resource, and related findings are checked.",
      evidence: ["Cerebro graph reasoning was unavailable during fallback.", "No graph evidence was verified for this alert."],
      actionsTaken: ["identity lookup"],
      recommendedActions: ["Review the source alert fields.", "Check related Cerebro findings or rerun triage when graph reasoning is available."],
      research,
      source: "cerebro_fallback",
    });
    assert.equal(result.research, research);
  });

  test("returns the fixed generic result when no security term is present", () => {
    const research: string[] = [];
    const result = heuristicTriage({ text: "Routine service update" }, research);

    assert.deepEqual(result, {
      classification: "needs_context",
      severity: "informational",
      confidence: 0.3,
      shouldRespond: false,
      responseReason: "Fallback did not verify enough signal to interrupt the thread.",
      summary: "Cerebro graph reasoning was unavailable and the alert text does not contain enough verified context for a security classification.",
      evidence: ["Cerebro graph reasoning was unavailable during fallback.", "No graph evidence was verified for this alert."],
      actionsTaken: [],
      recommendedActions: ["Review the source alert fields.", "Check related Cerebro findings or rerun triage when graph reasoning is available."],
      research,
      source: "cerebro_fallback",
    });
  });

  test("redacts frozen secret forms before selecting the fallback branch", () => {
    const keyLabel = "PRIVATE KEY";
    const privateKeyFixture = [
      `-----BEGIN TEST ${keyLabel}-----`,
      "canary",
      `-----END TEST ${keyLabel}-----`,
    ].join("\n");
    const awsAccessKeyFixture = ["AKIA", "1234567890ABCDEF"].join("");
    const slackTokenFixture = ["xoxb", "canary"].join("-");

    assert.deepEqual(
      fallbackDecision("password=canary"),
      { classification: "needs_context", confidence: 0.3, severity: "informational" },
    );
    assert.deepEqual(
      fallbackDecision("token=canary"),
      { classification: "needs_context", confidence: 0.4, severity: "medium" },
    );
    assert.deepEqual(
      fallbackDecision(awsAccessKeyFixture),
      { classification: "needs_context", confidence: 0.3, severity: "informational" },
    );
    assert.deepEqual(
      fallbackDecision(privateKeyFixture),
      { classification: "needs_context", confidence: 0.3, severity: "informational" },
    );
    assert.deepEqual(
      fallbackDecision(slackTokenFixture),
      { classification: "needs_context", confidence: 0.3, severity: "informational" },
    );
  });
});

describe("fallback result helpers", () => {
  test("extracts checked and fallback research actions in order", () => {
    assert.deepEqual(actionsFromResearch([
      "source_query: checked",
      "ignored note",
      "PI FALLBACK: local_cache",
      "middle: CHECKED extra",
      ": checked",
      "fallback only",
    ]), [
      "source query",
      "Used fallback path: local cache",
      "middle: CHECKED extra",
      "fallback only",
    ]);
  });

  test("returns no more than six research actions", () => {
    const research = Array.from({ length: 8 }, (_, index) => `step_${index}: checked`);
    assert.deepEqual(actionsFromResearch(research), [
      "step 0",
      "step 1",
      "step 2",
      "step 3",
      "step 4",
      "step 5",
    ]);
  });

  test("normalizes error whitespace and caps the result at 160 characters", () => {
    assert.equal(shortError(new Error("first\n\tsecond   third")), "first second third");
    assert.equal(shortError({ code: "failed" }), "[object Object]");
    assert.equal(shortError("x".repeat(200)), "x".repeat(160));
  });

  test("returns an empty graph summary for no value and truncates after 899 characters", () => {
    assert.equal(graphSummary(undefined), "");
    assert.equal(graphSummary("x".repeat(900)), "x".repeat(900));
    assert.equal(graphSummary("x".repeat(901)), `${"x".repeat(899)}…`);
  });
});

function fallbackDecision(text: string) {
  const result = heuristicTriage({ text }, []);
  return {
    classification: result.classification,
    confidence: result.confidence,
    severity: result.severity,
  };
}
