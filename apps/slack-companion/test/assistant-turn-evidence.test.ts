import assert from "node:assert/strict";
import test from "node:test";
import {
  buildAssistantTurnEvidenceFallback,
  AssistantTurnEvidenceInputError,
} from "../src/index.js";

test("fallback preserves verified evidence when another source fails", () => {
  const output = buildAssistantTurnEvidenceFallback({
    evidence: [evidence("later", "2026-07-21T12:00:02.000Z", "Two active findings matched."), evidence("first", "2026-07-21T12:00:01.000Z", "The runtime is connected.")],
    gaps: [{
      scope: "graph path verification was not checked",
      source_label: "Graph reasoning",
      source_ref: "source://graph/reason",
      state: "timed_out",
    }],
    next_action: "I will recheck graph reasoning and update this thread.",
  });

  assert.equal(output.state, "partial");
  assert.equal(output.answer, "- The runtime is connected.\n- Two active findings matched.");
  assert.equal(
    output.coverage_notice,
    "Graph reasoning: graph path verification was not checked (timed out).",
  );
  assert.equal(output.content_digest.startsWith("sha256:"), true);
  assert.equal(JSON.stringify(output).includes("receipt://"), false);
});

test("fallback returns an exact block when no evidence was collected", () => {
  const output = buildAssistantTurnEvidenceFallback({
    evidence: [],
    gaps: [{
      scope: "current findings could not be read",
      source_label: "Cerebro findings",
      source_ref: "source://cerebro/findings",
      state: "unavailable",
    }],
    next_action: "I will retry after the source recovers.",
  });

  assert.equal(output.state, "blocked");
  assert.equal(output.answer, undefined);
  assert.match(output.coverage_notice!, /current findings could not be read/);
});

test("fallback rejects unsafe display statements and ambiguous empty input", () => {
  assert.throws(
    () => buildAssistantTurnEvidenceFallback({ evidence: [], gaps: [], next_action: "Retry." }),
    AssistantTurnEvidenceInputError,
  );
  assert.throws(
    () => buildAssistantTurnEvidenceFallback({
      evidence: [evidence("bad", "2026-07-21T12:00:00.000Z", "Visible\u0000hidden")],
      gaps: [],
      next_action: "Retry.",
    }),
    AssistantTurnEvidenceInputError,
  );
});

function evidence(id: string, observedAt: string, statement: string) {
  return {
    evidence_id: id,
    observed_at: observedAt,
    receipt_digest: `sha256:${id.padEnd(64, "a")}`,
    receipt_ref: `receipt://${id}`,
    source_label: "Cerebro",
    source_ref: "source://cerebro",
    statement,
  };
}
