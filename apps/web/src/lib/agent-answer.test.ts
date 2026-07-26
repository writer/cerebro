import { describe, expect, it } from "vitest";

import { collectUrns, validateAgentAnswer } from "./agent-answer";

describe("agent answer evidence", () => {
  it("collects bounded URNs from structured tool results", () => {
    expect([...collectUrns({
      finding: { urn: "urn:cerebro:writer:finding:f-1" },
      evidence: ["See urn:cerebro:writer:evidence:e-1."],
    })]).toEqual([
      "urn:cerebro:writer:finding:f-1",
      "urn:cerebro:writer:evidence:e-1.",
    ]);
  });

  it("keeps only observed citations and adds concrete spans and evidence gaps", () => {
    const observed = new Set(["urn:cerebro:writer:finding:f-1"]);
    const summary = validateAgentAnswer({
      markdown: "The finding needs attention.",
      citations: [
        "urn:cerebro:writer:finding:f-1",
        "urn:cerebro:writer:finding:invented",
      ],
      evidence_gaps: ["Asset ownership is not present in the tool result."],
      confidence: "medium",
    }, observed);

    expect(summary.markdown).toContain("urn:cerebro:writer:finding:f-1");
    expect(summary.markdown).toContain("### Evidence gaps");
    expect(summary.citations).toHaveLength(1);
    expect(summary.markdown.slice(...summary.citations[0].span))
      .toBe("urn:cerebro:writer:finding:f-1");
  });
});
