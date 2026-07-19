import { describe, expect, it } from "vitest";

import type { AskEvalReport } from "./types";

describe("Ask eval report contract", () => {
  it("keeps the persisted report shape stable for the developer eval page", () => {
    const report: AskEvalReport = {
      generatedAt: "2026-01-01T00:00:00.000Z",
      localOnly: true,
      totals: { passed: 1, failed: 0, total: 1 },
      runs: [
        {
          id: "high-risk-repos",
          kind: "ask",
          name: "High-risk repository summary",
          question: "Summarize high-risk repositories",
          tenantId: "tenant-a",
          model: "claude-sonnet-4-6",
          status: "passed",
          score: 100,
          startedAt: "2026-01-01T00:00:00.000Z",
          completedAt: "2026-01-01T00:00:00.100Z",
          durationMs: 100,
          traceId: "upstream-trace",
          rowCount: 1,
          citationCount: 1,
          cypherRefused: false,
          queryPlanIntent: "top_risk_findings",
          queryPlanSource: "deterministic_template",
          queryPlanCorrected: false,
          conversionDiagnosticsCount: 1,
          summary: "repo has one high finding",
          events: [{ event: "query_plan", data: { plan: { intent: "top_risk_findings" } } }],
          fixtureKind: "golden",
          provenance: { source: "ask-eval-scenarios", generatedAt: "2026-01-01T00:00:00.000Z" },
          baseline: { summary: "repo has one high finding" },
          diff: { added: [], removed: [], changed: false },
          judges: {
            citationIntegrity: { passed: true, detail: "1 citations validated" },
            summaryGrounding: { passed: true, detail: "all Cerebro URNs in summary are row-backed" },
          },
          cypherPreview: "MATCH (e:Entity)",
          rubrics: [
            {
              id: "citations",
              label: "required citations are present",
              passed: true,
              detail: "1 citations >= 1",
            },
          ],
        },
      ],
    };

    expect(report.runs[0].kind).toBe("ask");
    expect(report.runs[0].queryPlanIntent).toBe("top_risk_findings");
    expect(report.runs[0].rubrics[0].passed).toBe(true);
  });
});
