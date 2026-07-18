import { describe, expect, it } from "vitest";

import { normalizeRuntimeFreshness } from "./runtime-freshness";

describe("normalizeRuntimeFreshness", () => {
  it("normalizes canonical runtime freshness responses", () => {
    const view = normalizeRuntimeFreshness({
      generated_at: "2026-06-12T00:00:00Z",
      status: "degraded",
      runtimes: [
        {
          runtime_id: "example-gcp-runtime",
          source_id: "gcp",
          freshness_state: "graph_missing",
          source_sync_state: "current",
          graph_ingest_state: "not_observed",
          backfill_eligible: true,
          next_action: "plan_backfill",
          failure_class: "graph_ingest_missing",
        },
      ],
      summaries: [
        {
          source_id: "gcp",
          total: 1,
          needs_attention: 1,
          backfill_eligible: 1,
          graph_missing: 1,
        },
      ],
    });

    expect(view.source).toBe("canonical");
    expect(view.status).toBe("degraded");
    expect(view.rows[0]).toMatchObject({
      runtime_id: "example-gcp-runtime",
      source_id: "gcp",
      freshness_state: "graph_missing",
      backfill_eligible: true,
      next_action: "plan_backfill",
    });
    expect(view.summaries[0]).toMatchObject({
      source_id: "gcp",
      needs_attention: 1,
      backfill_eligible: 1,
    });
  });

  it("falls back to graph ingest health when canonical data is unavailable", () => {
    const view = normalizeRuntimeFreshness({
      status: "failed",
      ingest: {
        missing_runtime_ids: ["example-aws-prod-runtime"],
      },
      failures: ["example-gcp-prod-runtime:graph-ingest:example-gcp-prod-runtime: failed"],
    });

    expect(view.source).toBe("graph-ingest-health");
    expect(view.status).toBe("degraded");
    expect(view.rows).toHaveLength(2);
    expect(view.rows.map((row) => row.freshness_state).sort()).toEqual(["graph_failed", "graph_missing"]);
    expect(view.summaries.map((summary) => summary.source_id).sort()).toEqual(["aws", "gcp"]);
  });
});
