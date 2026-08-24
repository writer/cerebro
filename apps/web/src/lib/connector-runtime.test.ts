import { describe, expect, it } from "vitest";

import {
  attachGraphFreshness,
  formatCount,
  formatDelta,
  formatDuration,
  latestGraphRunsByRuntime,
  normalizeRuntime,
  normalizeSourceRuntimeSummary,
  runtimeHealth,
  runtimeIsBackfill,
  sourceBreakdown,
  summarizeConnectorRuntime,
} from "./connector-runtime";

const now = new Date("2026-06-03T12:00:00Z");

describe("Connector runtime normalization", () => {
  it("marks recently active runtimes healthy", () => {
    const runtime = normalizeRuntime(
      {
        id: "example-okta-audit",
        source_id: "okta",
        tenant_id: "tenant-a",
        status: "running",
        last_synced_at: "2026-06-03T11:30:00Z",
        config: { family: "audit" },
      },
      now,
      24,
    );

    expect(runtime).toMatchObject({
      runtime_id: "example-okta-audit",
      source_id: "okta",
      tenant_id: "tenant-a",
      family: "audit",
      health: "healthy",
      age_hours: 0.5,
    });
  });

  it("keeps legacy sync field compatibility", () => {
    expect(runtimeHealth({ last_sync_at: "2026-06-03T11:30:00Z" }, now, 24)).toMatchObject({
      health: "healthy",
      ageHours: 0.5,
    });
  });

  it("marks old runtime activity stale", () => {
    expect(runtimeHealth({ last_synced_at: "2026-06-01T00:00:00Z" }, now, 24)).toMatchObject({
      health: "stale",
      ageHours: 60,
    });
  });

  it("uses health endpoint schedule threshold and watermark lag when present", () => {
    const runtime = normalizeRuntime(
      {
        runtime_id: "example-okta-audit",
        source_id: "okta",
        tenant_id: "tenant-a",
        family: "audit",
        last_synced_at: "2026-06-03T11:30:00Z",
        sync_lag_seconds: 1_800,
        checkpoint_watermark: "2026-06-01T12:00:00Z",
        watermark_lag_seconds: 172_800,
        stale_after_seconds: 86_400,
        cursor_pending: false,
        checkpoint_cursor_present: true,
        generated_at: "2026-06-03T12:00:00Z",
      },
      now,
      72,
    );

    expect(runtime).toMatchObject({
      runtime_id: "example-okta-audit",
      family: "audit",
      health: "stale",
      checkpoint_watermark: "2026-06-01T12:00:00Z",
      watermark_lag_seconds: 172_800,
      watermark_age_hours: 48,
      cursor_state: "caught_up",
      checkpoint_cursor_present: true,
      stale_after_seconds: 86_400,
    });
  });

  it("reports pending cursor state without exposing opaque cursor values", () => {
    const runtime = normalizeRuntime(
      {
        runtime_id: "example-github-audit",
        last_synced_at: "2026-06-03T11:30:00Z",
        cursor_pending: true,
        checkpoint_cursor_present: true,
      },
      now,
      24,
    );

    expect(runtime.cursor_state).toBe("pending");
    expect(runtime.cursor_pending).toBe(true);
    expect(Object.keys(runtime)).not.toContain("next_cursor");
    expect(Object.keys(runtime)).not.toContain("cursor_opaque");
  });

  it("marks missing activity unknown", () => {
    expect(runtimeHealth({}, now, 24)).toEqual({ health: "unknown" });
  });

  it("marks explicit failures degraded even with recent activity", () => {
    expect(runtimeHealth({ status: "failed", last_sync_at: "2026-06-03T11:50:00Z" }, now, 24)).toMatchObject({
      health: "degraded",
    });
  });

  it("marks graph and finding evaluation failures degraded when health fields exist", () => {
    expect(
      runtimeHealth(
        {
          last_synced_at: "2026-06-03T11:50:00Z",
          latest_graph_run: { id: "graph-run", status: "failed", error: "projection failed" },
        },
        now,
        24,
      ),
    ).toMatchObject({ health: "degraded" });

    expect(
      runtimeHealth(
        {
          last_synced_at: "2026-06-03T11:50:00Z",
          latest_finding_evaluation: { id: "finding-run", status: "error", error: "evaluation failed" },
        },
        now,
        24,
      ),
    ).toMatchObject({ health: "degraded" });
  });

  it("detects backfills from runtime id or bounded config", () => {
    expect(runtimeIsBackfill({ id: "example-okta-audit-backfill", config: {} })).toBe(true);
    expect(runtimeIsBackfill({ id: "example-okta-audit-2026-q1", config: { since: "2026-01-01T00:00:00Z" } })).toBe(true);
    expect(runtimeIsBackfill({ id: "example-okta-audit", config: {} })).toBe(false);
  });

  it("summarizes runtime health and source coverage", () => {
    const runtimes = [
      normalizeRuntime({ id: "a", source_id: "okta", tenant_id: "tenant-a", last_sync_at: "2026-06-03T11:00:00Z" }, now, 24),
      normalizeRuntime({ id: "b", source_id: "aws", tenant_id: "tenant-a", last_synced_at: "2026-06-01T00:00:00Z" }, now, 24),
      normalizeRuntime({ id: "c", source_id: "aws", tenant_id: "tenant-a" }, now, 24),
      normalizeRuntime({ id: "d-backfill", source_id: "okta", tenant_id: "tenant-a", status: "failed" }, now, 24),
    ];

    expect(summarizeConnectorRuntime(runtimes)).toEqual({
      total: 4,
      healthy: 1,
      stale: 1,
      unknown: 1,
      degraded: 1,
      backfills: 1,
      sources: 2,
      tenants: 1,
      graph_current: 0,
      graph_behind: 0,
      graph_running: 0,
      graph_failed: 0,
      graph_not_observed: 4,
    });
  });

  it("sorts source breakdown by runtime count", () => {
    const runtimes = [
      normalizeRuntime({ id: "a", source_id: "okta", last_sync_at: "2026-06-03T11:00:00Z" }, now, 24),
      normalizeRuntime({ id: "b", source_id: "aws", last_sync_at: "2026-06-01T00:00:00Z" }, now, 24),
      normalizeRuntime({ id: "c", source_id: "aws" }, now, 24),
    ];

    expect(sourceBreakdown(runtimes)).toEqual([
      { source_id: "aws", total: 2, stale: 1, degraded: 0, unknown: 1 },
      { source_id: "okta", total: 1, stale: 0, degraded: 0, unknown: 0 },
    ]);
  });

  it("uses Rust-produced readiness, action, graph, and rollup fields without reclassifying them", () => {
    const runtime = normalizeRuntime({
      runtime_id: "aws-finding",
      source_id: "aws",
      status: "healthy",
      readiness: "bad",
      next_action: "inspect_finding_evaluation",
      graph_state: "current",
      cursor_pending: false,
      schedule_context_configured: true,
      contract_probe_state: "passing",
      finding_evaluation_state: "failed",
      last_synced_at: "2026-06-03T11:50:00Z",
    }, now, 24);

    expect(runtime).toMatchObject({
      readiness: "bad",
      next_action: "inspect_finding_evaluation",
      health: "degraded",
      graph_freshness: "current",
      contract_probe_state: "passing",
      finding_evaluation_state: "failed",
    });

    expect(normalizeSourceRuntimeSummary({
      source_id: "aws",
      total: 3,
      healthy: 1,
      needs_refresh: 1,
      poor: 0,
      bad: 1,
      readiness: "bad",
      next_action: "inspect_finding_evaluation",
      cursor_pending: 1,
      graph_current: 3,
    })).toMatchObject({
      source_id: "aws",
      total: 3,
      healthy: 1,
      stale: 1,
      degraded: 1,
      performance: "bad",
      next_action: "Inspect the failed finding evaluation",
      cursor_pending: 1,
      graph_current: 3,
    });
  });

  it("classifies graph projection freshness against source sync time", () => {
    const runtime = normalizeRuntime(
      {
        id: "acme-github-audit-platform",
        source_id: "github",
        last_synced_at: "2026-06-03T11:30:00Z",
      },
      now,
      24,
    );
    const graphRuns = latestGraphRunsByRuntime([
      {
        id: "older-run",
        runtime_id: "acme-github-audit-platform",
        status: "completed",
        finished_at: "2026-06-03T09:00:00Z",
      },
      {
        id: "latest-run",
        runtime_id: "acme-github-audit-platform",
        status: "completed",
        finished_at: "2026-06-03T11:35:00Z",
      },
    ]);

    expect(attachGraphFreshness(runtime, graphRuns.get(runtime.runtime_id), now)).toMatchObject({
      graph_freshness: "current",
      graph_run_id: "latest-run",
      graph_age_hours: 0.4,
    });
  });

  it("normalizes endpoint graph run counts, deltas, duration, errors, and finding evaluation", () => {
    const runtime = normalizeRuntime(
      {
        runtime_id: "example-github-audit",
        source_id: "github",
        tenant_id: "tenant-a",
        family: "audit",
        last_synced_at: "2026-06-03T11:30:00Z",
        latest_graph_run: {
          id: "graph-run",
          status: "completed",
          started_at: "2026-06-03T11:31:00Z",
          finished_at: "2026-06-03T11:35:00Z",
          error: "minor warning",
          pages_read: 2,
          events_read: 1200,
          entities_projected: 100,
          links_projected: 42,
          graph_nodes_before: 900,
          graph_nodes_after: 1000,
          graph_links_before: 2000,
          graph_links_after: 2042,
          graph_node_delta: 100,
          graph_link_delta: 42,
          duration_seconds: 240,
        },
        latest_finding_evaluation: {
          id: "finding-run",
          runtime_id: "example-github-audit",
          status: "completed",
          events_evaluated: 1200,
          events_processed: 1190,
          events_matched: 3,
          findings_upserted: 2,
          duration_seconds: 30,
        },
      },
      now,
      24,
    );

    expect(runtime).toMatchObject({
      graph_freshness: "current",
      graph_run_id: "graph-run",
      graph_status: "completed",
      graph_age_hours: 0.4,
      latest_graph_run: {
        events_read: 1200,
        entities_projected: 100,
        links_projected: 42,
        graph_node_delta: 100,
        graph_link_delta: 42,
        duration_seconds: 240,
        error: "minor warning",
      },
      latest_finding_evaluation: {
        id: "finding-run",
        status: "completed",
        events_evaluated: 1200,
        duration_seconds: 30,
      },
      finding_evaluation_status: "completed",
      finding_evaluation_duration_seconds: 30,
    });
  });

  it("marks graph projection behind when source sync is newer than graph ingest", () => {
    const runtime = normalizeRuntime({ id: "example-okta-audit", last_synced_at: "2026-06-03T11:30:00Z" }, now, 24);

    expect(
      attachGraphFreshness(
        runtime,
        {
          id: "graph-run",
          runtime_id: "example-okta-audit",
          status: "completed",
          finished_at: "2026-06-03T10:00:00Z",
        },
        now,
      ),
    ).toMatchObject({
      graph_freshness: "behind",
      graph_run_id: "graph-run",
    });
  });

  it("keeps endpoint graph health when no fallback graph run is attached", () => {
    const runtime = normalizeRuntime(
      {
        runtime_id: "example-okta-audit",
        last_synced_at: "2026-06-03T11:30:00Z",
        latest_graph_run: {
          id: "endpoint-graph-run",
          status: "completed",
          finished_at: "2026-06-03T11:35:00Z",
        },
      },
      now,
      24,
    );

    expect(attachGraphFreshness(runtime, undefined, now)).toMatchObject({
      graph_freshness: "current",
      graph_run_id: "endpoint-graph-run",
    });
  });

  it("formats durations, compact counts, and signed deltas", () => {
    expect(formatDuration(45)).toBe("45s");
    expect(formatDuration(360)).toBe("6m");
    expect(formatCount(12_500)).toBe("12.5K");
    expect(formatDelta(42)).toBe("+42");
    expect(formatDelta(-7)).toBe("-7");
    expect(formatDelta(0)).toBe("±0");
  });
});
