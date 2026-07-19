import { describe, expect, it } from "vitest";

import type { GRCControl, GRCProgramReadiness, GRCProgramReadinessSummary } from "@/lib/grc";

import { buildIssueQueue, buildReadinessChecks } from "./page";

const summary = (patch: Partial<GRCProgramReadinessSummary> = {}): GRCProgramReadinessSummary => ({
  status: "needs_attention",
  score: 76,
  controls: 5,
  passing_controls: 2,
  failing_controls: 1,
  missing_evidence_controls: 1,
  stale_evidence_controls: 0,
  manual_review_controls: 1,
  evidence_items: 8,
  missing_evidence_items: 1,
  stale_evidence_items: 0,
  open_findings: 2,
  critical_findings: 1,
  high_findings: 1,
  connectors: 3,
  stale_connectors: 1,
  coverage_blind_spots: 1,
  ...patch,
});

describe("GRC page helpers", () => {
  it("builds issue queue rows with owner, assignee, due date, SLA, and source", () => {
    const readinessData = {
      work_items: [
        {
          id: "finding-1",
          kind: "finding",
          title: "Privileged account missing MFA",
          framework_name: "SOC 2",
          control_id: "CC6.2",
          status: "open",
          action: "Review finding",
          assignee: "Alex",
          due_at: "2026-01-10T12:00:00.000Z",
          owner_domain: "Security",
          severity: "HIGH",
          sla_status: "due_soon",
          source_id: "okta",
          href: "/findings/finding-1",
          reasons: ["Owner and due date set by triage."],
        },
      ],
    } as GRCProgramReadiness;

    expect(buildIssueQueue(readinessData, [])).toEqual([
      expect.objectContaining({
        action: "Review finding",
        assignee: "Alex",
        detail: "Owner and due date set by triage.",
        dueLabel: "Jan 10",
        href: "/findings/finding-1",
        owner: "Security",
        severity: "HIGH",
        slaStatus: "due_soon",
        source: "okta",
        title: "Privileged account missing MFA",
        type: "Issue",
      }),
    ]);
  });

  it("falls back to failing controls when readiness work items are missing", () => {
    const controls = [
      {
        framework_name: "SOC 2",
        control_id: "CC6.2",
        status: "failing",
        owner_domain: "Security",
        open_findings: 2,
        critical_findings: 1,
        high_findings: 1,
        evidence_items: 3,
        missing_evidence_items: 1,
        stale_evidence_items: 0,
      },
    ] as GRCControl[];

    expect(buildIssueQueue(null, controls)).toEqual([
      expect.objectContaining({
        assignee: "Unassigned",
        dueLabel: "No due date",
        owner: "Security",
        source: "SOC 2",
        title: "SOC 2 CC6.2",
        type: "Control",
      }),
    ]);
  });

  it("builds packet blocker checks instead of roadmap steps", () => {
    const checks = buildReadinessChecks({ summary: summary() });

    expect(checks.map((check) => check.label)).toEqual(["Source gaps", "Failing controls", "Evidence gaps"]);
    expect(checks.map((check) => check.action)).toEqual(["Refresh sources", "Resolve controls", "Collect evidence"]);
    expect(checks.map((check) => check.href)).toEqual([
      "/reports/audit-packages#source-freshness",
      "/reports/audit-packages#control-owner-queue",
      "/reports/audit-packages#evidence-review",
    ]);
    expect(checks.map((check) => check.label)).not.toContain("Tests mapped");
  });

  it("returns a ready packet check when nothing blocks export", () => {
    expect(buildReadinessChecks({
      summary: summary({
        failing_controls: 0,
        manual_review_controls: 0,
        missing_evidence_items: 0,
        stale_evidence_items: 0,
        stale_connectors: 0,
        coverage_blind_spots: 0,
      }),
    })).toEqual([
      expect.objectContaining({
        action: "Open packet",
        href: "/reports/audit-packages",
        label: "Packet ready",
        status: "ready",
        value: "Clear",
      }),
    ]);
  });
});
