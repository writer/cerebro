import { describe, expect, it } from "vitest";

import { buildNotifications, notificationSignatures, reportRunNotifications, unreadNotifications } from "@/lib/notifications";
import type { GRCDashboard, GRCFinding, GRCSummary } from "@/lib/grc";
import type { ReportDefinition, ReportRun } from "@/lib/report-schedules";

const makeSummary = (overrides: Partial<GRCSummary> = {}): GRCSummary => ({
  open_findings: 0,
  critical_findings: 0,
  high_findings: 0,
  overdue_findings: 0,
  unassigned: 0,
  controls_failing: 0,
  evidence_items: 0,
  connectors: 0,
  stale_connectors: 0,
  ...overrides,
});

const makeFinding = (overrides: Partial<GRCFinding> = {}): GRCFinding => ({
  id: "f1",
  title: "Example finding",
  severity: "LOW",
  status: "open",
  evidence_count: 0,
  owner: "",
  sla_status: "on_track",
  ...overrides,
});

const makeDashboard = (overrides: Partial<GRCDashboard> = {}): GRCDashboard => ({
  summary: makeSummary(),
  findings: [],
  controls: [],
  evidence: [],
  connectors: [],
  generated_at: "",
  ...overrides,
});

describe("buildNotifications", () => {
  it("returns nothing when the dashboard is missing", () => {
    expect(buildNotifications(null)).toEqual([]);
    expect(buildNotifications(undefined)).toEqual([]);
  });

  it("returns nothing when findings are healthy and the summary is clean", () => {
    const dashboard = makeDashboard({
      findings: [makeFinding({ severity: "MEDIUM", sla_status: "on_track" })],
    });
    expect(buildNotifications(dashboard)).toEqual([]);
  });

  it("creates a per-item alert for a critical open finding that deep-links to it", () => {
    const dashboard = makeDashboard({
      findings: [makeFinding({ id: "abc", title: "Public bucket", severity: "CRITICAL" })],
    });
    const [item] = buildNotifications(dashboard);
    expect(item.id).toBe("finding:abc");
    expect(item.href).toBe("/findings/abc");
    expect(item.intent).toBe("danger");
    expect(item.title).toBe("Critical finding: Public bucket");
  });

  it("labels an overdue finding by SLA and includes its severity", () => {
    const dashboard = makeDashboard({
      findings: [makeFinding({ id: "h1", title: "Open port", severity: "HIGH", sla_status: "overdue" })],
    });
    const [item] = buildNotifications(dashboard);
    expect(item.title).toBe("Past SLA: Open port");
    expect(item.detail).toContain("HIGH");
  });

  it("treats a finding that is both critical and overdue as a single SLA alert", () => {
    const dashboard = makeDashboard({
      findings: [makeFinding({ id: "x", severity: "CRITICAL", sla_status: "overdue" })],
    });
    const items = buildNotifications(dashboard);
    expect(items).toHaveLength(1);
    expect(items[0].title).toContain("Past SLA");
  });

  it("orders finding alerts by risk score and caps the count", () => {
    const findings = Array.from({ length: 10 }, (_, index) =>
      makeFinding({ id: `f${index}`, severity: "CRITICAL", risk_score: index }),
    );
    const items = buildNotifications(makeDashboard({ findings }));
    expect(items).toHaveLength(8);
    expect(items[0].id).toBe("finding:f9");
    expect(items[1].id).toBe("finding:f8");
  });

  it("appends coarse summary warnings after the finding alerts", () => {
    const dashboard = makeDashboard({
      findings: [makeFinding({ id: "c1", severity: "CRITICAL" })],
      summary: makeSummary({ unassigned: 2, controls_failing: 1, stale_connectors: 3 }),
    });
    const items = buildNotifications(dashboard);
    expect(items.map((item) => item.intent)).toEqual(["danger", "warning", "warning", "warning"]);
    expect(items.find((item) => item.id === "unassigned-findings")?.title).toBe("2 unassigned findings");
    expect(items.find((item) => item.id === "failing-controls")?.title).toBe("1 control failing");
    expect(items.find((item) => item.id === "stale-connectors")?.title).toBe("3 stale connectors");
  });

  it("changes a finding signature when its severity or SLA state changes", () => {
    const before = buildNotifications(makeDashboard({ findings: [makeFinding({ id: "s", severity: "CRITICAL" })] }));
    const after = buildNotifications(makeDashboard({ findings: [makeFinding({ id: "s", severity: "CRITICAL", sla_status: "overdue" })] }));
    expect(before[0].id).toBe(after[0].id);
    expect(before[0].signature).not.toBe(after[0].signature);
  });
});

describe("reportRunNotifications", () => {
  const definitions: ReportDefinition[] = [{ id: "finding-summary", name: "Finding Summary" }];
  const makeRun = (overrides: Partial<ReportRun> = {}): ReportRun => ({
    id: "run-1",
    report_id: "finding-summary",
    status: "completed",
    generated_at: "2026-06-22T16:00:00Z",
    ...overrides,
  });

  it("returns nothing without runs", () => {
    expect(reportRunNotifications(undefined)).toEqual([]);
    expect(reportRunNotifications([])).toEqual([]);
  });

  it("surfaces a completed run as an info notification linking to schedules", () => {
    const [item] = reportRunNotifications([makeRun()], definitions);
    expect(item.id).toBe("report-run:run-1");
    expect(item.intent).toBe("info");
    expect(item.title).toBe("Report ready: Finding Summary");
    expect(item.href).toBe("/reports/schedules");
  });

  it("marks a failed run as a warning", () => {
    const [item] = reportRunNotifications([makeRun({ id: "run-2", status: "failed" })], definitions);
    expect(item.intent).toBe("warning");
    expect(item.title).toBe("Report failed: Finding Summary");
  });

  it("falls back to the report id when no definitions are provided", () => {
    const [item] = reportRunNotifications([makeRun()]);
    expect(item.title).toBe("Report ready: finding-summary");
  });

  it("changes the signature when run status changes and caps the list", () => {
    const completed = reportRunNotifications([makeRun()], definitions)[0];
    const failed = reportRunNotifications([makeRun({ status: "failed" })], definitions)[0];
    expect(completed.signature).not.toBe(failed.signature);

    const manyRuns = Array.from({ length: 9 }, (_, index) => makeRun({ id: `run-${index}` }));
    expect(reportRunNotifications(manyRuns, definitions)).toHaveLength(5);
  });
});

describe("unreadNotifications", () => {
  it("hides notifications whose signature was already seen", () => {
    const items = buildNotifications(
      makeDashboard({ findings: [makeFinding({ id: "a", severity: "CRITICAL" }), makeFinding({ id: "b", sla_status: "overdue" })] }),
    );
    const seen = [items[0].signature];
    const unread = unreadNotifications(items, seen);
    expect(unread).toHaveLength(1);
    expect(unread[0].id).toBe("finding:b");
  });

  it("re-surfaces a finding whose state changed since it was last seen", () => {
    const previous = buildNotifications(makeDashboard({ findings: [makeFinding({ id: "s", severity: "CRITICAL" })] }));
    const current = buildNotifications(makeDashboard({ findings: [makeFinding({ id: "s", severity: "CRITICAL", sla_status: "overdue" })] }));
    const seen = notificationSignatures(previous);
    expect(unreadNotifications(current, seen)).toHaveLength(1);
  });

  it("surfaces a brand-new finding as unread", () => {
    const previous = buildNotifications(makeDashboard({ findings: [makeFinding({ id: "old", severity: "CRITICAL" })] }));
    const current = buildNotifications(
      makeDashboard({ findings: [makeFinding({ id: "old", severity: "CRITICAL" }), makeFinding({ id: "new", severity: "CRITICAL" })] }),
    );
    const seen = notificationSignatures(previous);
    const unread = unreadNotifications(current, seen);
    expect(unread.map((item) => item.id)).toEqual(["finding:new"]);
  });
});

describe("notificationSignatures", () => {
  it("returns the signature of every notification", () => {
    const items = buildNotifications(
      makeDashboard({ findings: [makeFinding({ id: "a", severity: "CRITICAL" })], summary: makeSummary({ stale_connectors: 1 }) }),
    );
    expect(notificationSignatures(items)).toEqual(items.map((item) => item.signature));
  });
});
