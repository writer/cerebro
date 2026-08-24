import type { GRCControl } from "@/lib/grc";

const readyStatuses = new Set(["audit_ready", "passing", "ready"]);

const normalizedStatus = (value?: string) => (value ?? "").trim().toLowerCase();

export const isControlAuditReady = (control: GRCControl) =>
  readyStatuses.has(normalizedStatus(control.status)) &&
  control.open_findings === 0 &&
  (control.missing_evidence_items ?? 0) === 0 &&
  (control.stale_evidence_items ?? 0) === 0;

export type FrameworkReadiness = {
  evidenceGapControls: number;
  failingControls: number;
  needsWorkControls: number;
  readyControls: number;
  score: number;
  totalControls: number;
};

export function deriveFrameworkReadiness({
  byStatus,
  controls,
  total,
}: {
  byStatus?: Record<string, number>;
  controls: GRCControl[];
  total?: number;
}): FrameworkReadiness {
  const normalizedCounts = Object.entries(byStatus ?? {}).reduce<Record<string, number>>((counts, [status, count]) => {
    counts[normalizedStatus(status)] = count;
    return counts;
  }, {});
  const statusCount = Object.values(normalizedCounts).reduce((sum, count) => sum + count, 0);
  const totalControls = Math.max(total ?? 0, statusCount, controls.length);
  const readyFromSummary = [...readyStatuses].reduce((sum, status) => sum + (normalizedCounts[status] ?? 0), 0);
  const readyFromControls = controls.filter(isControlAuditReady).length;
  const summaryReadyControlsWithBlockers = controls.filter((control) =>
    readyStatuses.has(normalizedStatus(control.status)) && !isControlAuditReady(control),
  ).length;
  const readyControls = Math.min(
    totalControls,
    statusCount > 0
      ? controls.length >= totalControls
        ? readyFromControls
        : Math.max(0, readyFromSummary - summaryReadyControlsWithBlockers)
      : readyFromControls,
  );
  const failingControls = Math.max(
    (normalizedCounts.failing ?? 0) + (normalizedCounts.failed ?? 0),
    controls.filter((control) => normalizedStatus(control.status) === "failing" || control.open_findings > 0).length,
  );
  const evidenceGapControls = Math.max(
    (normalizedCounts.missing_evidence ?? 0) + (normalizedCounts.stale_evidence ?? 0),
    controls.filter((control) => (control.missing_evidence_items ?? 0) > 0 || (control.stale_evidence_items ?? 0) > 0).length,
  );

  return {
    evidenceGapControls,
    failingControls,
    needsWorkControls: Math.max(0, totalControls - readyControls),
    readyControls,
    score: totalControls === 0 ? 0 : Math.round((readyControls / totalControls) * 100),
    totalControls,
  };
}
