"use client";

import { Activity, CheckCircle2, Clock3, GitBranch, HelpCircle, ListChecks, RefreshCw, SearchCheck, XCircle } from "lucide-react";

import { Badge, EmptyBlock } from "@/components/grc/Primitives";
import { countLabel } from "@/lib/format";
import { displayDate, humanize } from "@/lib/grc";
import { formatDuration } from "@/lib/connector-runtime";
import {
  connectorDiagnosticStageLabel,
  connectorDiagnosticStatusLabel,
  type ConnectorDiagnosticTimeline,
} from "@/lib/connectors";

const statusIcon = (status: string) => {
  switch (status) {
    case "success":
      return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
    case "warning":
      return <RefreshCw className="h-4 w-4 text-amber-500" />;
    case "failed":
      return <XCircle className="h-4 w-4 text-red-500" />;
    case "running":
      return <Clock3 className="h-4 w-4 text-blue-500" />;
    default:
      return <HelpCircle className="h-4 w-4 text-[var(--text-muted)]" />;
  }
};

const stageIcon = (stage: string) => {
  switch (stage) {
    case "setup":
    case "preflight":
      return <ListChecks className="h-4 w-4" />;
    case "source_sync":
      return <RefreshCw className="h-4 w-4" />;
    case "contract_probe":
      return <SearchCheck className="h-4 w-4" />;
    case "graph_projection":
      return <GitBranch className="h-4 w-4" />;
    case "finding_evaluation":
      return <Activity className="h-4 w-4" />;
    default:
      return <Activity className="h-4 w-4" />;
  }
};

const countSummary = (entry: ConnectorDiagnosticTimeline) => {
  if (entry.stage === "graph_projection") {
    return [
      countLabel(entry.entities_projected ?? 0, "entity", "entities"),
      countLabel(entry.links_projected ?? 0, "link", "links"),
    ].join(", ");
  }
  if (entry.stage === "finding_evaluation") {
    return [
      countLabel(entry.findings_evaluated ?? 0, "finding", "findings"),
      `${entry.findings_opened ?? 0} opened`,
    ].join(", ");
  }
  if (typeof entry.records_accepted === "number" || typeof entry.records_rejected === "number") {
    return `${entry.records_accepted ?? 0} accepted, ${entry.records_rejected ?? 0} rejected`;
  }
  return "";
};

export default function ConnectorDiagnosticTimelinePanel({ timeline }: { timeline: ConnectorDiagnosticTimeline[] }) {
  if (timeline.length === 0) {
    return <EmptyBlock label="No diagnostic telemetry has been observed yet." />;
  }

  return (
    <div className="space-y-3">
      {timeline.map((entry, index) => {
        const counts = countSummary(entry);
        const key = `${entry.stage}-${entry.runtime_id || "runtime"}-${entry.correlation_id || entry.occurred_at || index}`;
        return (
          <div key={key} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                    {stageIcon(entry.stage)}
                    {connectorDiagnosticStageLabel(entry.stage)}
                  </span>
                  <span className="inline-flex items-center gap-1.5">
                    {statusIcon(entry.status)}
                    <Badge value={entry.status} />
                  </span>
                </div>
                <div className="mt-2 text-[14px] font-semibold text-[var(--text-primary)]">{entry.title}</div>
                <div className="mt-1 max-w-3xl text-[12px] leading-5 text-[var(--text-muted)]">
                  {entry.description || connectorDiagnosticStatusLabel(entry.status)}
                </div>
              </div>
              <div className="text-right text-[12px] text-[var(--text-muted)]">
                <div>{displayDate(entry.occurred_at)}</div>
                {typeof entry.duration_seconds === "number" && <div className="mt-0.5">{formatDuration(entry.duration_seconds)}</div>}
              </div>
            </div>
            <div className="mt-3 grid gap-2 text-[12px] sm:grid-cols-2 lg:grid-cols-4">
              {entry.runtime_id && (
                <div>
                  <div className="font-semibold text-[var(--text-muted)]">Runtime</div>
                  <div className="mt-0.5 truncate font-mono text-[var(--text-primary)]">{entry.runtime_id}</div>
                </div>
              )}
              {entry.correlation_id && (
                <div>
                  <div className="font-semibold text-[var(--text-muted)]">Correlation</div>
                  <div className="mt-0.5 truncate font-mono text-[var(--text-primary)]">{entry.correlation_id}</div>
                </div>
              )}
              {counts && (
                <div>
                  <div className="font-semibold text-[var(--text-muted)]">Counts</div>
                  <div className="mt-0.5 text-[var(--text-primary)]">{counts}</div>
                </div>
              )}
              <div>
                <div className="font-semibold text-[var(--text-muted)]">Next action</div>
                <div className="mt-0.5 text-[var(--text-primary)]">{humanize(entry.next_action || entry.failure_class || "inspect")}</div>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
