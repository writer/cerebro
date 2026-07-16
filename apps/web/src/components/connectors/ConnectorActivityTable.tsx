"use client";

import { Activity, CheckCircle2, Clock3, RefreshCw, XCircle } from "lucide-react";

import { Badge, EmptyBlock } from "@/components/grc/Primitives";
import { displayDate } from "@/lib/grc";
import { formatDuration } from "@/lib/connector-runtime";
import { countLabel } from "@/lib/format";
import type { ConnectorActivity } from "@/lib/connectors";

const statusIcon = (status: string) => {
  switch (status) {
    case "success":
      return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
    case "failed":
      return <XCircle className="h-4 w-4 text-red-500" />;
    case "needs_refresh":
      return <RefreshCw className="h-4 w-4 text-amber-500" />;
    case "running":
      return <Clock3 className="h-4 w-4 text-blue-500" />;
    default:
      return <Activity className="h-4 w-4 text-[var(--text-muted)]" />;
  }
};

export default function ConnectorActivityTable({ activity }: { activity: ConnectorActivity[] }) {
  if (activity.length === 0) {
    return <EmptyBlock label="No connector activity has been observed yet." />;
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-[color:var(--border)] bg-[var(--surface)]">
      <table className="data-table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Event</th>
            <th>Runtime</th>
            <th>Count</th>
            <th>Duration</th>
            <th>Observed</th>
          </tr>
        </thead>
        <tbody>
          {activity.map((event) => (
            <tr key={event.id || `${event.runtime_id}-${event.type}-${event.occurred_at}`}>
              <td>
                <div className="flex items-center gap-2">
                  {statusIcon(event.status)}
                  <Badge value={event.status} />
                </div>
              </td>
              <td>
                <div className="font-medium text-[var(--text-primary)]">{event.title}</div>
                <div className="mt-0.5 max-w-xl text-[11px] leading-4 text-[var(--text-muted)]">
                  {event.description || event.failure_class || event.type}
                </div>
              </td>
              <td>
                <div className="font-mono text-[12px] text-[var(--text-primary)]">{event.runtime_id}</div>
                {event.family && <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">{event.family}</div>}
              </td>
              <td>
                {event.type === "graph" ? (
                  <span>{countLabel(event.entities_projected ?? 0, "entity", "entities")}</span>
                ) : (
                  <span>{event.records_accepted ?? 0} accepted</span>
                )}
              </td>
              <td>{formatDuration(event.duration_seconds)}</td>
              <td>{displayDate(event.occurred_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
