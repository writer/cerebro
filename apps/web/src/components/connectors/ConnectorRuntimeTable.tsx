"use client";

import Link from "next/link";

import { Badge, EmptyBlock } from "@/components/grc/Primitives";
import { displayDate, shortEntity } from "@/lib/grc";
import { formatDuration } from "@/lib/connector-runtime";
import type { ConnectorRuntime } from "@/lib/connector-runtime";

export default function ConnectorRuntimeTable({
  runtimes,
  showSource = true,
}: {
  runtimes: ConnectorRuntime[];
  showSource?: boolean;
}) {
  if (runtimes.length === 0) {
    return <EmptyBlock label="No connections match these filters." />;
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-[color:var(--border)] bg-[var(--surface)]">
      <table className="data-table">
        <thead>
          <tr>
            {showSource && <th>Connector</th>}
            <th>Connection</th>
            <th>Sync</th>
            <th>Graph</th>
            <th>Last Activity</th>
            <th>Watermark</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {runtimes.map((runtime) => (
            <tr key={runtime.runtime_id}>
              {showSource && (
                <td>
                  <Link href={`/connectors/${encodeURIComponent(runtime.source_id || "unknown")}`} className="font-semibold text-[var(--text-primary)] hover:text-[var(--primary)]">
                    {runtime.source_id || "Unknown"}
                  </Link>
                </td>
              )}
              <td>
                <div className="font-medium text-[var(--text-primary)]">{runtime.family || "Default"}</div>
                <div className="mt-0.5 font-mono text-[11px] text-[var(--text-muted)]">{shortEntity(runtime.runtime_id)}</div>
              </td>
              <td><Badge value={runtime.health} /></td>
              <td><Badge value={runtime.graph_freshness} /></td>
              <td>{displayDate(runtime.last_activity_at)}</td>
              <td>
                <div className="text-[var(--text-secondary)]">{displayDate(runtime.checkpoint_watermark)}</div>
                <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">
                  {runtime.cursor_state} - {formatDuration(runtime.watermark_lag_seconds)} lag
                </div>
              </td>
              <td>
                <Link
                  href={`/connectors/${encodeURIComponent(runtime.source_id || "unknown")}?tab=connections&runtime_id=${encodeURIComponent(runtime.runtime_id)}`}
                  className="text-[12px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]"
                >
                  Inspect
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
