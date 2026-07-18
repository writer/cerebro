"use client";

import { Activity, RefreshCw, Search, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import {
  AppliedFilterChips,
  Badge,
  EmptyBlock,
  ErrorBlock,
  MetricCard,
  Panel,
} from "@/components/grc/Primitives";
import { summarizeAuditLog } from "@/lib/audit-log";
import type { AuditLogEvent, AuditLogSummary } from "@/lib/audit-log";

type AuditLogResponse = {
  error?: string;
  events?: AuditLogEvent[];
  receiptId?: string;
  status?: string;
  summary?: AuditLogSummary;
};

type Filters = {
  limit: string;
  minutes: string;
  query: string;
  runtimeId: string;
  service: string;
  sourceId: string;
  status: string;
  traceId: string;
};

const defaultFilters: Filters = {
  limit: "100",
  minutes: "60",
  query: "",
  runtimeId: "",
  service: "",
  sourceId: "",
  status: "",
  traceId: "",
};

export default function AuditLogWorkbench() {
  const [filters, setFilters] = useState(defaultFilters);
  const [response, setResponse] = useState<AuditLogResponse | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<AuditLogEvent | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async (nextFilters: Filters) => {
    setLoading(true);
    setError("");
    const params = new URLSearchParams();
    Object.entries(nextFilters).forEach(([key, value]) => {
      if (value.trim()) params.set(filterParameter(key as keyof Filters), value.trim());
    });

    try {
      const result = await fetch(`/api/audit-log?${params.toString()}`, { cache: "no-store" });
      const payload = await result.json() as AuditLogResponse;
      if (!result.ok) throw new Error(payload.error || `Audit log request failed with ${result.status}`);
      setResponse(payload);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Audit log request failed.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(defaultFilters), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const events = response?.events ?? [];
  const summary = response?.summary ?? summarizeAuditLog(events);
  const appliedFilters = [
    { label: "Query", value: filters.query, onClear: () => clearFilter("query") },
    { label: "Runtime", value: filters.runtimeId, onClear: () => clearFilter("runtimeId") },
    { label: "Source", value: filters.sourceId, onClear: () => clearFilter("sourceId") },
    { label: "Service", value: filters.service, onClear: () => clearFilter("service") },
    { label: "Status", value: filters.status, onClear: () => clearFilter("status") },
    { label: "Trace", value: filters.traceId, onClear: () => clearFilter("traceId") },
  ];

  const update = (key: keyof Filters, value: string) =>
    setFilters((current) => ({ ...current, [key]: value }));
  const clearFilter = (key: keyof Filters) => update(key, "");

  return (
    <div className="space-y-6">
      <Panel
        title="Audit event query"
        action={(
          <button type="button" className="secondary-button inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px]" onClick={() => void load(filters)} disabled={loading}>
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        )}
      >
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <FilterInput label="Search" value={filters.query} onChange={(value) => update("query", value)} icon={<Search className="h-3.5 w-3.5" />} />
          <FilterInput label="Runtime" value={filters.runtimeId} onChange={(value) => update("runtimeId", value)} />
          <FilterInput label="Source" value={filters.sourceId} onChange={(value) => update("sourceId", value)} />
          <FilterInput label="Service" value={filters.service} onChange={(value) => update("service", value)} />
          <FilterInput label="Status" value={filters.status} onChange={(value) => update("status", value)} />
          <FilterInput label="Trace" value={filters.traceId} onChange={(value) => update("traceId", value)} />
          <FilterSelect label="Window" value={filters.minutes} onChange={(value) => update("minutes", value)} options={[["15", "15 minutes"], ["60", "1 hour"], ["180", "3 hours"], ["720", "12 hours"], ["1440", "24 hours"]]} />
          <FilterSelect label="Limit" value={filters.limit} onChange={(value) => update("limit", value)} options={[["50", "50"], ["100", "100"], ["250", "250"], ["500", "500"]]} />
        </div>
        <div className="mt-3 flex justify-end">
          <button type="button" className="primary-button inline-flex items-center gap-1.5 px-4 py-2 text-[13px]" onClick={() => void load(filters)} disabled={loading}>
            <Activity className="h-3.5 w-3.5" />
            Run query
          </button>
        </div>
        <AppliedFilterChips filters={appliedFilters} onClearAll={() => setFilters((current) => ({ ...defaultFilters, minutes: current.minutes, limit: current.limit }))} />
      </Panel>

      {error && <ErrorBlock error={error} onRetry={() => void load(filters)} />}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Events" value={summary.total} detail={response?.status || (loading ? "loading" : "complete")} state={loading ? "loading" : "ready"} />
        <MetricCard label="Failures" value={summary.failures} detail={`${Math.round(summary.failureRate * 100)}% of matched events`} intent={summary.failures > 0 ? "danger" : "success"} state={loading ? "loading" : "ready"} />
        <MetricCard label="Average latency" value={formatMilliseconds(summary.averageDurationMs)} detail="event duration" state={loading ? "loading" : "ready"} />
        <MetricCard label="p95 latency" value={formatMilliseconds(summary.p95DurationMs)} detail="event duration" state={loading ? "loading" : "ready"} />
      </div>

      <Panel title="Event timeline" action={response?.receiptId ? <span className="font-mono text-[11px] text-[var(--text-muted)]">{response.receiptId}</span> : null}>
        {loading && <div className="text-[13px] text-[var(--text-muted)]">Loading events...</div>}
        {!loading && events.length === 0 && <EmptyBlock label="No events matched the current filters." />}
        {events.length > 0 && (
          <div className="overflow-x-auto rounded-lg border border-[color:var(--border)] bg-[var(--surface)]">
            <table className="data-table">
              <thead><tr><th>Status</th><th>Event</th><th>Service</th><th>Runtime</th><th>Trace</th><th>Observed</th></tr></thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id} className="cursor-pointer hover:bg-[var(--surface-muted)]" onClick={() => setSelectedEvent(event)}>
                    <td><Badge value={event.status || event.outcome || "observed"} /></td>
                    <td><div className="font-medium text-[var(--text-primary)]">{event.name}</div><div className="text-[11px] text-[var(--text-muted)]">{event.phase || event.dependency || "event"}</div></td>
                    <td>{event.service || "unknown"}</td>
                    <td className="font-mono text-[11px]">{event.runtimeId || "none"}</td>
                    <td className="font-mono text-[11px]">{event.traceId || "none"}</td>
                    <td>{formatTimestamp(event.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/25" role="dialog" aria-modal="true">
          <div className="h-full w-full max-w-2xl overflow-y-auto border-l border-[color:var(--border)] bg-[var(--surface)] p-6 shadow-2xl">
            <div className="flex items-start justify-between gap-4">
              <div><div className="text-[11px] uppercase tracking-[0.14em] text-[var(--text-muted)]">Audit event</div><h2 className="mt-1 text-lg font-semibold">{selectedEvent.name}</h2></div>
              <button type="button" className="icon-button" aria-label="Close event details" onClick={() => setSelectedEvent(null)}><X className="h-4 w-4" /></button>
            </div>
            <dl className="mt-6 grid gap-3 sm:grid-cols-2">
              <Detail label="Status" value={selectedEvent.status || selectedEvent.outcome} />
              <Detail label="Service" value={selectedEvent.service} />
              <Detail label="Runtime" value={selectedEvent.runtimeId} />
              <Detail label="Source" value={selectedEvent.sourceId} />
              <Detail label="Trace" value={selectedEvent.traceId} />
              <Detail label="Duration" value={formatMilliseconds(selectedEvent.durationMs)} />
            </dl>
            <pre className="mt-6 overflow-x-auto rounded-lg bg-[var(--surface-muted)] p-4 text-[11px] leading-5">{JSON.stringify(selectedEvent.rawEvent, null, 2)}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

function FilterInput({ icon, label, onChange, value }: { icon?: React.ReactNode; label: string; onChange: (value: string) => void; value: string }) {
  return <label className={labelClass}>{label}<div className="flex items-center gap-2 rounded-md border border-[color:var(--border)] px-3 py-2">{icon}<input className="min-w-0 flex-1 bg-transparent text-[13px] outline-none" value={value} onChange={(event) => onChange(event.target.value)} /></div></label>;
}

function FilterSelect({ label, onChange, options, value }: { label: string; onChange: (value: string) => void; options: [string, string][]; value: string }) {
  return <label className={labelClass}>{label}<select className={selectClass} value={value} onChange={(event) => onChange(event.target.value)}>{options.map(([optionValue, optionLabel]) => <option key={optionValue} value={optionValue}>{optionLabel}</option>)}</select></label>;
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div className="rounded-lg border border-[color:var(--border)] p-3"><dt className="text-[11px] uppercase tracking-[0.12em] text-[var(--text-muted)]">{label}</dt><dd className="mt-1 break-all font-mono text-[12px]">{value || "none"}</dd></div>;
}

const filterParameters: Partial<Record<keyof Filters, string>> = {
  runtimeId: "runtime_id",
  sourceId: "source_id",
  traceId: "trace_id",
};
const filterParameter = (key: keyof Filters) => filterParameters[key] ?? key;
const formatMilliseconds = (value: number | null) => value === null ? "n/a" : value >= 1000 ? `${(value / 1000).toFixed(1)}s` : `${Math.round(value)}ms`;
const formatTimestamp = (value: string) => value ? new Date(value).toLocaleString() : "unknown";
const labelClass = "space-y-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]";
const selectClass = "w-full rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-2 text-[13px] text-[var(--text-primary)]";
