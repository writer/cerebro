"use client";

import {
  Activity,
  ChevronRight,
  Clock3,
  RefreshCw,
  Search,
  ShieldAlert,
  UserRound,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import {
  AppliedFilterChips,
  Badge,
  EmptyBlock,
  ErrorBlock,
  MetricCard,
  Panel,
} from "@/components/grc/Primitives";
import type { AuditEvent, AuditLogPage } from "@/lib/audit-log";

type Filters = {
  action: string;
  actor: string;
  limit: string;
  minutes: string;
  outcome: string;
  query: string;
  resourceType: string;
  service: string;
  traceId: string;
};

const defaultFilters: Filters = {
  action: "",
  actor: "",
  limit: "100",
  minutes: "60",
  outcome: "",
  query: "",
  resourceType: "",
  service: "",
  traceId: "",
};

export default function AuditLogWorkbench() {
  const [error, setError] = useState("");
  const [filters, setFilters] = useState<Filters>(defaultFilters);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState<AuditLogPage | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const load = useCallback(async (nextFilters: Filters, cursor = "") => {
    setLoading(true);
    setError("");
    const params = filtersToSearchParams(nextFilters);
    if (cursor) params.set("cursor", cursor);

    try {
      const response = await fetch(`/api/audit-log?${params.toString()}`, { cache: "no-store" });
      const payload = await response.json() as AuditLogPage & { error?: string };
      if (!response.ok) {
        throw new Error(payload.error || `Audit events request failed with ${response.status}.`);
      }
      setPage(payload);
      setSelectedEvent(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Audit events request failed.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(defaultFilters), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const update = (key: keyof Filters, value: string) => {
    setFilters((current) => ({ ...current, [key]: value }));
  };
  const appliedFilters = useMemo(() => [
    { label: "Search", value: filters.query, onClear: () => update("query", "") },
    { label: "Actor", value: filters.actor, onClear: () => update("actor", "") },
    { label: "Action", value: filters.action, onClear: () => update("action", "") },
    { label: "Resource type", value: filters.resourceType, onClear: () => update("resourceType", "") },
    { label: "Service", value: filters.service, onClear: () => update("service", "") },
    { label: "Outcome", value: filters.outcome, onClear: () => update("outcome", "") },
    { label: "Trace", value: filters.traceId, onClear: () => update("traceId", "") },
  ], [filters]);

  const summary = page?.summary ?? emptySummary;
  const events = page?.events ?? [];

  return (
    <div className="space-y-6">
      <Panel
        title="Find audit events"
        action={(
          <button
            type="button"
            onClick={() => void load(filters)}
            className="secondary-button inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px]"
            disabled={loading}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        )}
      >
        <div className="grid gap-3 lg:grid-cols-3 xl:grid-cols-5">
          <label className={`${labelClass} xl:col-span-2`}>
            Search
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-muted)]" />
              <input
                value={filters.query}
                onChange={(event) => update("query", event.target.value)}
                className={`${inputClass} pl-8`}
                placeholder="Action, resource, or summary"
              />
            </div>
          </label>
          <FilterInput label="Actor" value={filters.actor} onChange={(value) => update("actor", value)} />
          <FilterInput label="Action" value={filters.action} onChange={(value) => update("action", value)} />
          <FilterInput label="Resource type" value={filters.resourceType} onChange={(value) => update("resourceType", value)} />
          <FilterInput label="Service" value={filters.service} onChange={(value) => update("service", value)} />
          <label className={labelClass}>
            Outcome
            <select value={filters.outcome} onChange={(event) => update("outcome", event.target.value)} className={inputClass}>
              <option value="">All</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="denied">Denied</option>
              <option value="unknown">Unknown</option>
            </select>
          </label>
          <FilterInput label="Trace" value={filters.traceId} onChange={(value) => update("traceId", value)} />
          <label className={labelClass}>
            Window
            <select value={filters.minutes} onChange={(event) => update("minutes", event.target.value)} className={inputClass}>
              <option value="15">15 minutes</option>
              <option value="60">1 hour</option>
              <option value="180">3 hours</option>
              <option value="720">12 hours</option>
              <option value="1440">24 hours</option>
            </select>
          </label>
          <label className={labelClass}>
            Limit
            <select value={filters.limit} onChange={(event) => update("limit", event.target.value)} className={inputClass}>
              <option value="50">50</option>
              <option value="100">100</option>
              <option value="250">250</option>
              <option value="500">500</option>
            </select>
          </label>
        </div>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
          <AppliedFilterChips
            filters={appliedFilters}
            onClearAll={() => setFilters((current) => ({
              ...defaultFilters,
              limit: current.limit,
              minutes: current.minutes,
            }))}
          />
          <button
            type="button"
            onClick={() => void load(filters)}
            className="primary-button inline-flex items-center justify-center gap-1.5 px-4 py-2 text-[13px]"
            disabled={loading}
          >
            <Activity className="h-3.5 w-3.5" />
            Run query
          </button>
        </div>
      </Panel>

      {error && <ErrorBlock error={error} onRetry={() => void load(filters)} />}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Events" value={summary.total} detail={page?.status ?? (loading ? "loading" : "complete")} state={loading ? "loading" : "ready"} />
        <MetricCard label="Failures" value={summary.failures} detail="failed actions" intent={summary.failures > 0 ? "danger" : "success"} state={loading ? "loading" : "ready"} />
        <MetricCard label="Denied" value={summary.denied} detail="blocked actions" intent={summary.denied > 0 ? "warning" : "neutral"} state={loading ? "loading" : "ready"} />
        <MetricCard label="p95 duration" value={formatDuration(summary.p95DurationMs)} detail="matched events" state={loading ? "loading" : "ready"} />
      </div>

      <Panel
        title="Event timeline"
        action={page?.window ? (
          <span className="text-[11px] text-[var(--text-muted)]">
            {displayTime(page.window.startTime)} – {displayTime(page.window.endTime)}
          </span>
        ) : null}
      >
        {loading && <div className="text-[13px] text-[var(--text-muted)]">Loading audit events...</div>}
        {!loading && events.length === 0 && <EmptyBlock label="No audit events matched these filters." />}
        {events.length > 0 && (
          <AuditEventTable events={events} onSelect={setSelectedEvent} />
        )}
        {page?.nextCursor && (
          <div className="mt-4 flex justify-end">
            <button
              type="button"
              className="secondary-button inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px]"
              onClick={() => void load(filters, page.nextCursor)}
              disabled={loading}
            >
              Next page
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
      </Panel>

      {selectedEvent && <AuditEventDetail event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
    </div>
  );
}

function AuditEventTable({ events, onSelect }: { events: AuditEvent[]; onSelect: (event: AuditEvent) => void }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-[color:var(--border)] bg-[var(--surface)]">
      <table className="data-table">
        <thead>
          <tr>
            <th>Outcome</th>
            <th>Action</th>
            <th>Actor</th>
            <th>Resource</th>
            <th>Service</th>
            <th>Observed</th>
            <th aria-label="Event details" />
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td><Badge value={event.outcome} /></td>
              <td>
                <div className="font-medium text-[var(--text-primary)]">{event.action}</div>
                {event.summary && <div className="mt-1 max-w-xl text-[11px] text-[var(--text-muted)]">{event.summary}</div>}
              </td>
              <td>{actorLabel(event)}</td>
              <td>{resourceLabel(event)}</td>
              <td className="font-mono text-[12px]">{event.service || "—"}</td>
              <td>
                <div>{displayTime(event.occurredAt)}</div>
                <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">{formatDuration(event.durationMs)}</div>
              </td>
              <td>
                <button
                  type="button"
                  onClick={() => onSelect(event)}
                  className="secondary-button px-2.5 py-1 text-[11px]"
                  aria-label={`Inspect ${event.action}`}
                >
                  Inspect
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AuditEventDetail({ event, onClose }: { event: AuditEvent; onClose: () => void }) {
  const rows = [
    ["Event ID", event.id],
    ["Category", event.category],
    ["Actor", actorLabel(event)],
    ["Actor ID", event.actor?.id ?? ""],
    ["Resource", resourceLabel(event)],
    ["Resource ID", event.resource?.id ?? ""],
    ["Service", event.service],
    ["Trace ID", event.traceId],
    ["Request ID", event.requestId],
    ["Duration", formatDuration(event.durationMs)],
  ].filter(([, value]) => value);

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/25" role="dialog" aria-modal="true" aria-label="Audit event details">
      <div className="h-full w-full max-w-xl overflow-y-auto border-l border-[color:var(--border)] bg-[var(--surface)] p-6 shadow-xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <Badge value={event.outcome} />
            <h2 className="mt-3 text-lg font-semibold text-[var(--text-primary)]">{event.action}</h2>
            <p className="mt-1 text-[13px] text-[var(--text-muted)]">{event.summary || "No event summary was provided."}</p>
          </div>
          <button type="button" onClick={onClose} className="secondary-button p-2" aria-label="Close event details">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="mt-6 grid gap-3 sm:grid-cols-2">
          {rows.map(([label, value]) => (
            <div key={label} className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{label}</div>
              <div className="mt-1 break-words font-mono text-[12px] text-[var(--text-primary)]">{value}</div>
            </div>
          ))}
        </div>
        <div className="mt-6 flex items-center gap-4 text-[12px] text-[var(--text-muted)]">
          <span className="inline-flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5" />{displayTime(event.occurredAt)}</span>
          {event.actor && <span className="inline-flex items-center gap-1.5"><UserRound className="h-3.5 w-3.5" />{actorLabel(event)}</span>}
          {event.outcome === "denied" && <span className="inline-flex items-center gap-1.5"><ShieldAlert className="h-3.5 w-3.5" />Denied</span>}
        </div>
      </div>
    </div>
  );
}

function FilterInput({ label, onChange, value }: { label: string; onChange: (value: string) => void; value: string }) {
  return (
    <label className={labelClass}>
      {label}
      <input value={value} onChange={(event) => onChange(event.target.value)} className={inputClass} />
    </label>
  );
}

const filtersToSearchParams = (filters: Filters) => {
  const params = new URLSearchParams({ limit: filters.limit, minutes: filters.minutes });
  const values = {
    action: filters.action,
    actor: filters.actor,
    outcome: filters.outcome,
    q: filters.query,
    resource_type: filters.resourceType,
    service: filters.service,
    trace_id: filters.traceId,
  };
  for (const [key, value] of Object.entries(values)) {
    if (value.trim()) params.set(key, value.trim());
  }
  return params;
};

const actorLabel = (event: AuditEvent) => event.actor?.label || event.actor?.id || event.actor?.kind || "—";
const resourceLabel = (event: AuditEvent) => event.resource?.label || event.resource?.id || event.resource?.type || "—";

const displayTime = (value: string) => {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return value || "—";
  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    month: "short",
  }).format(parsed);
};

const formatDuration = (value: number | null) => {
  if (value === null) return "n/a";
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(value < 10_000 ? 1 : 0)} s`;
};

const emptySummary = {
  actions: [],
  averageDurationMs: null,
  denied: 0,
  failures: 0,
  p95DurationMs: null,
  services: [],
  total: 0,
};

const inputClass = "mt-1 w-full rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-2 text-[13px] text-[var(--text-primary)] outline-none transition focus:border-[var(--primary)] focus:ring-2 focus:ring-[var(--ring)]";
const labelClass = "text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]";
