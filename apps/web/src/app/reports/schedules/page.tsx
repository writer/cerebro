"use client";

import { CalendarClock, Plus, RefreshCw, Trash2 } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

import { Badge, ErrorBlock, LoadingBlock, PageHeader, Panel } from "@/components/grc/Primitives";
import { displayDate } from "@/lib/grc";
import { grcPath, useGRCMutation, useGRCQuery } from "@/lib/grc-client";
import {
  describeInterval,
  INTERVAL_UNITS,
  intervalToSeconds,
  missingRequiredParameters,
  reportNameForID,
  reportRunIntent,
  sanitizeScheduleParameters,
  scheduleParameterFields,
  type IntervalUnit,
  type ReportDefinitionsResponse,
  type ReportRunIntent,
  type ReportRunListResponse,
  type ReportSchedule,
  type ReportScheduleListResponse,
} from "@/lib/report-schedules";

const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30 dark:border-white/10 dark:bg-white/5 dark:text-slate-100";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400";
const buttonClass = "inline-flex items-center gap-1.5 rounded-md border border-[color:var(--border)] bg-white px-3 py-1.5 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-50 dark:bg-white/5";
const primaryButtonClass = "inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50";

const runIntentDotClass = (intent: ReportRunIntent) =>
  intent === "success"
    ? "bg-emerald-500"
    : intent === "danger"
      ? "bg-rose-500"
      : intent === "warning"
        ? "bg-amber-500"
        : "bg-sky-500";

export default function ReportSchedulesPage() {
  const definitionsQuery = useGRCQuery<ReportDefinitionsResponse>("/reports");
  const schedulesQuery = useGRCQuery<ReportScheduleListResponse>("/report-schedules");
  const runsQuery = useGRCQuery<ReportRunListResponse>(grcPath("/report-runs", { limit: 20 }));
  const { mutate, saving, error: mutationError, setError } = useGRCMutation();

  const definitions = useMemo(() => definitionsQuery.data?.reports ?? [], [definitionsQuery.data]);
  const schedules = schedulesQuery.data?.schedules ?? [];
  const runs = runsQuery.data?.runs ?? [];

  const [reportID, setReportID] = useState("");
  const selectedReportID = reportID || definitions[0]?.id || "";
  const selectedDefinition = definitions.find((definition) => definition.id === selectedReportID);
  const [parameters, setParameters] = useState<Record<string, string>>({});
  const [intervalValue, setIntervalValue] = useState(24);
  const [intervalUnit, setIntervalUnit] = useState<IntervalUnit>("hours");
  const [enabled, setEnabled] = useState(true);
  const [formError, setFormError] = useState<string | null>(null);

  const fields = scheduleParameterFields(selectedDefinition);
  const intervalSeconds = intervalToSeconds(intervalValue, intervalUnit);
  const listError = schedulesQuery.error || definitionsQuery.error;
  const canCreateSchedule = definitions.length > 0 && !listError && !definitionsQuery.loading;

  const onSelectReport = (value: string) => {
    setReportID(value);
    setParameters({});
    setFormError(null);
    setError(null);
  };

  const setParameter = (id: string, value: string) =>
    setParameters((previous) => ({ ...previous, [id]: value }));

  const submit = async () => {
    setFormError(null);
    setError(null);
    if (!selectedReportID) {
      setFormError("Select a report to schedule.");
      return;
    }
    const missing = missingRequiredParameters(selectedDefinition, parameters);
    if (missing.length > 0) {
      setFormError(`Provide required parameters: ${missing.join(", ")}`);
      return;
    }
    if (intervalSeconds < 60) {
      setFormError("Interval must be at least 1 minute.");
      return;
    }
    try {
      await mutate("/report-schedules", {
        report_id: selectedReportID,
        interval_seconds: intervalSeconds,
        enabled,
        parameters: sanitizeScheduleParameters(parameters),
      });
      setParameters({});
      void schedulesQuery.reload();
    } catch {
      // Mutation error surfaced via mutationError.
    }
  };

  const toggleEnabled = async (schedule: ReportSchedule) => {
    setError(null);
    try {
      await mutate(`/report-schedules/${encodeURIComponent(schedule.id)}`, { enabled: !schedule.enabled }, "PATCH");
      void schedulesQuery.reload();
    } catch {
      // Mutation error surfaced via mutationError.
    }
  };

  const removeSchedule = async (schedule: ReportSchedule) => {
    setError(null);
    try {
      await mutate(`/report-schedules/${encodeURIComponent(schedule.id)}`, undefined, "DELETE");
      void schedulesQuery.reload();
    } catch {
      // Mutation error surfaced via mutationError.
    }
  };

  const reload = () => {
    void definitionsQuery.reload();
    void schedulesQuery.reload();
    void runsQuery.reload();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="report-schedules"
        title="Report schedules"
        description="Run reports automatically on a fixed interval and review recent scheduled runs."
        action={
          <div className="flex flex-wrap items-center justify-end gap-2">
            <Link href="/reports" className={buttonClass}>
              Back to reports
            </Link>
            <button type="button" onClick={reload} className={primaryButtonClass}>
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
          </div>
        }
      />

      <Panel title="Schedule a report">
        <div className="grid gap-3 md:grid-cols-3">
          <label className={labelClass}>
            Report
            <select value={selectedReportID} onChange={(event) => onSelectReport(event.target.value)} className={inputClass} disabled={!canCreateSchedule}>
              {definitions.length === 0 && <option value="">No reports available</option>}
              {definitions.map((definition) => (
                <option key={definition.id} value={definition.id}>
                  {definition.name}
                </option>
              ))}
            </select>
          </label>
          <label className={labelClass}>
            Interval
            <input
              type="number"
              min={1}
              value={intervalValue}
              onChange={(event) => setIntervalValue(Math.max(1, Number.parseInt(event.target.value, 10) || 1))}
              className={inputClass}
            />
          </label>
          <label className={labelClass}>
            Unit
            <select value={intervalUnit} onChange={(event) => setIntervalUnit(event.target.value as IntervalUnit)} className={inputClass}>
              {INTERVAL_UNITS.map((unit) => (
                <option key={unit.value} value={unit.value}>
                  {unit.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        {selectedDefinition?.description && (
          <p className="mt-3 text-[12px] leading-5 text-[var(--text-muted)]">{selectedDefinition.description}</p>
        )}

        {fields.length > 0 && (
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            {fields.map((field) => (
              <label key={field.id} className={labelClass}>
                <span className="flex items-center gap-2">
                  {field.id}
                  {field.required && <Badge value="required" />}
                </span>
                <input
                  value={parameters[field.id] ?? ""}
                  onChange={(event) => setParameter(field.id, event.target.value)}
                  placeholder={field.description || field.id}
                  className={inputClass}
                />
              </label>
            ))}
          </div>
        )}

        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <label className="flex items-center gap-2 text-[13px] text-[var(--text-secondary)]">
            <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
            Enabled
          </label>
          <div className="flex items-center gap-3">
            <span className="text-[12px] text-[var(--text-muted)]">{describeInterval(intervalSeconds)}</span>
            <button type="button" onClick={() => void submit()} disabled={saving || !canCreateSchedule} className={primaryButtonClass}>
              <Plus className="h-3.5 w-3.5" />
              {saving ? "Saving..." : "Create schedule"}
            </button>
          </div>
        </div>

        {(formError || mutationError) && (
          <div className="mt-3 rounded-md border border-rose-300 bg-rose-50 px-3 py-2 text-[12px] text-rose-800 dark:border-rose-500/40 dark:bg-rose-500/10 dark:text-rose-100">
            {formError || mutationError}
          </div>
        )}
      </Panel>

      {listError && <ErrorBlock error={listError} onRetry={reload} />}
      {schedulesQuery.loading && schedules.length === 0 && <LoadingBlock label="Loading schedules..." />}

      <Panel title="Active schedules">
        {schedules.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-10 text-center">
            <CalendarClock className="h-6 w-6 text-[var(--text-muted)]" />
            <div className="text-[13px] text-[var(--text-muted)]">
              {canCreateSchedule ? "No report schedules yet. Create one above." : "Report definitions are not loaded."}
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px]">
              <thead>
                <tr className="border-b border-[color:var(--border)] text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
                  <th className="px-2 py-2 font-medium">Report</th>
                  <th className="px-2 py-2 font-medium">Cadence</th>
                  <th className="px-2 py-2 font-medium">Next run</th>
                  <th className="px-2 py-2 font-medium">Last run</th>
                  <th className="px-2 py-2 font-medium">Status</th>
                  <th className="px-2 py-2 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {schedules.map((schedule) => (
                  <tr key={schedule.id} className="border-b border-[color:var(--border)] last:border-b-0">
                    <td className="px-2 py-2.5">
                      <div className="font-medium text-[var(--text-primary)]">{reportNameForID(definitions, schedule.report_id)}</div>
                      {schedule.parameters.runtime_ids && (
                        <div className="mt-0.5 truncate font-mono text-[11px] text-[var(--text-muted)]">{schedule.parameters.runtime_ids}</div>
                      )}
                    </td>
                    <td className="px-2 py-2.5 text-[var(--text-secondary)]">{describeInterval(schedule.interval_seconds)}</td>
                    <td className="px-2 py-2.5 text-[var(--text-secondary)]">{displayDate(schedule.next_run_at)}</td>
                    <td className="px-2 py-2.5 text-[var(--text-secondary)]">{displayDate(schedule.last_run_at)}</td>
                    <td className="px-2 py-2.5">
                      <Badge value={schedule.enabled ? "enabled" : "disabled"} />
                    </td>
                    <td className="px-2 py-2.5">
                      <div className="flex items-center justify-end gap-2">
                        <button type="button" onClick={() => void toggleEnabled(schedule)} disabled={saving} className={buttonClass}>
                          {schedule.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          type="button"
                          onClick={() => void removeSchedule(schedule)}
                          disabled={saving}
                          className="inline-flex items-center gap-1.5 rounded-md border border-rose-200 bg-white px-2.5 py-1.5 text-[12px] font-medium text-rose-600 transition hover:border-rose-300 hover:bg-rose-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-rose-500/30 dark:bg-white/5 dark:text-rose-300"
                          aria-label="Delete schedule"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="Recent runs">
        {runs.length === 0 ? (
          <div className="py-8 text-center text-[13px] text-[var(--text-muted)]">No report runs recorded yet.</div>
        ) : (
          <div className="divide-y divide-[color:var(--border)]">
            {runs.map((run) => (
              <div key={run.id} className="flex items-center gap-3 py-2.5">
                <span className={`h-2 w-2 shrink-0 rounded-full ${runIntentDotClass(reportRunIntent(run.status))}`} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px] font-medium text-[var(--text-primary)]">{reportNameForID(definitions, run.report_id)}</div>
                  <div className="truncate font-mono text-[11px] text-[var(--text-muted)]">{run.id}</div>
                </div>
                <Badge value={run.status || "unknown"} />
                <span className="shrink-0 text-[12px] text-[var(--text-muted)]">{displayDate(run.generated_at)}</span>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
