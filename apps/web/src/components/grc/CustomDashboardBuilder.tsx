"use client";

import { useState } from "react";

import { Panel } from "@/components/grc/Primitives";
import { type CustomDashboard, type CustomDashboardWidget, customDashboardPath } from "@/lib/custom-dashboards";
import { humanize } from "@/lib/grc";
import { useGRCMutation } from "@/lib/grc-client";
import {
  catalogWidgetSourceID,
  findSource,
  useReportCatalog,
  validateWidgetReportQuery,
  type ReportParam,
  type ReportSource,
} from "@/lib/grc-report-catalog";

const inputClass =
  "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const selectClass =
  "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500";

const FILTER_FIELDS = ["runtime_id", "source_id", "severity", "framework", "status", "days"];
const WIDGET_WIDTHS = [4, 6, 8, 12];

const newWidgetID = () =>
  typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `w-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

const stringFilters = (filters: CustomDashboard["filters"]): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(filters ?? {})) {
    if (value !== undefined) out[key] = String(value);
  }
  return out;
};

const prunedFilters = (filters: Record<string, string>): Record<string, string> =>
  Object.fromEntries(Object.entries(filters).filter(([, value]) => value.trim() !== "").map(([key, value]) => [key, value.trim()]));

const widgetParamRecord = (widget: CustomDashboardWidget): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(widget.query?.params ?? {})) {
    if (value !== undefined && String(value).trim() !== "") out[key] = String(value);
  }
  return out;
};

export default function CustomDashboardBuilder({
  dashboard,
  onSaved,
}: {
  dashboard: CustomDashboard;
  onSaved: () => Promise<void> | void;
}) {
  const catalog = useReportCatalog();
  const mutation = useGRCMutation();
  const [widgets, setWidgets] = useState<CustomDashboardWidget[]>(() => [...(dashboard.widgets ?? [])]);
  const [filters, setFilters] = useState<Record<string, string>>(() => stringFilters(dashboard.filters));
  const [addSourceID, setAddSourceID] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const updateWidget = (id: string, update: (widget: CustomDashboardWidget) => CustomDashboardWidget) =>
    setWidgets((current) => current.map((widget) => (widget.id === id ? update(widget) : widget)));

  const removeWidget = (id: string) => setWidgets((current) => current.filter((widget) => widget.id !== id));

  const moveWidget = (id: string, delta: number) =>
    setWidgets((current) => {
      const index = current.findIndex((widget) => widget.id === id);
      const target = index + delta;
      if (index < 0 || target < 0 || target >= current.length) return current;
      const next = [...current];
      const [moved] = next.splice(index, 1);
      next.splice(target, 0, moved);
      return next;
    });

  const addReportWidget = () => {
    const source = findSource(catalog.sources, addSourceID);
    if (!source) return;
    setWidgets((current) => [
      ...current,
      {
        id: newWidgetID(),
        type: "report",
        title: source.title,
        query: { source_id: source.id, params: {}, limit: source.default_limit > 0 ? source.default_limit : undefined },
        layout: { w: 12 },
      },
    ]);
    setAddSourceID("");
    setFormError(null);
  };

  const setWidgetParam = (id: string, key: string, value: string) =>
    updateWidget(id, (widget) => ({
      ...widget,
      query: { ...widget.query, params: { ...(widget.query?.params ?? {}), [key]: value } },
    }));

  const setWidgetLimit = (id: string, value: string) =>
    updateWidget(id, (widget) => {
      const parsed = Number.parseInt(value, 10);
      return { ...widget, query: { ...widget.query, limit: value.trim() === "" || !Number.isFinite(parsed) ? undefined : parsed } };
    });

  const save = async () => {
    for (const widget of widgets) {
      const sourceID = catalogWidgetSourceID(widget);
      if (sourceID === "") continue;
      const error = validateWidgetReportQuery(findSource(catalog.sources, sourceID), {
        source_id: sourceID,
        params: widgetParamRecord(widget),
        limit: widget.query?.limit,
      });
      if (error) {
        setFormError(`${widget.title ?? sourceID}: ${error}`);
        return;
      }
    }
    setFormError(null);
    await mutation.mutate(
      customDashboardPath(dashboard.id),
      { widgets, filters: prunedFilters(filters), layout: dashboard.layout ?? { columns: 12 } },
      "PATCH",
    );
    await onSaved();
  };

  return (
    <Panel title="Report builder">
      <div className="space-y-5">
        {catalog.error && (
          <div className="rounded-md border border-amber-200 bg-amber-50 p-2 text-[12px] text-amber-700">
            Report catalog unavailable: {catalog.error}
          </div>
        )}

        <section>
          <h3 className="text-[12px] font-semibold text-slate-700">Dashboard filters</h3>
          <p className="mt-0.5 text-[11px] text-slate-500">Applied to every report widget that declares the parameter.</p>
          <div className="mt-2 grid gap-3 md:grid-cols-3 xl:grid-cols-6">
            {FILTER_FIELDS.map((field) => (
              <label key={field} className={labelClass}>
                {humanize(field)}
                <input
                  value={filters[field] ?? ""}
                  onChange={(event) => setFilters((current) => ({ ...current, [field]: event.target.value }))}
                  placeholder="Any"
                  className={inputClass}
                />
              </label>
            ))}
          </div>
        </section>

        <section className="space-y-3">
          <h3 className="text-[12px] font-semibold text-slate-700">Widgets</h3>
          {widgets.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-300 p-4 text-[13px] text-slate-500">No widgets yet. Add a report below.</div>
          ) : (
            widgets.map((widget, index) => (
              <WidgetEditor
                key={widget.id}
                widget={widget}
                source={findSource(catalog.sources, catalogWidgetSourceID(widget))}
                isFirst={index === 0}
                isLast={index === widgets.length - 1}
                onTitleChange={(value) => updateWidget(widget.id, (current) => ({ ...current, title: value }))}
                onWidthChange={(value) => updateWidget(widget.id, (current) => ({ ...current, layout: { ...current.layout, w: value } }))}
                onParamChange={(key, value) => setWidgetParam(widget.id, key, value)}
                onLimitChange={(value) => setWidgetLimit(widget.id, value)}
                onMove={(delta) => moveWidget(widget.id, delta)}
                onRemove={() => removeWidget(widget.id)}
              />
            ))
          )}
        </section>

        <section className="flex flex-wrap items-end gap-2 border-t border-slate-100 pt-4">
          <label className={`${labelClass} grow`}>
            Add report
            <select value={addSourceID} onChange={(event) => setAddSourceID(event.target.value)} disabled={catalog.loading} className={selectClass}>
              <option value="">{catalog.loading ? "Loading catalog..." : "Select a report source"}</option>
              {catalog.sources.map((source) => (
                <option key={source.id} value={source.id}>
                  {humanize(source.domain)} · {source.title}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={addReportWidget}
            disabled={addSourceID === ""}
            className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-indigo-300 hover:text-indigo-600 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Add widget
          </button>
          <button
            type="button"
            onClick={() => void save()}
            disabled={mutation.saving}
            className="ml-auto rounded-md bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {mutation.saving ? "Saving..." : "Save layout"}
          </button>
        </section>

        {(formError || mutation.error) && (
          <div className="rounded-md border border-rose-200 bg-rose-50 p-2 text-[12px] text-rose-700">{formError ?? mutation.error}</div>
        )}
      </div>
    </Panel>
  );
}

function WidgetEditor({
  widget,
  source,
  isFirst,
  isLast,
  onTitleChange,
  onWidthChange,
  onParamChange,
  onLimitChange,
  onMove,
  onRemove,
}: {
  widget: CustomDashboardWidget;
  source: ReportSource | undefined;
  isFirst: boolean;
  isLast: boolean;
  onTitleChange: (value: string) => void;
  onWidthChange: (value: number) => void;
  onParamChange: (key: string, value: string) => void;
  onLimitChange: (value: string) => void;
  onMove: (delta: number) => void;
  onRemove: () => void;
}) {
  const sourceID = catalogWidgetSourceID(widget);
  const isReport = sourceID !== "";
  const params = source?.params ?? [];
  return (
    <div className="rounded-lg border border-slate-200 p-3">
      <div className="grid gap-3 md:grid-cols-12">
        <label className={`${labelClass} md:col-span-6`}>
          Title
          <input value={widget.title ?? ""} onChange={(event) => onTitleChange(event.target.value)} placeholder="Untitled widget" className={inputClass} />
        </label>
        <label className={`${labelClass} md:col-span-3`}>
          Width
          <select value={Math.max(3, Math.min(12, Number(widget.layout?.w) || 12))} onChange={(event) => onWidthChange(Number(event.target.value))} className={selectClass}>
            {WIDGET_WIDTHS.map((width) => (
              <option key={width} value={width}>
                {width} / 12
              </option>
            ))}
          </select>
        </label>
        <div className="flex items-end justify-end gap-1 md:col-span-3">
          <button type="button" onClick={() => onMove(-1)} disabled={isFirst} className="rounded-md border border-slate-200 px-2 py-1.5 text-[12px] text-slate-600 transition hover:border-indigo-300 disabled:opacity-40" aria-label="Move up">
            ↑
          </button>
          <button type="button" onClick={() => onMove(1)} disabled={isLast} className="rounded-md border border-slate-200 px-2 py-1.5 text-[12px] text-slate-600 transition hover:border-indigo-300 disabled:opacity-40" aria-label="Move down">
            ↓
          </button>
          <button type="button" onClick={onRemove} className="rounded-md border border-rose-200 px-2 py-1.5 text-[12px] font-medium text-rose-700 transition hover:border-rose-300">
            Remove
          </button>
        </div>
      </div>

      {isReport ? (
        <div className="mt-3 border-t border-slate-100 pt-3">
          <p className="text-[11px] text-slate-500">
            Source: <span className="font-medium text-slate-700">{source?.title ?? sourceID}</span>
            {!source && " (unavailable)"}
          </p>
          {params.length > 0 && (
            <div className="mt-2 grid gap-3 md:grid-cols-3 xl:grid-cols-4">
              {params.map((param) => (
                <ParamField key={param.id} param={param} value={String(widget.query?.params?.[param.id] ?? "")} onChange={(value) => onParamChange(param.id, value)} />
              ))}
            </div>
          )}
          <label className={`${labelClass} mt-3 block max-w-[160px]`}>
            Row limit
            <input
              type="number"
              min={1}
              max={source?.max_limit || undefined}
              value={widget.query?.limit ?? ""}
              onChange={(event) => onLimitChange(event.target.value)}
              placeholder={String(source?.default_limit ?? "")}
              className={inputClass}
            />
          </label>
        </div>
      ) : (
        <p className="mt-2 text-[11px] text-slate-500">Type: {widget.type}</p>
      )}
    </div>
  );
}

function ParamField({ param, value, onChange }: { param: ReportParam; value: string; onChange: (value: string) => void }) {
  const label = (
    <>
      {humanize(param.id)}
      {param.required && <span className="text-rose-500"> *</span>}
    </>
  );
  if (param.type === "enum") {
    return (
      <label className={labelClass}>
        {label}
        <select value={value} onChange={(event) => onChange(event.target.value)} className={selectClass}>
          <option value="">Any</option>
          {(param.allowed_values ?? []).map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </label>
    );
  }
  if (param.type === "bool") {
    return (
      <label className={labelClass}>
        {label}
        <select value={value} onChange={(event) => onChange(event.target.value)} className={selectClass}>
          <option value="">Any</option>
          <option value="true">True</option>
          <option value="false">False</option>
        </select>
      </label>
    );
  }
  return (
    <label className={labelClass}>
      {label}
      <input
        type={param.type === "int" ? "number" : "text"}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder="Any"
        className={inputClass}
      />
    </label>
  );
}
