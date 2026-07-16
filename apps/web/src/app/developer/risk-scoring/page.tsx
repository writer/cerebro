"use client";

import { RefreshCw, RotateCcw, Save, SlidersHorizontal } from "lucide-react";
import { useEffect, useState } from "react";

import { ErrorBlock, LoadingBlock, PageHeader, Panel } from "@/components/grc/Primitives";
import { grcPath, useDebouncedValue, useGRCMutation, useGRCQuery } from "@/lib/grc-client";
import {
  DEFAULT_RISK_SCORING_CONFIG,
  type RiskScoringConfigFormState,
  type RiskScoringConfigResponse,
  riskScoringFormFromConfig,
  riskScoringPayloadFromForm,
} from "@/lib/risk-scoring-config";

const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30 dark:border-white/10 dark:bg-white/5 dark:text-slate-100";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400";
const buttonClass = "inline-flex items-center gap-1.5 rounded-md border border-[color:var(--border)] bg-white px-3 py-1.5 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-50 dark:bg-white/5";
const primaryButtonClass = "inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50";

export default function RiskScoringSettingsPage() {
  const [form, setForm] = useState<RiskScoringConfigFormState>(() => riskScoringFormFromConfig(DEFAULT_RISK_SCORING_CONFIG));
  const [formError, setFormError] = useState<string | null>(null);
  const debouncedTenantID = useDebouncedValue(form.tenantID, 300);
  const configPath = grcPath("/grc/risk-scoring-config", { tenant_id: debouncedTenantID || "local" });
  const configQuery = useGRCQuery<RiskScoringConfigResponse>(configPath);
  const { mutate, saving, error: mutationError, setError } = useGRCMutation<RiskScoringConfigResponse>();
  const loaded = configQuery.data;
  const configLoadFailed = Boolean(configQuery.error && !loaded);
  const canWriteConfig = !configLoadFailed && !configQuery.loading;

  useEffect(() => {
    if (!loaded?.config) return;
    const timer = window.setTimeout(() => {
      setForm(riskScoringFormFromConfig(loaded.config));
      setFormError(null);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loaded]);

  const setThreshold = (key: keyof RiskScoringConfigFormState["thresholds"], value: string) =>
    setForm((previous) => ({
      ...previous,
      thresholds: { ...previous.thresholds, [key]: Number(value) },
    }));

  const setSignal = (key: keyof RiskScoringConfigFormState["signals"], value: string) =>
    setForm((previous) => ({
      ...previous,
      signals: { ...previous.signals, [key]: Number(value) },
    }));

  const save = async () => {
    setFormError(null);
    setError(null);
    const result = riskScoringPayloadFromForm(form);
    if (!result.ok) {
      setFormError(result.error);
      return;
    }
    try {
      const response = await mutate("/grc/risk-scoring-config", result.payload, "PUT");
      setForm(riskScoringFormFromConfig(response.config));
      void configQuery.reload();
    } catch {
      // Surfaced through mutationError.
    }
  };

  const reset = async () => {
    setFormError(null);
    setError(null);
    try {
      const response = await mutate(grcPath("/grc/risk-scoring-config", { tenant_id: form.tenantID || "local" }), undefined, "DELETE");
      setForm(riskScoringFormFromConfig(response.config));
      void configQuery.reload();
    } catch {
      // Surfaced through mutationError.
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Risk scoring"
        description="Tune tenant-specific risk thresholds, signal cutoffs, graph relation weights, and factor weights used by the finding risk model."
      />

      <Panel title="Tenant configuration">
        <div className="grid gap-4 lg:grid-cols-[1fr_auto] lg:items-end">
          <label>
            <div className={labelClass}>Tenant ID</div>
            <input
              value={form.tenantID}
              onChange={(event) => setForm((previous) => ({ ...previous, tenantID: event.target.value }))}
              className={inputClass}
              placeholder="local"
            />
          </label>
          <div className="flex flex-wrap gap-2">
            <button type="button" className={buttonClass} onClick={() => configQuery.reload()} disabled={configQuery.loading}>
              <RefreshCw className="h-3.5 w-3.5" />
              Reload
            </button>
            <button type="button" className={buttonClass} onClick={reset} disabled={saving || !canWriteConfig}>
              <RotateCcw className="h-3.5 w-3.5" />
              Reset
            </button>
            <button type="button" className={primaryButtonClass} onClick={save} disabled={saving || !canWriteConfig}>
              <Save className="h-3.5 w-3.5" />
              {saving ? "Saving..." : "Save config"}
            </button>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-2 text-[12px] text-slate-500">
          <span className="rounded-md bg-slate-100 px-2 py-1">Persisted: {loaded ? loaded.persisted ? "yes" : "no" : "not loaded"}</span>
          <span className="rounded-md bg-slate-100 px-2 py-1">Model: {loaded?.config.model_version ?? DEFAULT_RISK_SCORING_CONFIG.model_version}</span>
        </div>
        {configQuery.loading && <div className="mt-3"><LoadingBlock label="Loading risk scoring config..." /></div>}
        {configQuery.error && <div className="mt-3"><ErrorBlock error={configQuery.error} onRetry={configQuery.reload} /></div>}
        {(formError || mutationError) && <div className="mt-3 rounded-md border border-rose-200 bg-rose-50 p-3 text-[13px] text-rose-700">{formError ?? mutationError}</div>}
      </Panel>

      <Panel title="Level thresholds">
        <div className="grid gap-3 md:grid-cols-3">
          <NumberField label="Critical" value={form.thresholds.critical} onChange={(value) => setThreshold("critical", value)} />
          <NumberField label="High" value={form.thresholds.high} onChange={(value) => setThreshold("high", value)} />
          <NumberField label="Medium" value={form.thresholds.medium} onChange={(value) => setThreshold("medium", value)} />
        </div>
      </Panel>

      <Panel title="Signal thresholds">
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-5">
          <NumberField label="EPSS high" step="0.01" value={form.signals.epss_high} onChange={(value) => setSignal("epss_high", value)} />
          <NumberField label="EPSS elevated" step="0.01" value={form.signals.epss_elevated} onChange={(value) => setSignal("epss_elevated", value)} />
          <NumberField label="CVSS critical" step="0.1" value={form.signals.cvss_critical} onChange={(value) => setSignal("cvss_critical", value)} />
          <NumberField label="CVSS high" step="0.1" value={form.signals.cvss_high} onChange={(value) => setSignal("cvss_high", value)} />
          <NumberField label="Private cap" value={form.signals.private_network_likelihood_cap} onChange={(value) => setSignal("private_network_likelihood_cap", value)} />
        </div>
      </Panel>

      <div className="grid gap-6 xl:grid-cols-2">
        <JSONEditor
          title="Relation weights"
          description="Graph edge weights keyed by relation name. Include default for unknown relations."
          value={form.relationWeightsJSON}
          onChange={(value) => setForm((previous) => ({ ...previous, relationWeightsJSON: value }))}
        />
        <JSONEditor
          title="Factor weights"
          description="Risk factor deltas keyed by factor name. Supports likelihood, impact, confidence, and likelihood_cap."
          value={form.factorWeightsJSON}
          onChange={(value) => setForm((previous) => ({ ...previous, factorWeightsJSON: value }))}
        />
      </div>

      <Panel title="How this is applied">
        <div className="flex items-start gap-3 text-[13px] leading-6 text-slate-600">
          <SlidersHorizontal className="mt-0.5 h-4 w-4 text-indigo-500" />
          <div>
            Saving creates a tenant override used by the backend risk model for future finding enrichment and risk recomputation. Reset deletes the override and returns to the built-in likelihood/impact model defaults.
          </div>
        </div>
      </Panel>
    </div>
  );
}

function NumberField({ label, value, onChange, step = "1" }: { label: string; value: number; onChange: (value: string) => void; step?: string }) {
  return (
    <label>
      <div className={labelClass}>{label}</div>
      <input type="number" step={step} value={value} onChange={(event) => onChange(event.target.value)} className={inputClass} />
    </label>
  );
}

function JSONEditor({ title, description, value, onChange }: { title: string; description: string; value: string; onChange: (value: string) => void }) {
  return (
    <Panel title={title}>
      <div className="text-[12px] text-slate-500">{description}</div>
      <textarea
        value={value}
        onChange={(event) => onChange(event.target.value)}
        rows={16}
        spellCheck={false}
        className="mt-3 w-full rounded-md border border-slate-200 bg-slate-950 p-3 font-mono text-[12px] leading-5 text-slate-50 shadow-inner focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30"
      />
    </Panel>
  );
}
