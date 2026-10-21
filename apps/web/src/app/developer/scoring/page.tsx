"use client";

import { ArrowRight, Plus, RotateCcw, Save, Trash2, Undo2 } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";

import { DataStateBanner, PageHeader, Panel } from "@/components/grc/Primitives";
import {
  ghostButtonClass,
  iconButtonClass,
  inputClass,
  ListField,
  NamedPercentTable,
  NumberField,
  PercentField,
  PercentInput,
} from "@/components/scoring/ModelFields";
import {
  ASSET_RISK_MODEL_PATH,
  type AssetRiskForm,
  assetRiskFormFromModel,
  type AssetRiskModelResponse,
  assetRiskModelPath,
  assetRiskPayloadFromForm,
  type AssetRiskRelationDirection,
  type CountermeasureForm,
  DEFAULT_ASSET_RISK_MODEL,
  exampleAttackPath,
  newRowID,
  type RelationForm,
} from "@/lib/asset-risk-model";
import { useGRCMutation, useGRCQuery } from "@/lib/grc-client";

const primaryButtonClass =
  "inline-flex items-center gap-1.5 rounded-md bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50";

const levelClass: Record<string, string> = {
  critical: "bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300",
  high: "bg-orange-100 text-orange-700 dark:bg-orange-500/15 dark:text-orange-300",
  medium: "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300",
  low: "bg-slate-100 text-slate-600 dark:bg-white/10 dark:text-slate-300",
};

const directionLabels: Record<AssetRiskRelationDirection, string> = {
  outgoing: "Along the edge",
  incoming: "Against the edge",
  both: "Either way",
};

const percentLabel = (fraction: number) => `${(fraction * 100).toFixed(fraction > 0 && fraction < 0.1 ? 1 : 0)}%`;

export default function RiskModelPage() {
  const searchParams = useSearchParams();
  const tenantID = (searchParams.get("tenant_id") ?? "").trim();
  const modelQuery = useGRCQuery<AssetRiskModelResponse>(assetRiskModelPath(tenantID));
  const { mutate, saving, error: mutationError, setError } = useGRCMutation<AssetRiskModelResponse>();
  const loaded = modelQuery.data;
  const baseForm = useMemo(() => assetRiskFormFromModel(loaded?.model ?? DEFAULT_ASSET_RISK_MODEL), [loaded]);
  const [draft, setDraft] = useState<AssetRiskForm | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const form = draft ?? baseForm;
  const ready = Boolean(loaded) && !modelQuery.loading;
  const disabled = !ready || saving;

  const dirty = useMemo(() => {
    if (!draft) return false;
    const current = assetRiskPayloadFromForm(draft);
    const base = assetRiskPayloadFromForm(baseForm);
    return !current.ok || !base.ok || JSON.stringify(current.payload) !== JSON.stringify(base.payload);
  }, [draft, baseForm]);

  const example = useMemo(() => exampleAttackPath(form), [form]);

  const edit = (update: (previous: AssetRiskForm) => AssetRiskForm) => {
    setFormError(null);
    setDraft((previous) => update(previous ?? baseForm));
  };
  const editSection = <K extends keyof AssetRiskForm>(section: K, patch: Partial<AssetRiskForm[K]>) =>
    edit((previous) => ({ ...previous, [section]: { ...previous[section], ...patch } }));

  const save = async () => {
    setError(null);
    const result = assetRiskPayloadFromForm(form, tenantID);
    if (!result.ok) {
      setFormError(result.error);
      return;
    }
    try {
      const response = await mutate(ASSET_RISK_MODEL_PATH, result.payload, "PUT");
      setDraft(assetRiskFormFromModel(response.model));
      setFormError(null);
      void modelQuery.reload();
    } catch {
      // Surfaced through mutationError.
    }
  };

  const reset = async () => {
    if (!window.confirm("Replace the saved model with the built-in defaults?")) return;
    setError(null);
    try {
      const response = await mutate(assetRiskModelPath(tenantID), undefined, "DELETE");
      setDraft(assetRiskFormFromModel(response.model));
      setFormError(null);
      void modelQuery.reload();
    } catch {
      // Surfaced through mutationError.
    }
  };

  const discard = () => {
    setDraft(null);
    setFormError(null);
    setError(null);
  };

  const updateCountermeasure = (id: string, patch: Partial<CountermeasureForm>) =>
    edit((previous) => ({ ...previous, countermeasures: previous.countermeasures.map((row) => (row.id === id ? { ...row, ...patch } : row)) }));
  const updateRelation = (id: string, patch: Partial<RelationForm>) =>
    edit((previous) => ({ ...previous, relations: previous.relations.map((row) => (row.id === id ? { ...row, ...patch } : row)) }));

  const updatedAt = loaded?.model.updated_at ? new Date(loaded.model.updated_at).toLocaleString() : null;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Risk Model"
        description="How Cerebro scores assets and attack paths. Each step of a path has a chance of succeeding, based on vulnerabilities, exposure, and countermeasures. The chance of reaching an asset, multiplied by what the asset is worth, gives its risk."
        action={
          <div className="flex flex-wrap items-center gap-2">
            {dirty && (
              <button type="button" className={ghostButtonClass} onClick={discard} disabled={saving}>
                <Undo2 className="h-3.5 w-3.5" />
                Discard changes
              </button>
            )}
            <button type="button" className={ghostButtonClass} onClick={reset} disabled={disabled || !loaded?.persisted}>
              <RotateCcw className="h-3.5 w-3.5" />
              Reset to defaults
            </button>
            <button type="button" className={primaryButtonClass} onClick={save} disabled={disabled || !dirty}>
              <Save className="h-3.5 w-3.5" />
              {saving ? "Saving..." : "Save model"}
            </button>
          </div>
        }
      />

      <div className="flex flex-wrap items-center gap-2 text-[12px] text-[var(--text-secondary)]">
        <span className="rounded-md bg-[var(--surface-muted,rgba(148,163,184,0.12))] px-2 py-1">
          {loaded ? (loaded.persisted ? "Saved model" : "Built-in model") : "Loading model"}
        </span>
        <span className="rounded-md bg-[var(--surface-muted,rgba(148,163,184,0.12))] px-2 py-1 font-mono">{loaded?.model.model_version ?? DEFAULT_ASSET_RISK_MODEL.model_version}</span>
        {updatedAt && <span>Saved {updatedAt}</span>}
        {dirty && <span className="font-medium text-amber-700 dark:text-amber-300">Unsaved changes</span>}
      </div>

      <DataStateBanner state={modelQuery.state} error={modelQuery.error} onRetry={modelQuery.reload} subject="Risk model" />
      {(formError || mutationError) && (
        <div role="alert" className="rounded-md border border-rose-200 bg-rose-50 p-3 text-[13px] text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300">
          {formError ?? mutationError}
        </div>
      )}

      <Panel
        title="How a path is scored"
        description="A worked example using the values below. It updates as you edit."
      >
        <div className="flex flex-wrap items-stretch gap-2">
          {example.steps.map((step, index) => (
            <div key={step.label} className="flex items-stretch gap-2">
              {index > 0 && <ArrowRight className="mt-5 h-4 w-4 shrink-0 text-[var(--text-muted)]" />}
              <div className="min-w-[9.5rem] rounded-md border border-[color:var(--border)] px-3 py-2">
                <div className="text-[13px] font-medium text-[var(--text-primary)]">{step.label}</div>
                <div className="text-[11px] text-[var(--text-muted)]">{step.detail}</div>
                <div className="mt-1.5 text-[12px] text-[var(--text-secondary)]">
                  Step <span className="font-mono">{percentLabel(step.probability)}</span> · Reached <span className="font-mono">{percentLabel(step.cumulative)}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-[var(--text-secondary)]">
          <span>
            Reached <span className="font-mono">{percentLabel(example.probability)}</span> × database worth <span className="font-mono">{percentLabel(example.targetValue)}</span> = score <span className="font-mono font-semibold text-[var(--text-primary)]">{example.score}</span>
          </span>
          <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase ${levelClass[example.level]}`}>{example.level}</span>
        </div>
      </Panel>

      <div className="grid gap-6 xl:grid-cols-2">
        <Panel title="Asset value" description="What an asset is worth to an attacker. Cerebro takes the highest of its kind value, its data classification, and crown jewel status, then adds the production boost.">
          <div className="grid gap-4 sm:grid-cols-3">
            <PercentField label="Default value" hint="Kinds not listed below." value={form.value.defaultPercent} onChange={(defaultPercent) => editSection("value", { defaultPercent })} disabled={disabled} />
            <PercentField label="Crown jewel" hint="Assets marked crown_jewel or critical." value={form.value.crownJewelPercent} onChange={(crownJewelPercent) => editSection("value", { crownJewelPercent })} disabled={disabled} />
            <PercentField label="Production boost" hint="Added when environment is production." value={form.value.productionBoostPercent} onChange={(productionBoostPercent) => editSection("value", { productionBoostPercent })} disabled={disabled} />
          </div>
          <div className="mt-5">
            <ListField
              label="Classification attributes"
              hint="Asset attributes that hold a data classification, checked in order."
              value={form.value.classificationAttributes}
              onChange={(classificationAttributes) => editSection("value", { classificationAttributes })}
              disabled={disabled}
            />
          </div>
          <div className="mt-5 grid gap-6 2xl:grid-cols-2">
            <div>
              <h3 className="mb-2 text-[13px] font-semibold text-[var(--text-primary)]">Data classification</h3>
              <NamedPercentTable
                rows={form.value.classifications}
                onChange={(classifications) => editSection("value", { classifications })}
                nameLabel="Label"
                valueLabel="Worth"
                addLabel="Add classification"
                disabled={disabled}
              />
            </div>
            <div>
              <h3 className="mb-2 text-[13px] font-semibold text-[var(--text-primary)]">Asset kind</h3>
              <NamedPercentTable
                rows={form.value.kinds}
                onChange={(kinds) => editSection("value", { kinds })}
                nameLabel="Kind"
                valueLabel="Worth"
                addLabel="Add kind"
                disabled={disabled}
              />
              <p className="mt-2 text-[11px] leading-4 text-[var(--text-muted)]">A kind matches the entity type exactly or as one part of it, so database matches aws.rds_database.</p>
            </div>
          </div>
        </Panel>

        <div className="space-y-6">
          <Panel title="Vulnerability signals" description="The chance that one vulnerability lets an attacker take over its asset. Cerebro uses the strongest signal, then combines all open vulnerabilities on the asset.">
            <div className="grid gap-4 sm:grid-cols-3">
              <PercentField label="Known exploited (CISA KEV)" value={form.vulnerability.knownExploitedPercent} onChange={(knownExploitedPercent) => editSection("vulnerability", { knownExploitedPercent })} disabled={disabled} />
              <PercentField label="Used in ransomware" value={form.vulnerability.ransomwarePercent} onChange={(ransomwarePercent) => editSection("vulnerability", { ransomwarePercent })} disabled={disabled} />
              <PercentField label="EPSS weight" hint="Chance = EPSS score × this weight." value={form.vulnerability.epssWeightPercent} onChange={(epssWeightPercent) => editSection("vulnerability", { epssWeightPercent })} disabled={disabled} />
              <NumberField label="Critical CVSS from" step={0.1} value={form.vulnerability.cvssCritical} onChange={(cvssCritical) => editSection("vulnerability", { cvssCritical })} disabled={disabled} />
              <PercentField label="Critical CVSS chance" value={form.vulnerability.cvssCriticalPercent} onChange={(cvssCriticalPercent) => editSection("vulnerability", { cvssCriticalPercent })} disabled={disabled} />
              <div className="hidden sm:block" />
              <NumberField label="High CVSS from" step={0.1} value={form.vulnerability.cvssHigh} onChange={(cvssHigh) => editSection("vulnerability", { cvssHigh })} disabled={disabled} />
              <PercentField label="High CVSS chance" value={form.vulnerability.cvssHighPercent} onChange={(cvssHighPercent) => editSection("vulnerability", { cvssHighPercent })} disabled={disabled} />
              <div className="hidden sm:block" />
              <PercentField label="Any open vulnerability" hint="Floor when no signal applies." value={form.vulnerability.basePercent} onChange={(basePercent) => editSection("vulnerability", { basePercent })} disabled={disabled} />
              <PercentField label="No known vulnerability" hint="Unknown flaws and misconfiguration." value={form.vulnerability.noKnownPercent} onChange={(noKnownPercent) => editSection("vulnerability", { noKnownPercent })} disabled={disabled} />
              <NumberField label="Counted per asset" hint="Strongest vulnerabilities combined." value={form.vulnerability.maxPerAsset} onChange={(maxPerAsset) => editSection("vulnerability", { maxPerAsset })} disabled={disabled} />
            </div>
            <div className="mt-4">
              <ListField label="Vulnerability relations" hint="Graph relations that attach vulnerabilities to assets." value={form.vulnerability.relations} onChange={(relations) => editSection("vulnerability", { relations })} disabled={disabled} />
            </div>
          </Panel>

          <Panel title="Exposure" description="How likely the starting point of a path is to be compromised in the first place.">
            <div className="grid gap-4 sm:grid-cols-3">
              <PercentField label="Direct compromise" hint="Phishing, stolen credentials, insider." value={form.exposure.entryPercent} onChange={(entryPercent) => editSection("exposure", { entryPercent })} disabled={disabled} />
              <PercentField label="Internet-exposed factor" hint="Scales vulnerability chance when exposed." value={form.exposure.internetPercent} onChange={(internetPercent) => editSection("exposure", { internetPercent })} disabled={disabled} />
              <PercentField label="Internal factor" hint="Scales vulnerability chance otherwise." value={form.exposure.internalPercent} onChange={(internalPercent) => editSection("exposure", { internalPercent })} disabled={disabled} />
            </div>
            <div className="mt-4">
              <ListField label="Internet exposure attributes" hint="Any of these set to true marks an entity as internet-exposed." value={form.exposure.internetAttributes} onChange={(internetAttributes) => editSection("exposure", { internetAttributes })} disabled={disabled} />
            </div>
          </Panel>
        </div>
      </div>

      <Panel
        title="Countermeasures"
        description="Controls that make a step harder. When an entity has one, the chance of taking it over drops by the reduction. Several countermeasures stack."
        action={
          <button
            type="button"
            className={ghostButtonClass}
            disabled={disabled}
            onClick={() => edit((previous) => ({
              ...previous,
              countermeasures: [...previous.countermeasures, { id: newRowID(), key: "", label: "", attributes: "", values: "", appliesTo: "", reductionPercent: 30 }],
            }))}
          >
            <Plus className="h-3.5 w-3.5" />
            Add countermeasure
          </button>
        }
      >
        {form.countermeasures.length === 0 ? (
          <p className="text-[13px] text-[var(--text-muted)]">No countermeasures. Every step is scored at full strength.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] text-left text-[13px]">
              <thead className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-muted)]">
                <tr>
                  <th className="pb-2 pr-3 font-medium">Name</th>
                  <th className="pb-2 pr-3 font-medium">Attributes that show it</th>
                  <th className="pb-2 pr-3 font-medium">Matching values</th>
                  <th className="pb-2 pr-3 font-medium">Entity kinds</th>
                  <th className="w-28 pb-2 pr-3 font-medium">Reduction</th>
                  <th className="w-8 pb-2" />
                </tr>
              </thead>
              <tbody>
                {form.countermeasures.map((row) => (
                  <tr key={row.id} className="align-top">
                    <td className="py-1 pr-3">
                      <input value={row.label} onChange={(event) => updateCountermeasure(row.id, { label: event.target.value })} placeholder="MFA enforced" aria-label="Countermeasure name" disabled={disabled} className={inputClass} />
                    </td>
                    <td className="py-1 pr-3">
                      <input value={row.attributes} onChange={(event) => updateCountermeasure(row.id, { attributes: event.target.value })} placeholder="mfa_enabled" aria-label={`Attributes for ${row.label || "countermeasure"}`} disabled={disabled} spellCheck={false} className={`${inputClass} font-mono text-[12px]`} />
                    </td>
                    <td className="py-1 pr-3">
                      <input value={row.values} onChange={(event) => updateCountermeasure(row.id, { values: event.target.value })} placeholder="any true value" aria-label={`Matching values for ${row.label || "countermeasure"}`} disabled={disabled} spellCheck={false} className={`${inputClass} font-mono text-[12px]`} />
                    </td>
                    <td className="py-1 pr-3">
                      <input value={row.appliesTo} onChange={(event) => updateCountermeasure(row.id, { appliesTo: event.target.value })} placeholder="all kinds" aria-label={`Entity kinds for ${row.label || "countermeasure"}`} disabled={disabled} spellCheck={false} className={`${inputClass} font-mono text-[12px]`} />
                    </td>
                    <td className="py-1 pr-3">
                      <PercentInput value={row.reductionPercent} onChange={(reductionPercent) => updateCountermeasure(row.id, { reductionPercent })} disabled={disabled} ariaLabel={`Reduction for ${row.label || "countermeasure"}`} />
                    </td>
                    <td className="py-1">
                      <button type="button" className={iconButtonClass} onClick={() => edit((previous) => ({ ...previous, countermeasures: previous.countermeasures.filter((item) => item.id !== row.id) }))} disabled={disabled} aria-label={`Remove ${row.label || "countermeasure"}`}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="mt-2 text-[11px] leading-4 text-[var(--text-muted)]">Separate lists with commas. Leave matching values empty to accept any true value such as true, yes, enabled, or active.</p>
          </div>
        )}
      </Panel>

      <Panel
        title="Attack steps"
        description="Graph relations an attacker can follow, and the chance each step succeeds. Steps that need an exploit are multiplied by the target's vulnerability chance."
        action={
          <button
            type="button"
            className={ghostButtonClass}
            disabled={disabled}
            onClick={() => edit((previous) => ({
              ...previous,
              relations: [...previous.relations, { id: newRowID(), name: "", percent: 50, direction: "outgoing", requiresExploit: false }],
            }))}
          >
            <Plus className="h-3.5 w-3.5" />
            Add step
          </button>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-[13px]">
            <thead className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-muted)]">
              <tr>
                <th className="pb-2 pr-3 font-medium">Relation</th>
                <th className="w-28 pb-2 pr-3 font-medium">Success</th>
                <th className="w-44 pb-2 pr-3 font-medium">Attacker moves</th>
                <th className="w-32 pb-2 pr-3 font-medium">Needs exploit</th>
                <th className="w-8 pb-2" />
              </tr>
            </thead>
            <tbody>
              {form.relations.map((row) => (
                <tr key={row.id}>
                  <td className="py-1 pr-3">
                    <input value={row.name} onChange={(event) => updateRelation(row.id, { name: event.target.value })} placeholder="can_admin" aria-label="Relation" disabled={disabled} spellCheck={false} className={`${inputClass} font-mono text-[12px]`} />
                  </td>
                  <td className="py-1 pr-3">
                    <PercentInput value={row.percent} onChange={(percent) => updateRelation(row.id, { percent })} disabled={disabled} ariaLabel={`Success for ${row.name || "step"}`} />
                  </td>
                  <td className="py-1 pr-3">
                    <select value={row.direction} onChange={(event) => updateRelation(row.id, { direction: event.target.value as AssetRiskRelationDirection })} aria-label={`Direction for ${row.name || "step"}`} disabled={disabled} className={inputClass}>
                      {(Object.keys(directionLabels) as AssetRiskRelationDirection[]).map((direction) => (
                        <option key={direction} value={direction}>{directionLabels[direction]}</option>
                      ))}
                    </select>
                  </td>
                  <td className="py-1 pr-3">
                    <input type="checkbox" checked={row.requiresExploit} onChange={(event) => updateRelation(row.id, { requiresExploit: event.target.checked })} aria-label={`${row.name || "Step"} needs an exploit`} disabled={disabled} className="h-4 w-4 accent-indigo-500" />
                  </td>
                  <td className="py-1">
                    <button type="button" className={iconButtonClass} onClick={() => edit((previous) => ({ ...previous, relations: previous.relations.filter((item) => item.id !== row.id) }))} disabled={disabled} aria-label={`Remove ${row.name || "step"}`}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="grid gap-6 xl:grid-cols-2">
        <Panel title="Path search" description="Limits on how far Cerebro explores from a starting point.">
          <div className="grid gap-4 sm:grid-cols-2">
            <NumberField label="Longest path" hint="Steps, 1 to 6." value={form.traversal.maxDepth} onChange={(maxDepth) => editSection("traversal", { maxDepth })} disabled={disabled} />
            <NumberField label="Paths returned" hint="Riskiest first, up to 200." value={form.traversal.maxPaths} onChange={(maxPaths) => editSection("traversal", { maxPaths })} disabled={disabled} />
            <NumberField label="Exploration budget" hint="Entities examined per search, up to 1000." value={form.traversal.maxExpansions} onChange={(maxExpansions) => editSection("traversal", { maxExpansions })} disabled={disabled} />
            <PercentField label="Ignore paths below" hint="Stops following very unlikely routes." value={form.traversal.minProbabilityPercent} onChange={(minProbabilityPercent) => editSection("traversal", { minProbabilityPercent })} disabled={disabled} />
          </div>
        </Panel>
        <Panel title="Risk levels" description="Scores run from 0 to 100: the chance of reaching an asset times its worth.">
          <div className="grid gap-4 sm:grid-cols-3">
            <NumberField label="Critical from" value={form.thresholds.critical} onChange={(critical) => editSection("thresholds", { critical })} disabled={disabled} />
            <NumberField label="High from" value={form.thresholds.high} onChange={(high) => editSection("thresholds", { high })} disabled={disabled} />
            <NumberField label="Medium from" value={form.thresholds.medium} onChange={(medium) => editSection("thresholds", { medium })} disabled={disabled} />
          </div>
        </Panel>
      </div>
    </div>
  );
}
