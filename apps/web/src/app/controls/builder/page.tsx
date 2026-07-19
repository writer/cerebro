"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import { useApiKey } from "@/components/providers";
import { fetchCerebro } from "@/lib/cerebro-client";
import { countLabel } from "@/lib/format";
import {
  Badge,
  ErrorBlock,
  LoadingBlock,
  MetricCard,
  PageHeader,
  Panel,
} from "@/components/grc/Primitives";
import {
  GRCControlArchetype,
  GRCControlArchetypesResponse,
  GRCControlPackIssueResponse,
  GRCControlPackPreview,
  GRCControlPackResponse,
  GRCControlProfilesResponse,
  GRCCustomControlEvidencePacketResponse,
} from "@/lib/grc";
import { useGRCQuery } from "@/lib/grc-client";
import { runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";

const inputClass = "control-input mt-0.5 w-full px-3 py-1 text-[13px]";
const labelClass = "text-[11px] font-semibold uppercase leading-3 tracking-wider text-[var(--text-muted)]";
const yamlFiles = ["extension.yaml", "controls.yaml", "profiles.yaml", "coverage.yaml"];
type BuilderViewMode = "family" | "all";

const selectedRecord = (ids: string[]) => new Set(ids.map((id) => id.trim()).filter(Boolean));

const profileOptions = (profiles: GRCControlProfilesResponse | null) =>
  (profiles?.profiles ?? []).map((profile) => ({
    id: profile.id,
    label: profile.name || profile.id,
    detail: `${countLabel(profile.summary.selected_controls, "control")}, ${countLabel(profile.summary.mapped_rules, "mapped rule")}`,
  }));

const downloadYAML = (name: string, content: string) => {
  const type = name.endsWith(".md") ? "text/markdown;charset=utf-8" : "application/x-yaml;charset=utf-8";
  const blob = new Blob([content], { type });
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  window.URL.revokeObjectURL(url);
};

function ArchetypeRow({
  archetype,
  checked,
  onToggle,
}: {
  archetype: GRCControlArchetype;
  checked: boolean;
  onToggle: () => void;
}) {
  const expectations = archetype.control.evidence_expectations ?? [];
  return (
    <button
      type="button"
      aria-pressed={checked}
      onClick={onToggle}
      className={`w-full rounded-lg border px-4 py-3 text-left transition ${checked ? "border-[color:var(--ring)] bg-indigo-50/70" : "border-[color:var(--border)] bg-white hover:border-[color:var(--border-strong)]"}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] font-semibold text-[var(--text-primary)]">{archetype.control.title || archetype.id}</span>
            {archetype.recommended && <Badge value="recommended" />}
          </div>
          <div className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">{archetype.control.objective}</div>
        </div>
        <span className={`mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-md border ${checked ? "border-[color:var(--primary)] bg-[var(--primary)]" : "border-[color:var(--border-strong)]"}`}>
          {checked && <span className="h-2 w-2 rounded-sm bg-white" />}
        </span>
      </div>
      <div className="mt-3 flex flex-wrap gap-1.5">
        <span className="rounded-md bg-[var(--surface-muted)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)]">{archetype.family_name}</span>
        <span className="rounded-md bg-[var(--surface-muted)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)]">{archetype.control.freshness_sla || "freshness set"}</span>
        <span className="rounded-md bg-[var(--surface-muted)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)]">{expectations.length} evidence</span>
      </div>
    </button>
  );
}

function CoveragePreview({
  auditPacket,
  auditLoading,
  exportLoading,
  onBuildAudit,
  onExportAudit,
  preview,
  stale,
}: {
  auditPacket: GRCCustomControlEvidencePacketResponse | null;
  auditLoading: boolean;
  exportLoading: boolean;
  onBuildAudit: () => void;
  onExportAudit: () => void;
  preview: GRCControlPackPreview;
  stale: boolean;
}) {
  const controls = preview.coverage.controls ?? [];
  return (
    <div className="space-y-4">
      {stale && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-[13px] text-amber-900">
          This preview was generated from previous inputs. Generate a fresh preview before downloading YAML.
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 md:gap-4">
        <MetricCard label="Controls" value={preview.summary.controls} detail={`${preview.summary.families} families`} />
        <MetricCard label="Auditor Ready" value={preview.summary.auditor_ready_controls} detail="ready controls" intent="success" />
        <MetricCard label="Mapped" value={preview.summary.mapped_controls} detail={`${preview.summary.mapped_rules} rules`} intent={preview.summary.mapped_controls > 0 ? "success" : "warning"} />
        <MetricCard label="Gaps" value={preview.summary.unmapped_controls} detail="unmapped controls" intent={preview.summary.unmapped_controls > 0 ? "warning" : "success"} />
      </div>

      <Panel title="Generated Controls">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[13px]">
            <thead>
              <tr className="border-b border-[color:var(--border)] bg-[var(--surface-muted)]">
                <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Control</th>
                <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Family</th>
                <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Readiness</th>
                <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Coverage</th>
                <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {controls.map((control) => (
                <tr key={`${control.framework_name}-${control.control_id}`} className="border-b border-[color:var(--border)] last:border-b-0">
                  <td className="px-3 py-3">
                    <div className="font-semibold text-[var(--text-primary)]">{control.control_id}</div>
                    <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">{control.title}</div>
                  </td>
                  <td className="px-3 py-3 text-[12px] text-[var(--text-secondary)]">{control.family_name}</td>
                  <td className="px-3 py-3"><Badge value={control.audit_readiness.status} /></td>
                  <td className="px-3 py-3">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge value={control.coverage_status} />
                      <span className="text-[12px] text-[var(--text-muted)]">{control.rule_count} rules</span>
                    </div>
                  </td>
                  <td className="px-3 py-3 text-[12px] text-[var(--text-secondary)]">{control.evidence_plan?.expectations?.length ?? 0} expectations</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="YAML Outputs">
        <div className="grid gap-3 lg:grid-cols-2">
          {yamlFiles.map((name) => (
            <div key={name} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)]">
              <div className="flex items-center justify-between gap-3 border-b border-[color:var(--border)] px-3 py-2">
                <div className="font-mono text-[12px] font-semibold text-[var(--text-primary)]">{name}</div>
                <button
                  type="button"
                  disabled={stale}
                  onClick={() => downloadYAML(name, preview.files[name] ?? "")}
                  className="rounded-md border border-[color:var(--border)] bg-white px-2.5 py-1 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Download
                </button>
              </div>
              <pre className="max-h-64 overflow-auto p-3 text-[11px] leading-5 text-[var(--text-secondary)]">{preview.files[name]}</pre>
            </div>
          ))}
        </div>
      </Panel>

      <Panel
        title="Generated Evidence Packet"
        action={
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={stale || auditLoading}
              onClick={onBuildAudit}
              className="rounded-md border border-[color:var(--border)] bg-white px-2.5 py-1 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {auditLoading ? "Building..." : "Build packet"}
            </button>
            <button
              type="button"
              disabled={stale || !auditPacket || exportLoading}
              onClick={onExportAudit}
              className="rounded-md border border-[color:var(--border)] bg-white px-2.5 py-1 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {exportLoading ? "Exporting..." : "Export markdown"}
            </button>
          </div>
        }
      >
        {auditPacket ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <MetricCard label="Packet Controls" value={auditPacket.packet.summary.total} detail={auditPacket.profile.name || auditPacket.profile.id} />
              <MetricCard label="Failing" value={auditPacket.packet.summary.by_status.failing ?? 0} detail="with open findings" intent={(auditPacket.packet.summary.by_status.failing ?? 0) > 0 ? "danger" : "success"} />
              <MetricCard label="Missing Evidence" value={auditPacket.packet.summary.by_status.missing_evidence ?? 0} detail="controls waiting on proof" intent={(auditPacket.packet.summary.by_status.missing_evidence ?? 0) > 0 ? "warning" : "success"} />
              <MetricCard label="Evidence Quality" value={auditPacket.controls[0]?.evidence_quality ? <Badge value={auditPacket.controls[0].evidence_quality} /> : "-"} detail="first control" />
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[13px]">
                <thead>
                  <tr className="border-b border-[color:var(--border)] bg-[var(--surface-muted)]">
                    <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Control</th>
                    <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Status</th>
                    <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Score</th>
                    <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Evidence</th>
                    <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {auditPacket.controls.map((control) => (
                    <tr key={`${control.framework_name}-${control.control_id}`} className="border-b border-[color:var(--border)] last:border-b-0">
                      <td className="px-3 py-3">
                        <div className="font-semibold text-[var(--text-primary)]">{control.framework_name} {control.control_id}</div>
                        <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">{control.title || control.family_name}</div>
                      </td>
                      <td className="px-3 py-3"><Badge value={control.status} /></td>
                      <td className="px-3 py-3 font-mono text-[12px] text-[var(--text-primary)]">{control.evidence_score ?? "-"}</td>
                      <td className="px-3 py-3 text-[12px] text-[var(--text-secondary)]">{countLabel(control.evidence_items, "item")}, {control.missing_evidence_items ?? 0} missing</td>
                      <td className="px-3 py-3 text-[12px] text-[var(--text-secondary)]">{control.audit_summary || control.reasons?.[0] || "No assessment summary is available."}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div className="py-8 text-center text-[13px] text-[var(--text-muted)]">
            Build the packet to see live evidence posture for the generated custom framework.
          </div>
        )}
      </Panel>
    </div>
  );
}

export default function ControlBuilderPage() {
  const { apiKey } = useApiKey();
  const archetypesQuery = useGRCQuery<GRCControlArchetypesResponse>("/grc/control-archetypes");
  const profilesQuery = useGRCQuery<GRCControlProfilesResponse>("/grc/control-profiles");
  const [frameworkName, setFrameworkName] = useState("Customer Security Framework");
  const [frameworkID, setFrameworkID] = useState("customer-security");
  const [profileName, setProfileName] = useState("Customer Security Audit");
  const [profileID, setProfileID] = useState("customer-security-audit");
  const [selectedArchetypes, setSelectedArchetypes] = useState<string[] | null>(null);
  const [includedProfiles, setIncludedProfiles] = useState<string[]>([]);
  const [preview, setPreview] = useState<GRCControlPackPreview | null>(null);
  const [previewRequestKey, setPreviewRequestKey] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [auditPacket, setAuditPacket] = useState<GRCCustomControlEvidencePacketResponse | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditExportLoading, setAuditExportLoading] = useState(false);
  const [viewMode, setViewMode] = useState<BuilderViewMode>("family");

  const archetypes = useMemo(() => archetypesQuery.data?.archetypes ?? [], [archetypesQuery.data?.archetypes]);
  const recommendedArchetypes = useMemo(() => archetypes.filter((item) => item.recommended).map((item) => item.id), [archetypes]);
  const effectiveSelectedArchetypes = selectedArchetypes ?? recommendedArchetypes;
  const families = useMemo(() => {
    const result = new Map<string, GRCControlArchetype[]>();
    for (const archetype of archetypes) {
      const key = archetype.family_name || archetype.family_id;
      result.set(key, [...(result.get(key) ?? []), archetype]);
    }
    return Array.from(result.entries()).sort(([left], [right]) => left.localeCompare(right));
  }, [archetypes]);
  const selected = useMemo(() => selectedRecord(effectiveSelectedArchetypes), [effectiveSelectedArchetypes]);
  const selectedFamilies = useMemo(() => {
    const familyIDs = new Set<string>();
    for (const archetype of archetypes) {
      if (selected.has(archetype.id)) familyIDs.add(archetype.family_id || archetype.family_name);
    }
    return familyIDs.size;
  }, [archetypes, selected]);
  const profileSet = useMemo(() => selectedRecord(includedProfiles), [includedProfiles]);
  const options = useMemo(() => profileOptions(profilesQuery.data), [profilesQuery.data]);
  const loading = archetypesQuery.loading || profilesQuery.loading;
  const error = archetypesQuery.error || profilesQuery.error;
  const runtimeState = runtimeStateForError(error);
  const metricState: RuntimeState = error ? runtimeState : loading && !archetypesQuery.data ? "loading" : "ready";
  const previewRequest = useMemo(() => ({
    framework_id: frameworkID,
    framework_name: frameworkName,
    profile_id: profileID,
    profile_name: profileName,
    archetype_ids: effectiveSelectedArchetypes,
    include_profiles: includedProfiles,
  }), [effectiveSelectedArchetypes, frameworkID, frameworkName, includedProfiles, profileID, profileName]);
  const currentPreviewRequestKey = useMemo(() => JSON.stringify(previewRequest), [previewRequest]);
  const previewIsStale = preview !== null && previewRequestKey !== currentPreviewRequestKey;

  const toggleArchetype = (id: string) => {
    setSelectedArchetypes((current) => {
      const base = current ?? effectiveSelectedArchetypes;
      return base.includes(id) ? base.filter((item) => item !== id) : [...base, id].sort();
    });
  };
  const toggleProfile = (id: string) => {
    setIncludedProfiles((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id].sort());
  };
  const submitPreview = async () => {
    setPreviewLoading(true);
    setPreviewError(null);
    try {
      const response = await fetchCerebro<GRCControlPackResponse | GRCControlPackIssueResponse>("/grc/control-packs/preview", apiKey, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(previewRequest),
      });
      if (!response.ok) {
        const data = response.data as GRCControlPackIssueResponse;
        const detail = Array.isArray(data.issues) && data.issues.length > 0
          ? data.issues.map((issue) => [issue.path ?? issue.Path, issue.message ?? issue.Message].filter(Boolean).join(": ")).join("; ")
          : `Preview failed (${response.status})`;
        setPreview(null);
        setPreviewRequestKey(null);
        setPreviewError(detail);
        return;
      }
      setPreview((response.data as GRCControlPackResponse).preview);
      setPreviewRequestKey(currentPreviewRequestKey);
      setAuditPacket(null);
      setAuditError(null);
    } catch (error) {
      setPreview(null);
      setPreviewRequestKey(null);
      setPreviewError(error instanceof Error ? error.message : "Preview failed");
    } finally {
      setPreviewLoading(false);
    }
  };
  const submitAuditPacket = async () => {
    setAuditLoading(true);
    setAuditError(null);
    try {
      const response = await fetchCerebro<GRCCustomControlEvidencePacketResponse | GRCControlPackIssueResponse>("/grc/control-packets", apiKey, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(previewRequest),
      });
      if (!response.ok) {
        const data = response.data as GRCControlPackIssueResponse;
        const detail = Array.isArray(data.issues) && data.issues.length > 0
          ? data.issues.map((issue) => [issue.path ?? issue.Path, issue.message ?? issue.Message].filter(Boolean).join(": ")).join("; ")
          : `Packet build failed (${response.status})`;
        setAuditPacket(null);
        setAuditError(detail);
        return;
      }
      setAuditPacket(response.data as GRCCustomControlEvidencePacketResponse);
    } catch (error) {
      setAuditPacket(null);
      setAuditError(error instanceof Error ? error.message : "Packet build failed");
    } finally {
      setAuditLoading(false);
    }
  };
  const exportAuditPacket = async () => {
    setAuditExportLoading(true);
    setAuditError(null);
    try {
      const response = await fetchCerebro<string>("/grc/control-packets/export?format=markdown", apiKey, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(previewRequest),
      });
      if (!response.ok || typeof response.data !== "string") {
        setAuditError(typeof response.data === "string" ? response.data : `Export failed (${response.status})`);
        return;
      }
      downloadYAML(`${profileID || "custom-control"}-evidence-packet.md`, response.data);
    } catch (error) {
      setAuditError(error instanceof Error ? error.message : "Export failed");
    } finally {
      setAuditExportLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="control-builder"
        title="Control Builder"
        description="Build a custom framework from reusable control families, preview mapped coverage, and export auditor-ready YAML."
        action={
          <Link href="/controls" className="rounded-md border border-[color:var(--border)] bg-white px-3 py-1.5 text-[13px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)]">
            Controls
          </Link>
        }
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 md:gap-4">
        <MetricCard label="Archetypes" value={archetypes.length} detail="available" state={metricState} />
        <MetricCard label="Selected" value={effectiveSelectedArchetypes.length} detail="for this pack" state={metricState} />
        <MetricCard label="Profiles" value={includedProfiles.length} detail="included scopes" state={metricState} />
        <MetricCard label="Preview" value={preview ? preview.summary.controls : "-"} detail={preview ? `${preview.summary.auditor_ready_controls} ready` : "not generated"} state={metricState} />
      </div>

      {loading && <LoadingBlock label="Loading control builder..." />}
      {error && <ErrorBlock error={error} onRetry={() => { void archetypesQuery.reload(); void profilesQuery.reload(); }} recoveryDetail="The builder will load when the compliance API is reachable." />}

      {!loading && !error && (
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
          <div className="order-2 space-y-5 xl:order-none">
            <div className="rounded-lg border border-[color:var(--border)] bg-white px-5 py-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">Common controls</h2>
                  <p className="mt-0.5 text-[12px] text-[var(--text-muted)]">{effectiveSelectedArchetypes.length} selected across {selectedFamilies} families</p>
                </div>
                <div className="inline-flex rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] p-0.5">
                  {([
                    ["family", "View by family"],
                    ["all", "View all"],
                  ] as const).map(([mode, label]) => (
                    <button
                      key={mode}
                      type="button"
                      onClick={() => setViewMode(mode)}
                      className={`rounded px-3 py-1.5 text-[12px] font-medium transition ${viewMode === mode ? "bg-white text-[var(--text-primary)] shadow-sm" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"}`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {viewMode === "family" ? (
              families.map(([family, items]) => (
                <Panel key={family} title={family}>
                  <div className="grid gap-3 lg:grid-cols-2">
                    {items.map((archetype) => (
                      <ArchetypeRow
                        key={archetype.id}
                        archetype={archetype}
                        checked={selected.has(archetype.id)}
                        onToggle={() => toggleArchetype(archetype.id)}
                      />
                    ))}
                  </div>
                </Panel>
              ))
            ) : (
              <Panel title="All Controls">
                <div className="grid gap-3 lg:grid-cols-2">
                  {archetypes.map((archetype) => (
                    <ArchetypeRow
                      key={archetype.id}
                      archetype={archetype}
                      checked={selected.has(archetype.id)}
                      onToggle={() => toggleArchetype(archetype.id)}
                    />
                  ))}
                </div>
              </Panel>
            )}
          </div>

          <aside className="order-1 space-y-5 pb-24 xl:order-none">
            <Panel title="Pack Details">
              <div className="space-y-2">
                <button
                  type="button"
                  disabled={previewLoading || effectiveSelectedArchetypes.length === 0}
                  onClick={() => void submitPreview()}
                  className="w-full rounded-md bg-[var(--primary)] px-3 py-2 text-[13px] font-medium text-white transition hover:bg-[var(--primary-hover)] disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {previewLoading ? "Generating..." : "Preview Pack"}
                </button>
                <label className={labelClass}>Framework Name<input value={frameworkName} onChange={(event) => setFrameworkName(event.target.value)} className={inputClass} /></label>
                <label className={labelClass}>Framework ID<input value={frameworkID} onChange={(event) => setFrameworkID(event.target.value)} className={inputClass} /></label>
                <label className={labelClass}>Profile Name<input value={profileName} onChange={(event) => setProfileName(event.target.value)} className={inputClass} /></label>
                <label className={labelClass}>Profile ID<input value={profileID} onChange={(event) => setProfileID(event.target.value)} className={inputClass} /></label>
              </div>
            </Panel>

            <div className="pt-5 lg:pt-24">
              <Panel title="Include Existing Profiles">
                <div className="max-h-96 space-y-2 overflow-y-auto">
                  {options.map((option) => (
                    <button
                      key={option.id}
                      type="button"
                      aria-pressed={profileSet.has(option.id)}
                      onClick={() => toggleProfile(option.id)}
                      className={`w-full rounded-lg border px-3 py-2 text-left transition ${profileSet.has(option.id) ? "border-[color:var(--ring)] bg-indigo-50/70" : "border-[color:var(--border)] bg-white hover:border-[color:var(--border-strong)]"}`}
                    >
                      <div className="text-[12px] font-semibold text-[var(--text-primary)]">{option.label}</div>
                      <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">{option.detail}</div>
                    </button>
                  ))}
                </div>
              </Panel>
            </div>

            {previewError && <ErrorBlock error={previewError} />}
            {auditError && <ErrorBlock error={auditError} />}
          </aside>
        </div>
      )}

      {preview && (
        <CoveragePreview
          auditPacket={auditPacket}
          auditLoading={auditLoading}
          exportLoading={auditExportLoading}
          onBuildAudit={() => void submitAuditPacket()}
          onExportAudit={() => void exportAuditPacket()}
          preview={preview}
          stale={previewIsStale}
        />
      )}
    </div>
  );
}
