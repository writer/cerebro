"use client";

import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCheck,
  FileText,
  GitMerge,
  Link2,
  PanelRightOpen,
  Play,
  Plus,
  RefreshCw,
  Search,
  SearchCheck,
  SlidersHorizontal,
  Upload,
  UserPlus,
  X,
} from "lucide-react";
import Link from "next/link";
import { type FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";

import DataTable, { type TableColumn, WorklistTable } from "@/components/grc/DataTable";
import { GRCUploadErrorActions, GRCUploadFileInput, GRCUploadHistoryList, GRCUploadProgress, GRCUploadReceipt } from "@/components/grc/GRCUpload";
import { AppliedFilterChips, Badge, ErrorBlock, LoadingBlock, PageHeader, Panel, ResultLimitNotice } from "@/components/grc/Primitives";
import { countLabel } from "@/lib/format";
import {
  displayDate,
  GRCUploadReplayResponse,
  GRCUploadResponse,
  GRCVendor,
  GRCVendorActionResponse,
  GRCVendorCreateRequest,
  GRCVendorCreateResponse,
  GRCVendorDetailResponse,
  GRCVendorDiscoveriesResponse,
  GRCVendorDiscovery,
  GRCVendorDiscoverySignal,
  GRCVendorDiscoverySyncResponse,
  GRCVendorDiscoverySourceSummary,
  GRCVendorsResponse,
  humanize,
  shortEntity,
} from "@/lib/grc";
import { grcPath, useDebouncedValue, useGRCFormMutation, useGRCMutation, useGRCQuery } from "@/lib/grc-client";
import { GRC_DETAIL_LIMIT, GRC_WORKLIST_LIMIT } from "@/lib/grc-list";
import { riskBadgeClassFor } from "@/lib/grc-status";
import { grcUploadHistoryKey, grcUploadHistoryWith, readGRCUploadHistory, writeGRCUploadHistory } from "@/lib/grc-upload-history";
import { grcUploadFileError } from "@/lib/grc-upload-limits";
import { useQueryParamState } from "@/lib/query-params";
import { runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";
import {
  boundedVendorDiscoveries,
  boundedVendorRows,
  discoveryNeedsReviewState,
  vendorAssuranceItemCount,
  vendorFirstQueueAction as firstQueueAction,
  vendorFreshnessLabel as freshnessLabel,
  vendorOwnerLabel as ownerLabel,
  vendorPacketDetail as packetDetail,
  vendorReviewDetail as reviewDetail,
  vendorRiskDrivers,
  vendorRiskScoreLabel as riskScoreLabel,
  vendorSourceLabel as sourceLabel,
} from "@/lib/vendors";

const inputClass = "control-input mt-1 w-full px-3 py-1.5 text-[13px]";
const labelClass = "text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]";

const riskFilters = [
  { value: "", label: "All risk" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "unknown", label: "Unknown" },
];

const reviewFilters = [
  { value: "", label: "All reviews" },
  { value: "overdue", label: "Overdue" },
  { value: "due_soon", label: "Due soon" },
  { value: "current", label: "Current" },
  { value: "not_scheduled", label: "Not scheduled" },
];

const ownerFilters = [
  { value: "", label: "All owners" },
  { value: "missing", label: "Missing owner" },
  { value: "assigned", label: "Assigned owner" },
];

const lifecycleFilters = [
  { value: "", label: "All lifecycle" },
  { value: "active", label: "Active" },
  { value: "approved", label: "Approved" },
  { value: "in_review", label: "In review" },
  { value: "conditionally_approved", label: "Conditional" },
  { value: "restricted", label: "Restricted" },
  { value: "offboarding", label: "Offboarding" },
  { value: "retired", label: "Retired" },
  { value: "rejected", label: "Rejected" },
  { value: "ignored", label: "Ignored" },
  { value: "unknown", label: "Unknown" },
];

const queueFilters = [
  { value: "", label: "All vendors" },
  { value: "true", label: "Risk queue" },
  { value: "false", label: "Register only" },
];

type DiscoveryDecision = "approved" | "rejected" | "ignored" | "linked";

type DiscoveryDecisionDraft = {
  reason: string;
  linkedVendorURN: string;
};

type VendorCreateDraft = {
  name: string;
  owner: string;
  category: string;
  websiteURL: string;
  servicesProvided: string;
  riskLevel: string;
  lifecycleState: string;
  reviewState: string;
};

type DuplicateMatch = {
  id: string;
  label: string;
  detail: string;
  reason: string;
  vendorURN?: string;
  discoveryURN?: string;
};

type BulkDiscoveryDraft = {
  owner: string;
  riskLevel: string;
  linkedVendorURN: string;
  reason: string;
};

type VendorQuickActionDraft = {
  owner: string;
  lifecycleState: string;
  reviewState: string;
};

type VendorSection = "register" | "discoveries" | "uploads";

const vendorSections: Array<{ id: VendorSection; label: string }> = [
  { id: "register", label: "Vendor register" },
  { id: "discoveries", label: "Discovery queue" },
  { id: "uploads", label: "Uploads" },
];

const vendorSectionFromParam = (value: string): VendorSection =>
  vendorSections.some((section) => section.id === value) ? value as VendorSection : "register";

const defaultVendorCreateDraft = (): VendorCreateDraft => ({
  name: "",
  owner: "",
  category: "",
  websiteURL: "",
  servicesProvided: "",
  riskLevel: "unknown",
  lifecycleState: "in_review",
  reviewState: "not_scheduled",
});

const defaultBulkDiscoveryDraft = (): BulkDiscoveryDraft => ({
  owner: "",
  riskLevel: "unknown",
  linkedVendorURN: "",
  reason: "",
});

const defaultVendorQuickActionDraft = (): VendorQuickActionDraft => ({
  owner: "",
  lifecycleState: "approved",
  reviewState: "in_progress",
});

const createRiskOptions = riskFilters.filter((item) => item.value);
const createLifecycleOptions = lifecycleFilters.filter((item) =>
  ["active", "approved", "in_review", "conditionally_approved", "restricted"].includes(item.value));
const createReviewOptions = reviewFilters.filter((item) => item.value);
const quickReviewOptions = [
  { value: "in_progress", label: "In progress" },
  ...createReviewOptions,
];

const compactAttributes = (attributes: Record<string, string | undefined>) =>
  Object.fromEntries(Object.entries(attributes).filter(([, value]) => Boolean(value))) as Record<string, string>;

const vendorCreateRequest = (draft: VendorCreateDraft, tenantID: string): GRCVendorCreateRequest => ({
  tenant_id: tenantID.trim() || undefined,
  name: draft.name.trim(),
  source_id: "grc",
  owner: draft.owner.trim() || undefined,
  category: draft.category.trim() || undefined,
  website_url: draft.websiteURL.trim() || undefined,
  services_provided: draft.servicesProvided.trim() || undefined,
  risk_level: draft.riskLevel,
  lifecycle_state: draft.lifecycleState,
  review_state: draft.reviewState,
});

const normalizeMatchText = (value?: string) =>
  (value ?? "").trim().toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();

const compactMatchKey = (value?: string) =>
  normalizeMatchText(value).replace(/\s+/g, "");

const hostForURL = (value?: string) => {
  const trimmed = value?.trim();
  if (!trimmed) return "";
  try {
    const url = new URL(trimmed.includes("://") ? trimmed : "https://" + trimmed);
    return url.hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
};

const websiteLooksValid = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return true;
  try {
    const url = new URL(trimmed.includes("://") ? trimmed : "https://" + trimmed);
    return Boolean(url.hostname) && ["http:", "https:"].includes(url.protocol);
  } catch {
    return false;
  }
};

const uniqueByID = <T extends { id: string }>(items: T[]) =>
  Array.from(new Map(items.map((item) => [item.id, item])).values());

const duplicateMatchesForValues = ({
  currentDiscoveryURN,
  discoveries,
  name,
  normalizedName,
  vendors,
  websiteURL,
}: {
  currentDiscoveryURN?: string;
  discoveries: GRCVendorDiscovery[];
  name?: string;
  normalizedName?: string;
  vendors: GRCVendor[];
  websiteURL?: string;
}): DuplicateMatch[] => {
  const nameKey = compactMatchKey(normalizedName || name);
  const host = hostForURL(websiteURL);
  if (!nameKey && !host) return [];

  const vendorMatches = vendors.flatMap((vendor): DuplicateMatch[] => {
    const vendorNameKey = compactMatchKey(vendor.name);
    const vendorHost = hostForURL(vendor.website_url);
    if (nameKey && vendorNameKey && nameKey === vendorNameKey) {
      return [{
        id: `vendor:${vendor.urn}:name`,
        label: vendor.name || shortEntity(vendor.urn),
        detail: ownerLabel(vendor),
        reason: "Same vendor name",
        vendorURN: vendor.urn,
      }];
    }
    if (host && vendorHost && host === vendorHost) {
      return [{
        id: `vendor:${vendor.urn}:host`,
        label: vendor.name || shortEntity(vendor.urn),
        detail: vendorHost,
        reason: "Same website",
        vendorURN: vendor.urn,
      }];
    }
    return [];
  });

  const discoveryMatches = discoveries.flatMap((discovery): DuplicateMatch[] => {
    if (discovery.urn === currentDiscoveryURN) return [];
    const discoveryNameKey = compactMatchKey(discovery.normalized_name || discovery.name);
    const discoveryHost = hostForURL(discovery.website_url);
    if (nameKey && discoveryNameKey && nameKey === discoveryNameKey) {
      return [{
        id: `discovery:${discovery.urn}:name`,
        label: discovery.name || shortEntity(discovery.urn),
        detail: discovery.provider || discovery.source_id || "Discovery",
        reason: "Same candidate name",
        discoveryURN: discovery.urn,
        vendorURN: discovery.linked_vendor_urn,
      }];
    }
    if (host && discoveryHost && host === discoveryHost) {
      return [{
        id: `discovery:${discovery.urn}:host`,
        label: discovery.name || shortEntity(discovery.urn),
        detail: discoveryHost,
        reason: "Same candidate website",
        discoveryURN: discovery.urn,
        vendorURN: discovery.linked_vendor_urn,
      }];
    }
    return [];
  });

  return uniqueByID([...vendorMatches, ...discoveryMatches]).slice(0, 4);
};

const duplicateMatchesForDiscovery = (
  discovery: GRCVendorDiscovery,
  vendors: GRCVendor[],
  discoveries: GRCVendorDiscovery[],
) =>
  duplicateMatchesForValues({
    currentDiscoveryURN: discovery.urn,
    discoveries,
    name: discovery.name,
    normalizedName: discovery.normalized_name,
    vendors,
    websiteURL: discovery.website_url,
  });

const duplicateMatchesForDraft = (
  draft: VendorCreateDraft,
  vendors: GRCVendor[],
  discoveries: GRCVendorDiscovery[],
) =>
  duplicateMatchesForValues({
    discoveries,
    name: draft.name,
    vendors,
    websiteURL: draft.websiteURL,
  });

const formatSyncLag = (seconds?: number) => {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) return "Lag not reported";
  if (seconds < 60) return `${Math.round(seconds)}s lag`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m lag`;
  return `${Math.round(seconds / 3600)}h lag`;
};

function VendorRiskBadge({ level }: { level?: string }) {
  const normalized = level?.trim().toLowerCase() || "unknown";
  return (
    <span className={`inline-flex rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${riskBadgeClassFor(normalized)}`}>
      {humanize(normalized)}
    </span>
  );
}

function RiskDriverList({ drivers, limit = 4 }: { drivers: string[]; limit?: number }) {
  if (drivers.length === 0) {
    return <span className="text-[12px] text-[var(--text-muted)]">No risk drivers reported</span>;
  }
  const visible = drivers.slice(0, limit);
  return (
    <div className="flex flex-wrap gap-1.5">
      {visible.map((driver) => <Badge key={driver} value={driver} />)}
      {drivers.length > visible.length && (
        <span className="rounded-md bg-[var(--surface-muted)] px-2 py-0.5 text-[11px] font-semibold text-[var(--text-muted)]">
          +{drivers.length - visible.length}
        </span>
      )}
    </div>
  );
}

function DuplicateMatchList({
  matches,
  onOpenVendor,
  onUseMatch,
}: {
  matches: DuplicateMatch[];
  onOpenVendor?: (vendorURN: string) => void;
  onUseMatch?: (vendorURN: string) => void;
}) {
  if (matches.length === 0) return null;
  return (
    <div className="rounded-md border border-amber-500/25 bg-amber-500/10 p-3 text-[12px]">
      <div className="flex items-center gap-2 font-semibold text-amber-800 dark:text-amber-200">
        <GitMerge className="h-3.5 w-3.5" aria-hidden="true" />
        Possible duplicate
      </div>
      <div className="mt-2 space-y-2">
        {matches.map((match) => (
          <div key={match.id} className="flex flex-wrap items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="truncate font-semibold text-[var(--text-primary)]">{match.label}</div>
              <div className="text-[var(--text-muted)]">{match.reason}. {match.detail}</div>
            </div>
            {match.vendorURN && (
              <div className="flex shrink-0 gap-1.5">
                {onUseMatch && (
                  <button type="button" onClick={() => onUseMatch(match.vendorURN!)} className="secondary-button px-2 py-1 text-[12px]">
                    Use match
                  </button>
                )}
                {onOpenVendor && (
                  <button type="button" onClick={() => onOpenVendor(match.vendorURN!)} className="secondary-button px-2 py-1 text-[12px]">
                    Open
                  </button>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

const vendorDetailHref = (vendor: GRCVendor) =>
  `/vendors/${encodeURIComponent(vendor.urn)}`;

function DiscoveryStateBadge({ state }: { state?: string }) {
  const normalized = state?.trim().toLowerCase() || "discovered";
  const tone = normalized === "rejected" || normalized === "ignored"
    ? "bg-[color:var(--surface-muted)] text-[var(--text-muted)]"
    : normalized === "approved" || normalized === "linked"
      ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
      : "bg-amber-500/10 text-amber-700 dark:text-amber-300";
  return <span className={`inline-flex rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${tone}`}>{humanize(normalized)}</span>;
}

const confidenceLabel = (score?: number) =>
  typeof score === "number" && Number.isFinite(score) ? `${Math.round(score)}%` : "No score";

const discoverySourceIDs = (discovery: GRCVendorDiscovery) =>
  Array.from(new Set([
    discovery.source_id,
    ...(discovery.source_ids ?? []),
    ...(discovery.signals ?? []).map((signal) => signal.source_id),
  ].filter((value): value is string => Boolean(value))));

const discoverySourceLabel = (source: Pick<GRCVendorDiscoverySourceSummary, "provider" | "source_id">) =>
  source.provider || humanize(source.source_id);

function SourceStat({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{label}</div>
      <div className="mt-1 text-[13px] font-semibold text-[var(--text-primary)]">{value.toLocaleString()}</div>
    </div>
  );
}

function latestSourceSync(sources: GRCVendorDiscoverySourceSummary[]) {
  const latest = sources.reduce<string | undefined>((current, source) => {
    if (!source.last_synced_at) return current;
    if (!current) return source.last_synced_at;
    return Date.parse(source.last_synced_at) > Date.parse(current) ? source.last_synced_at : current;
  }, undefined);
  return latest ? displayDate(latest) : "not recorded";
}

function DiscoverySignals({ signals }: { signals?: GRCVendorDiscoverySignal[] }) {
  const visibleSignals = signals?.slice(0, 3) ?? [];
  if (visibleSignals.length === 0) {
    return <span className="text-[var(--text-muted)]">No source signals</span>;
  }
  return (
    <div className="space-y-2">
      {visibleSignals.map((signal) => (
        <div key={signal.id} className="text-[12px]">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-semibold text-[var(--text-primary)]">{signal.label}</span>
            {signal.source_id && <Badge value={signal.source_id} />}
            {typeof signal.confidence_score === "number" && (
              <span className="text-[var(--text-muted)]">{confidenceLabel(signal.confidence_score)}</span>
            )}
          </div>
          <div className="mt-1 text-[var(--text-muted)]">
            {signal.reason || humanize(signal.entity_type)}
          </div>
          {signal.entity_urn && <div className="mt-1 font-mono text-[var(--text-muted)]">{shortEntity(signal.entity_urn)}</div>}
        </div>
      ))}
      {(signals?.length ?? 0) > visibleSignals.length && (
        <div className="text-[12px] text-[var(--text-muted)]">
          +{(signals?.length ?? 0) - visibleSignals.length} more signals
        </div>
      )}
    </div>
  );
}

function DiscoverySourceSummary({
  loading,
  onRefresh,
  onRunSource,
  onSelectSource,
  runSaving,
  selectedSourceID,
  sources,
  summary,
}: {
  loading: boolean;
  onRefresh: () => void;
  onRunSource: (sourceID?: string) => void;
  onSelectSource: (sourceID: string) => void;
  runSaving: boolean;
  selectedSourceID: string;
  sources: GRCVendorDiscoverySourceSummary[];
  summary?: GRCVendorDiscoveriesResponse["summary"];
}) {
  const pending = summary?.discovered ?? 0;
  const linked = summary?.linked ?? 0;
  const sourceCount = summary?.source_count ?? sources.length;
  const signals = summary?.evidence_signals ?? sources.reduce((sum, source) => sum + source.total, 0);
  const sourcesWithIssues = sources.filter((source) => (source.failed ?? 0) > 0 || (source.stale ?? 0) > 0 || source.status === "needs_refresh").length;
  const latestSync = latestSourceSync(sources);
  return (
    <section className="surface-panel px-5 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] text-[var(--text-secondary)]">
            <SearchCheck className="h-4 w-4" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">Source coverage</h2>
            <p className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">
              {loading ? "Loading source candidates." : `${countLabel(sourceCount, "source")} checked. ${countLabel(pending, "candidate")} need review, ${linked} linked, ${countLabel(signals, "source signal")}, ${sourcesWithIssues} sources need attention. Last sync ${latestSync}.`}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => onRunSource()} disabled={runSaving} className="primary-button inline-flex items-center gap-2 px-3 py-1.5 text-[13px] disabled:opacity-50">
            <Play className="h-3.5 w-3.5" aria-hidden="true" />
            Run discovery
          </button>
          <button type="button" onClick={onRefresh} disabled={loading} className="secondary-button inline-flex items-center gap-2 px-3 py-1.5 text-[13px] disabled:opacity-50">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>
      {sources.length > 0 && (
        <div className="mt-4 grid gap-3 lg:grid-cols-3">
          {sources.map((source) => {
            const selected = selectedSourceID === source.source_id;
            return (
              <div
                key={source.source_id}
                className={`rounded-md border px-3 py-3 transition ${selected ? "border-[color:var(--primary)] bg-[var(--surface-muted)]" : "border-[color:var(--border)] bg-[var(--surface-raised)]"}`}
              >
                <div className="flex items-start justify-between gap-3">
                  <button
                    type="button"
                    onClick={() => onSelectSource(selected ? "" : source.source_id)}
                    className={`min-w-0 text-left ${selected ? "text-[var(--primary)]" : "text-[var(--text-primary)] hover:text-[var(--primary)]"}`}
                    aria-pressed={selected}
                  >
                    <span className="block truncate text-[13px] font-semibold">{discoverySourceLabel(source)}</span>
                    <span className="mt-1 block truncate font-mono text-[12px] text-[var(--text-muted)]">{source.runtime_id || source.source_id}</span>
                  </button>
                  <Badge value={source.status || "unknown"} />
                </div>
                <div className="mt-3 grid grid-cols-3 gap-2 text-[12px]">
                  <SourceStat label="Candidates" value={source.total} />
                  <SourceStat label="Needs review" value={source.discovered} />
                  <SourceStat label="Issues" value={(source.failed ?? 0) + (source.stale ?? 0) + (source.cursor_pending ?? 0)} />
                </div>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  <Badge value={source.freshness || "freshness_unknown"} />
                  {source.cursor_pending ? <Badge value="cursor pending" /> : null}
                  {source.last_error ? <Badge value="sync error" /> : null}
                </div>
                <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-[color:var(--border)] pt-3 text-[12px] text-[var(--text-muted)]">
                  <span>Last sync {displayDate(source.last_synced_at)}. {formatSyncLag(source.sync_lag_seconds)}</span>
                  <div className="flex gap-2">
                    <button type="button" onClick={() => onSelectSource(selected ? "" : source.source_id)} className="font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">
                      {selected ? "Clear filter" : "Filter"}
                    </button>
                    <button type="button" onClick={() => onRunSource(source.source_id)} disabled={runSaving} className="font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)] disabled:opacity-50">
                      Run
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
      {sources.length === 0 && !loading && (
        <div className="mt-4 rounded-md border border-dashed border-[color:var(--border)] px-4 py-5 text-[13px] text-[var(--text-muted)]">
          No discovery sources reported status.
        </div>
      )}
    </section>
  );
}

function CreateVendorModal({
  duplicateMatches,
  draft,
  error,
  onClose,
  onOpenVendor,
  onSubmit,
  onUpdateDraft,
  open,
  saving,
}: {
  duplicateMatches: DuplicateMatch[];
  draft: VendorCreateDraft;
  error: string | null;
  onClose: () => void;
  onOpenVendor: (vendorURN: string) => void;
  onSubmit: (draft: VendorCreateDraft) => Promise<void> | void;
  onUpdateDraft: (patch: Partial<VendorCreateDraft>) => void;
  open: boolean;
  saving: boolean;
}) {
  if (!open) return null;
  const nameMissing = draft.name.trim() === "";
  const websiteInvalid = !websiteLooksValid(draft.websiteURL);
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (nameMissing || websiteInvalid || saving) return;
    void Promise.resolve(onSubmit(draft)).catch(() => undefined);
  };
  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-stone-950/45 px-4 py-10 backdrop-blur-sm">
      <form onSubmit={submit} role="dialog" aria-modal="true" aria-labelledby="add-vendor-title" className="surface-raised mx-auto w-full max-w-2xl overflow-hidden rounded-lg border border-[color:var(--border)] shadow-2xl">
        <div className="flex items-center justify-between gap-3 border-b border-[color:var(--border)] px-5 py-4">
          <div>
            <h2 id="add-vendor-title" className="text-[15px] font-semibold text-[var(--text-primary)]">Add vendor</h2>
            <p className="mt-1 text-[12px] text-[var(--text-muted)]">Create a vendor record for review and owner tracking.</p>
          </div>
          <button type="button" onClick={onClose} className="secondary-button inline-flex h-8 w-8 items-center justify-center p-0" aria-label="Close add vendor">
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
        <div className="space-y-4 px-5 py-4">
          {error && <ErrorBlock error={error} recoveryDetail="Vendor was not saved." />}
          <DuplicateMatchList
            matches={duplicateMatches}
            onOpenVendor={(vendorURN) => {
              onClose();
              onOpenVendor(vendorURN);
            }}
          />
          <div className="grid gap-3 sm:grid-cols-2">
            <label className={`${labelClass} sm:col-span-2`}>
              Vendor name
              <input
                value={draft.name}
                onChange={(event) => onUpdateDraft({ name: event.target.value })}
                className={inputClass}
                required
                autoFocus
              />
            </label>
            <label className={labelClass}>
              Owner
              <input
                value={draft.owner}
                onChange={(event) => onUpdateDraft({ owner: event.target.value })}
                placeholder="Security"
                className={inputClass}
              />
            </label>
            <label className={labelClass}>
              Category
              <input
                value={draft.category}
                onChange={(event) => onUpdateDraft({ category: event.target.value })}
                placeholder="Identity"
                className={inputClass}
              />
            </label>
            <label className={`${labelClass} sm:col-span-2`}>
              Website
              <input
                value={draft.websiteURL}
                onChange={(event) => onUpdateDraft({ websiteURL: event.target.value })}
                placeholder="Enter vendor website"
                className={`${inputClass} ${websiteInvalid ? "border-red-400" : ""}`}
                aria-invalid={websiteInvalid}
              />
              {websiteInvalid && <span className="mt-1 block text-[12px] normal-case tracking-normal text-red-700 dark:text-red-300">Enter a valid website.</span>}
            </label>
            <label className={`${labelClass} sm:col-span-2`}>
              Services provided
              <textarea
                value={draft.servicesProvided}
                onChange={(event) => onUpdateDraft({ servicesProvided: event.target.value })}
                rows={3}
                className={inputClass}
              />
            </label>
            <label className={labelClass}>
              Risk
              <select value={draft.riskLevel} onChange={(event) => onUpdateDraft({ riskLevel: event.target.value })} className={inputClass}>
                {createRiskOptions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
              </select>
            </label>
            <label className={labelClass}>
              Lifecycle
              <select value={draft.lifecycleState} onChange={(event) => onUpdateDraft({ lifecycleState: event.target.value })} className={inputClass}>
                {createLifecycleOptions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
              </select>
            </label>
            <label className={labelClass}>
              Review
              <select value={draft.reviewState} onChange={(event) => onUpdateDraft({ reviewState: event.target.value })} className={inputClass}>
                {createReviewOptions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
              </select>
            </label>
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[color:var(--border)] px-5 py-4">
          <button type="button" onClick={onClose} className="secondary-button px-3 py-1.5 text-[13px]">Cancel</button>
          <button type="submit" disabled={nameMissing || websiteInvalid || saving} className="primary-button inline-flex items-center gap-2 px-3 py-1.5 text-[13px] disabled:opacity-50">
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            Add vendor
          </button>
        </div>
      </form>
    </div>
  );
}

const selectLabel = (options: Array<{ value: string; label: string }>, value: string) =>
  options.find((item) => item.value === value)?.label ?? value;

const discoveryNeedsReview = (discovery: GRCVendorDiscovery) =>
  discoveryNeedsReviewState(discovery);

const discoveryHandledLabel = (discovery: GRCVendorDiscovery) => {
  const state = (discovery.decision_state || "").toLowerCase();
  if (state === "approved") return "Vendor saved";
  if (state === "linked") return "Vendor linked";
  if (state === "ignored") return "Discovery dismissed";
  if (state === "rejected") return "Discovery rejected";
  return "Decision recorded";
};

function HealthStat({
  detail,
  intent = "neutral",
  label,
  pendingDetail = "Waiting for vendor data",
  state,
  value,
}: {
  detail: string;
  intent?: "danger" | "neutral" | "success" | "warning";
  label: string;
  pendingDetail?: string;
  state: RuntimeState;
  value: number | string;
}) {
  const accents = {
    danger: "border-l-red-500",
    neutral: "border-l-[color:var(--border-strong)]",
    success: "border-l-emerald-500",
    warning: "border-l-amber-500",
  };
  const formattedValue = typeof value === "number" ? value.toLocaleString() : value;
  const displayValue = state === "loading" ? "..." : state === "ready" || state === "empty" ? formattedValue : "Unavailable";
  const displayDetail = state === "ready" || state === "empty" ? detail : pendingDetail;
  const accentIntent = state === "ready" ? intent : "neutral";
  return (
    <div className={`border-l-[3px] ${accents[accentIntent]} px-4 py-3`}>
      <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{label}</div>
      <div className="mt-2 text-xl font-semibold text-[var(--text-primary)]">{displayValue}</div>
      <div className="mt-1 text-[12px] text-[var(--text-muted)]">{displayDetail}</div>
    </div>
  );
}

function VendorHealthStrip({
  discoveries,
  discoveriesLoaded,
  discoveryMetricState,
  discoverySummary,
  summary,
  vendorMetricState,
  vendors,
}: {
  discoveries: GRCVendorDiscovery[];
  discoveriesLoaded: boolean;
  discoveryMetricState: RuntimeState;
  discoverySummary?: GRCVendorDiscoveriesResponse["summary"];
  summary?: GRCVendorsResponse["summary"];
  vendorMetricState: RuntimeState;
  vendors: GRCVendor[];
}) {
  const vendorCount = summary?.total_vendors ?? vendors.length;
  const activeCount = summary?.active_vendors ?? vendors.filter((vendor) => vendor.status === "active").length;
  const needsReview = discoverySummary?.discovered ?? discoveries.filter(discoveryNeedsReview).length;
  const missingOwner = summary?.owner_missing_vendors ?? vendors.filter((vendor) => vendor.owner_state === "missing").length;
  const highRisk = summary?.high_risk_vendors ?? vendors.filter((vendor) => ["critical", "high"].includes(vendor.risk_level)).length;
  const reviewValue = discoveriesLoaded ? needsReview : "Open queue";
  const reviewDetailCopy = discoveriesLoaded ? "discovery candidates" : "Load candidates when triaging discoveries";

  return (
    <section className="surface-panel grid overflow-hidden sm:grid-cols-2 xl:grid-cols-4">
      <HealthStat label="Vendors" value={vendorCount} detail={`${activeCount.toLocaleString()} active`} state={vendorMetricState} intent="success" />
      <HealthStat label="Needs review" value={reviewValue} detail={reviewDetailCopy} state={discoveryMetricState} intent={needsReview > 0 ? "warning" : "success"} pendingDetail="Waiting for discovery data" />
      <HealthStat label="Missing owner" value={missingOwner} detail={missingOwner === 1 ? "vendor without an owner" : "vendors without an owner"} state={vendorMetricState} intent={missingOwner > 0 ? "warning" : "success"} />
      <HealthStat label="High risk" value={highRisk} detail="critical or high vendors" state={vendorMetricState} intent={highRisk > 0 ? "danger" : "success"} />
    </section>
  );
}

function DiscoveryActionButtons({
  createSaving,
  discovery,
  draft,
  onCreateVendor,
  onDecision,
  saving,
}: {
  createSaving: boolean;
  discovery: GRCVendorDiscovery;
  draft: DiscoveryDecisionDraft;
  onCreateVendor: (discovery: GRCVendorDiscovery) => Promise<void> | void;
  onDecision: (discovery: GRCVendorDiscovery, decision: DiscoveryDecision) => Promise<void> | void;
  saving: boolean;
}) {
  if (!discoveryNeedsReview(discovery)) {
    return <div className="text-[12px] font-semibold text-[var(--text-muted)]">{discoveryHandledLabel(discovery)}</div>;
  }
  const busy = saving || createSaving;
  const linkDisabled = busy || draft.linkedVendorURN.trim() === "";
  const commitDecision = (decision: DiscoveryDecision) => {
    void Promise.resolve(onDecision(discovery, decision)).catch(() => undefined);
  };
  const createVendor = () => {
    void Promise.resolve(onCreateVendor(discovery)).catch(() => undefined);
  };
  return (
    <div className="flex flex-wrap gap-1.5">
      <button
        type="button"
        disabled={linkDisabled}
        onClick={() => commitDecision("linked")}
        className="secondary-button inline-flex items-center gap-1.5 px-2.5 py-1 text-[12px] disabled:opacity-50"
      >
        <Link2 className="h-3.5 w-3.5" aria-hidden="true" />
        Link
      </button>
      <button
        type="button"
        disabled={busy}
        onClick={createVendor}
        className="primary-button inline-flex items-center gap-1.5 px-2.5 py-1 text-[12px] disabled:opacity-50"
      >
        <Plus className="h-3.5 w-3.5" aria-hidden="true" />
        Create vendor
      </button>
      <button
        type="button"
        disabled={busy}
        onClick={() => commitDecision("ignored")}
        className="secondary-button inline-flex items-center gap-1.5 px-2.5 py-1 text-[12px] disabled:opacity-50"
      >
        <X className="h-3.5 w-3.5" aria-hidden="true" />
        Dismiss
      </button>
    </div>
  );
}

function DiscoveryCandidateTitle({ discovery, duplicateMatches }: { discovery: GRCVendorDiscovery; duplicateMatches: DuplicateMatch[] }) {
  return (
    <div className="min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <div className="font-semibold text-[var(--text-primary)]">{discovery.name || shortEntity(discovery.urn)}</div>
        {duplicateMatches.length > 0 && (
          <span className="inline-flex items-center gap-1 rounded-md bg-amber-500/10 px-2 py-0.5 text-[11px] font-semibold text-amber-700 dark:text-amber-300">
            <GitMerge className="h-3 w-3" aria-hidden="true" />
            Possible duplicate
          </span>
        )}
        {typeof discovery.confidence_score === "number" && (
          <span className="rounded-md bg-[var(--surface-muted)] px-2 py-0.5 text-[11px] font-semibold text-[var(--text-secondary)]">
            {confidenceLabel(discovery.confidence_score)}
          </span>
        )}
      </div>
      <div className="mt-1 text-[12px] text-[var(--text-muted)]">{discovery.normalized_name || discovery.discovery_id || shortEntity(discovery.urn)}</div>
      {discovery.discovery_reason && <div className="mt-1 max-w-[24rem] text-[12px] leading-5 text-[var(--text-secondary)]">{discovery.discovery_reason}</div>}
      <div className="mt-2 flex flex-wrap gap-1.5">
        {discovery.category && <Badge value={discovery.category} />}
        <Badge value={discovery.source_status || "discovered"} />
      </div>
    </div>
  );
}

function DiscoverySourceCell({ discovery }: { discovery: GRCVendorDiscovery }) {
  return (
    <div className="text-[12px] text-[var(--text-muted)]">
      <div className="font-semibold text-[var(--text-primary)]">{discovery.provider || discovery.source_id || "Source not set"}</div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {discoverySourceIDs(discovery).map((id) => <Badge key={id} value={id} />)}
      </div>
      <div className="mt-1 font-mono">{shortEntity(discovery.runtime_id)}</div>
      <div className="mt-2 text-[var(--text-muted)]">
        <div>First seen {displayDate(discovery.first_observed_at)}</div>
        <div>Last seen {displayDate(discovery.last_observed_at)}</div>
      </div>
    </div>
  );
}

function SuggestedVendorInputs({
  discovery,
  duplicateMatches,
  draft,
  onOpenVendor,
  onUpdateDraft,
}: {
  discovery: GRCVendorDiscovery;
  duplicateMatches: DuplicateMatch[];
  draft: DiscoveryDecisionDraft;
  onOpenVendor: (vendorURN: string) => void;
  onUpdateDraft: (urn: string, patch: Partial<DiscoveryDecisionDraft>) => void;
}) {
  return (
    <div className="grid gap-2">
      <DuplicateMatchList
        matches={duplicateMatches}
        onOpenVendor={onOpenVendor}
        onUseMatch={(vendorURN) => onUpdateDraft(discovery.urn, { linkedVendorURN: vendorURN })}
      />
      {discovery.linked_vendor_urn ? (
        <Link href={`/vendors/${encodeURIComponent(discovery.linked_vendor_urn)}`} className="font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">
          {shortEntity(discovery.linked_vendor_urn)}
        </Link>
      ) : (
        <span className="text-[12px] text-[var(--text-muted)]">No linked vendor</span>
      )}
      <input
        value={draft.linkedVendorURN}
        onChange={(event) => onUpdateDraft(discovery.urn, { linkedVendorURN: event.target.value })}
        placeholder="Search or paste vendor ID"
        className="control-input px-2 py-1 font-mono text-[12px]"
      />
      <input
        value={draft.reason}
        onChange={(event) => onUpdateDraft(discovery.urn, { reason: event.target.value })}
        placeholder="Decision note"
        className="control-input px-2 py-1 text-[12px]"
      />
    </div>
  );
}

function DiscoveryEmptyState({
  latestSync,
  onRefresh,
  sourceCount,
}: {
  latestSync: string;
  onRefresh: () => void;
  sourceCount: number;
}) {
  return (
    <div className="px-5 py-10 text-center">
      <h3 className="text-[14px] font-semibold text-[var(--text-primary)]">No candidates need review</h3>
      <p className="mx-auto mt-2 max-w-xl text-[13px] leading-5 text-[var(--text-muted)]">
        {countLabel(sourceCount, "source")} checked. Last sync {latestSync}.
      </p>
      <button type="button" onClick={onRefresh} className="secondary-button mt-4 inline-flex items-center gap-2 px-3 py-1.5 text-[13px]">
        <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
        Refresh sources
      </button>
    </div>
  );
}

function DiscoveryQueue({
  bulkDraft,
  bulkSaving,
  createSaving,
  decisionDrafts,
  decisionSaving,
  discoveries,
  duplicateMatchesByURN,
  latestSync,
  onBulkAction,
  onBulkDraftChange,
  onClearSelection,
  onCreateVendor,
  onDecision,
  onOpenVendor,
  onRefresh,
  onToggleDiscovery,
  onToggleVisible,
  onUpdateDraft,
  selectedDiscoveryURNs,
  sourceCount,
}: {
  bulkDraft: BulkDiscoveryDraft;
  bulkSaving: boolean;
  createSaving: boolean;
  decisionDrafts: Record<string, DiscoveryDecisionDraft>;
  decisionSaving: boolean;
  discoveries: GRCVendorDiscovery[];
  duplicateMatchesByURN: Record<string, DuplicateMatch[]>;
  latestSync: string;
  onBulkAction: (action: "create" | "dismiss" | "link") => Promise<void> | void;
  onBulkDraftChange: (patch: Partial<BulkDiscoveryDraft>) => void;
  onClearSelection: () => void;
  onCreateVendor: (discovery: GRCVendorDiscovery) => Promise<void> | void;
  onDecision: (discovery: GRCVendorDiscovery, decision: DiscoveryDecision) => Promise<void> | void;
  onOpenVendor: (vendorURN: string) => void;
  onRefresh: () => void;
  onToggleDiscovery: (urn: string) => void;
  onToggleVisible: () => void;
  onUpdateDraft: (urn: string, patch: Partial<DiscoveryDecisionDraft>) => void;
  selectedDiscoveryURNs: Set<string>;
  sourceCount: number;
}) {
  const signalCount = discoveries.reduce((sum, discovery) => sum + (discovery.signals?.length ?? 0), 0);
  const reviewableDiscoveries = discoveries.filter(discoveryNeedsReview);
  const allVisibleSelected = reviewableDiscoveries.length > 0 && reviewableDiscoveries.every((discovery) => selectedDiscoveryURNs.has(discovery.urn));
  const selectedCount = reviewableDiscoveries.filter((discovery) => selectedDiscoveryURNs.has(discovery.urn)).length;
  const busy = bulkSaving || decisionSaving || createSaving;
  const discoveryColumns = useMemo<TableColumn<GRCVendorDiscovery>[]>(() => [
    {
      key: "selected",
      label: "",
      render: (_value, discovery) => discoveryNeedsReview(discovery) ? (
        <input
          type="checkbox"
          checked={selectedDiscoveryURNs.has(discovery.urn)}
          onClick={(event) => event.stopPropagation()}
          onChange={() => onToggleDiscovery(discovery.urn)}
          className="h-4 w-4"
          aria-label={`Select ${discovery.name || discovery.urn}`}
        />
      ) : null,
    },
    {
      key: "candidate",
      label: "Candidate",
      render: (_value, discovery) => (
        <div className="min-w-[17rem]">
          <DiscoveryCandidateTitle discovery={discovery} duplicateMatches={duplicateMatchesByURN[discovery.urn] ?? []} />
          <div className="mt-3 rounded-md bg-[var(--surface-muted)] p-2">
            <DiscoverySourceCell discovery={discovery} />
          </div>
        </div>
      ),
    },
    {
      key: "signals",
      label: "Evidence",
      render: (_value, discovery) => (
        <div className="min-w-[18rem] text-[12px] text-[var(--text-secondary)]">
          <DiscoverySignals signals={discovery.signals} />
        </div>
      ),
    },
    {
      key: "suggested_vendor",
      label: "Suggested vendor",
      render: (_value, discovery) => {
        const draft = decisionDrafts[discovery.urn] ?? { reason: "", linkedVendorURN: "" };
        return (
          <div className="min-w-[16rem]">
            <SuggestedVendorInputs
              discovery={discovery}
              duplicateMatches={duplicateMatchesByURN[discovery.urn] ?? []}
              draft={draft}
              onOpenVendor={onOpenVendor}
              onUpdateDraft={onUpdateDraft}
            />
          </div>
        );
      },
    },
    {
      key: "decision_state",
      label: "State",
      render: (_value, discovery) => (
        <div className="min-w-[9rem]">
          <DiscoveryStateBadge state={discovery.decision_state} />
          <div className="mt-2 text-[12px] text-[var(--text-muted)]">Confidence {confidenceLabel(discovery.confidence_score)}</div>
          {discovery.decision_updated_by && <div className="mt-1 text-[12px] text-[var(--text-muted)]">{discovery.decision_updated_by}</div>}
        </div>
      ),
    },
  ], [decisionDrafts, duplicateMatchesByURN, onOpenVendor, onToggleDiscovery, onUpdateDraft, selectedDiscoveryURNs]);
  return (
    <section className="surface-panel overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[color:var(--border)] px-5 py-3">
        <div>
          <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">Discovery queue</h2>
          <p className="mt-1 text-[12px] text-[var(--text-muted)]">
            {countLabel(discoveries.length, "candidate")} in this view. {countLabel(signalCount, "source signal")}.
          </p>
        </div>
        {reviewableDiscoveries.length > 0 && (
          <label className="inline-flex items-center gap-2 text-[12px] font-semibold text-[var(--text-secondary)]">
            <input type="checkbox" checked={allVisibleSelected} onChange={onToggleVisible} className="h-4 w-4" />
            Select visible
          </label>
        )}
      </div>
      {selectedCount > 0 && (
        <div className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] px-5 py-3">
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[8rem]">
              <div className={labelClass}>{selectedCount} selected</div>
              <button type="button" onClick={onClearSelection} className="mt-1 text-[12px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">
                Clear selection
              </button>
            </div>
            <label className={`${labelClass} min-w-[10rem] flex-1`}>
              Owner for new vendors
              <input value={bulkDraft.owner} onChange={(event) => onBulkDraftChange({ owner: event.target.value })} placeholder="Security" className={inputClass} />
            </label>
            <label className={`${labelClass} min-w-[9rem]`}>
              Risk for new vendors
              <select value={bulkDraft.riskLevel} onChange={(event) => onBulkDraftChange({ riskLevel: event.target.value })} className={inputClass}>
                {createRiskOptions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
              </select>
            </label>
            <label className={`${labelClass} min-w-[14rem] flex-1`}>
              Link selected to vendor
              <input value={bulkDraft.linkedVendorURN} onChange={(event) => onBulkDraftChange({ linkedVendorURN: event.target.value })} placeholder="Search or paste vendor ID" className={`${inputClass} font-mono`} />
            </label>
            <label className={`${labelClass} min-w-[12rem] flex-1`}>
              Decision note
              <input value={bulkDraft.reason} onChange={(event) => onBulkDraftChange({ reason: event.target.value })} placeholder="Reason for this decision" className={inputClass} />
            </label>
            <div className="flex flex-wrap gap-2">
              <button type="button" disabled={busy} onClick={() => { void Promise.resolve(onBulkAction("create")).catch(() => undefined); }} className="primary-button px-3 py-1.5 text-[13px] disabled:opacity-50">
                Create vendors
              </button>
              <button type="button" disabled={busy || !bulkDraft.linkedVendorURN.trim()} onClick={() => { void Promise.resolve(onBulkAction("link")).catch(() => undefined); }} className="secondary-button px-3 py-1.5 text-[13px] disabled:opacity-50">
                Link selected
              </button>
              <button type="button" disabled={busy} onClick={() => { void Promise.resolve(onBulkAction("dismiss")).catch(() => undefined); }} className="secondary-button px-3 py-1.5 text-[13px] disabled:opacity-50">
                Dismiss selected
              </button>
            </div>
          </div>
        </div>
      )}
      {discoveries.length === 0 ? (
        <DiscoveryEmptyState sourceCount={sourceCount} latestSync={latestSync} onRefresh={onRefresh} />
      ) : (
        <div className="p-4">
          <DataTable
            rows={discoveries}
            columns={discoveryColumns}
            emptyMessage="No vendor candidates match these filters."
            searchPlaceholder="Filter loaded candidates"
            filterKeys={["urn", "name", "provider", "source_id", "decision_state", "signals", "website_url", "discovery_reason"]}
            pageSize={10}
            resultLimit={GRC_DETAIL_LIMIT}
            resultNoun="discoveries"
            getRowKey={(discovery) => discovery.urn}
            tableContainerClassName="max-h-[36rem] overflow-auto"
            rowActions={(discovery) => {
              const draft = decisionDrafts[discovery.urn] ?? { reason: "", linkedVendorURN: "" };
              return (
                <div className="min-w-[13rem]">
                  <DiscoveryActionButtons createSaving={createSaving} discovery={discovery} draft={draft} onCreateVendor={onCreateVendor} onDecision={onDecision} saving={decisionSaving} />
                </div>
              );
            }}
          />
        </div>
      )}
    </section>
  );
}

function DuplicateQueue({
  decisionSaving,
  discoveries,
  duplicateMatchesByURN,
  onDecision,
  onOpenVendor,
}: {
  decisionSaving: boolean;
  discoveries: GRCVendorDiscovery[];
  duplicateMatchesByURN: Record<string, DuplicateMatch[]>;
  onDecision: (discovery: GRCVendorDiscovery, decision: DiscoveryDecision, draft?: DiscoveryDecisionDraft) => Promise<void> | void;
  onOpenVendor: (vendorURN: string) => void;
}) {
  const duplicateRows = discoveries
    .filter(discoveryNeedsReview)
    .map((discovery) => ({
      discovery,
      matches: duplicateMatchesByURN[discovery.urn] ?? [],
    }))
    .filter((row) => row.matches.length > 0)
    .slice(0, 6);

  if (duplicateRows.length === 0) return null;

  return (
    <section className="surface-panel overflow-hidden">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[color:var(--border)] px-5 py-3">
        <div>
          <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">Possible duplicates</h2>
          <p className="mt-1 text-[12px] text-[var(--text-muted)]">
            {countLabel(duplicateRows.length, "candidate")} match a vendor or another discovery.
          </p>
        </div>
        <GitMerge className="h-4 w-4 text-[var(--text-muted)]" aria-hidden="true" />
      </div>
      <div className="divide-y divide-[color:var(--border)]">
        {duplicateRows.map(({ discovery, matches }) => {
          const firstVendorMatch = matches.find((match) => match.vendorURN);
          return (
            <div key={discovery.urn} className="grid gap-3 px-5 py-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
              <div className="min-w-0">
                <div className="font-semibold text-[var(--text-primary)]">{discovery.name || shortEntity(discovery.urn)}</div>
                <div className="mt-1 text-[12px] text-[var(--text-muted)]">{discovery.provider || discovery.source_id || "Source not set"} · Confidence {confidenceLabel(discovery.confidence_score)}</div>
              </div>
              <div className="space-y-2">
                {matches.slice(0, 2).map((match) => (
                  <div key={match.id} className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px]">
                    <div className="font-semibold text-[var(--text-primary)]">{match.label}</div>
                    <div className="text-[var(--text-muted)]">{match.reason}. {match.detail}</div>
                  </div>
                ))}
              </div>
              <div className="flex flex-wrap items-start gap-2 lg:justify-end">
                {firstVendorMatch?.vendorURN && (
                  <>
                    <button type="button" onClick={() => onOpenVendor(firstVendorMatch.vendorURN!)} className="secondary-button px-3 py-1.5 text-[12px]">
                      Open match
                    </button>
                    <button
                      type="button"
                      disabled={decisionSaving}
                      onClick={() => {
                        void Promise.resolve(onDecision(discovery, "linked", {
                          linkedVendorURN: firstVendorMatch.vendorURN!,
                          reason: "Linked from duplicate review.",
                        })).catch(() => undefined);
                      }}
                      className="primary-button px-3 py-1.5 text-[12px] disabled:opacity-50"
                    >
                      Link match
                    </button>
                  </>
                )}
                <button
                  type="button"
                  disabled={decisionSaving}
                  onClick={() => {
                    void Promise.resolve(onDecision(discovery, "ignored", {
                      linkedVendorURN: "",
                      reason: "Dismissed from duplicate review.",
                    })).catch(() => undefined);
                  }}
                  className="secondary-button px-3 py-1.5 text-[12px] disabled:opacity-50"
                >
                  Dismiss
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function VendorRegisterSection({
  assuranceItems,
  meta,
  onOpenVendor,
  vendors,
}: {
  assuranceItems: number;
  meta?: GRCVendorsResponse["meta"];
  onOpenVendor: (vendorURN: string) => void;
  vendors: GRCVendor[];
}) {
  const vendorColumns = useMemo<TableColumn<GRCVendor>[]>(() => [
    {
      key: "name",
      label: "Vendor",
      render: (_value, vendor) => (
        <div className="min-w-[16rem]">
          <button type="button" onClick={() => onOpenVendor(vendor.urn)} className="block max-w-[20rem] truncate text-left text-[13px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">
            {vendor.name || shortEntity(vendor.urn)}
          </button>
          <div className="mt-1 max-w-[22rem] truncate text-[12px] text-[var(--text-muted)]">
            {[vendor.services_provided || (vendor.category ? humanize(vendor.category) : ""), sourceLabel(vendor)].filter(Boolean).join(" | ")}
          </div>
        </div>
      ),
    },
    {
      key: "lifecycle_state",
      label: "Status",
      render: (_value, vendor) => {
        const action = firstQueueAction(vendor);
        const drivers = vendorRiskDrivers(vendor);
        return (
          <div className="min-w-[10rem]">
            <Badge value={vendor.lifecycle_state || vendor.status || "unknown"} />
            <div className="mt-1 text-[12px] text-[var(--text-muted)]">{action?.label || drivers[0] || "No queued action"}</div>
          </div>
        );
      },
    },
    {
      key: "risk_level",
      label: "Risk",
      render: (_value, vendor) => (
        <div className="min-w-[8rem]">
          <VendorRiskBadge level={vendor.risk_score_level || vendor.risk_level} />
          <div className="mt-1 text-[12px] text-[var(--text-muted)]">{riskScoreLabel(vendor)}</div>
        </div>
      ),
    },
    {
      key: "owner",
      label: "Owner",
      render: (_value, vendor) => (
        <div className="min-w-[10rem]">
          <div className="max-w-[12rem] truncate text-[13px] font-medium text-[var(--text-primary)]">{ownerLabel(vendor)}</div>
          <div className="mt-1 text-[12px] text-[var(--text-muted)]">{vendor.owner_state === "missing" ? "Missing owner" : "Assigned"}</div>
        </div>
      ),
    },
    {
      key: "review_state",
      label: "Review",
      render: (_value, vendor) => (
        <div className="min-w-[10rem]">
          <Badge value={vendor.review_state} />
          <div className="mt-1 text-[12px] text-[var(--text-muted)]">{reviewDetail(vendor)}</div>
        </div>
      ),
    },
    {
      key: "evidence",
      label: "Evidence",
      render: (_value, vendor) => (
        <div className="min-w-[11rem] text-[12px] text-[var(--text-muted)]">
          <div className="font-medium text-[var(--text-secondary)]">{freshnessLabel(vendor)}</div>
          <div className="mt-1">{packetDetail(vendor)}</div>
          <div className="mt-1">{vendor.evidence_items ?? 0} evidence items</div>
        </div>
      ),
    },
    {
      key: "open_findings",
      label: "Open risk",
      render: (_value, vendor) => (
        <div className="min-w-[7rem] text-[13px] font-semibold text-[var(--text-primary)]">
          {(vendor.open_findings ?? 0).toLocaleString()}
        </div>
      ),
    },
  ], [onOpenVendor]);
  return (
    <WorklistTable
      title="Vendor status"
      description={`${countLabel(vendors.length, "vendor")} in this view. ${assuranceItems.toLocaleString()} linked records.`}
      rows={vendors}
      columns={vendorColumns}
      emptyMessage="No vendors match these filters."
      searchPlaceholder="Search loaded vendors"
      filterKeys={["urn", "name", "owner", "security_owner_user_id", "business_owner_user_id", "services_provided", "category", "provider", "source_id", "risk_level", "review_state", "owner_state", "lifecycle_state", "queue_reasons"]}
      pageSize={12}
      resultLimit={GRC_WORKLIST_LIMIT}
      resultMeta={meta}
      resultNoun="vendors"
      getRowKey={(vendor) => vendor.urn}
      onRowClick={(vendor) => onOpenVendor(vendor.urn)}
      tableContainerClassName="max-h-[36rem] overflow-auto"
      action={(
        <Link href="/inventory?entity_type=vendor" className="text-[12px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">
          Inventory
        </Link>
      )}
      rowActions={(vendor) => (
        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={(event) => {
              event.stopPropagation();
              onOpenVendor(vendor.urn);
            }}
            className="secondary-button inline-flex items-center gap-1.5 px-2.5 py-1 text-[12px]"
          >
            <PanelRightOpen className="h-3.5 w-3.5" aria-hidden="true" />
            Open
          </button>
          <Link
            href={vendorDetailHref(vendor)}
            onClick={(event) => event.stopPropagation()}
            className="text-[12px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]"
          >
            Full detail
          </Link>
        </div>
      )}
    />
  );
}

function VendorSectionSwitcher({
  activeSection,
  discoveriesLoaded,
  discoveryCount,
  onChange,
  uploadCount,
  vendorCount,
}: {
  activeSection: VendorSection;
  discoveriesLoaded: boolean;
  discoveryCount: number;
  onChange: (section: VendorSection) => void;
  uploadCount: number;
  vendorCount: number;
}) {
  const detailBySection: Record<VendorSection, string> = {
    register: countLabel(vendorCount, "loaded vendor"),
    discoveries: discoveriesLoaded ? countLabel(discoveryCount, "loaded candidate") : "Load candidates",
    uploads: uploadCount > 0 ? countLabel(uploadCount, "recent upload") : "Add documents",
  };
  return (
    <section className="border-b border-[color:var(--border)] pb-2">
      <div role="tablist" aria-label="Vendor work areas" className="flex flex-wrap gap-1.5">
        {vendorSections.map((section) => {
          const selected = activeSection === section.id;
          return (
            <button
              key={section.id}
              type="button"
              role="tab"
              aria-selected={selected}
              onClick={() => onChange(section.id)}
              className={`rounded-md border px-3 py-2 text-left text-[13px] transition ${selected ? "border-[color:var(--border-strong)] bg-[var(--surface-muted)] text-[var(--text-primary)]" : "border-transparent text-[var(--text-secondary)] hover:border-[color:var(--border)] hover:bg-[var(--surface-muted)] hover:text-[var(--text-primary)]"}`}
            >
              <span className="block font-semibold">{section.label}</span>
              <span className="mt-0.5 block text-[11px] text-[var(--text-muted)]">{detailBySection[section.id]}</span>
            </button>
          );
        })}
      </div>
    </section>
  );
}

function DetailField({ label, value }: { label: string; value?: string | number }) {
  return (
    <div className="grid grid-cols-[116px_minmax(0,1fr)] gap-3 border-t border-[color:var(--border)] py-2 text-[12px]">
      <dt className="text-[var(--text-muted)]">{label}</dt>
      <dd className="break-words font-medium text-[var(--text-primary)]">{value === undefined || value === "" ? "Not set" : value}</dd>
    </div>
  );
}

function DrawerCount({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2">
      <div className="text-lg font-semibold text-[var(--text-primary)]">{value.toLocaleString()}</div>
      <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{label}</div>
    </div>
  );
}

function VendorDetailDrawer({
  actionDraft,
  actionError,
  actionSaving,
  detail,
  detailError,
  detailLoading,
  linkedDiscoveries,
  linkedDiscoveriesLoaded,
  onClose,
  onOpenUpload,
  onQuickAction,
  onReload,
  onUpdateActionDraft,
  vendor,
}: {
  actionDraft: VendorQuickActionDraft;
  actionError: string | null;
  actionSaving: boolean;
  detail?: GRCVendorDetailResponse | null;
  detailError: string | null;
  detailLoading: boolean;
  linkedDiscoveries: GRCVendorDiscovery[];
  linkedDiscoveriesLoaded: boolean;
  onClose: () => void;
  onOpenUpload: (vendor: GRCVendor) => void;
  onQuickAction: (action: "assign_owner" | "change_lifecycle" | "start_review") => Promise<void> | void;
  onReload: () => void;
  onUpdateActionDraft: (patch: Partial<VendorQuickActionDraft>) => void;
  vendor?: GRCVendor | null;
}) {
  const activeVendor = detail?.vendor ?? vendor;
  if (!activeVendor) return null;
  const relationships = detail?.relationships ?? {};
  const reviewRecords = [
    ...(relationships.security_reviews ?? []),
    ...(relationships.security_questionnaires ?? []),
    ...(relationships.assurance_documents ?? []),
  ];
  const drivers = vendorRiskDrivers(activeVendor);
  const nextActions = detail?.packet?.next_actions ?? activeVendor.next_actions ?? [];
  const evidence = detail?.evidence ?? [];
  const findings = detail?.findings ?? [];
  const recentChanges = [
    activeVendor.last_material_change_at ? `Material change ${displayDate(activeVendor.last_material_change_at)}` : "",
    activeVendor.last_review_completed_at ? `Review completed ${displayDate(activeVendor.last_review_completed_at)}` : "",
    activeVendor.review_due_at ? `Review due ${displayDate(activeVendor.review_due_at)}` : "",
    activeVendor.renewal_notice_at ? `Renewal notice ${displayDate(activeVendor.renewal_notice_at)}` : "",
  ].filter(Boolean);

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-stone-950/45 backdrop-blur-sm">
      <div className="absolute inset-y-0 right-0 flex w-full max-w-2xl">
        <aside role="dialog" aria-modal="true" aria-labelledby="vendor-drawer-title" className="surface-raised flex w-full flex-col border-l border-[color:var(--border)] shadow-2xl">
          <div className="flex items-start justify-between gap-4 border-b border-[color:var(--border)] px-5 py-4">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h2 id="vendor-drawer-title" className="truncate text-[16px] font-semibold text-[var(--text-primary)]">{activeVendor.name || shortEntity(activeVendor.urn)}</h2>
                <VendorRiskBadge level={activeVendor.risk_score_level || activeVendor.risk_level} />
              </div>
              <p className="mt-1 text-[12px] text-[var(--text-muted)]">{activeVendor.category ? humanize(activeVendor.category) : "No category"} · {humanize(activeVendor.lifecycle_state || "unknown")}</p>
            </div>
            <button type="button" onClick={onClose} className="secondary-button inline-flex h-8 w-8 items-center justify-center p-0" aria-label="Close vendor detail">
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto px-5 py-4">
            {detailError && <ErrorBlock error={detailError} onRetry={onReload} recoveryDetail="Using register data until detail loads." />}
            {actionError && <ErrorBlock error={actionError} recoveryDetail="Vendor action was not saved." />}
            {detailLoading && !detail && <LoadingBlock label="Loading vendor detail..." />}

            <div className="grid gap-3 sm:grid-cols-4">
              <DrawerCount label="Open risk" value={activeVendor.open_findings ?? findings.length} />
              <DrawerCount label="Documents" value={activeVendor.assurance_document_count + activeVendor.contract_count + activeVendor.questionnaire_count} />
              <DrawerCount label="Evidence" value={activeVendor.evidence_items ?? evidence.length} />
              <DrawerCount label="Actions" value={nextActions.length} />
            </div>

            <section className="mt-5 rounded-md border border-[color:var(--border)] p-4">
              <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
                <AlertTriangle className="h-4 w-4 text-amber-500" aria-hidden="true" />
                Risk drivers
              </div>
              <RiskDriverList drivers={drivers} limit={8} />
            </section>

            <section className="mt-4 rounded-md border border-[color:var(--border)] p-4">
              <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
                <ClipboardCheck className="h-4 w-4 text-[var(--text-muted)]" aria-hidden="true" />
                Next actions
              </div>
              {nextActions.length === 0 ? (
                <div className="text-[13px] text-[var(--text-muted)]">No queued action.</div>
              ) : (
                <div className="space-y-3">
                  {nextActions.slice(0, 4).map((action) => (
                    <div key={action.id} className="rounded-md bg-[var(--surface-muted)] px-3 py-2 text-[12px]">
                      <div className="font-semibold text-[var(--text-primary)]">{action.label}</div>
                      <div className="mt-1 text-[var(--text-muted)]">{action.reason || humanize(action.action_type)}</div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="mt-4 rounded-md border border-[color:var(--border)] p-4">
              <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
                <FileText className="h-4 w-4 text-[var(--text-muted)]" aria-hidden="true" />
                Documents and evidence
              </div>
              <dl>
                <DetailField label="Assurance" value={activeVendor.assurance_document_count} />
                <DetailField label="Contracts" value={activeVendor.contract_count} />
                <DetailField label="Questionnaires" value={activeVendor.questionnaire_count} />
                <DetailField label="Freshness" value={freshnessLabel(activeVendor)} />
                <DetailField label="Packet" value={packetDetail(activeVendor)} />
              </dl>
              {reviewRecords.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {reviewRecords.slice(0, 4).map((record) => <Badge key={record.urn} value={record.entity_type} />)}
                </div>
              )}
            </section>

            <section className="mt-4 rounded-md border border-[color:var(--border)] p-4">
              <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
                <GitMerge className="h-4 w-4 text-[var(--text-muted)]" aria-hidden="true" />
                Linked discoveries
              </div>
              {!linkedDiscoveriesLoaded ? (
                <div className="text-[13px] text-[var(--text-muted)]">Open the discovery queue to load candidate links.</div>
              ) : linkedDiscoveries.length === 0 ? (
                <div className="text-[13px] text-[var(--text-muted)]">No linked discoveries.</div>
              ) : (
                <div className="space-y-2">
                  {linkedDiscoveries.map((discovery) => (
                    <div key={discovery.urn} className="rounded-md bg-[var(--surface-muted)] px-3 py-2 text-[12px]">
                      <div className="font-semibold text-[var(--text-primary)]">{discovery.name || shortEntity(discovery.urn)}</div>
                      <div className="mt-1 text-[var(--text-muted)]">{discovery.provider || discovery.source_id || "Source not set"} · {humanize(discovery.decision_state)}</div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="mt-4 rounded-md border border-[color:var(--border)] p-4">
              <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
                <CheckCircle2 className="h-4 w-4 text-[var(--text-muted)]" aria-hidden="true" />
                Vendor detail
              </div>
              <dl>
                <DetailField label="Owner" value={ownerLabel(activeVendor)} />
                <DetailField label="Review" value={humanize(activeVendor.review_state)} />
                <DetailField label="Source" value={sourceLabel(activeVendor)} />
                <DetailField label="Website" value={activeVendor.website_url} />
                <DetailField label="Services" value={activeVendor.services_provided} />
              </dl>
            </section>

            <section className="mt-4 rounded-md border border-[color:var(--border)] p-4">
              <div className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">Recent changes</div>
              {recentChanges.length === 0 ? (
                <div className="text-[13px] text-[var(--text-muted)]">No recent changes reported.</div>
              ) : (
                <ul className="space-y-2 text-[12px] text-[var(--text-secondary)]">
                  {recentChanges.map((change) => <li key={change}>{change}</li>)}
                </ul>
              )}
            </section>

            <section className="mt-4 rounded-md border border-[color:var(--border)] p-4">
              <div className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">Quick actions</div>
              <div className="grid gap-3">
                <label className={labelClass}>
                  Owner
                  <div className="mt-1 flex gap-2">
                    <input value={actionDraft.owner} onChange={(event) => onUpdateActionDraft({ owner: event.target.value })} placeholder={ownerLabel(activeVendor)} className="control-input min-w-0 flex-1 px-3 py-1.5 text-[13px]" />
                    <button type="button" disabled={actionSaving || !actionDraft.owner.trim()} onClick={() => { void Promise.resolve(onQuickAction("assign_owner")).catch(() => undefined); }} className="secondary-button inline-flex items-center gap-1.5 px-3 py-1.5 text-[13px] disabled:opacity-50">
                      <UserPlus className="h-3.5 w-3.5" aria-hidden="true" />
                      Assign
                    </button>
                  </div>
                </label>
                <label className={labelClass}>
                  Lifecycle
                  <div className="mt-1 flex gap-2">
                    <select value={actionDraft.lifecycleState} onChange={(event) => onUpdateActionDraft({ lifecycleState: event.target.value })} className="control-input min-w-0 flex-1 px-3 py-1.5 text-[13px]">
                      {createLifecycleOptions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                    </select>
                    <button type="button" disabled={actionSaving} onClick={() => { void Promise.resolve(onQuickAction("change_lifecycle")).catch(() => undefined); }} className="secondary-button px-3 py-1.5 text-[13px] disabled:opacity-50">
                      Change
                    </button>
                  </div>
                </label>
                <label className={labelClass}>
                  Review
                  <div className="mt-1 flex gap-2">
                    <select value={actionDraft.reviewState} onChange={(event) => onUpdateActionDraft({ reviewState: event.target.value })} className="control-input min-w-0 flex-1 px-3 py-1.5 text-[13px]">
                      {quickReviewOptions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                    </select>
                    <button type="button" disabled={actionSaving} onClick={() => { void Promise.resolve(onQuickAction("start_review")).catch(() => undefined); }} className="secondary-button px-3 py-1.5 text-[13px] disabled:opacity-50">
                      Start
                    </button>
                  </div>
                </label>
              </div>
            </section>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[color:var(--border)] px-5 py-4">
            <button type="button" onClick={() => onOpenUpload(activeVendor)} className="secondary-button inline-flex items-center gap-1.5 px-3 py-1.5 text-[13px]">
              <Upload className="h-3.5 w-3.5" aria-hidden="true" />
              Add document
            </button>
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={onReload} className="secondary-button inline-flex items-center gap-1.5 px-3 py-1.5 text-[13px]">
                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                Refresh
              </button>
              <Link href={vendorDetailHref(activeVendor)} className="primary-button px-3 py-1.5 text-[13px]">
                Open full detail
              </Link>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}

export default function VendorsPage() {
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [query, setQuery] = useQueryParamState("q");
  const [sourceID, setSourceID] = useQueryParamState("source_id");
  const [riskLevel, setRiskLevel] = useQueryParamState("risk_level");
  const [reviewState, setReviewState] = useQueryParamState("review_state");
  const [ownerState, setOwnerState] = useQueryParamState("owner_state");
  const [lifecycleState, setLifecycleState] = useQueryParamState("lifecycle_state");
  const [queueState, setQueueState] = useQueryParamState("queue");
  const [sectionParam, setSectionParam] = useQueryParamState("view");
  const [decisionDrafts, setDecisionDrafts] = useState<Record<string, DiscoveryDecisionDraft>>({});
  const [vendorUploadFile, setVendorUploadFile] = useState<File | null>(null);
  const [vendorUploadName, setVendorUploadName] = useState("");
  const [vendorUploadID, setVendorUploadID] = useState("");
  const [vendorUploadDocumentType, setVendorUploadDocumentType] = useState("assurance_document");
  const [vendorUploadRiskLevel, setVendorUploadRiskLevel] = useState("");
  const [vendorUploadWebsite, setVendorUploadWebsite] = useState("");
  const [lastVendorUpload, setLastVendorUpload] = useState<GRCUploadResponse | null>(null);
  const [vendorUploadHistory, setVendorUploadHistory] = useState<GRCUploadResponse[]>([]);
  const [vendorReplayMessage, setVendorReplayMessage] = useState("");
  const vendorUploadFormRef = useRef<HTMLFormElement>(null);
  const vendorUploadInputRef = useRef<HTMLInputElement>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [createDraft, setCreateDraft] = useState<VendorCreateDraft>(() => defaultVendorCreateDraft());
  const [createMessage, setCreateMessage] = useState("");
  const [createdVendor, setCreatedVendor] = useState<GRCVendor | null>(null);
  const [selectedVendorURN, setSelectedVendorURN] = useState("");
  const [bulkDraft, setBulkDraft] = useState<BulkDiscoveryDraft>(() => defaultBulkDiscoveryDraft());
  const [bulkSaving, setBulkSaving] = useState(false);
  const [selectedDiscoveryURNs, setSelectedDiscoveryURNs] = useState<Set<string>>(() => new Set());
  const [syncMessage, setSyncMessage] = useState("");
  const [quickActionMessage, setQuickActionMessage] = useState("");
  const [quickActionDraft, setQuickActionDraft] = useState<VendorQuickActionDraft>(() => defaultVendorQuickActionDraft());
  const uploadPanelRef = useRef<HTMLDivElement>(null);
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedQuery = useDebouncedValue(query.trim());
  const debouncedSourceID = useDebouncedValue(sourceID.trim());
  const debouncedRiskLevel = useDebouncedValue(riskLevel.trim());
  const debouncedReviewState = useDebouncedValue(reviewState.trim());
  const debouncedOwnerState = useDebouncedValue(ownerState.trim());
  const debouncedLifecycleState = useDebouncedValue(lifecycleState.trim());
  const debouncedQueueState = useDebouncedValue(queueState.trim());
  const activeSection = vendorSectionFromParam(sectionParam);
  const shouldLoadDiscoveries = activeSection === "discoveries";
  const setActiveSection = useCallback((section: VendorSection) => {
    if (section !== "discoveries") {
      setSelectedDiscoveryURNs(new Set());
    }
    setSectionParam(section === "register" ? "" : section);
  }, [setSectionParam]);

  const vendorsQuery = useGRCQuery<GRCVendorsResponse>(
    grcPath("/grc/vendors", {
      tenant_id: debouncedTenantID,
      source_id: debouncedSourceID,
      q: debouncedQuery,
      risk_level: debouncedRiskLevel,
      review_state: debouncedReviewState,
      owner_state: debouncedOwnerState,
      lifecycle_state: debouncedLifecycleState,
      queue: debouncedQueueState,
      limit: GRC_WORKLIST_LIMIT,
    }),
  );
  const discoveriesQuery = useGRCQuery<GRCVendorDiscoveriesResponse>(
    shouldLoadDiscoveries ? grcPath("/grc/vendor-discoveries", {
      tenant_id: debouncedTenantID,
      source_id: debouncedSourceID,
      q: debouncedQuery,
      limit: GRC_DETAIL_LIMIT,
    }) : null,
  );
  const vendorDetailQuery = useGRCQuery<GRCVendorDetailResponse>(
    selectedVendorURN
      ? grcPath(`/grc/vendors/${encodeURIComponent(selectedVendorURN)}`, { tenant_id: debouncedTenantID, limit: GRC_DETAIL_LIMIT })
      : null,
  );
  const { mutate: mutateDiscoveryDecision, saving: decisionSaving, error: decisionError } = useGRCMutation();
  const { mutate: uploadVendorDocument, saving: vendorUploadSaving, error: vendorUploadError, setError: setVendorUploadError, cancel: cancelVendorUpload } =
    useGRCFormMutation<GRCUploadResponse>();
  const { mutate: replayVendorUploadEvents, saving: vendorReplaySaving, error: vendorReplayError, setError: setVendorReplayError } =
    useGRCMutation<GRCUploadReplayResponse>();
  const {
    mutate: mutateCreateVendor,
    saving: createSaving,
    error: createError,
    setError: setCreateError,
  } = useGRCMutation<GRCVendorCreateResponse>();
  const { mutate: mutateDiscoverySync, saving: syncSaving, error: syncError } = useGRCMutation<GRCVendorDiscoverySyncResponse>();
  const { mutate: mutateVendorAction, saving: quickActionSaving, error: quickActionError } = useGRCMutation<GRCVendorActionResponse>();

  const vendorRows = useMemo(() => boundedVendorRows(vendorsQuery.data, GRC_WORKLIST_LIMIT), [vendorsQuery.data]);
  const vendors = vendorRows.vendors;
  const vendorMeta = vendorRows.meta;
  const summary = vendorsQuery.data?.summary;
  const discoveryRows = useMemo(() => boundedVendorDiscoveries(discoveriesQuery.data, GRC_DETAIL_LIMIT), [discoveriesQuery.data]);
  const discoveries = discoveryRows.discoveries;
  const discoveryMeta = discoveryRows.meta;
  const discoverySummary = discoveriesQuery.data?.summary;
  const discoverySources = useMemo(() => discoveriesQuery.data?.source_summaries ?? [], [discoveriesQuery.data?.source_summaries]);
  const error = vendorsQuery.error;
  const discoveryError = discoveriesQuery.error;
  const vendorMetricState: RuntimeState = error ? runtimeStateForError(error) : vendorsQuery.loading && !vendorsQuery.data ? "loading" : "ready";
  const discoveryMetricState: RuntimeState = !shouldLoadDiscoveries
    ? "empty"
    : discoveryError ? runtimeStateForError(discoveryError) : discoveriesQuery.loading && !discoveriesQuery.data ? "loading" : "ready";
  const assuranceItems = useMemo(() => vendors.reduce((sum, vendor) => sum + vendorAssuranceItemCount(vendor), 0), [vendors]);
  const sourceFilterOptions = useMemo(() => {
    const options = new Map<string, string>();
    discoverySources.forEach((source) => options.set(source.source_id, discoverySourceLabel(source)));
    discoveries.forEach((discovery) => {
      discoverySourceIDs(discovery).forEach((id) => options.set(id, options.get(id) ?? humanize(id)));
    });
    vendors.forEach((vendor) => {
      if (vendor.source_id) options.set(vendor.source_id, options.get(vendor.source_id) ?? sourceLabel(vendor));
    });
    if (sourceID.trim() && !options.has(sourceID.trim())) {
      options.set(sourceID.trim(), humanize(sourceID.trim()));
    }
    return Array.from(options, ([value, label]) => ({ value, label })).sort((left, right) => left.label.localeCompare(right.label));
  }, [discoveries, discoverySources, sourceID, vendors]);
  const duplicateMatchesByURN = useMemo(() => Object.fromEntries(
    discoveries.map((discovery) => [discovery.urn, duplicateMatchesForDiscovery(discovery, vendors, discoveries)]),
  ), [discoveries, vendors]);
  const createDuplicateMatches = useMemo(
    () => duplicateMatchesForDraft(createDraft, vendors, discoveries),
    [createDraft, discoveries, vendors],
  );
  const selectedVendor = useMemo(
    () => vendors.find((vendor) => vendor.urn === selectedVendorURN) ?? vendorDetailQuery.data?.vendor ?? null,
    [selectedVendorURN, vendorDetailQuery.data?.vendor, vendors],
  );
  const linkedDiscoveriesForSelectedVendor = useMemo(() => {
    if (!selectedVendorURN) return [];
    const selectedHost = hostForURL(selectedVendor?.website_url);
    const selectedNameKey = compactMatchKey(selectedVendor?.name);
    return discoveries.filter((discovery) => {
      if (discovery.linked_vendor_urn === selectedVendorURN) return true;
      if (discovery.attributes?.discovery_urn === selectedVendorURN) return true;
      const discoveryHost = hostForURL(discovery.website_url);
      const discoveryNameKey = compactMatchKey(discovery.normalized_name || discovery.name);
      return Boolean((selectedHost && discoveryHost === selectedHost) || (selectedNameKey && discoveryNameKey === selectedNameKey));
    });
  }, [discoveries, selectedVendor?.name, selectedVendor?.website_url, selectedVendorURN]);
  const vendorUploadStorageKey = useMemo(() => grcUploadHistoryKey("vendor", tenantID), [tenantID]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setVendorUploadHistory(readGRCUploadHistory(window.localStorage, vendorUploadStorageKey));
    }, 0);
    return () => window.clearTimeout(timer);
  }, [vendorUploadStorageKey]);

  const rememberVendorUpload = (upload: GRCUploadResponse) => {
    setVendorUploadHistory((current) => {
      const next = grcUploadHistoryWith(current, upload);
      writeGRCUploadHistory(window.localStorage, vendorUploadStorageKey, next);
      return next;
    });
  };

  const replayVendorUpload = async (upload: GRCUploadResponse) => {
    setVendorReplayMessage("");
    setVendorReplayError(null);
    try {
      const response = await replayVendorUploadEvents(
        grcPath(`/grc/vendors/uploads/${encodeURIComponent(upload.upload_id)}/replay`, { tenant_id: tenantID.trim() }),
        {},
      );
      setVendorReplayMessage(`${countLabel(response.events_projected ?? 0, "event")} replayed. ${countLabel((response.entities_projected ?? 0) + (response.links_projected ?? 0), "graph update")} projected.`);
      setLastVendorUpload((current) => current?.upload_id === upload.upload_id ? {
        ...current,
        status: response.status || current.status,
        projection_status: response.status || current.projection_status,
        projection_failures: response.projection_failures ?? current.projection_failures,
      } : current);
      await Promise.all([vendorsQuery.reload(), vendorDetailQuery.reload()]);
    } catch {
      return;
    }
  };

  const openVendorDrawer = useCallback((vendorURN: string) => {
    const vendor = vendors.find((item) => item.urn === vendorURN) ?? vendorDetailQuery.data?.vendor;
    setSelectedVendorURN(vendorURN);
    setQuickActionMessage("");
    setQuickActionDraft({
      owner: vendor?.owner || vendor?.security_owner_user_id || vendor?.business_owner_user_id || "",
      lifecycleState: vendor?.lifecycle_state || "approved",
      reviewState: "in_progress",
    });
  }, [vendorDetailQuery.data?.vendor, vendors]);
  const closeVendorDrawer = useCallback(() => {
    setSelectedVendorURN("");
  }, []);
  const updateBulkDraft = useCallback((patch: Partial<BulkDiscoveryDraft>) => {
    setBulkDraft((current) => ({ ...current, ...patch }));
  }, []);
  const updateQuickActionDraft = useCallback((patch: Partial<VendorQuickActionDraft>) => {
    setQuickActionDraft((current) => ({ ...current, ...patch }));
  }, []);
  const toggleDiscoverySelection = useCallback((urn: string) => {
    setSelectedDiscoveryURNs((current) => {
      const next = new Set(current);
      if (next.has(urn)) next.delete(urn);
      else next.add(urn);
      return next;
    });
  }, []);
  const clearDiscoverySelection = useCallback(() => {
    setSelectedDiscoveryURNs(new Set());
  }, []);
  const toggleVisibleDiscoveries = useCallback(() => {
    const visible = discoveries.filter(discoveryNeedsReview).map((discovery) => discovery.urn);
    setSelectedDiscoveryURNs((current) => {
      const allSelected = visible.length > 0 && visible.every((urn) => current.has(urn));
      const next = new Set(current);
      visible.forEach((urn) => {
        if (allSelected) next.delete(urn);
        else next.add(urn);
      });
      return next;
    });
  }, [discoveries]);
  const openUploadForVendor = useCallback((vendor: GRCVendor) => {
    setActiveSection("uploads");
    setVendorUploadName(vendor.name || "");
    setVendorUploadID(vendor.vendor_id || shortEntity(vendor.urn));
    setVendorUploadWebsite(vendor.website_url || "");
    window.setTimeout(() => uploadPanelRef.current?.scrollIntoView({ block: "start", behavior: "smooth" }), 0);
  }, [setActiveSection]);
  const updateCreateDraft = useCallback((patch: Partial<VendorCreateDraft>) => {
    setCreateDraft((current) => ({ ...current, ...patch }));
  }, []);
  const openCreateVendor = useCallback(() => {
    setCreateDraft(defaultVendorCreateDraft());
    setCreateMessage("");
    setCreatedVendor(null);
    setCreateError(null);
    setCreateOpen(true);
  }, [setCreateError]);
  const closeCreateVendor = useCallback(() => {
    setCreateOpen(false);
    setCreateError(null);
  }, [setCreateError]);
  const submitVendorCreate = useCallback(async (draft: VendorCreateDraft) => {
    const response = await mutateCreateVendor("/grc/vendors", vendorCreateRequest(draft, tenantID));
    setCreateOpen(false);
    setCreateDraft(defaultVendorCreateDraft());
    setCreateMessage(`${response.vendor.name} saved.`);
    setCreatedVendor(response.vendor);
    const reloads = [vendorsQuery.reload()];
    if (shouldLoadDiscoveries) reloads.push(discoveriesQuery.reload());
    await Promise.all(reloads);
  }, [discoveriesQuery, mutateCreateVendor, shouldLoadDiscoveries, tenantID, vendorsQuery]);
  const updateDecisionDraft = useCallback((urn: string, patch: Partial<DiscoveryDecisionDraft>) => {
    setDecisionDrafts((current) => ({
      ...current,
      [urn]: {
        reason: current[urn]?.reason ?? "",
        linkedVendorURN: current[urn]?.linkedVendorURN ?? "",
        ...patch,
      },
    }));
  }, []);
  const setDiscoveryDecision = useCallback(async (discovery: GRCVendorDiscovery, decision: DiscoveryDecision, overrideDraft?: DiscoveryDecisionDraft) => {
    const draft = overrideDraft ?? decisionDrafts[discovery.urn] ?? { reason: "", linkedVendorURN: "" };
    await mutateDiscoveryDecision(`/grc/vendor-discoveries/${encodeURIComponent(discovery.urn)}/decision`, {
      tenant_id: tenantID.trim(),
      discovery_urn: discovery.urn,
      source_id: discovery.source_id,
      decision,
      reason: draft.reason.trim(),
      linked_vendor_urn: decision === "linked" ? draft.linkedVendorURN.trim() : undefined,
    });
    setDecisionDrafts((current) => {
      const next = { ...current };
      delete next[discovery.urn];
      return next;
    });
    await discoveriesQuery.reload();
    await vendorsQuery.reload();
  }, [decisionDrafts, discoveriesQuery, mutateDiscoveryDecision, tenantID, vendorsQuery]);
  const createVendorFromDiscovery = useCallback(async (discovery: GRCVendorDiscovery, overrides?: Partial<Pick<VendorCreateDraft, "owner" | "riskLevel">>) => {
    setCreateMessage("");
    const response = await mutateCreateVendor("/grc/vendors", {
      tenant_id: tenantID.trim() || undefined,
      name: discovery.name || shortEntity(discovery.urn),
      source_id: discovery.source_id || "grc",
      runtime_id: discovery.runtime_id,
      provider: discovery.provider,
      category: discovery.category,
      website_url: discovery.website_url,
      services_provided: discovery.discovery_reason,
      lifecycle_state: "in_review",
      review_state: "not_scheduled",
      owner: overrides?.owner?.trim() || undefined,
      risk_level: overrides?.riskLevel || "unknown",
      discovery_urn: discovery.urn,
      attributes: compactAttributes({
        discovery_id: discovery.discovery_id,
        source_status: discovery.source_status,
      }),
    } satisfies GRCVendorCreateRequest);
    await mutateDiscoveryDecision(`/grc/vendor-discoveries/${encodeURIComponent(discovery.urn)}/decision`, {
      tenant_id: tenantID.trim(),
      discovery_urn: discovery.urn,
      source_id: discovery.source_id,
      decision: "approved",
      reason: "Candidate approved and vendor record created.",
      linked_vendor_urn: response.vendor.urn,
    });
    setDecisionDrafts((current) => {
      const next = { ...current };
      delete next[discovery.urn];
      return next;
    });
    setCreateMessage(`${response.vendor.name} saved.`);
    setCreatedVendor(response.vendor);
    await Promise.all([discoveriesQuery.reload(), vendorsQuery.reload()]);
  }, [discoveriesQuery, mutateCreateVendor, mutateDiscoveryDecision, tenantID, vendorsQuery]);

  const runBulkDiscoveryAction = useCallback(async (action: "create" | "dismiss" | "link") => {
    const selectedDiscoveries = discoveries.filter((discovery) => selectedDiscoveryURNs.has(discovery.urn) && discoveryNeedsReview(discovery));
    if (selectedDiscoveries.length === 0) return;
    setBulkSaving(true);
    setCreateMessage("");
    setCreatedVendor(null);
    try {
      if (action === "create") {
        for (const discovery of selectedDiscoveries) {
          await createVendorFromDiscovery(discovery, {
            owner: bulkDraft.owner,
            riskLevel: bulkDraft.riskLevel,
          });
        }
        setCreateMessage(`${countLabel(selectedDiscoveries.length, "vendor")} saved.`);
      } else if (action === "link") {
        const linkedVendorURN = bulkDraft.linkedVendorURN.trim();
        if (!linkedVendorURN) return;
        for (const discovery of selectedDiscoveries) {
          await setDiscoveryDecision(discovery, "linked", {
            linkedVendorURN,
            reason: bulkDraft.reason.trim() || "Candidate linked to existing vendor.",
          });
        }
        setCreateMessage(`${countLabel(selectedDiscoveries.length, "candidate")} linked.`);
      } else {
        for (const discovery of selectedDiscoveries) {
          await setDiscoveryDecision(discovery, "ignored", {
            linkedVendorURN: "",
            reason: bulkDraft.reason.trim() || "Candidate dismissed after review.",
          });
        }
        setCreateMessage(`${countLabel(selectedDiscoveries.length, "candidate")} dismissed.`);
      }
      setSelectedDiscoveryURNs(new Set());
    } finally {
      setBulkSaving(false);
    }
  }, [bulkDraft.linkedVendorURN, bulkDraft.owner, bulkDraft.reason, bulkDraft.riskLevel, createVendorFromDiscovery, discoveries, selectedDiscoveryURNs, setDiscoveryDecision]);

  const runDiscoverySync = useCallback(async (runSourceID?: string) => {
    const response = await mutateDiscoverySync("/grc/vendor-discoveries/sync", {
      tenant_id: tenantID.trim() || undefined,
      source_id: runSourceID,
    });
    const sourceName = runSourceID
      ? discoverySources.find((source) => source.source_id === runSourceID)?.provider || humanize(runSourceID)
      : "All sources";
    setSyncMessage(`${sourceName} discovery ${response.status}.`);
    await discoveriesQuery.reload();
  }, [discoveriesQuery, discoverySources, mutateDiscoverySync, tenantID]);

  const runVendorQuickAction = useCallback(async (action: "assign_owner" | "change_lifecycle" | "start_review") => {
    if (!selectedVendorURN) return;
    const response = await mutateVendorAction(`/grc/vendors/${encodeURIComponent(selectedVendorURN)}/actions`, {
      tenant_id: tenantID.trim() || undefined,
      action,
      owner: action === "assign_owner" ? quickActionDraft.owner.trim() : undefined,
      lifecycle_state: action === "change_lifecycle" ? quickActionDraft.lifecycleState : undefined,
      review_state: action === "start_review" ? quickActionDraft.reviewState : undefined,
      reason: action === "change_lifecycle" ? "Lifecycle changed from vendor review." : undefined,
    });
    setQuickActionMessage(`${response.vendor.name} updated.`);
    await Promise.all([vendorsQuery.reload(), vendorDetailQuery.reload()]);
  }, [mutateVendorAction, quickActionDraft.lifecycleState, quickActionDraft.owner, quickActionDraft.reviewState, selectedVendorURN, tenantID, vendorDetailQuery, vendorsQuery]);

  const submitVendorUpload = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!vendorUploadFile) {
      setVendorUploadError("Select a vendor document.");
      return;
    }
    const fileError = grcUploadFileError(vendorUploadFile);
    if (fileError) {
      setVendorUploadError(fileError);
      setVendorUploadFile(null);
      if (vendorUploadInputRef.current) {
        vendorUploadInputRef.current.value = "";
      }
      return;
    }
    const vendorName = vendorUploadName.trim() || vendorUploadFile.name.replace(/\.[^.]+$/, "");
    const body = new FormData();
    body.set("file", vendorUploadFile);
    body.set("vendor_name", vendorName);
    body.set("document_title", vendorUploadFile.name);
    body.set("document_type", vendorUploadDocumentType.trim() || "assurance_document");
    body.set("status", "active");
    if (tenantID.trim()) body.set("tenant_id", tenantID.trim());
    if (sourceID.trim()) body.set("source_id", sourceID.trim());
    if (vendorUploadID.trim()) body.set("vendor_id", vendorUploadID.trim());
    if (vendorUploadRiskLevel.trim()) body.set("risk_level", vendorUploadRiskLevel.trim());
    if (vendorUploadWebsite.trim()) body.set("website_url", vendorUploadWebsite.trim());
    try {
      const response = await uploadVendorDocument(
        grcPath("/grc/vendors/uploads", { tenant_id: tenantID.trim(), source_id: sourceID.trim() }),
        body,
      );
      setLastVendorUpload(response);
      rememberVendorUpload(response);
      setVendorUploadFile(null);
      setVendorUploadName("");
      setVendorUploadID("");
      setVendorUploadDocumentType("assurance_document");
      setVendorUploadRiskLevel("");
      setVendorUploadWebsite("");
      if (vendorUploadInputRef.current) {
        vendorUploadInputRef.current.value = "";
      }
      await vendorsQuery.reload();
    } catch {
      return;
    }
  };

  const filterChips = [
    { label: "Search", value: query, onClear: () => setQuery("") },
    { label: "Risk", value: riskLevel ? selectLabel(riskFilters, riskLevel) : "", onClear: () => setRiskLevel("") },
    { label: "Review", value: reviewState ? selectLabel(reviewFilters, reviewState) : "", onClear: () => setReviewState("") },
    { label: "Owner", value: ownerState ? selectLabel(ownerFilters, ownerState) : "", onClear: () => setOwnerState("") },
    { label: "Lifecycle", value: lifecycleState ? selectLabel(lifecycleFilters, lifecycleState) : "", onClear: () => setLifecycleState("") },
    { label: "Queue", value: queueState ? selectLabel(queueFilters, queueState) : "", onClear: () => setQueueState("") },
    { label: "Source", value: sourceID ? sourceFilterOptions.find((item) => item.value === sourceID)?.label ?? sourceID : "", onClear: () => setSourceID("") },
    { label: "Tenant", value: tenantID, onClear: () => setTenantID("") },
  ];
  const clearFilters = () => {
    setQuery("");
    setRiskLevel("");
    setReviewState("");
    setOwnerState("");
    setLifecycleState("");
    setQueueState("");
    setSourceID("");
    setTenantID("");
  };

  return (
    <main className="flex flex-col gap-6">
      <PageHeader
        contractId="vendors"
        title="Vendors"
        description="Vendor status, review ownership, and evidence readiness."
        action={
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                void vendorsQuery.reload();
                if (shouldLoadDiscoveries) void discoveriesQuery.reload();
              }}
              className="secondary-button inline-flex items-center gap-2 px-3 py-1.5 text-[13px]"
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
              Refresh
            </button>
            <button type="button" onClick={openCreateVendor} className="primary-button inline-flex items-center gap-2 px-3 py-1.5 text-[13px]">
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              Add vendor
            </button>
          </div>
        }
      />
      <CreateVendorModal
        duplicateMatches={createDuplicateMatches}
        draft={createDraft}
        error={createError}
        onClose={closeCreateVendor}
        onOpenVendor={openVendorDrawer}
        onSubmit={submitVendorCreate}
        onUpdateDraft={updateCreateDraft}
        open={createOpen}
        saving={createSaving}
      />
      <VendorDetailDrawer
        actionDraft={quickActionDraft}
        actionError={quickActionError}
        actionSaving={quickActionSaving}
        detail={vendorDetailQuery.data}
        detailError={vendorDetailQuery.error}
        detailLoading={vendorDetailQuery.loading}
        linkedDiscoveries={linkedDiscoveriesForSelectedVendor}
        linkedDiscoveriesLoaded={Boolean(discoveriesQuery.data)}
        onClose={closeVendorDrawer}
        onOpenUpload={openUploadForVendor}
        onQuickAction={runVendorQuickAction}
        onReload={() => { void vendorDetailQuery.reload(); }}
        onUpdateActionDraft={updateQuickActionDraft}
        vendor={selectedVendor}
      />

      {error && (
        <ErrorBlock
          error={error}
          onRetry={() => { void vendorsQuery.reload(); }}
          recoveryDetail="Vendor records appear when the API is reachable."
        />
      )}
      {shouldLoadDiscoveries && discoveryError && (
        <ErrorBlock
          error={discoveryError}
          onRetry={() => { void discoveriesQuery.reload(); }}
          recoveryDetail="Vendor discoveries appear when the API is reachable."
        />
      )}
      {decisionError && (
        <ErrorBlock
          error={decisionError}
          recoveryDetail="Discovery decisions need GRC inventory write access."
        />
      )}
      {syncError && (
        <ErrorBlock
          error={syncError}
          recoveryDetail="Discovery run was not started."
        />
      )}
      {createError && !createOpen && (
        <ErrorBlock
          error={createError}
          recoveryDetail="Vendor was not saved."
        />
      )}
      {quickActionMessage && (
        <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-[13px] font-semibold text-emerald-700 dark:text-emerald-200">
          {quickActionMessage}
        </div>
      )}
      {syncMessage && (
        <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-[13px] font-semibold text-emerald-700 dark:text-emerald-200">
          {syncMessage}
        </div>
      )}
      {createMessage && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-[13px] font-semibold text-emerald-700 dark:text-emerald-200">
          <span>{createMessage}</span>
          {createdVendor && (
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={() => openVendorDrawer(createdVendor.urn)} className="secondary-button px-3 py-1.5 text-[12px]">
                Open vendor
              </button>
              <button type="button" onClick={() => openUploadForVendor(createdVendor)} className="secondary-button px-3 py-1.5 text-[12px]">
                Add document
              </button>
            </div>
          )}
        </div>
      )}

      <VendorHealthStrip
        discoveries={discoveries}
        discoveriesLoaded={shouldLoadDiscoveries}
        discoveryMetricState={discoveryMetricState}
        discoverySummary={discoverySummary}
        summary={summary}
        vendorMetricState={vendorMetricState}
        vendors={vendors}
      />

      <VendorSectionSwitcher
        activeSection={activeSection}
        discoveriesLoaded={Boolean(discoveriesQuery.data)}
        discoveryCount={discoveries.length}
        onChange={setActiveSection}
        uploadCount={vendorUploadHistory.length}
        vendorCount={vendors.length}
      />

      {activeSection === "uploads" && (
      <div ref={uploadPanelRef}>
        <Panel
          title="Upload vendor document"
          action={<Upload className="h-4 w-4 text-[var(--text-muted)]" aria-hidden="true" />}
        >
        <form ref={vendorUploadFormRef} onSubmit={submitVendorUpload} className="grid gap-3 lg:grid-cols-2 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,0.75fr)_minmax(0,0.85fr)_minmax(0,0.7fr)_minmax(0,1fr)_auto]">
          <label className={labelClass}>
            File
            <GRCUploadFileInput
              file={vendorUploadFile}
              inputClassName={inputClass}
              inputRef={vendorUploadInputRef}
              disabled={vendorUploadSaving}
              onAccepted={(file) => {
                setVendorUploadFile(file);
                setVendorUploadError(null);
                setVendorReplayError(null);
                setVendorReplayMessage("");
                setLastVendorUpload(null);
              }}
              onRejected={(message) => {
                setVendorUploadFile(null);
                setLastVendorUpload(null);
                setVendorUploadError(message);
                setVendorReplayError(null);
                setVendorReplayMessage("");
              }}
              onClear={() => {
                setVendorUploadFile(null);
                setVendorUploadError(null);
              }}
            />
          </label>
          <label className={labelClass}>
            Vendor name
            <input value={vendorUploadName} onChange={(event) => setVendorUploadName(event.target.value)} placeholder="From file name" className={inputClass} />
          </label>
          <label className={labelClass}>
            Vendor ID
            <input value={vendorUploadID} onChange={(event) => setVendorUploadID(event.target.value)} placeholder="Leave blank to assign" className={inputClass} />
          </label>
          <label className={labelClass}>
            Document type
            <select value={vendorUploadDocumentType} onChange={(event) => setVendorUploadDocumentType(event.target.value)} className={inputClass}>
              <option value="assurance_document">Assurance</option>
              <option value="soc2">SOC 2</option>
              <option value="contract">Contract</option>
              <option value="questionnaire">Questionnaire</option>
              <option value="security_review">Security review</option>
            </select>
          </label>
          <label className={labelClass}>
            Risk
            <select value={vendorUploadRiskLevel} onChange={(event) => setVendorUploadRiskLevel(event.target.value)} className={inputClass}>
              <option value="">Not set</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </label>
          <label className={labelClass}>
            Website
            <input value={vendorUploadWebsite} onChange={(event) => setVendorUploadWebsite(event.target.value)} placeholder="Enter vendor website" className={inputClass} />
          </label>
          <button
            type="submit"
            disabled={vendorUploadSaving || !vendorUploadFile}
            className="primary-button inline-flex items-center justify-center gap-1.5 self-end px-3 py-1.5 text-[13px] disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Upload className="h-3.5 w-3.5" aria-hidden="true" />
            {vendorUploadSaving ? "Uploading" : "Upload vendor"}
          </button>
        </form>
        {vendorUploadSaving && <GRCUploadProgress onCancel={cancelVendorUpload} />}
        {vendorUploadError && !vendorUploadSaving && (
          <GRCUploadErrorActions
            error={vendorUploadError}
            canRetry={Boolean(vendorUploadFile)}
            onRetry={() => vendorUploadFormRef.current?.requestSubmit()}
          />
        )}
        {lastVendorUpload && (
          <GRCUploadReceipt
            upload={lastVendorUpload}
            actions={(() => {
              const vendorRef = lastVendorUpload.events.find((event) => event.event_kind === "grc.vendor");
              const vendorURN = vendorRef?.record_urn || vendorRef?.record_id;
              return (
                <div className="flex flex-wrap gap-2">
                  {vendorURN && (
                    <>
                      <button type="button" onClick={() => setSelectedVendorURN(vendorURN)} className="inline-flex items-center rounded-md border border-emerald-300 bg-white/80 px-3 py-1.5 text-[12px] font-semibold text-emerald-800 transition hover:border-emerald-400 hover:text-emerald-950">
                        Open vendor
                      </button>
                      <Link href={`/vendors/${encodeURIComponent(vendorURN)}`} className="inline-flex items-center rounded-md border border-emerald-300 bg-white/80 px-3 py-1.5 text-[12px] font-semibold text-emerald-800 transition hover:border-emerald-400 hover:text-emerald-950">
                        Open full detail
                      </Link>
                    </>
                  )}
                  <button
                    type="button"
                    disabled={vendorReplaySaving || lastVendorUpload.replayable === false}
                    onClick={() => replayVendorUpload(lastVendorUpload)}
                    className="inline-flex items-center gap-1.5 rounded-md border border-emerald-300 bg-white/80 px-3 py-1.5 text-[12px] font-semibold text-emerald-800 transition hover:border-emerald-400 hover:text-emerald-950 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${vendorReplaySaving ? "animate-spin" : ""}`} aria-hidden="true" />
                    {vendorReplaySaving ? "Replaying" : "Replay events"}
                  </button>
                </div>
              );
            })()}
          />
        )}
        {vendorReplayMessage && !vendorReplaySaving && (
          <div className="mt-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-[12px] font-medium text-emerald-800">
            {vendorReplayMessage}
          </div>
        )}
        {vendorReplayError && !vendorReplaySaving && (
          <div className="mt-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-[12px] font-medium text-red-700">
            {vendorReplayError}
          </div>
        )}
        <GRCUploadHistoryList uploads={vendorUploadHistory} />
        </Panel>
      </div>
      )}

      {activeSection !== "uploads" && (
      <section className="surface-panel p-4">
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_180px_160px]">
          <label className={labelClass}>
            Search
            <div className="relative mt-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-muted)]" aria-hidden="true" />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Vendor, owner, source" className="control-input w-full px-9 py-2 text-[13px]" />
            </div>
          </label>
          <label className={labelClass}>
            Source
            <select value={sourceID} onChange={(event) => setSourceID(event.target.value)} className={inputClass}>
              <option value="">All sources</option>
              {sourceFilterOptions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
            </select>
          </label>
          <label className={labelClass}>
            Risk
            <select value={riskLevel} onChange={(event) => setRiskLevel(event.target.value)} className={inputClass}>
              {riskFilters.map((item) => <option key={item.value || "all"} value={item.value}>{item.label}</option>)}
            </select>
          </label>
        </div>
        <details className="mt-3 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2">
          <summary className="flex cursor-pointer list-none items-center gap-2 text-[12px] font-semibold text-[var(--text-secondary)]">
            <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
            More filters
          </summary>
          <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            <label className={labelClass}>
              Review
              <select value={reviewState} onChange={(event) => setReviewState(event.target.value)} className={inputClass}>
                {reviewFilters.map((item) => <option key={item.value || "all"} value={item.value}>{item.label}</option>)}
              </select>
            </label>
            <label className={labelClass}>
              Owner
              <select value={ownerState} onChange={(event) => setOwnerState(event.target.value)} className={inputClass}>
                {ownerFilters.map((item) => <option key={item.value || "all"} value={item.value}>{item.label}</option>)}
              </select>
            </label>
            <label className={labelClass}>
              Lifecycle
              <select value={lifecycleState} onChange={(event) => setLifecycleState(event.target.value)} className={inputClass}>
                {lifecycleFilters.map((item) => <option key={item.value || "all"} value={item.value}>{item.label}</option>)}
              </select>
            </label>
            <label className={labelClass}>
              Register
              <select value={queueState} onChange={(event) => setQueueState(event.target.value)} className={inputClass}>
                {queueFilters.map((item) => <option key={item.value || "all"} value={item.value}>{item.label}</option>)}
              </select>
            </label>
            <label className={labelClass}>
              Tenant
              <input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="Current" className={inputClass} />
            </label>
          </div>
        </details>
        <AppliedFilterChips filters={filterChips} onClearAll={clearFilters} />
      </section>
      )}

      {activeSection === "discoveries" && (
        <>
          <DiscoverySourceSummary
            loading={discoveriesQuery.loading && !discoveriesQuery.data}
            onRefresh={() => { void discoveriesQuery.reload(); }}
            onRunSource={(runSourceID) => { void runDiscoverySync(runSourceID).catch(() => undefined); }}
            onSelectSource={setSourceID}
            runSaving={syncSaving}
            selectedSourceID={sourceID}
            sources={discoverySources}
            summary={discoverySummary}
          />

          <DuplicateQueue
            decisionSaving={decisionSaving}
            discoveries={discoveries}
            duplicateMatchesByURN={duplicateMatchesByURN}
            onDecision={setDiscoveryDecision}
            onOpenVendor={openVendorDrawer}
          />

          {discoveriesQuery.loading && !discoveriesQuery.data ? (
            <LoadingBlock label="Loading vendor discoveries..." />
          ) : (
            <div className="space-y-3">
              <ResultLimitNotice
                loaded={discoveries.length}
                limit={GRC_DETAIL_LIMIT}
                meta={discoveryMeta}
                noun="discoveries"
              />
              <DiscoveryQueue
                bulkDraft={bulkDraft}
                bulkSaving={bulkSaving}
                createSaving={createSaving}
                decisionDrafts={decisionDrafts}
                decisionSaving={decisionSaving}
                discoveries={discoveries}
                duplicateMatchesByURN={duplicateMatchesByURN}
                latestSync={latestSourceSync(discoverySources)}
                onBulkAction={runBulkDiscoveryAction}
                onBulkDraftChange={updateBulkDraft}
                onClearSelection={clearDiscoverySelection}
                onCreateVendor={createVendorFromDiscovery}
                onDecision={setDiscoveryDecision}
                onOpenVendor={openVendorDrawer}
                onRefresh={() => { void discoveriesQuery.reload(); }}
                onToggleDiscovery={toggleDiscoverySelection}
                onToggleVisible={toggleVisibleDiscoveries}
                onUpdateDraft={updateDecisionDraft}
                selectedDiscoveryURNs={selectedDiscoveryURNs}
                sourceCount={discoverySummary?.source_count ?? discoverySources.length}
              />
            </div>
          )}
        </>
      )}

      {activeSection === "register" && (vendorsQuery.loading && !vendorsQuery.data ? (
        <LoadingBlock label="Loading vendors..." />
      ) : (
        <VendorRegisterSection assuranceItems={assuranceItems} meta={vendorMeta} onOpenVendor={openVendorDrawer} vendors={vendors} />
      ))}
    </main>
  );
}
