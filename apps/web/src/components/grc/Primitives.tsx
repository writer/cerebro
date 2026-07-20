"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import type { GRCFinding, GRCListMeta } from "@/lib/grc";

import { productErrorCopy } from "@/lib/cerebro-errors";
import { humanize, riskLevelFromScore } from "@/lib/grc";
import { grcLoadedRowsCopy } from "@/lib/grc-list";
import { badgeClassFor, riskBadgeClassFor, severityDotClassFor } from "@/lib/grc-status";
import {
  metricDetailForState,
  metricValueForState,
  runtimeStateDescription,
  runtimeStateForError,
  runtimeStateTimestamp,
  type RuntimeState,
} from "@/lib/runtime-state";

export function Badge({ value, tone = "status" }: { value: string; tone?: "severity" | "status" }) {
  const className = badgeClassFor(value, tone);
  return (
    <span className={`inline-flex rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${className}`}>
      {humanize(value)}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: string }) {
  return <span className={`inline-block h-2 w-2 rounded-full ${severityDotClassFor(severity)}`} />;
}

export function RiskBadge({ score, level }: { score?: number; level?: string }) {
  const numericScore = Number(score ?? 0);
  const normalizedLevel = (level || riskLevelFromScore(numericScore)).toLowerCase();
  const className = riskBadgeClassFor(normalizedLevel);
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${className}`}>
      <span>{numericScore > 0 ? numericScore : "\u2014"}</span>
      <span>{humanize(normalizedLevel)}</span>
    </span>
  );
}

export function RiskBreakdown({ finding }: { finding: GRCFinding }) {
  const reasons = finding.risk_reasons ?? [];
  return (
    <div className="surface-panel p-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">Risk Assessment</div>
          <div className="mt-2"><RiskBadge score={finding.risk_score} /></div>
        </div>
        <div className="grid grid-cols-3 gap-3 text-center">
          {[
            { label: "Likelihood", value: finding.likelihood_score },
            { label: "Impact", value: finding.impact_score },
            { label: "Confidence", value: finding.confidence_score },
          ].map((item) => (
            <div key={item.label} className="rounded-lg bg-[var(--surface-muted)] px-4 py-2.5">
              <div className="text-xl font-semibold text-[var(--text-primary)]">{item.value ?? "\u2014"}</div>
              <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">{item.label}</div>
            </div>
          ))}
        </div>
      </div>
      {reasons.length > 0 && (
        <div className="mt-4 flex flex-wrap gap-1.5">
          {reasons.slice(0, 8).map((reason) => (
            <span key={reason} className="rounded-md bg-[var(--surface-muted)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)]">
              {humanize(reason)}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  detail,
  intent = "neutral",
  state = "ready",
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  intent?: "neutral" | "danger" | "warning" | "success";
  state?: RuntimeState;
}) {
  const accents: Record<string, string> = {
    danger: "border-l-red-500",
    warning: "border-l-amber-500",
    success: "border-l-emerald-500",
    neutral: "border-l-[color:var(--border-strong)]",
  };
  const stateIntent: Record<RuntimeState, "neutral" | "danger" | "warning" | "success"> = {
    empty: "neutral",
    error: "danger",
    loading: "neutral",
    partial: "warning",
    "permission-denied": "warning",
    ready: intent,
    stale: "warning",
    unavailable: "warning",
  };
  const deferred = ["loading", "unavailable", "permission-denied", "error"].includes(state);
  const displayedValue = deferred ? metricValueForState({ state, value: "" }) : value;
  const displayedDetail = metricDetailForState({ state, detail: typeof detail === "string" ? detail : undefined });
  return (
    <div className={`surface-panel border-l-[3px] ${accents[stateIntent[state]]} p-4`}>
      <div className="text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">{label}</div>
      <div className="mt-2 break-words text-2xl font-semibold text-[var(--text-primary)]">{displayedValue}</div>
      {(displayedDetail || detail) && <div className="mt-1.5 text-[13px] text-[var(--text-muted)]">{displayedDetail || detail}</div>}
    </div>
  );
}

export type AppliedFilter = {
  label: string;
  onClear: () => void;
  value: string;
};

export function AppliedFilterChips({
  filters,
  onClearAll,
}: {
  filters: AppliedFilter[];
  onClearAll?: () => void;
}) {
  const activeFilters = filters.filter((filter) => filter.value.trim());
  if (activeFilters.length === 0) return null;

  return (
    <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-[color:var(--border)] pt-3">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Applied filters</span>
      {activeFilters.map((filter) => (
        <button
          key={filter.label}
          type="button"
          onClick={filter.onClear}
          className="inline-flex max-w-full items-center gap-1.5 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-2.5 py-1 text-[12px] text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)]"
          aria-label={`Clear ${filter.label} filter`}
        >
          <span className="shrink-0 text-[var(--text-muted)]">{filter.label}</span>
          <span className="max-w-[18rem] truncate font-medium">{filter.value}</span>
          <span aria-hidden="true" className="text-[var(--text-muted)]">×</span>
        </button>
      ))}
      {onClearAll && activeFilters.length > 1 && (
        <button
          type="button"
          onClick={onClearAll}
          className="text-[12px] font-medium text-[var(--primary)] hover:text-[var(--primary-hover)]"
        >
          Clear all
        </button>
      )}
    </div>
  );
}

export function ProgressCard({
  title,
  percent,
  detail,
  total,
  href,
}: {
  title: string;
  percent: number;
  detail: string;
  total?: ReactNode;
  href?: string;
}) {
  const content = (
    <div className="surface-panel p-4 transition hover:border-[color:var(--ring)]">
      <div className="flex items-center justify-between">
        <div className="text-[13px] font-semibold text-[var(--text-primary)]">{title}</div>
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="h-4 w-4 text-[var(--text-muted)]">
          <path strokeLinecap="round" strokeLinejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5" />
        </svg>
      </div>
      <div className="mt-4 text-3xl font-semibold tracking-tight text-[var(--text-primary)]">{Math.round(percent)}%</div>
      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-[var(--surface-muted)]">
        <div
          className="h-full rounded-full bg-[var(--primary)] transition-all duration-500"
          style={{ width: `${Math.max(0, Math.min(100, percent))}%` }}
        />
      </div>
      <div className="mt-2 flex items-center justify-between text-[12px] text-[var(--text-muted)]">
        <span>{detail}</span>
        {total && <span>{total}</span>}
      </div>
    </div>
  );
  if (!href) return content;
  return <Link href={href}>{content}</Link>;
}

export function AttentionBanner({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-[13px] text-amber-900 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100">
      <div className="flex items-center gap-2.5">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="h-5 w-5 text-amber-600">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
        </svg>
        <span>{children}</span>
      </div>
      {action}
    </div>
  );
}

export function ResultLimitNotice({
  action,
  className = "",
  limit,
  loaded,
  meta,
  noun = "records",
}: {
  action?: ReactNode;
  className?: string;
  limit?: number;
  loaded: number;
  meta?: GRCListMeta;
  noun?: string;
}) {
  const copy = grcLoadedRowsCopy({ loaded, limit, meta, noun });
  return (
    <div data-grc-result-limit className={`flex flex-wrap items-center justify-between gap-3 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] text-[var(--text-muted)] ${className}`}>
      <span>{copy}</span>
      {action}
    </div>
  );
}

export function PageHeader({
  title,
  description,
  action,
  contractId,
}: {
  title: string;
  description: string;
  action?: ReactNode;
  contractId?: string;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4 pb-6" data-grc-page={contractId}>
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-[var(--text-primary)]">{title}</h1>
        <p className="mt-1 max-w-3xl text-[13px] leading-5 text-[var(--text-muted)]">{description}</p>
      </div>
      {action}
    </div>
  );
}

export function Panel({
  title,
  children,
  action,
}: {
  title: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className="surface-panel">
      <div className="flex items-center justify-between border-b border-[color:var(--border)] px-5 py-3.5">
        <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">{title}</h2>
        {action}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}

export function LoadingBlock({ label = "Loading..." }: { label?: string }) {
  return (
    <div className="surface-panel flex items-center gap-2.5 p-4 text-[13px] text-[var(--text-muted)]">
      <svg className="h-4 w-4 animate-spin text-[var(--primary)]" viewBox="0 0 24 24" fill="none">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
      </svg>
      {label}
    </div>
  );
}

export function DataStateBanner({
  className = "",
  detail,
  error,
  lastSuccessfulAt,
  onRetry,
  state,
  subject = "Graph data",
}: {
  className?: string;
  detail?: string;
  error?: string | null;
  lastSuccessfulAt?: number | null;
  onRetry?: () => void;
  state: RuntimeState;
  subject?: string;
}) {
  if (state === "ready" || state === "empty") return null;

  const lastLoaded = runtimeStateTimestamp(lastSuccessfulAt);
  const stateCopy: Record<RuntimeState, { label: string; description: string }> = {
    empty: { label: "No data", description: "No matching records were found." },
    error: { label: `Unable to load ${subject.toLowerCase()}`, description: detail || productErrorCopy(error, "This view could not load.") },
    loading: { label: `Loading ${subject.toLowerCase()}`, description: detail || "Fetching the latest records for this view." },
    partial: { label: `${subject} partially loaded`, description: detail || "Some records loaded, but one or more backing checks did not complete." },
    "permission-denied": { label: `${subject} access unavailable`, description: detail || runtimeStateDescription("permission-denied") },
    ready: { label: "Ready", description: "Data is current for this view." },
    stale: {
      label: `${subject} did not refresh`,
      description: detail || (lastLoaded ? `Showing last loaded results from ${lastLoaded}.` : runtimeStateDescription("stale")),
    },
    unavailable: { label: `${subject} unavailable`, description: detail || runtimeStateDescription("unavailable") },
  };
  const toneClasses: Record<RuntimeState, string> = {
    empty: "border-[color:var(--border)] bg-[var(--surface-muted)] text-[var(--text-muted)]",
    error: "border-red-200 bg-red-50 text-red-800 dark:border-red-500/25 dark:bg-red-500/10 dark:text-red-100",
    loading: "border-[color:var(--border)] bg-[var(--surface-muted)] text-[var(--text-secondary)]",
    partial: "border-amber-200 bg-amber-50 text-amber-950 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100",
    "permission-denied": "border-amber-200 bg-amber-50 text-amber-950 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100",
    ready: "border-emerald-200 bg-emerald-50 text-emerald-800",
    stale: "border-amber-200 bg-amber-50 text-amber-950 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100",
    unavailable: "border-amber-200 bg-amber-50 text-amber-950 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100",
  };
  const showHealth = state !== "loading";
  const copy = stateCopy[state];

  return (
    <div data-grc-data-state={state} className={`rounded-lg border px-4 py-3 text-[13px] ${toneClasses[state]} ${className}`}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 gap-3">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true">
            {state === "loading" ? (
              <>
                <circle className="opacity-25" cx="12" cy="12" r="9" stroke="currentColor" />
                <path className="opacity-75" strokeLinecap="round" strokeLinejoin="round" d="M12 3a9 9 0 0 1 9 9" />
              </>
            ) : state === "permission-denied" ? (
              <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 0 0-9 0v3.75m-.75 11.25h10.5A2.25 2.25 0 0 0 19.5 19.5v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
            ) : (
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
            )}
          </svg>
          <div className="min-w-0">
            <div className="font-semibold">{copy.label}</div>
            <div className="mt-1 leading-5 opacity-85">{copy.description}</div>
            {lastLoaded && state !== "stale" && (
              <div className="mt-2 text-[12px] opacity-75">Last loaded {lastLoaded}</div>
            )}
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {onRetry && state !== "loading" && (
            <button
              type="button"
              onClick={onRetry}
              className="inline-flex items-center gap-1.5 rounded-md border border-current/25 bg-white/80 px-3 py-1.5 text-[12px] font-medium transition hover:bg-white dark:bg-white/10 dark:hover:bg-white/15"
            >
              Retry
            </button>
          )}
          {showHealth && (
            <Link
              href="/developer#quick-status"
              className="inline-flex items-center gap-1.5 rounded-md border border-current/25 bg-white/80 px-3 py-1.5 text-[12px] font-medium transition hover:bg-white dark:bg-white/10 dark:hover:bg-white/15"
            >
              Health
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}

export function RuntimeRecoveryBlock({
  detail,
  onRetry,
  state,
}: {
  detail?: string;
  onRetry?: () => void;
  state: RuntimeState;
}) {
  return <DataStateBanner state={state} onRetry={onRetry} detail={detail} />;
}

export function ErrorBlock({
  error,
  onRetry,
  recoveryDetail,
}: {
  error: string;
  onRetry?: () => void;
  recoveryDetail?: string;
}) {
  const runtimeState = runtimeStateForError(error);
  const visibleCopy = productErrorCopy(error, recoveryDetail ?? "This view could not load.");

  if (runtimeState === "unavailable" || runtimeState === "permission-denied") {
    return <RuntimeRecoveryBlock state={runtimeState} onRetry={onRetry} detail={recoveryDetail} />;
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-red-200 bg-red-50 p-4 text-[13px] text-red-700 dark:border-red-500/25 dark:bg-red-500/10 dark:text-red-100">
      <div className="flex min-w-0 items-center gap-2.5">
      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="h-4 w-4">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 3.75h.008v.008H12v-.008Z" />
      </svg>
        <span>{visibleCopy}</span>
      </div>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center gap-1.5 rounded-md border border-red-200 bg-white px-3 py-1.5 text-[12px] font-medium text-red-700 transition hover:border-red-300 hover:bg-red-100 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-50 dark:hover:bg-red-500/20"
        >
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyBlock({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center rounded-lg border border-dashed border-[color:var(--border-strong)] p-8 text-[13px] text-[var(--text-muted)]">
      {label}
    </div>
  );
}
