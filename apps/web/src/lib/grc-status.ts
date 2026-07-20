export const defaultBadgeClass =
  "bg-stone-100 text-stone-600 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-200 dark:ring-stone-500/25";

export const severityBadgeClasses: Record<string, string> = {
  CRITICAL: "bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-500/15 dark:text-red-200 dark:ring-red-500/25",
  HIGH: "bg-orange-50 text-orange-700 ring-1 ring-inset ring-orange-200 dark:bg-orange-500/15 dark:text-orange-200 dark:ring-orange-500/25",
  MEDIUM: "bg-amber-50 text-amber-700 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-200 dark:ring-amber-500/25",
  LOW: "bg-blue-50 text-blue-700 ring-1 ring-inset ring-blue-200 dark:bg-blue-500/15 dark:text-blue-200 dark:ring-blue-500/25",
};

export const statusBadgeClasses: Record<string, string> = {
  OPEN: "bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-500/15 dark:text-red-200 dark:ring-red-500/25",
  RESOLVED: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:ring-emerald-500/25",
  SUPPRESSED: "bg-stone-100 text-stone-600 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-200 dark:ring-stone-500/25",
  failing: "bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-500/15 dark:text-red-200 dark:ring-red-500/25",
  blocked: "bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-500/15 dark:text-red-200 dark:ring-red-500/25",
  passing: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:ring-emerald-500/25",
  missing_evidence: "bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-100 dark:ring-amber-500/25",
  stale_evidence: "bg-orange-50 text-orange-800 ring-1 ring-inset ring-orange-200 dark:bg-orange-500/15 dark:text-orange-100 dark:ring-orange-500/25",
  manual_review: "bg-blue-50 text-blue-700 ring-1 ring-inset ring-blue-200 dark:bg-blue-500/15 dark:text-blue-200 dark:ring-blue-500/25",
  needs_review: "bg-blue-50 text-blue-700 ring-1 ring-inset ring-blue-200 dark:bg-blue-500/15 dark:text-blue-200 dark:ring-blue-500/25",
  exception: "bg-stone-100 text-stone-700 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-100 dark:ring-stone-500/25",
  not_applicable: "bg-stone-100 text-stone-600 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-200 dark:ring-stone-500/25",
  satisfied: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:ring-emerald-500/25",
  strong: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:ring-emerald-500/25",
  partial: "bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-100 dark:ring-amber-500/25",
  missing: "bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-100 dark:ring-amber-500/25",
  manual: "bg-blue-50 text-blue-700 ring-1 ring-inset ring-blue-200 dark:bg-blue-500/15 dark:text-blue-200 dark:ring-blue-500/25",
  optional: "bg-stone-100 text-stone-600 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-200 dark:ring-stone-500/25",
  upcoming: "bg-violet-50 text-violet-700 ring-1 ring-inset ring-violet-200 dark:bg-violet-500/15 dark:text-violet-100 dark:ring-violet-500/25",
  ok: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:ring-emerald-500/25",
  healthy: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:ring-emerald-500/25",
  ready: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:ring-emerald-500/25",
  stale: "bg-amber-50 text-amber-700 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-200 dark:ring-amber-500/25",
  needs_refresh: "bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-100 dark:ring-amber-500/25",
  poor: "bg-orange-50 text-orange-800 ring-1 ring-inset ring-orange-200 dark:bg-orange-500/15 dark:text-orange-100 dark:ring-orange-500/25",
  bad: "bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-500/15 dark:text-red-200 dark:ring-red-500/25",
  not_configured: "bg-stone-100 text-stone-600 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-200 dark:ring-stone-500/25",
  current: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:ring-emerald-500/25",
  behind: "bg-amber-50 text-amber-700 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-200 dark:ring-amber-500/25",
  running: "bg-blue-50 text-blue-700 ring-1 ring-inset ring-blue-200 dark:bg-blue-500/15 dark:text-blue-200 dark:ring-blue-500/25",
  pending: "bg-amber-50 text-amber-700 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-200 dark:ring-amber-500/25",
  caught_up: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:ring-emerald-500/25",
  failed: "bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-500/15 dark:text-red-200 dark:ring-red-500/25",
  not_observed: "bg-stone-100 text-stone-600 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-200 dark:ring-stone-500/25",
  graph_current: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:ring-emerald-500/25",
  graph_behind: "bg-amber-50 text-amber-700 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-200 dark:ring-amber-500/25",
  graph_running: "bg-blue-50 text-blue-700 ring-1 ring-inset ring-blue-200 dark:bg-blue-500/15 dark:text-blue-200 dark:ring-blue-500/25",
  graph_failed: "bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-500/15 dark:text-red-200 dark:ring-red-500/25",
  graph_unknown: "bg-stone-100 text-stone-600 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-200 dark:ring-stone-500/25",
  overdue: "bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-500/15 dark:text-red-200 dark:ring-red-500/25",
  in_triage: "bg-blue-50 text-blue-700 ring-1 ring-inset ring-blue-200 dark:bg-blue-500/15 dark:text-blue-200 dark:ring-blue-500/25",
  risk_accepted: "bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-100 dark:ring-amber-500/25",
  false_positive: "bg-stone-100 text-stone-600 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-200 dark:ring-stone-500/25",
  due_soon: "bg-amber-50 text-amber-700 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-200 dark:ring-amber-500/25",
  on_track: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:ring-emerald-500/25",
  no_due_date: "bg-stone-100 text-stone-600 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-200 dark:ring-stone-500/25",
};

export const riskBadgeClasses: Record<string, string> = {
  critical: "bg-red-50 text-red-800 ring-1 ring-inset ring-red-200 dark:bg-red-500/15 dark:text-red-100 dark:ring-red-500/25",
  high: "bg-orange-50 text-orange-800 ring-1 ring-inset ring-orange-200 dark:bg-orange-500/15 dark:text-orange-100 dark:ring-orange-500/25",
  medium: "bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-100 dark:ring-amber-500/25",
  low: "bg-blue-50 text-blue-800 ring-1 ring-inset ring-blue-200 dark:bg-blue-500/15 dark:text-blue-100 dark:ring-blue-500/25",
  unknown: "bg-stone-100 text-stone-600 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-200 dark:ring-stone-500/25",
};

export const severityDotClasses: Record<string, string> = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-amber-500",
  LOW: "bg-blue-500",
};

export const badgeClassFor = (value: string, tone: "severity" | "status" = "status") => {
  const upper = value?.toUpperCase();
  return (
    (tone === "severity" ? severityBadgeClasses[upper] : statusBadgeClasses[value]) ??
    statusBadgeClasses[upper] ??
    defaultBadgeClass
  );
};

export const riskBadgeClassFor = (level: string) =>
  riskBadgeClasses[level.toLowerCase()] ?? riskBadgeClasses.unknown;

export const severityDotClassFor = (severity: string) =>
  severityDotClasses[severity?.toUpperCase()] ?? "bg-slate-400";
