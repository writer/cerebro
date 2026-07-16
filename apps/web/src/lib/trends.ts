import type { GRCTrendPoint, GRCTrendSummary, GRCTrends } from "@/lib/grc";

export type TrendsSummary = {
  totalOpened: number;
  totalClosed: number;
  net: number;
  currentOpen: number;
  peakOpen: number;
  openedCritical: number;
  openedHigh: number;
  closedCritical: number;
  closedHigh: number;
  closedSLABreached: number;
  avgTimeToCloseSeconds: number;
  closedSLABreachedRate: number;
};

export type TrendSignal = {
  id: string;
  label: string;
  value: string;
  detail: string;
  intent: "neutral" | "danger" | "warning" | "success";
};

export type SeverityFlow = {
  severity: "CRITICAL" | "HIGH";
  label: string;
  opened: number;
  closed: number;
  net: number;
  closureRate: number;
};

const numberValue = (value: number | undefined): number => (Number.isFinite(value) ? Number(value) : 0);

const summaryFromResponse = (summary: GRCTrendSummary | undefined): TrendsSummary | null => {
  if (!summary) return null;
  const totalClosed = numberValue(summary.total_closed);
  const closedSLABreached = numberValue(summary.closed_sla_breached);
  return {
    totalOpened: numberValue(summary.total_opened),
    totalClosed,
    net: numberValue(summary.net),
    currentOpen: numberValue(summary.current_open),
    peakOpen: numberValue(summary.peak_open),
    openedCritical: numberValue(summary.opened_critical),
    openedHigh: numberValue(summary.opened_high),
    closedCritical: numberValue(summary.closed_critical),
    closedHigh: numberValue(summary.closed_high),
    closedSLABreached,
    avgTimeToCloseSeconds: numberValue(summary.avg_time_to_close_seconds),
    closedSLABreachedRate: Number.isFinite(summary.closed_sla_breached_rate) ? numberValue(summary.closed_sla_breached_rate) : totalClosed > 0 ? closedSLABreached / totalClosed : 0,
  };
};

export const summarizeTrends = (trends: GRCTrends | null | undefined): TrendsSummary => {
  const responseSummary = summaryFromResponse(trends?.summary);
  if (responseSummary) return responseSummary;

  const points = trends?.points ?? [];
  let totalOpened = 0;
  let totalClosed = 0;
  let openedCritical = 0;
  let openedHigh = 0;
  let closedCritical = 0;
  let closedHigh = 0;
  let closedSLABreached = 0;
  let timeToCloseTotal = 0;
  let timeToCloseCount = 0;
  let peakOpen = 0;
  for (const point of points) {
    totalOpened += point.opened;
    totalClosed += point.closed;
    openedCritical += point.opened_critical;
    openedHigh += point.opened_high;
    closedCritical += point.closed_critical ?? 0;
    closedHigh += point.closed_high ?? 0;
    closedSLABreached += point.closed_sla_breached ?? 0;
    if (point.closed > 0 && point.avg_time_to_close_seconds > 0) {
      timeToCloseTotal += point.avg_time_to_close_seconds * point.closed;
      timeToCloseCount += point.closed;
    }
    if (point.open_total > peakOpen) peakOpen = point.open_total;
  }
  const currentOpen = points.length > 0 ? points[points.length - 1].open_total : 0;
  return {
    totalOpened,
    totalClosed,
    net: totalOpened - totalClosed,
    currentOpen,
    peakOpen,
    openedCritical,
    openedHigh,
    closedCritical,
    closedHigh,
    closedSLABreached,
    avgTimeToCloseSeconds: timeToCloseCount > 0 ? timeToCloseTotal / timeToCloseCount : 0,
    closedSLABreachedRate: totalClosed > 0 ? closedSLABreached / totalClosed : 0,
  };
};

export const hasTrendActivity = (trends: GRCTrends | null | undefined): boolean =>
  (trends?.points ?? []).some((point) => point.opened > 0 || point.closed > 0);

const formatSignedInteger = (value: number): string => {
  if (!Number.isFinite(value) || value === 0) return "0";
  return `${value > 0 ? "+" : ""}${Math.round(value)}`;
};

export const formatTrendPercent = (value: number | undefined): string => {
  const percent = numberValue(value) * 100;
  if (percent <= 0) return "0%";
  if (percent < 10) return `${percent.toFixed(1)}%`;
  return `${Math.round(percent)}%`;
};

const signalIntentForRatio = (ratio: number): TrendSignal["intent"] => {
  if (ratio >= 1) return "success";
  if (ratio >= 0.8) return "warning";
  return "danger";
};

const targetIntent = (actual: number, target: number | undefined): TrendSignal["intent"] => {
  if (!target || target <= 0) return "neutral";
  if (actual <= target) return "success";
  if (actual <= target * 1.15) return "warning";
  return "danger";
};

const targetDetail = (actual: number, target: number | undefined, unit = ""): string => {
  if (!target || target <= 0) return `Current ${actual}${unit}`;
  const delta = actual - target;
  if (delta <= 0) return `${Math.abs(delta)}${unit} under target ${target}${unit}`;
  return `${delta}${unit} over target ${target}${unit}`;
};

const momentum = (points: GRCTrendPoint[]) => {
  if (points.length === 0) return { priorNet: 0, recentNet: 0, delta: 0 };
  const midpoint = Math.max(1, Math.floor(points.length / 2));
  const prior = points.slice(0, midpoint);
  const recent = points.slice(midpoint);
  const netFor = (slice: GRCTrendPoint[]) => slice.reduce((total, point) => total + point.opened - point.closed, 0);
  const priorNet = netFor(prior);
  const recentNet = netFor(recent.length > 0 ? recent : prior);
  return { priorNet, recentNet, delta: recentNet - priorNet };
};

export const buildTrendSignals = (trends: GRCTrends | null | undefined): TrendSignal[] => {
  const summary = summarizeTrends(trends);
  const targets = trends?.targets;
  const closureRatio = summary.totalOpened > 0 ? summary.totalClosed / summary.totalOpened : summary.totalClosed > 0 ? 1 : 0;
  const mttrTarget = targets?.mttr_seconds;
  const backlogTarget = targets?.backlog;
  const flowMomentum = momentum(trends?.points ?? []);

  return [
    {
      id: "closure-ratio",
      label: "Closure ratio",
      value: formatTrendPercent(closureRatio),
      detail: `${summary.totalClosed} closed / ${summary.totalOpened} opened`,
      intent: summary.totalOpened === 0 && summary.totalClosed === 0 ? "neutral" : signalIntentForRatio(closureRatio),
    },
    {
      id: "backlog-target",
      label: "Backlog target",
      value: backlogTarget && backlogTarget > 0 ? formatSignedInteger(summary.currentOpen - backlogTarget) : String(summary.currentOpen),
      detail: targetDetail(summary.currentOpen, backlogTarget),
      intent: targetIntent(summary.currentOpen, backlogTarget),
    },
    {
      id: "sla-miss-rate",
      label: "SLA miss rate",
      value: formatTrendPercent(summary.closedSLABreachedRate),
      detail: `${summary.closedSLABreached} late / ${summary.totalClosed} closed`,
      intent: summary.closedSLABreached === 0 ? "success" : summary.closedSLABreachedRate <= 0.1 ? "warning" : "danger",
    },
    {
      id: "mttr",
      label: "MTTR",
      value: formatTrendDuration(summary.avgTimeToCloseSeconds),
      detail: mttrTarget && mttrTarget > 0 ? `target ${formatTrendDuration(mttrTarget)}` : "closed finding average",
      intent: targetIntent(summary.avgTimeToCloseSeconds, mttrTarget),
    },
    {
      id: "momentum",
      label: "Recent momentum",
      value: formatSignedInteger(flowMomentum.delta),
      detail: `recent net ${formatSignedInteger(flowMomentum.recentNet)} vs prior ${formatSignedInteger(flowMomentum.priorNet)}`,
      intent: flowMomentum.delta < 0 ? "success" : flowMomentum.delta > 0 ? "warning" : "neutral",
    },
  ];
};

export const buildSeverityFlow = (summary: TrendsSummary): SeverityFlow[] => [
  {
    severity: "CRITICAL",
    label: "Critical",
    opened: summary.openedCritical,
    closed: summary.closedCritical,
    net: summary.openedCritical - summary.closedCritical,
    closureRate: summary.openedCritical > 0 ? summary.closedCritical / summary.openedCritical : summary.closedCritical > 0 ? 1 : 0,
  },
  {
    severity: "HIGH",
    label: "High",
    opened: summary.openedHigh,
    closed: summary.closedHigh,
    net: summary.openedHigh - summary.closedHigh,
    closureRate: summary.openedHigh > 0 ? summary.closedHigh / summary.openedHigh : summary.closedHigh > 0 ? 1 : 0,
  },
];

export const formatTrendDate = (iso: string): string => {
  const date = new Date(`${iso}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
};

export const formatTrendDuration = (seconds: number | undefined): string => {
  const value = Number(seconds ?? 0);
  if (!Number.isFinite(value) || value <= 0) return "—";
  const days = value / 86400;
  if (days >= 1) return `${days < 10 ? days.toFixed(1) : Math.round(days)}d`;
  const hours = value / 3600;
  if (hours >= 1) return `${hours < 10 ? hours.toFixed(1) : Math.round(hours)}h`;
  return `${Math.max(1, Math.round(value / 60))}m`;
};

export const trendBucketEndDate = (iso: string, interval: string): string => {
  const date = new Date(`${iso}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return iso;
  if (interval === "month") date.setUTCMonth(date.getUTCMonth() + 1);
  else date.setUTCDate(date.getUTCDate() + (interval === "week" ? 7 : 1));
  return date.toISOString().slice(0, 10);
};

const csvCell = (value: string | number | undefined) => `"${String(value ?? "").replaceAll("\"", "\"\"")}"`;

export const trendsToCSV = (trends: GRCTrends): string => {
  const columns = [
    "date",
    "opened",
    "opened_critical",
    "opened_high",
    "closed",
    "closed_critical",
    "closed_high",
    "closed_sla_breached",
    "avg_time_to_close_seconds",
    "open_total",
  ];
  const rows = (trends.points ?? []).map((point: GRCTrendPoint) => columns.map((key) => csvCell(point[key as keyof GRCTrendPoint] as string | number | undefined)).join(","));
  return [columns.join(","), ...rows].join("\n");
};

export const downloadTrendsCSV = (trends: GRCTrends, filename: string) => {
  const blob = new Blob([trendsToCSV(trends)], { type: "text/csv;charset=utf-8" });
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.URL.revokeObjectURL(url);
};

export const downloadTrendPNG = async (container: HTMLElement | null, filename: string): Promise<boolean> => {
  const svg = container?.querySelector("svg");
  if (!svg) return false;
  const serializer = new XMLSerializer();
  const svgText = serializer.serializeToString(svg);
  const svgBlob = new Blob([svgText], { type: "image/svg+xml;charset=utf-8" });
  const url = window.URL.createObjectURL(svgBlob);
  const image = new Image();
  const loaded = new Promise<boolean>((resolve) => {
    image.onload = () => resolve(true);
    image.onerror = () => resolve(false);
  });
  image.src = url;
  if (!(await loaded)) {
    window.URL.revokeObjectURL(url);
    return false;
  }
  const bounds = svg.getBoundingClientRect();
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.ceil(bounds.width));
  canvas.height = Math.max(1, Math.ceil(bounds.height));
  const context = canvas.getContext("2d");
  if (!context) {
    window.URL.revokeObjectURL(url);
    return false;
  }
  context.fillStyle = "#ffffff";
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.drawImage(image, 0, 0, canvas.width, canvas.height);
  window.URL.revokeObjectURL(url);
  const pngUrl = canvas.toDataURL("image/png");
  const anchor = document.createElement("a");
  anchor.href = pngUrl;
  anchor.download = filename;
  anchor.click();
  return true;
};
