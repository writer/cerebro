import type { GRCReportMetadata } from "@/lib/grc";

export type ReportRedactionMode = "share_safe" | "internal";

const sensitivePatterns: Array<[RegExp, string]> = [
  [/urn:cerebro:[^\s,)\]}|]+/g, "[resource]"],
  [/arn:[A-Za-z0-9_:/+=,.@-]+/g, "[resource]"],
  [/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[identity]"],
  [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[network]"],
  [/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, "[id]"],
  [/\b[a-f0-9]{32,}\b/gi, "[id]"],
  [/\b\d{12,}\b/g, "[id]"],
  [/\b(?:i|sg|subnet|vpc|eni|vol|snap|ami|rtb|acl)-[a-f0-9]{8,}\b/gi, "[resource]"],
  [/\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){2,}\b/gi, "[resource]"],
  [/\b(?:runtime|source|finding|evidence|event)-[A-Za-z0-9_.:-]+\b/g, "[id]"],
];

export const reportRedactionMode = (metadata?: GRCReportMetadata): ReportRedactionMode =>
  metadata?.redaction?.default_mode === "internal" ? "internal" : "share_safe";

export const redactReportText = (value: string, mode: ReportRedactionMode) => {
  if (mode === "internal") return value;
  return sensitivePatterns.reduce((text, [pattern, replacement]) => text.replace(pattern, replacement), value);
};

export const redactReportIdentifier = (value: string | undefined, mode: ReportRedactionMode, replacement = "[id]") => {
  const text = value?.trim() ?? "";
  if (!text || mode === "internal") return text;
  return replacement;
};

export const reportReadinessIntent = (status?: string): "danger" | "warning" | "success" | "neutral" => {
  switch ((status ?? "").toLowerCase()) {
    case "blocked":
      return "danger";
    case "needs_attention":
      return "warning";
    case "ready":
      return "success";
    default:
      return "neutral";
  }
};

export const reportReadinessLabel = (status?: string) => {
  switch ((status ?? "").toLowerCase()) {
    case "blocked":
      return "Blocked";
    case "needs_attention":
      return "Needs attention";
    case "ready":
      return "Ready";
    default:
      return "Unknown";
  }
};
