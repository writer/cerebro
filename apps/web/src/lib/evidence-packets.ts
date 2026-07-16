import type { GRCEvidencePacketsResponse } from "@/lib/grc";

export type EvidencePacketMetrics = {
  frameworks: number;
  controls: number;
  requests: number;
  packets: number;
  openReviews: number;
  missingRequests: number;
  staleRequests: number;
  readyPackets: number;
  sources: number;
  evidenceItems: number;
  resources: number;
  lineage: number;
  claims: number;
  runs: number;
  graphPaths: number;
  collectedSources: number;
  linkedLineage: number;
  questionnaireAnswers: number;
};

export const evidencePacketMetrics = (response?: GRCEvidencePacketsResponse | null): EvidencePacketMetrics => {
  const requests = response?.evidence_requests ?? [];
  const packets = response?.evidence_packets ?? [];
  const sources = response?.collection_sources ?? [];
  const lineage = response?.evidence_lineage ?? [];
  return {
    frameworks: response?.frameworks?.length ?? 0,
    controls: response?.controls?.length ?? 0,
    requests: requests.length,
    packets: packets.length,
    openReviews: response?.program?.open_review_count ?? 0,
    missingRequests: requests.filter((request) => (request.status ?? "").toLowerCase() === "missing").length,
    staleRequests: requests.filter((request) => (request.status ?? "").toLowerCase() === "stale").length,
    readyPackets: packets.filter((packet) => ["ready", "satisfied", "passing"].includes((packet.status ?? "").toLowerCase())).length,
    sources: sources.length,
    evidenceItems: response?.evidence_items?.length ?? 0,
    resources: response?.resource_subjects?.length ?? 0,
    lineage: lineage.length,
    claims: response?.claim_records?.length ?? 0,
    runs: response?.evaluation_runs?.length ?? 0,
    graphPaths: response?.graph_path_records?.length ?? 0,
    collectedSources: sources.filter((source) => source.status === "collected").length,
    linkedLineage: lineage.filter((item) => (item.evidence_packet_ids?.length ?? 0) > 0 && (item.control_ids?.length ?? 0) > 0).length,
    questionnaireAnswers: response?.questionnaire_answers?.length ?? 0,
  };
};

export const evidencePacketReadinessLabel = (status?: string) => {
  switch ((status ?? "").toLowerCase()) {
    case "ready":
      return "Ready";
    case "blocked":
      return "Blocked";
    case "needs_attention":
      return "Needs attention";
    default:
      return status || "Unknown";
  }
};

export const evidenceReviewState = (status?: string): "ready" | "attention" | "blocked" | "neutral" => {
  switch ((status ?? "").toLowerCase()) {
    case "ready":
    case "accepted":
    case "not_required":
      return "ready";
    case "missing":
    case "blocked":
    case "rejected":
      return "blocked";
    case "needs_review":
    case "flagged":
    case "stale":
      return "attention";
    default:
      return "neutral";
  }
};
