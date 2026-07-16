import { describe, expect, it } from "vitest";

import { evidencePacketMetrics, evidenceReviewState } from "@/lib/evidence-packets";
import type { GRCEvidencePacketsResponse } from "@/lib/grc";

describe("evidencePacketMetrics", () => {
  it("summarizes packaged evidence workflow records", () => {
    const response = {
      program: { open_review_count: 2 },
      frameworks: [{ id: "fw" }],
      controls: [{ id: "control-1" }, { id: "control-2" }],
      evidence_requests: [
        { id: "request-1", status: "missing" },
        { id: "request-2", status: "stale" },
        { id: "request-3", status: "satisfied" },
      ],
      evidence_packets: [
        { id: "packet-1", status: "satisfied", review: { status: "ready" } },
        { id: "packet-2", status: "missing", review: { status: "needs_review" } },
      ],
      collection_sources: [{ id: "source-1", status: "collected" }],
      evidence_items: [{ id: "evidence-1" }],
      resource_subjects: [{ id: "resource-1" }],
      claim_records: [{ id: "claim-1" }],
      evaluation_runs: [{ id: "run-1" }],
      graph_path_records: [{ id: "path-1" }],
      questionnaire_answers: [{ id: "answer-1" }],
      evidence_lineage: [
        { id: "lineage-1", control_ids: ["control-1"], evidence_packet_ids: ["packet-1"] },
        { id: "lineage-2", control_ids: [], evidence_packet_ids: ["packet-2"] },
      ],
    } as unknown as GRCEvidencePacketsResponse;

    expect(evidencePacketMetrics(response)).toEqual({
      frameworks: 1,
      controls: 2,
      requests: 3,
      packets: 2,
      openReviews: 2,
      missingRequests: 1,
      staleRequests: 1,
      readyPackets: 1,
      sources: 1,
      evidenceItems: 1,
      resources: 1,
      lineage: 2,
      claims: 1,
      runs: 1,
      graphPaths: 1,
      collectedSources: 1,
      linkedLineage: 1,
      questionnaireAnswers: 1,
    });
  });
});

describe("evidenceReviewState", () => {
  it("groups review states for UI treatment", () => {
    expect(evidenceReviewState("ready")).toBe("ready");
    expect(evidenceReviewState("needs_review")).toBe("attention");
    expect(evidenceReviewState("rejected")).toBe("blocked");
    expect(evidenceReviewState("unknown")).toBe("neutral");
  });
});
