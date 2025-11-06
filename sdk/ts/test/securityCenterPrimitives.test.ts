import { describe, expect, it } from "vitest";

import {
  evaluateEvidenceLifecycle,
  summarizeEvidenceSet,
  extractEvidenceArtifacts,
  type EvidenceArtifact,
} from "../src/securityCenter/primitives.js";

describe("security center evidence primitives", () => {
  it("evaluates lifecycle states with policy thresholds", () => {
    const artifact: EvidenceArtifact = {
      id: "artifact-1",
      entityId: "vendor-1",
      source: "metadata",
      collectedAt: new Date("2024-09-01T00:00:00Z"),
      expiresAt: new Date("2024-12-01T00:00:00Z"),
      labels: ["soc2"],
      metadata: {},
      contentType: "application/json",
    };

    const lifecycle = evaluateEvidenceLifecycle(artifact, { maxAgeDays: 30, refreshWindowDays: 15 }, new Date("2024-10-15T00:00:00Z"));
    expect(lifecycle.status).toBe("stale");
    expect(lifecycle.requiresAction).toBe(true);
    expect(lifecycle.nextRefreshAt?.toISOString()).toContain("2024-12-01");
  });

  it("summarizes evidence sets and dedupes artifacts", () => {
    const artifacts: EvidenceArtifact[] = [
      {
        id: "artifact-1",
        entityId: "vendor-1",
        source: "metadata",
        collectedAt: new Date("2024-09-01T00:00:00Z"),
        expiresAt: new Date("2024-09-30T00:00:00Z"),
        labels: [],
        metadata: {},
        contentType: "application/json",
      },
      {
        id: "artifact-1",
        entityId: "vendor-1",
        source: "metadata",
        collectedAt: new Date("2024-09-01T00:00:00Z"),
        expiresAt: new Date("2024-09-30T00:00:00Z"),
        labels: [],
        metadata: {},
        contentType: "application/json",
      },
    ];

    const summary = summarizeEvidenceSet(artifacts, { maxAgeDays: 10 }, new Date("2024-10-05T00:00:00Z"));
    expect(summary.status).toBe("expired");
    expect(summary.expiredArtifacts).toHaveLength(1);
    expect(summary.lifecycle).toHaveLength(1);
  });

  it("extracts artifacts from nested metadata structures", () => {
    const artifacts = extractEvidenceArtifacts({
      kind: "vendor",
      entityId: "vendor-1",
      metadata: {
        evidence: {
          id: "primary",
          collected_at: "2024-09-01T00:00:00Z",
          expires_at: "2024-12-01T00:00:00Z",
          tags: { control: "cc-2.1" },
        },
        attachments: [
          {
            id: "attachment-1",
            source: "pentest",
            collectedAt: "2024-08-01T00:00:00Z",
            expiresAt: "2025-08-01T00:00:00Z",
            labels: ["pentest"],
          },
        ],
      },
    });

    expect(artifacts).toHaveLength(2);
    expect(artifacts[0].id).toBe("primary");
    expect(artifacts[1].source).toBe("pentest");
  });
});
