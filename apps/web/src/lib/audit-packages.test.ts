import { describe, expect, it } from "vitest";

import {
  auditEvidenceDecision,
  auditEvidenceScope,
  auditEvidenceVisibility,
  buildActionableControlOwnerRows,
  buildAuditExportManifestRows,
  buildAuditPackageSummary,
  buildAuditPriorityWorkRows,
  buildAuditReadinessRows,
  buildAuditStatusLedgerRows,
  buildAuditorQuestionRows,
  buildEvidenceCurationRows,
  buildScopeExceptionRows,
  type AuditPackageSummary,
  type ControlOwnerRow,
  type EvidenceCurationRow,
  type SourceTrustRow,
} from "@/lib/audit-packages";
import type { GRCControlEvidencePacketResponse, GRCEvidencePacketsResponse } from "@/lib/grc";

const packet = (overrides: Partial<GRCControlEvidencePacketResponse> = {}): GRCControlEvidencePacketResponse => ({
  profile: { id: "baseline", name: "Baseline" },
  packet: {
    version: "test",
    generated_at: "2026-01-01T00:00:00Z",
    summary: {
      total: 2,
      by_status: {
        failing: 1,
        missing_evidence: 1,
        stale_evidence: 0,
      },
    },
    controls: [],
  },
  controls: [],
  generated_at: "2026-01-01T00:00:00Z",
  ...overrides,
});

const summary = (overrides: Partial<AuditPackageSummary> = {}): AuditPackageSummary => ({
  controls: 4,
  evidenceItems: 6,
  exclusions: 0,
  failingControls: 0,
  missingEvidence: 0,
  openReviews: 0,
  readinessScore: 92,
  sourceCount: 2,
  staleEvidence: 0,
  staleSources: 0,
  state: "approved",
  ...overrides,
});

describe("audit package helpers", () => {
  it("classifies stale and rejected evidence before included evidence", () => {
    expect(auditEvidenceDecision({ status: "ready", quality: "stale" })).toBe("needs_replacement");
    expect(auditEvidenceDecision({ status: "ready", reviewStatus: "rejected" })).toBe("rejected");
    expect(auditEvidenceDecision({ status: "ready", quality: "ready" })).toBe("included");
    expect(auditEvidenceDecision({ status: "ready_for_auditor" })).toBe("included");
  });

  it("separates evidence scope from review visibility", () => {
    expect(auditEvidenceScope("excluded")).toBe("excluded");
    expect(auditEvidenceScope("internal_only")).toBe("internal_only");
    expect(auditEvidenceScope("accepted")).toBe("included");
    expect(auditEvidenceVisibility({ decision: "accepted", owner: "Security", reviewStatus: "accepted", status: "ready" })).toBe("ready_for_auditor");
    expect(auditEvidenceVisibility({ decision: "accepted", owner: "", reviewStatus: "accepted", status: "ready" })).toBe("needs_owner");
    expect(auditEvidenceVisibility({ decision: "included", owner: "Security", reviewStatus: "needs_review", status: "ready" })).toBe("needs_reviewer");
    expect(auditEvidenceVisibility({ decision: "internal_only", owner: "Security", status: "internal_only" })).toBe("internal_only");
  });

  it("marks packages with failing controls or missing evidence as needing evidence", () => {
    expect(buildAuditPackageSummary({ controlPacket: packet() })).toMatchObject({
      controls: 2,
      failingControls: 1,
      missingEvidence: 1,
      state: "needs_evidence",
    });
  });

  it("marks otherwise complete packages stale when sources are stale", () => {
    expect(buildAuditPackageSummary({
      controlPacket: packet({
        packet: {
          version: "test",
          generated_at: "2026-01-01T00:00:00Z",
          summary: { total: 1, by_status: { failing: 0, missing_evidence: 0, stale_evidence: 0 } },
          controls: [],
        },
        metadata: {
          readiness: { status: "ready", score: 94 },
          provenance: { report_type: "control", generated_at: "2026-01-01T00:00:00Z" },
          redaction: { default_mode: "share_safe" },
          scope: {
            exclusions: { total: 0, applied_to_incremental_fetch: true, filtered_before_graph_projection: true },
            incremental_fetch: { status: "ready", policy_applied_before_read: true, event_filtering_before_projection: true },
          },
        },
      }),
      dashboard: {
        summary: {
          open_findings: 0,
          critical_findings: 0,
          high_findings: 0,
          overdue_findings: 0,
          unassigned: 0,
          controls_failing: 0,
          evidence_items: 0,
          connectors: 1,
          stale_connectors: 1,
        },
        findings: [],
        controls: [],
        evidence: [],
        connectors: [{ runtime_id: "runtime-1", source_id: "github", status: "healthy", freshness: "stale" }],
        generated_at: "2026-01-01T00:00:00Z",
      },
    })).toMatchObject({
      readinessScore: 94,
      staleSources: 1,
      state: "stale",
    });
  });

  it("flattens package scope exclusions into operator rows", () => {
    const rows = buildScopeExceptionRows({
      readiness: { status: "ready", score: 90 },
      provenance: { report_type: "control", generated_at: "2026-01-01T00:00:00Z" },
      redaction: { default_mode: "share_safe" },
      scope: {
        exclusions: {
          total: 2,
          excluded_families: ["support"],
          excluded_resources: [{ type: "asset", id: "asset-1", reason: "Support asset" }],
          applied_to_incremental_fetch: true,
          filtered_before_graph_projection: true,
        },
        incremental_fetch: { status: "ready", policy_applied_before_read: true, event_filtering_before_projection: true },
      },
    });

    expect(rows).toEqual([
      expect.objectContaining({ kind: "Family", value: "support" }),
      expect.objectContaining({ kind: "asset", reason: "Support asset", value: "asset-1" }),
    ]);
  });

  it("builds readiness rows that separate blocked, review, waiting, and ready work", () => {
    const rows = buildAuditReadinessRows(summary({
      failingControls: 1,
      missingEvidence: 2,
      openReviews: 1,
      staleEvidence: 1,
      staleSources: 1,
      state: "needs_review",
    }), "snapshot-123", "");

    expect(rows).toEqual([
      expect.objectContaining({ action: "Collect evidence", id: "evidence", state: "blocked", title: "Evidence set" }),
      expect.objectContaining({ action: "Resolve controls", id: "controls", state: "blocked" }),
      expect.objectContaining({ action: "Complete reviews", id: "reviews", state: "needs_review" }),
      expect.objectContaining({ action: "Refresh sources", id: "sources", state: "blocked" }),
      expect.objectContaining({ action: "Approve snapshot", detail: "Snapshot snapshot-123", id: "snapshot", state: "waiting", title: "Shared snapshot" }),
    ]);

    expect(buildAuditReadinessRows(summary(), "snapshot-456", "2026-01-01T00:00:00Z").at(-1)).toMatchObject({
      action: "Share snapshot",
      state: "ready",
    });
  });

  it("carries packet reasons into evidence review rows", () => {
    const rows = buildEvidenceCurationRows({
      evidencePackets: {
        evidence_requests: [
          {
            control_id: "SOC 2 CC6.1",
            evidence_packet_ids: ["packet-1"],
            id: "request-1",
            quality: "ready",
            required: true,
            review_status: "accepted",
            owner_domain: "Security",
            status: "ready",
            title: "Access review",
          },
        ],
        evidence_packets: [
          {
            citations: {},
            export_artifact: { format: "markdown" },
            freshness: { status: "fresh" },
            id: "packet-1",
            reason: "Runtime export includes the control test and source event.",
            review: { id: "review-1", subject_id: "packet-1", status: "accepted", actor: "auditor@example.com" },
            request_id: "request-1",
            status: "ready",
          },
        ],
      } as GRCEvidencePacketsResponse,
    });

    expect(rows[0]).toMatchObject({
      decision: "accepted",
      owner: "Security",
      packets: 1,
      reason: "Runtime export includes the control test and source event.",
      reviewer: "auditor@example.com",
      scope: "included",
      visibility: "ready_for_auditor",
    });
  });

  it("carries visibility blockers and reviewers into evidence rows", () => {
    const rows = buildEvidenceCurationRows({
      evidencePackets: {
        evidence_requests: [
          {
            control_id: "SOC 2 CC6.1",
            evidence_packet_ids: ["packet-owner"],
            id: "request-owner",
            quality: "ready",
            required: true,
            review_status: "accepted",
            status: "ready",
            title: "Access review",
          },
          {
            control_id: "SOC 2 CC7.2",
            evidence_packet_ids: ["packet-review"],
            id: "request-review",
            owner_domain: "Security",
            quality: "ready",
            required: true,
            review_status: "needs_review",
            status: "ready",
            title: "Log review",
          },
          {
            control_id: "SOC 2 CC8.1",
            evidence_packet_ids: ["packet-internal"],
            id: "request-internal",
            owner_domain: "Security",
            quality: "ready",
            required: true,
            review_status: "accepted",
            status: "internal_only",
            title: "Internal memo",
          },
          {
            control_id: "SOC 2 CC9.1",
            id: "request-excluded",
            owner_domain: "Security",
            quality: "ready",
            required: false,
            review_status: "accepted",
            status: "out_of_scope",
            title: "Excluded evidence",
          },
        ],
        evidence_packets: [
          {
            citations: {},
            export_artifact: { format: "markdown" },
            freshness: { status: "fresh" },
            id: "packet-owner",
            request_id: "request-owner",
            status: "ready",
          },
          {
            citations: {},
            export_artifact: { format: "markdown" },
            freshness: { status: "fresh" },
            id: "packet-review",
            request_id: "request-review",
            review: { id: "review-2", subject_id: "packet-review", status: "needs_review", actor: "reviewer@example.com" },
            status: "ready",
          },
          {
            citations: {},
            export_artifact: { format: "markdown" },
            freshness: { status: "fresh" },
            id: "packet-internal",
            request_id: "request-internal",
            status: "internal_only",
          },
        ],
      } as GRCEvidencePacketsResponse,
    });

    expect(rows).toEqual([
      expect.objectContaining({ id: "request-owner", owner: "Unassigned", scope: "included", visibility: "needs_owner" }),
      expect.objectContaining({ id: "request-review", reviewer: "reviewer@example.com", scope: "included", visibility: "needs_reviewer" }),
      expect.objectContaining({ id: "request-internal", scope: "internal_only", visibility: "internal_only" }),
      expect.objectContaining({ id: "request-excluded", scope: "excluded", visibility: "excluded" }),
    ]);
  });

  it("derives evidence reasons when packet records do not provide one", () => {
    const rows = buildEvidenceCurationRows({
      evidencePackets: {
        evidence_requests: [
          {
            control_id: "SOC 2 CC6.1",
            id: "request-missing",
            quality: "missing",
            required: true,
            review_status: "needs_review",
            status: "missing",
            title: "Access review",
          },
          {
            accepted_from: ["runtime"],
            control_id: "SOC 2 CC7.2",
            evidence_packet_ids: ["packet-stale"],
            freshness_sla: "30d",
            id: "request-stale",
            quality: "stale",
            required: true,
            review_status: "needs_review",
            status: "stale",
            title: "Log evidence",
          },
          {
            accepted_from: ["upload"],
            control_id: "SOC 2 CC8.1",
            evidence_packet_ids: ["packet-review"],
            id: "request-review",
            quality: "ready",
            required: true,
            review_status: "needs_review",
            status: "ready",
            title: "Change record",
          },
        ],
        evidence_packets: [
          {
            citations: {},
            export_artifact: { format: "markdown" },
            freshness: { status: "stale" },
            id: "packet-stale",
            request_id: "request-stale",
            status: "needs_review",
          },
          {
            citations: {},
            export_artifact: { format: "markdown" },
            freshness: { status: "fresh" },
            id: "packet-review",
            request_id: "request-review",
            status: "needs_review",
          },
        ],
      } as GRCEvidencePacketsResponse,
    });

    expect(rows.map((row) => row.reason)).toEqual([
      "No packet is attached to this request.",
      "Evidence is stale against 30d freshness.",
      "Reviewer decision is pending.",
    ]);
  });

  it("queues reviewer questions from evidence gaps, owner work, and stale sources", () => {
    const evidenceRows: EvidenceCurationRow[] = [
      {
        controlID: "SOC 2 CC6.1",
        decision: "needs_review",
        freshness: "7d",
        id: "request-1",
        packets: 1,
        owner: "Security",
        quality: "ready",
        reason: "Reviewer decision is pending.",
        review: "manual_review",
        reviewer: "Unassigned",
        source: "GitHub",
        scope: "included",
        status: "needs_review",
        title: "Access review",
        visibility: "needs_reviewer",
      },
      {
        controlID: "SOC 2 CC7.1",
        decision: "included",
        freshness: "30d",
        id: "request-2",
        packets: 1,
        owner: "Security",
        quality: "ready",
        reason: "1 packet accepted from AWS.",
        review: "accepted",
        reviewer: "auditor@example.com",
        source: "AWS",
        scope: "included",
        status: "ready",
        title: "Cloud logs",
        visibility: "ready_for_auditor",
      },
    ];
    const ownerRows: ControlOwnerRow[] = [
      {
        action: "Add evidence",
        control: "SOC 2 CC6.1",
        evidence: "0/1",
        findings: 0,
        id: "soc2:cc6.1",
        missing: 1,
        owner: "Security",
        stale: 0,
        status: "failing",
        title: "Logical access",
      },
    ];
    const sourceRows: SourceTrustRow[] = [
      {
        action: "Repair source",
        evidence: 0,
        findings: 0,
        id: "jira:runtime-1",
        lastSynced: "2026-01-01T00:00:00Z",
        source: "Jira",
        status: "failed",
      },
      {
        action: "Use in packet",
        evidence: 4,
        findings: 1,
        id: "github:runtime-2",
        lastSynced: "2026-01-01T00:00:00Z",
        source: "GitHub",
        status: "healthy",
      },
    ];

    const rows = buildAuditorQuestionRows({ evidenceRows, ownerRows, sourceRows });

    expect(rows.map((row) => row.area)).toEqual(["Evidence", "Control", "Source"]);
    expect(rows[0]).toMatchObject({ owner: "GitHub", status: "Needs review" });
    expect(rows[0].source).toBe("Access review: Reviewer decision is pending.");
    expect(rows[1].question).toContain("SOC 2 CC6.1");
    expect(rows[2]).toMatchObject({ owner: "Jira", status: "Repair source" });
  });

  it("adds source provenance to evidence curation rows", () => {
    const rows = buildEvidenceCurationRows({
      evidencePackets: {
        evidence_requests: [
          {
            id: "request-1",
            control_id: "CC6.1",
            required: true,
            status: "ready",
            quality: "ready",
            review_status: "accepted",
            title: "MFA evidence",
            evidence_packet_ids: ["packet-1"],
          },
        ],
        evidence_packets: [
          {
            id: "packet-1",
            request_id: "request-1",
            status: "ready",
            quality: "ready",
            source: "okta-runtime",
            observed_at: "2026-01-02T00:00:00.000Z",
            citations: { evidence_ids: ["evidence-1"] },
            freshness: { status: "fresh", observed_at: "2026-01-02T00:00:00.000Z" },
            export_artifact: { format: "markdown" },
          },
        ],
        evidence_items: [
          {
            id: "evidence-1",
            runtime_id: "okta-runtime",
            source_id: "okta",
            last_observed_at: "2026-01-03T00:00:00.000Z",
            evidence_request_ids: ["request-1"],
            evidence_packet_ids: ["packet-1"],
          },
        ],
      } as GRCEvidencePacketsResponse,
    });

    expect(rows[0]).toMatchObject({
      collectedAt: "2026-01-03T00:00:00.000Z",
      runtimeID: "okta-runtime",
      sourceID: "okta",
      title: "MFA evidence",
    });
  });

  it("builds an export manifest with action states for package records", () => {
    const rows = buildAuditExportManifestRows({
      generatedAt: "",
      snapshotID: "snapshot-123",
      summary: summary({
        evidenceItems: 8,
        exclusions: 2,
        failingControls: 1,
        missingEvidence: 1,
        staleSources: 1,
        state: "stale",
      }),
    });

    expect(rows).toEqual([
      expect.objectContaining({ id: "snapshot", state: "Stale", value: "snapshot-123" }),
      expect.objectContaining({ id: "generated", state: "Not generated", value: "Not generated" }),
      expect.objectContaining({ id: "controls", state: "Action needed", value: 4 }),
      expect.objectContaining({ id: "evidence", state: "Missing evidence", value: 8 }),
      expect.objectContaining({ id: "sources", state: "Refresh needed", value: 2 }),
      expect.objectContaining({ id: "scope", state: "Documented", value: 2 }),
    ]);
  });

  it("filters owner queue rows to controls that need action", () => {
    const rows: ControlOwnerRow[] = [
      {
        action: "Keep current",
        control: "ISO 27001 A.5.15",
        evidence: "1/1",
        findings: 1,
        id: "iso:a.5.15",
        missing: 0,
        owner: "Platform",
        stale: 0,
        status: "passing",
        title: "Access control",
      },
      {
        action: "Keep current",
        control: "SOC 2 CC7.1",
        evidence: "1/1",
        findings: 0,
        id: "soc2:cc7.1",
        missing: 0,
        owner: "Security",
        stale: 0,
        status: "passing",
        title: "Detection control",
      },
      {
        action: "Refresh evidence",
        control: "SOC 2 CC7.2",
        evidence: "1/2",
        findings: 0,
        id: "soc2:cc7.2",
        missing: 0,
        owner: "AppSec",
        stale: 1,
        status: "manual_review",
        title: "Monitoring control",
      },
      {
        action: "Resolve mapped findings",
        control: "SOC 2 CC6.1",
        evidence: "0/1",
        findings: 1,
        id: "soc2:cc6.1",
        missing: 1,
        owner: "Security",
        stale: 0,
        status: "failing",
        title: "Access control",
      },
    ];

    expect(buildActionableControlOwnerRows(rows).map((row) => row.control)).toEqual([
      "SOC 2 CC6.1",
      "SOC 2 CC7.2",
    ]);
  });

  it("builds priority work rows from readiness, owner, and reviewer queues", () => {
    const readinessRows = buildAuditReadinessRows(summary({
      failingControls: 1,
      missingEvidence: 1,
      openReviews: 1,
      staleSources: 1,
      state: "needs_review",
    }), "snapshot-123", "");
    const ownerRows: ControlOwnerRow[] = [
      {
        action: "Add evidence",
        control: "SOC 2 CC6.1",
        evidence: "0/1",
        findings: 0,
        id: "soc2:cc6.1",
        missing: 1,
        owner: "Security",
        stale: 0,
        status: "failing",
        title: "Logical access",
      },
    ];
    const auditorQuestionRows = buildAuditorQuestionRows({
      evidenceRows: [
        {
          controlID: "SOC 2 CC6.1",
          decision: "needs_review",
          freshness: "7d",
          id: "request-1",
          packets: 1,
          owner: "Security",
          quality: "ready",
          reason: "Reviewer decision is pending.",
          review: "manual_review",
          reviewer: "Unassigned",
          source: "GitHub",
          scope: "included",
          status: "needs_review",
          title: "Access review",
          visibility: "needs_reviewer",
        },
      ],
      ownerRows,
      sourceRows: [],
    });

    const rows = buildAuditPriorityWorkRows({ auditorQuestionRows, ownerRows, readinessRows, limit: 8 });

    expect(rows[0]).toMatchObject({ area: "Packet gate", state: "Blocked", title: "Control status" });
    expect(rows).toEqual(expect.arrayContaining([
      expect.objectContaining({ href: "#control-owner-queue", id: "packet:controls" }),
      expect.objectContaining({ href: "#evidence-review", id: "packet:evidence" }),
      expect.objectContaining({ href: "#source-freshness", id: "packet:sources" }),
      expect.objectContaining({ href: "#reviewer-questions", id: "question:evidence:request-1" }),
    ]));
    expect(rows.map((row) => row.area)).toContain("Control");
    expect(rows.map((row) => row.area)).toContain("Evidence");
    expect(rows).toHaveLength(8);
  });

  it("builds a packet status ledger from gates, evidence, controls, and sources", () => {
    const readinessRows = buildAuditReadinessRows(summary({
      failingControls: 1,
      missingEvidence: 1,
      openReviews: 1,
      staleSources: 1,
      state: "needs_review",
    }), "snapshot-123", "");
    const evidenceRows: EvidenceCurationRow[] = [
      {
        controlID: "SOC 2 CC6.1",
        decision: "needs_review",
        freshness: "7d",
        id: "request-review",
        packets: 1,
        owner: "Security",
        quality: "ready",
        reason: "Reviewer decision is pending.",
        review: "manual_review",
        reviewer: "Unassigned",
        source: "GitHub",
        scope: "included",
        status: "needs_review",
        title: "Access review",
        visibility: "needs_reviewer",
      },
      {
        controlID: "SOC 2 CC7.1",
        decision: "included",
        freshness: "30d",
        id: "request-owner",
        packets: 1,
        owner: "Unassigned",
        quality: "ready",
        reason: "1 packet accepted from AWS.",
        review: "accepted",
        reviewer: "reviewer@example.com",
        source: "AWS",
        scope: "included",
        status: "ready",
        title: "Cloud logs",
        visibility: "needs_owner",
      },
    ];
    const ownerRows: ControlOwnerRow[] = [
      {
        action: "Add evidence",
        control: "SOC 2 CC6.1",
        evidence: "0/1",
        findings: 0,
        id: "soc2:cc6.1",
        missing: 1,
        owner: "Security",
        stale: 0,
        status: "failing",
        title: "Logical access",
      },
    ];
    const sourceRows: SourceTrustRow[] = [
      {
        action: "Repair source",
        evidence: 0,
        findings: 0,
        id: "jira:runtime-1",
        lastSynced: "2026-01-01T00:00:00Z",
        source: "Jira",
        status: "failed",
      },
    ];

    const rows = buildAuditStatusLedgerRows({
      evidenceRows,
      ownerRows,
      readinessRows,
      snapshotID: "snapshot-123",
      sourceRows,
      limit: 20,
    });

    expect(rows).toEqual(expect.arrayContaining([
      expect.objectContaining({ area: "Packet gate", href: "#control-owner-queue", id: "gate:controls", state: "blocked" }),
      expect.objectContaining({ action: "Assign evidence owner", href: "#evidence-review", id: "evidence:request-owner", owner: "Audit lead", state: "needs_owner" }),
      expect.objectContaining({ action: "Review evidence", id: "evidence:request-review", state: "needs_review" }),
      expect.objectContaining({ href: "#source-freshness", id: "source:jira:runtime-1", state: "blocked" }),
    ]));
    expect(rows[0].rank).toBeLessThanOrEqual(rows[1].rank);
  });

  it("returns a ready snapshot ledger row when no packet work is queued", () => {
    const rows = buildAuditStatusLedgerRows({
      evidenceRows: [
        {
          controlID: "SOC 2 CC6.1",
          decision: "accepted",
          freshness: "30d",
          id: "request-ready",
          packets: 1,
          owner: "Security",
          quality: "ready",
          reason: "1 packet accepted from AWS.",
          review: "accepted",
          reviewer: "reviewer@example.com",
          source: "AWS",
          scope: "included",
          status: "ready",
          title: "Cloud logs",
          visibility: "ready_for_auditor",
        },
      ],
      ownerRows: [],
      readinessRows: buildAuditReadinessRows(summary(), "snapshot-456", "2026-01-01T00:00:00Z"),
      snapshotID: "snapshot-456",
      sourceRows: [],
    });

    expect(rows).toEqual([
      expect.objectContaining({
        action: "Share snapshot",
        href: "#shared-snapshot",
        id: "snapshot:ready",
        proof: "All packet gates are ready.",
        state: "ready",
      }),
    ]);
  });
});
