import {
  displayDate,
  type GRCDashboard,
  type GRCConnector,
  type GRCControl,
  type GRCControlEvidencePacketResponse,
  type GRCControlPacketControl,
  type GRCEvidenceItemRecord,
  type GRCEvidencePacketsResponse,
  type GRCEvidenceRequest,
  type GRCPackagedEvidencePacket,
  type GRCFramework,
  type GRCReportMetadata,
} from "@/lib/grc";

export type AuditPackageState = "draft" | "needs_evidence" | "needs_review" | "approved" | "published" | "stale";

export type AuditEvidenceDecision =
  | "candidate"
  | "included"
  | "internal_only"
  | "excluded"
  | "needs_replacement"
  | "needs_review"
  | "accepted"
  | "rejected";

export type AuditEvidenceScope = "included" | "excluded" | "internal_only";

export type AuditEvidenceVisibility = "ready_for_auditor" | "needs_owner" | "needs_reviewer" | "internal_only" | "excluded";

export type AuditPackageSummary = {
  state: AuditPackageState;
  readinessScore: number;
  controls: number;
  evidenceItems: number;
  failingControls: number;
  missingEvidence: number;
  staleEvidence: number;
  openReviews: number;
  staleSources: number;
  sourceCount: number;
  exclusions: number;
};

export type AuditWorkflowState = "blocked" | "needs_review" | "ready" | "waiting";

export type EvidenceCurationRow = {
  collectedAt?: string;
  id: string;
  controlID: string;
  decision: AuditEvidenceDecision;
  freshness: string;
  packets: number;
  quality: string;
  reason: string;
  review: string;
  reviewer: string;
  source: string;
  sourceID?: string;
  scope: AuditEvidenceScope;
  status: string;
  title: string;
  runtimeID?: string;
  visibility: AuditEvidenceVisibility;
  owner: string;
};

export type ControlOwnerRow = {
  id: string;
  action: string;
  control: string;
  evidence: string;
  findings: number;
  missing: number;
  owner: string;
  stale: number;
  status: string;
  title: string;
};

export type TeamQueueRow = {
  id: string;
  action: string;
  detail: string;
  owner: string;
  source: string;
  status: string;
  title: string;
  type: string;
};

export type FrameworkCoverageRow = {
  id: string;
  controls: number;
  framework: string;
  mapped: number;
  maturity: number;
  needsAction: number;
  status: string;
};

export type SourceTrustRow = {
  id: string;
  action: string;
  evidence: number;
  findings: number;
  lastSynced: string;
  source: string;
  status: string;
};

export type ScopeExceptionRow = {
  id: string;
  kind: string;
  reason: string;
  value: string;
};

export type AuditReadinessRow = {
  id: string;
  action: string;
  detail: string;
  owner: string;
  state: AuditWorkflowState;
  title: string;
};

export type AuditorQuestionRow = {
  id: string;
  area: string;
  owner: string;
  question: string;
  source: string;
  status: string;
};

export type AuditExportManifestRow = {
  id: string;
  label: string;
  state: string;
  value: number | string;
};

export type AuditPriorityWorkRow = {
  id: string;
  action: string;
  area: string;
  detail: string;
  href: string;
  owner: string;
  rank: number;
  state: string;
  title: string;
};

export type AuditStatusLedgerState =
  | "blocked"
  | "excluded"
  | "internal_only"
  | "needs_owner"
  | "needs_review"
  | "ready"
  | "waiting";

export type AuditStatusLedgerRow = {
  id: string;
  action: string;
  area: string;
  detail: string;
  href: string;
  owner: string;
  proof: string;
  rank: number;
  reviewer: string;
  state: AuditStatusLedgerState;
  title: string;
};

const normalized = (value?: string) => (value ?? "").trim().toLowerCase();

const statusCount = (packet: GRCControlEvidencePacketResponse | null | undefined, status: string) =>
  packet?.packet.summary.by_status?.[status] ?? 0;

const evidenceItemCount = (control: GRCControlPacketControl) =>
  control.evidence.items?.length ?? control.evidence.summary?.evidence_ids?.length ?? 0;

const connectorIsStale = (connector: GRCConnector) => {
  const status = normalized(connector.status);
  const freshness = normalized(connector.freshness || connector.watermark_freshness);
  return status !== "healthy" || (freshness !== "" && freshness !== "fresh" && freshness !== "current");
};

const firstDefined = (...values: Array<string | undefined>) =>
  values.find((value) => value && value.trim() !== "");

const packetGateHref = (id: string) => {
  switch (id) {
    case "controls":
      return "#control-owner-queue";
    case "evidence":
      return "#evidence-review";
    case "reviews":
      return "#reviewer-questions";
    case "snapshot":
      return "#shared-snapshot";
    case "sources":
      return "#source-freshness";
    default:
      return "#packet-checklist";
  }
};

const citedEvidenceItem = (
  packet: GRCPackagedEvidencePacket | undefined,
  evidenceItemByID: Map<string, GRCEvidenceItemRecord>,
) => {
  const evidenceIDs = packet?.citations?.evidence_ids ?? [];
  for (const evidenceID of evidenceIDs) {
    const item = evidenceItemByID.get(evidenceID);
    if (item) return item;
  }
  return undefined;
};

export const auditEvidenceDecision = (input: {
  freshnessStatus?: string;
  manual?: boolean;
  quality?: string;
  reviewStatus?: string;
  status?: string;
}): AuditEvidenceDecision => {
  const status = normalized(input.status);
  const quality = normalized(input.quality);
  const reviewStatus = normalized(input.reviewStatus);
  const freshness = normalized(input.freshnessStatus);

  if (reviewStatus === "rejected" || status === "rejected" || quality === "rejected") return "rejected";
  if (status === "excluded" || status === "out_of_scope") return "excluded";
  if (status === "internal_only" || status === "internal") return "internal_only";
  if (["accepted", "approved", "auditor_ready", "ready_for_auditor"].includes(reviewStatus)) return "accepted";
  if (["missing", "blocked", "failed"].includes(status) || ["missing", "stale", "expired"].includes(freshness) || quality === "stale") {
    return "needs_replacement";
  }
  if (input.manual || ["needs_review", "flagged", "manual_review"].includes(reviewStatus) || ["needs_review", "manual_review"].includes(status)) {
    return "needs_review";
  }
  if (["ready", "satisfied", "passing", "collected", "auditor_ready", "ready_for_auditor"].includes(status) || ["ready", "valid"].includes(quality)) return "included";
  return "candidate";
};

export const auditEvidenceScope = (decision: AuditEvidenceDecision): AuditEvidenceScope => {
  if (decision === "excluded") return "excluded";
  if (decision === "internal_only") return "internal_only";
  return "included";
};

const firstPresent = (...values: Array<string | null | undefined>) =>
  values.map((value) => value?.trim()).find((value): value is string => Boolean(value));

const assignedValue = (value?: string) => {
  const cleaned = firstPresent(value);
  if (!cleaned) return undefined;
  return ["none", "no owner", "unassigned", "unknown"].includes(normalized(cleaned)) ? undefined : cleaned;
};

export const auditEvidenceVisibility = ({
  decision,
  owner,
  reviewStatus,
  status,
}: {
  decision: AuditEvidenceDecision;
  owner?: string;
  reviewStatus?: string;
  status?: string;
}): AuditEvidenceVisibility => {
  const scope = auditEvidenceScope(decision);
  if (scope === "excluded") return "excluded";
  if (scope === "internal_only") return "internal_only";
  if (!assignedValue(owner)) return "needs_owner";

  const review = normalized(reviewStatus);
  const packetStatus = normalized(status);
  if (["accepted", "approved", "auditor_ready", "ready_for_auditor"].includes(review) || decision === "accepted") {
    return "ready_for_auditor";
  }
  if (decision === "included" && review === "" && ["passing", "ready", "satisfied"].includes(packetStatus)) {
    return "ready_for_auditor";
  }
  return "needs_reviewer";
};

export const auditEvidenceDecisionLabel = (decision: AuditEvidenceDecision) => {
  switch (decision) {
    case "accepted":
      return "Accepted";
    case "candidate":
      return "Candidate";
    case "excluded":
      return "Excluded";
    case "included":
      return "Included";
    case "internal_only":
      return "Internal only";
    case "needs_replacement":
      return "Needs replacement";
    case "needs_review":
      return "Needs review";
    case "rejected":
      return "Rejected";
  }
};

export const auditEvidenceScopeLabel = (scope: AuditEvidenceScope) => {
  switch (scope) {
    case "excluded":
      return "Excluded";
    case "included":
      return "Included";
    case "internal_only":
      return "Internal only";
  }
};

export const auditEvidenceVisibilityLabel = (visibility: AuditEvidenceVisibility) => {
  switch (visibility) {
    case "excluded":
      return "Excluded";
    case "internal_only":
      return "Internal only";
    case "needs_owner":
      return "Needs owner";
    case "needs_reviewer":
      return "Needs reviewer";
    case "ready_for_auditor":
      return "Ready to share";
  }
};

export const auditPackageStateLabel = (state: AuditPackageState) => {
  switch (state) {
    case "approved":
      return "Approved";
    case "draft":
      return "Draft";
    case "needs_evidence":
      return "Needs evidence";
    case "needs_review":
      return "Needs review";
    case "published":
      return "Published";
    case "stale":
      return "Stale";
  }
};

export const auditWorkflowStateLabel = (state: AuditWorkflowState) => {
  switch (state) {
    case "blocked":
      return "Blocked";
    case "needs_review":
      return "Needs review";
    case "ready":
      return "Ready";
    case "waiting":
      return "Waiting";
  }
};

export const auditStatusLedgerStateLabel = (state: AuditStatusLedgerState) => {
  switch (state) {
    case "blocked":
      return "Blocked";
    case "excluded":
      return "Excluded";
    case "internal_only":
      return "Internal only";
    case "needs_owner":
      return "Needs owner";
    case "needs_review":
      return "Needs review";
    case "ready":
      return "Ready to share";
    case "waiting":
      return "Waiting";
  }
};

const packetCountLabel = (count: number) => `${count.toLocaleString()} ${count === 1 ? "packet" : "packets"}`;
const findingCountLabel = (count: number) => `${count.toLocaleString()} ${count === 1 ? "finding" : "findings"}`;
const generatedPrefix = "Generated ";

const readableWorkflowDetail = (detail: string) =>
  detail.startsWith(generatedPrefix) ? `${generatedPrefix}${displayDate(detail.slice(generatedPrefix.length))}` : detail;

const evidenceReason = ({
  decision,
  freshness,
  packetCount,
  packetReason,
  quality,
  review,
  source,
  status,
}: {
  decision: AuditEvidenceDecision;
  freshness?: string;
  packetCount: number;
  packetReason?: string;
  quality?: string;
  review?: string;
  source?: string;
  status?: string;
}) => {
  const suppliedReason = firstPresent(packetReason);
  if (suppliedReason) return suppliedReason;

  const normalizedStatus = normalized(status);
  const normalizedQuality = normalized(quality);
  const normalizedReview = normalized(review);
  const freshnessLabel = firstPresent(freshness);
  const sourceLabel = firstPresent(source);

  if (decision === "rejected" || normalizedReview === "rejected") return "Reviewer rejected this packet.";
  if (normalizedStatus === "missing" || (decision === "needs_replacement" && packetCount === 0)) return "No packet is attached to this request.";
  if (normalizedStatus === "stale" || normalizedQuality === "stale" || decision === "needs_replacement") {
    return freshnessLabel && freshnessLabel !== "Not set"
      ? `Evidence is stale against ${freshnessLabel} freshness.`
      : "Evidence is stale and needs replacement.";
  }
  if (decision === "needs_review" || ["manual_review", "needs_review"].includes(normalizedReview)) return "Reviewer decision is pending.";
  if (decision === "excluded") return "Request is outside packet scope.";
  if (decision === "internal_only") return "Packet is marked internal only.";
  if (decision === "accepted" || decision === "included") {
    return sourceLabel
      ? `${packetCountLabel(packetCount)} accepted from ${sourceLabel}.`
      : `${packetCountLabel(packetCount)} linked to this request.`;
  }
  return packetCount > 0 ? `${packetCountLabel(packetCount)} available for review.` : "No packet attachment is reported.";
};

export const buildAuditPackageSummary = ({
  controlPacket,
  dashboard,
  evidencePackets,
}: {
  controlPacket?: GRCControlEvidencePacketResponse | null;
  dashboard?: GRCDashboard | null;
  evidencePackets?: GRCEvidencePacketsResponse | null;
}): AuditPackageSummary => {
  const controls = controlPacket?.packet.summary.total ?? controlPacket?.controls.length ?? evidencePackets?.controls.length ?? 0;
  const failingControls = statusCount(controlPacket, "failing") || (controlPacket?.controls ?? []).filter((control) => control.status === "failing").length;
  const missingEvidence = statusCount(controlPacket, "missing_evidence") ||
    (controlPacket?.controls ?? []).reduce((sum, control) => sum + (control.missing_evidence_items ?? 0), 0) ||
    (evidencePackets?.evidence_requests ?? []).filter((request) => normalized(request.status) === "missing").length;
  const staleEvidence = statusCount(controlPacket, "stale_evidence") ||
    (controlPacket?.controls ?? []).reduce((sum, control) => sum + (control.stale_evidence_items ?? 0), 0) ||
    (evidencePackets?.evidence_requests ?? []).filter((request) => normalized(request.quality) === "stale").length;
  const evidenceItems = evidencePackets?.snapshot?.evidence_item_count ??
    evidencePackets?.evidence_items?.length ??
    evidencePackets?.evidence_packets?.length ??
    (controlPacket?.packet.controls ?? []).reduce((sum, control) => sum + evidenceItemCount(control), 0);
  const openReviews = evidencePackets?.snapshot?.open_review_count ?? evidencePackets?.program?.open_review_count ?? evidencePackets?.evidence_reviews?.filter((review) => normalized(review.status) !== "accepted").length ?? 0;
  const staleSources = (dashboard?.connectors ?? []).filter(connectorIsStale).length;
  const sourceCount = evidencePackets?.collection_sources?.length ?? dashboard?.connectors.length ?? 0;
  const exclusions = controlPacket?.metadata?.scope?.exclusions?.total ?? evidencePackets?.metadata?.scope?.exclusions?.total ?? 0;
  const readinessScore = evidencePackets?.program?.readiness_score ?? controlPacket?.metadata?.readiness?.score ?? 0;

  const state: AuditPackageState = staleSources > 0
    ? "stale"
    : missingEvidence > 0 || failingControls > 0
      ? "needs_evidence"
      : openReviews > 0
        ? "needs_review"
        : readinessScore >= 90
          ? "approved"
          : controls > 0
            ? "draft"
            : "needs_evidence";

  return {
    state,
    readinessScore,
    controls,
    evidenceItems,
    failingControls,
    missingEvidence,
    staleEvidence,
    openReviews,
    staleSources,
    sourceCount,
    exclusions,
  };
};

export const buildEvidenceCurationRows = ({
  controlPacket,
  evidencePackets,
  limit = 12,
}: {
  controlPacket?: GRCControlEvidencePacketResponse | null;
  evidencePackets?: GRCEvidencePacketsResponse | null;
  limit?: number;
}): EvidenceCurationRow[] => {
  const requests = evidencePackets?.evidence_requests ?? [];
  if (requests.length > 0) {
    const reviewSummaries = new Map<string, { reason?: string; reviewer?: string; status?: string }>();
    (evidencePackets?.evidence_reviews ?? []).forEach((review) => {
      const current = reviewSummaries.get(review.subject_id) ?? {};
      reviewSummaries.set(review.subject_id, {
        reason: current.reason ?? firstPresent(review.reason),
        reviewer: current.reviewer ?? firstPresent(review.actor),
        status: current.status ?? firstPresent(review.status),
      });
    });
    const packetSummaries = new Map<string, { count: number; reason?: string; reviewer?: string; reviewStatus?: string }>();
    const evidenceItems = evidencePackets?.evidence_items ?? [];
    const evidenceItemByID = new Map(evidenceItems.map((item) => [item.id, item]));
    const packetsByRequestID = new Map<string, GRCPackagedEvidencePacket[]>();
    const packetsByID = new Map<string, GRCPackagedEvidencePacket>();
    (evidencePackets?.evidence_packets ?? []).forEach((packet) => {
      packetsByID.set(packet.id, packet);
      const requestID = packet.request_id;
      if (!requestID) return;
      const current = packetSummaries.get(requestID) ?? { count: 0 };
      const reviewSummary = reviewSummaries.get(packet.id);
      packetSummaries.set(requestID, {
        count: current.count + 1,
        reason: current.reason ?? firstPresent(packet.reason, packet.review?.reason, reviewSummary?.reason, packet.freshness?.reason),
        reviewer: current.reviewer ?? firstPresent(packet.review?.actor, reviewSummary?.reviewer),
        reviewStatus: current.reviewStatus ?? firstPresent(packet.review?.status, reviewSummary?.status),
      });
      const packets = packetsByRequestID.get(requestID) ?? [];
      packets.push(packet);
      packetsByRequestID.set(requestID, packets);
    });
    const itemForRequest = (request: GRCEvidenceRequest) => {
      const packetIDs = request.evidence_packet_ids ?? [];
      const packets = [
        ...(packetsByRequestID.get(request.id) ?? []),
        ...packetIDs.map((packetID) => packetsByID.get(packetID)).filter((packet): packet is GRCPackagedEvidencePacket => Boolean(packet)),
      ];
      for (const packet of packets) {
        const item = citedEvidenceItem(packet, evidenceItemByID);
        if (item) return { item, packet };
      }
      const item = evidenceItems.find((candidate) =>
        candidate.evidence_request_ids?.includes(request.id) ||
        candidate.evidence_packet_ids?.some((packetID) => packetIDs.includes(packetID)),
      );
      return { item, packet: packets[0] };
    };
    return requests.slice(0, limit).map((request: GRCEvidenceRequest) => {
      const { item, packet } = itemForRequest(request);
      const sourceID = firstDefined(item?.source_id, packet?.source);
      const runtimeID = item?.runtime_id;
      const collectedAt = firstDefined(item?.last_observed_at, item?.created_at, packet?.observed_at, packet?.freshness?.observed_at);
      const packetSummary = packetSummaries.get(request.id);
      const requestReview = reviewSummaries.get(request.id);
      const packets = packetSummary?.count ?? request.evidence_packet_ids?.length ?? 0;
      const review = request.review_status || packetSummary?.reviewStatus || requestReview?.status || "needs_review";
      const decision = auditEvidenceDecision({
        quality: request.quality,
        reviewStatus: review,
        status: request.status,
      });
      const freshness = request.freshness_sla || "Not set";
      const source = request.accepted_from?.join(", ") || sourceID || runtimeID || "Any source";
      const owner = assignedValue(request.owner_domain) ?? "Unassigned";
      const reviewer = assignedValue(packetSummary?.reviewer ?? requestReview?.reviewer) ?? "Unassigned";
      const scope = auditEvidenceScope(decision);
      const visibility = auditEvidenceVisibility({
        decision,
        owner,
        reviewStatus: review,
        status: request.status,
      });

      return {
        collectedAt,
        id: request.id,
        controlID: request.control_id,
        decision,
        freshness,
        packets,
        quality: request.quality || "unknown",
        reason: evidenceReason({
          decision,
          freshness,
          packetCount: packets,
          packetReason: packetSummary?.reason ?? requestReview?.reason,
          quality: request.quality,
          review,
          source,
          status: request.status,
        }),
        review,
        reviewer,
        source,
        sourceID,
        scope,
        status: request.status || "candidate",
        title: request.title || request.id,
        runtimeID,
        visibility,
        owner,
      };
    });
  }

  return (controlPacket?.packet.controls ?? []).flatMap((control) =>
    (control.evidence.expectations ?? []).map((expectation) => {
      const decision = auditEvidenceDecision({
        freshnessStatus: expectation.status,
        quality: expectation.quality,
        status: expectation.status,
      });
      const freshness = expectation.freshness_sla || control.evidence.summary?.freshness_sla || "Not set";
      const packets = expectation.evidence_ids?.length ?? 0;
      const source = expectation.type || "Evidence";
      const owner = assignedValue(control.control.owner_domain) ?? "Unassigned";
      const review = expectation.status || "needs_review";
      const scope = auditEvidenceScope(decision);
      const visibility = auditEvidenceVisibility({
        decision,
        owner,
        reviewStatus: review,
        status: expectation.status,
      });

      return {
        id: expectation.id,
        controlID: `${control.control.framework_name} ${control.control.control_id}`,
        decision,
        freshness,
        packets,
        quality: expectation.quality || "unknown",
        reason: evidenceReason({
          decision,
          freshness,
          packetCount: packets,
          quality: expectation.quality,
          source,
          status: expectation.status,
        }),
        review,
        reviewer: "Unassigned",
        source,
        scope,
        status: expectation.status,
        title: expectation.title || expectation.id,
        visibility,
        owner,
      };
    }),
  ).slice(0, limit);
};

const controlOwner = (control: GRCControl) =>
  control.owner_domain || control.findings?.find((finding) => finding.owner && finding.owner !== "Unassigned")?.owner || "Unassigned";

const controlEvidenceLabel = (control: GRCControl) => {
  const expected = Math.max(control.evidence_expectations ?? 0, control.evidence_items + (control.missing_evidence_items ?? 0));
  return expected > 0 ? `${control.evidence_items}/${expected}` : `${control.evidence_items}`;
};

const controlAction = (control: GRCControl) => {
  if (control.status === "failing" && control.open_findings > 0) return "Resolve mapped findings";
  if ((control.missing_evidence_items ?? 0) > 0) return "Add evidence";
  if ((control.stale_evidence_items ?? 0) > 0) return "Refresh evidence";
  if (control.status === "manual_review") return "Complete review";
  return "Keep current";
};

export const buildControlOwnerRows = (controls: GRCControl[], limit = 12): ControlOwnerRow[] =>
  controls
    .slice()
    .sort((left, right) =>
      (right.open_findings + (right.missing_evidence_items ?? 0) + (right.stale_evidence_items ?? 0)) -
      (left.open_findings + (left.missing_evidence_items ?? 0) + (left.stale_evidence_items ?? 0)),
    )
    .slice(0, limit)
    .map((control) => ({
      id: `${control.framework_name}:${control.control_id}`,
      action: controlAction(control),
      control: `${control.framework_name} ${control.control_id}`,
      evidence: controlEvidenceLabel(control),
      findings: control.open_findings,
      missing: control.missing_evidence_items ?? 0,
      owner: controlOwner(control),
      stale: control.stale_evidence_items ?? 0,
      status: control.status,
      title: control.title || control.family_name || "Control objective",
    }));

export const buildTeamQueueRows = (dashboard?: GRCDashboard | null, limit = 12): TeamQueueRow[] => {
  const findingRows = (dashboard?.findings ?? []).map((finding) => ({
    id: `finding:${finding.id}`,
    action: finding.owner && finding.owner !== "Unassigned" ? "Confirm fix" : "Assign owner",
    detail: finding.summary || finding.entity || "Open finding",
    owner: finding.owner || "Unassigned",
    source: finding.source_id || "Unknown",
    status: finding.sla_status || finding.status,
    title: finding.title,
    type: "Finding",
  }));
  const sourceRows = (dashboard?.connectors ?? []).filter(connectorIsStale).map((connector) => ({
    id: `source:${connector.runtime_id}`,
    action: "Repair source",
    detail: connector.runtime_id,
    owner: connector.tenant_id || "Source owner",
    source: connector.source_id || "Unknown",
    status: connector.status,
    title: connector.source_id || connector.runtime_id,
    type: "Source",
  }));
  return [...sourceRows, ...findingRows].slice(0, limit);
};

export const buildFrameworkCoverageRows = (frameworks: GRCFramework[], limit = 12): FrameworkCoverageRow[] =>
  frameworks.slice(0, limit).map((framework) => ({
    id: framework.id || framework.name,
    controls: framework.control_count,
    framework: framework.name,
    mapped: framework.coverage?.mapped_controls ?? 0,
    maturity: framework.lifecycle === "upcoming" ? 0 : framework.maturity?.score ?? 0,
    needsAction: (framework.readiness?.needs_enrichment_controls ?? 0) + (framework.readiness?.placeholder_controls ?? 0),
    status: framework.lifecycle === "upcoming" ? "planning" : framework.maturity?.status || "not_configured",
  }));

export const buildSourceTrustRows = ({
  dashboard,
  evidencePackets,
  limit = 12,
}: {
  dashboard?: GRCDashboard | null;
  evidencePackets?: GRCEvidencePacketsResponse | null;
  limit?: number;
}): SourceTrustRow[] => {
  const collectionRows = (evidencePackets?.collection_sources ?? []).map((source) => ({
    id: `${source.source_id || source.runtime_id}:${source.runtime_id}`,
    action: normalized(source.status) === "collected" ? "Use in packet" : "Refresh source",
    evidence: source.evidence_item_count,
    findings: source.finding_count,
    lastSynced: source.last_synced_at || "Not observed",
    source: source.source_id || source.runtime_id,
    status: source.status,
  }));
  if (collectionRows.length > 0) return collectionRows.slice(0, limit);

  return (dashboard?.connectors ?? []).slice(0, limit).map((connector) => ({
    id: connector.runtime_id,
    action: connectorIsStale(connector) ? "Repair source" : "Use in packet",
    evidence: 0,
    findings: 0,
    lastSynced: connector.last_synced_at || connector.checkpoint_watermark || "Not observed",
    source: connector.source_id || connector.runtime_id,
    status: connector.status || connector.freshness,
  }));
};

export const buildScopeExceptionRows = (metadata?: GRCReportMetadata | null, limit = 12): ScopeExceptionRow[] => {
  const exclusions = metadata?.scope?.exclusions;
  if (!exclusions || exclusions.total === 0) return [];
  const rows: ScopeExceptionRow[] = [
    ...(exclusions.excluded_families ?? []).map((value) => ({ kind: "Family", reason: "Excluded from packet scope", value })),
    ...(exclusions.excluded_asset_classes ?? []).map((value) => ({ kind: "Asset class", reason: "Excluded from packet scope", value })),
    ...(exclusions.excluded_kinds ?? []).map((value) => ({ kind: "Kind", reason: "Excluded from packet scope", value })),
    ...(exclusions.excluded_resource_urns ?? []).map((value) => ({ kind: "Resource", reason: "Excluded from packet scope", value })),
    ...(exclusions.excluded_resources ?? []).map((value) => ({
      kind: value.type || "Resource",
      reason: value.reason || "Excluded from packet scope",
      value: value.urn || value.id || value.type || "Excluded resource",
    })),
  ].map((row, index) => ({ id: `${row.kind}:${row.value}:${index}`, ...row }));
  return rows.slice(0, limit);
};

const workflowRank = (state: AuditWorkflowState) => {
  switch (state) {
    case "blocked":
      return 0;
    case "needs_review":
      return 1;
    case "waiting":
      return 3;
    case "ready":
      return 9;
  }
};

const controlOwnerRank = (row: ControlOwnerRow) => {
  const status = normalized(row.status);
  const action = normalized(row.action);
  if (row.missing > 0) return 1;
  if (row.stale > 0) return 2;
  if (["blocked", "failing", "manual_review", "needs_review"].includes(status)) return 3;
  if (action !== "" && action !== "keep current") return 4;
  return 9;
};

const questionRank = (row: AuditorQuestionRow) =>
  /blocked|failed|missing|needs|overdue|rejected|stale/i.test(row.status) ? 2 : 5;

const sourceNeedsAttention = (status: string) =>
  !["collected", "current", "fresh", "healthy", "ready"].includes(normalized(status));

const auditStatusLedgerRank = (state: AuditStatusLedgerState) => {
  switch (state) {
    case "blocked":
      return 0;
    case "needs_owner":
      return 1;
    case "needs_review":
      return 2;
    case "waiting":
      return 3;
    case "internal_only":
      return 6;
    case "excluded":
      return 7;
    case "ready":
      return 9;
  }
};

const ledgerStateForWorkflow = (state: AuditWorkflowState): AuditStatusLedgerState =>
  state === "ready" ? "ready" : state;

const evidenceLedgerState = (row: EvidenceCurationRow): AuditStatusLedgerState => {
  if (row.visibility === "needs_owner") return "needs_owner";
  if (row.decision === "needs_replacement" || row.decision === "rejected") return "blocked";
  if (row.visibility === "needs_reviewer" || row.decision === "needs_review") return "needs_review";
  if (row.visibility === "internal_only") return "internal_only";
  if (row.visibility === "excluded") return "excluded";
  return "ready";
};

const evidenceLedgerAction = (row: EvidenceCurationRow) => {
  const state = evidenceLedgerState(row);
  if (state === "needs_owner") return "Assign evidence owner";
  if (row.decision === "rejected") return "Replace rejected evidence";
  if (row.decision === "needs_replacement") return "Replace evidence";
  if (state === "needs_review") return "Review evidence";
  if (state === "internal_only") return "Keep out of shared snapshot";
  if (state === "excluded") return "Document exclusion";
  return "Keep current";
};

export const buildActionableControlOwnerRows = (ownerRows: ControlOwnerRow[], limit = 12): ControlOwnerRow[] =>
  ownerRows
    .filter((row) => controlOwnerRank(row) < 9)
    .slice()
    .sort((left, right) =>
      controlOwnerRank(left) - controlOwnerRank(right) ||
      (right.missing + right.stale + right.findings) - (left.missing + left.stale + left.findings) ||
      left.control.localeCompare(right.control),
    )
    .slice(0, limit);

export const buildAuditStatusLedgerRows = ({
  evidenceRows,
  ownerRows,
  readinessRows,
  snapshotID,
  sourceRows,
  limit = 12,
}: {
  evidenceRows: EvidenceCurationRow[];
  ownerRows: ControlOwnerRow[];
  readinessRows: AuditReadinessRow[];
  snapshotID: string;
  sourceRows: SourceTrustRow[];
  limit?: number;
}): AuditStatusLedgerRow[] => {
  const readinessWork = readinessRows
    .filter((row) => row.state !== "ready")
    .map((row) => {
      const state = ledgerStateForWorkflow(row.state);
      const detail = readableWorkflowDetail(row.detail);
      return {
        id: `gate:${row.id}`,
        action: row.action,
        area: "Packet gate",
        detail,
        href: packetGateHref(row.id),
        owner: row.owner,
        proof: detail,
        rank: auditStatusLedgerRank(state),
        reviewer: row.id === "snapshot" ? "Packet reviewers" : "Evidence reviewers",
        state,
        title: row.title,
      };
    });

  const evidenceWork = evidenceRows
    .map((row) => ({ row, state: evidenceLedgerState(row) }))
    .filter(({ state }) => state !== "ready")
    .map(({ row, state }) => ({
      id: `evidence:${row.id}`,
      action: evidenceLedgerAction(row),
      area: "Evidence",
      detail: row.controlID,
      href: "#evidence-review",
      owner: state === "needs_owner" ? "Audit lead" : row.owner,
      proof: row.reason,
      rank: auditStatusLedgerRank(state),
      reviewer: row.reviewer,
      state,
      title: row.title,
    }));

  const controlWork = buildActionableControlOwnerRows(ownerRows, limit).map((row) => {
    const ownerMissing = normalized(row.owner) === "unassigned";
    const needsReview = /manual_review|needs_review/i.test(row.status);
    const state: AuditStatusLedgerState = ownerMissing ? "needs_owner" : needsReview ? "needs_review" : "blocked";
    return {
      id: `control:${row.id}`,
      action: row.action,
      area: "Control",
      detail: row.title,
      href: "#control-owner-queue",
      owner: ownerMissing ? "Audit lead" : row.owner,
      proof: `${row.evidence} evidence, ${findingCountLabel(row.findings)}`,
      rank: auditStatusLedgerRank(state) + controlOwnerRank(row) / 10,
      reviewer: "Control reviewers",
      state,
      title: row.control,
    };
  });

  const sourceWork = sourceRows
    .filter((row) => sourceNeedsAttention(row.status))
    .map((row) => ({
      id: `source:${row.id}`,
      action: row.action,
      area: "Source",
      detail: row.source,
      href: "#source-freshness",
      owner: row.source,
      proof: `Last synced ${displayDate(row.lastSynced)}`,
      rank: auditStatusLedgerRank("blocked"),
      reviewer: "Source reviewers",
      state: "blocked" as AuditStatusLedgerState,
      title: row.source,
    }));

  const workRows = [...readinessWork, ...evidenceWork, ...controlWork, ...sourceWork]
    .sort((left, right) =>
      left.rank - right.rank ||
      left.area.localeCompare(right.area) ||
      left.title.localeCompare(right.title),
    )
    .slice(0, limit);

  if (workRows.length > 0) return workRows;

  return [{
    id: "snapshot:ready",
    action: "Share snapshot",
    area: "Snapshot",
    detail: `Snapshot ${snapshotID}`,
    href: "#shared-snapshot",
    owner: "Audit lead",
    proof: "All packet gates are ready.",
    rank: auditStatusLedgerRank("ready"),
    reviewer: "Packet reviewers",
    state: "ready",
    title: "Shared snapshot",
  }];
};

export const buildAuditReadinessRows = (
  summary: AuditPackageSummary,
  snapshotID: string,
  generatedAt: string,
): AuditReadinessRow[] => {
  const evidenceGaps = summary.missingEvidence + summary.staleEvidence;
  const snapshotReady = summary.state === "approved" || summary.state === "published";

  return [
    {
      id: "evidence",
      action: evidenceGaps > 0 ? "Collect evidence" : "Keep current",
      detail: `${summary.missingEvidence} missing, ${summary.staleEvidence} stale`,
      owner: "Control owners",
      state: evidenceGaps > 0 ? "blocked" : "ready",
      title: "Evidence set",
    },
    {
      id: "controls",
      action: summary.failingControls > 0 ? "Resolve controls" : "Keep current",
      detail: `${summary.failingControls} failing of ${summary.controls} controls`,
      owner: "Control owners",
      state: summary.failingControls > 0 ? "blocked" : "ready",
      title: "Control status",
    },
    {
      id: "reviews",
      action: summary.openReviews > 0 ? "Complete reviews" : "Keep current",
      detail: `${summary.openReviews} open review records`,
      owner: "Evidence reviewers",
      state: summary.openReviews > 0 ? "needs_review" : "ready",
      title: "Evidence review",
    },
    {
      id: "sources",
      action: summary.staleSources > 0 ? "Refresh sources" : "Keep current",
      detail: `${summary.staleSources} stale of ${summary.sourceCount} sources`,
      owner: "Source owners",
      state: summary.staleSources > 0 ? "blocked" : "ready",
      title: "Source freshness",
    },
    {
      id: "snapshot",
      action: snapshotReady ? "Share snapshot" : "Approve snapshot",
      detail: generatedAt ? `Generated ${generatedAt}` : `Snapshot ${snapshotID}`,
      owner: "Audit lead",
      state: snapshotReady ? "ready" : "waiting",
      title: "Shared snapshot",
    },
  ];
};

export const buildAuditorQuestionRows = ({
  evidenceRows,
  ownerRows,
  sourceRows,
  limit = 8,
}: {
  evidenceRows: EvidenceCurationRow[];
  ownerRows: ControlOwnerRow[];
  sourceRows: SourceTrustRow[];
  limit?: number;
}): AuditorQuestionRow[] => {
  const evidenceQuestions = evidenceRows
    .filter((row) => row.visibility === "needs_owner" || row.visibility === "needs_reviewer" || ["needs_replacement", "needs_review", "rejected"].includes(row.decision))
    .map((row) => ({
      id: `evidence:${row.id}`,
      area: "Evidence",
      owner: row.visibility === "needs_owner" ? "Audit lead" : row.source || "Evidence owner",
      question: row.visibility === "needs_owner"
        ? `Who owns this evidence for ${row.controlID}?`
        : `Can this evidence be shared, refreshed, or replaced for ${row.controlID}?`,
      source: `${row.title}: ${row.reason}`,
      status: row.visibility === "needs_owner" ? auditEvidenceVisibilityLabel(row.visibility) : auditEvidenceDecisionLabel(row.decision),
    }));
  const controlQuestions = ownerRows
    .filter((row) => row.missing > 0 || row.stale > 0 || row.findings > 0)
    .map((row) => ({
      id: `control:${row.id}`,
      area: "Control",
      owner: row.owner,
      question: `Which evidence or remediation closes ${row.control}?`,
      source: row.title,
      status: row.action,
    }));
  const sourceQuestions = sourceRows
    .filter((row) => sourceNeedsAttention(row.status))
    .map((row) => ({
      id: `source:${row.id}`,
      area: "Source",
      owner: row.source,
      question: `Can ${row.source} be refreshed before packet review?`,
      source: row.lastSynced,
      status: row.action,
    }));

  return [...evidenceQuestions, ...controlQuestions, ...sourceQuestions].slice(0, limit);
};

export const buildAuditExportManifestRows = ({
  generatedAt,
  snapshotID,
  summary,
}: {
  generatedAt: string;
  snapshotID: string;
  summary: AuditPackageSummary;
}): AuditExportManifestRow[] => [
  { id: "snapshot", label: "Snapshot", state: auditPackageStateLabel(summary.state), value: snapshotID },
  { id: "generated", label: "Generated", state: generatedAt ? "Ready" : "Not generated", value: generatedAt || "Not generated" },
  { id: "controls", label: "Controls", state: summary.failingControls > 0 ? "Action needed" : "Ready", value: summary.controls },
  { id: "evidence", label: "Evidence", state: summary.missingEvidence > 0 ? "Missing evidence" : "Ready", value: summary.evidenceItems },
  { id: "sources", label: "Sources", state: summary.staleSources > 0 ? "Refresh needed" : "Ready", value: summary.sourceCount },
  { id: "scope", label: "Scope exclusions", state: summary.exclusions > 0 ? "Documented" : "None", value: summary.exclusions },
];

export const buildAuditPriorityWorkRows = ({
  auditorQuestionRows,
  ownerRows,
  readinessRows,
  limit = 8,
}: {
  auditorQuestionRows: AuditorQuestionRow[];
  ownerRows: ControlOwnerRow[];
  readinessRows: AuditReadinessRow[];
  limit?: number;
}): AuditPriorityWorkRow[] => {
  const readinessWork = readinessRows
    .filter((row) => row.state !== "ready")
    .map((row) => ({
      id: `packet:${row.id}`,
      action: row.action,
      area: "Packet gate",
      detail: row.detail,
      href: packetGateHref(row.id),
      owner: row.owner,
      rank: workflowRank(row.state),
      state: auditWorkflowStateLabel(row.state),
      title: row.title,
    }));
  const ownerWork = buildActionableControlOwnerRows(ownerRows, limit).map((row) => ({
    id: `owner:${row.id}`,
    action: row.action,
    area: "Control",
    detail: row.title,
    href: "#control-owner-queue",
    owner: row.owner,
    rank: controlOwnerRank(row),
    state: row.status,
    title: row.control,
  }));
  const questionWork = auditorQuestionRows.map((row) => ({
    id: `question:${row.id}`,
    action: "Answer question",
    area: row.area,
    detail: row.source,
    href: "#reviewer-questions",
    owner: row.owner,
    rank: questionRank(row),
    state: row.status,
    title: row.question,
  }));

  return [...readinessWork, ...ownerWork, ...questionWork]
    .sort((left, right) =>
      left.rank - right.rank ||
      left.area.localeCompare(right.area) ||
      left.title.localeCompare(right.title),
    )
    .slice(0, limit);
};
