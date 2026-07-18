import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import type { Finding, FindingEvidence } from "../../cerebro/types.js";
import type { AppConfig } from "../../config/index.js";
import { extractEvidenceCasRefs, type EvidenceCasReference } from "../../evidence-cas/client.js";
import { findingSummary } from "./cerebro-finding-summary.js";
import { limit, normalizeFindingOrder, normalizeFindingStatus, shortError, stringValue, unique } from "./normalizers.js";
import { resilientDetails, runResilient } from "./resilient-tool.js";
import type { SecurityToolDeps } from "./types.js";
import { safeToolResult, toolResult } from "./tool-result.js";

export function createCerebroFindingTools(deps: SecurityToolDeps): AgentTool[] {
  const findingsParams = Type.Object({
    runtime_id: Type.String(),
    status: Type.Optional(Type.String()),
    severity: Type.Optional(Type.String()),
    finding_id: Type.Optional(Type.String()),
    rule_id: Type.Optional(Type.String()),
    order: Type.Optional(Type.String()),
    limit: Type.Optional(Type.Number()),
  });
  const findingEvidenceParams = Type.Object({
    runtime_id: Type.String(),
    finding_id: Type.String(),
    limit: Type.Optional(Type.Number()),
  });
  const findingReadParams = Type.Object({
    runtime_id: Type.String(),
    finding_id: Type.String(),
    depth: Type.Optional(Type.String()),
    evidence_limit: Type.Optional(Type.Number()),
    related_limit: Type.Optional(Type.Number()),
    include_graph: Type.Optional(Type.Boolean()),
  });
  const findingInvestigationParams = Type.Object({
    runtime_id: Type.String(),
    finding_id: Type.String(),
    evidence_limit: Type.Optional(Type.Number()),
    related_limit: Type.Optional(Type.Number()),
    include_graph: Type.Optional(Type.Boolean()),
  });

  return [
    {
      name: "cerebro_findings",
      label: "Cerebro findings",
      description: "Read Cerebro findings for a runtime by status, priority, finding id, rule id, or severity.",
      parameters: findingsParams,
      execute: async (_toolCallId, params) => {
        const args = params as FindingsArgs;
        return toolResult(await openFindingsDetails(deps, args, 25));
      },
    },
    {
      name: "cerebro_open_findings",
      label: "Cerebro open findings",
      description: "Read open Cerebro findings for a runtime by priority, finding id, rule id, or severity.",
      parameters: findingsParams,
      execute: async (_toolCallId, params) => {
        const args = params as FindingsArgs;
        return toolResult(await openFindingsDetails(deps, args, 10));
      },
    },
    {
      name: "cerebro_finding",
      label: "Cerebro finding",
      description: "Read one Cerebro finding. Use depth=evidence for evidence rows or depth=full for the investigation packet.",
      parameters: findingReadParams,
      execute: async (_toolCallId, params) => {
        const args = params as FindingReadArgs;
        return toolResult(await findingReadDetails(deps, args));
      },
    },
    {
      name: "cerebro_finding_evidence",
      label: "Cerebro finding evidence",
      description: "Read evidence rows for a specific Cerebro finding.",
      parameters: findingEvidenceParams,
      execute: async (_toolCallId, params) => {
        const args = params as { runtime_id: string; finding_id: string; limit?: number };
        return toolResult(await findingEvidenceDetails(deps, args));
      },
    },
    {
      name: "cerebro_finding_investigation",
      label: "Cerebro finding investigation",
      description: "Build a deep read-only investigation packet for one finding: finding record, evidence rows, EvidenceCAS refs, runtime health, same-rule related findings, resource graph neighborhood, proved facts, gaps, and safe next actions.",
      parameters: findingInvestigationParams,
      execute: async (_toolCallId, params) => {
        const args = params as {
          runtime_id: string;
          finding_id: string;
          evidence_limit?: number;
          related_limit?: number;
          include_graph?: boolean;
        };
        return safeToolResult(async () => findingInvestigation(deps, {
          runtimeId: args.runtime_id,
          findingId: args.finding_id,
          evidenceLimit: limit(args.evidence_limit, 12),
          relatedLimit: limit(args.related_limit, 8),
          includeGraph: args.include_graph !== false,
        }));
      },
    },
  ];
}

interface FindingsArgs {
  runtime_id: string;
  status?: string;
  severity?: string;
  finding_id?: string;
  rule_id?: string;
  order?: string;
  limit?: number;
}

interface FindingReadArgs {
  runtime_id: string;
  finding_id: string;
  depth?: string;
  evidence_limit?: number;
  related_limit?: number;
  include_graph?: boolean;
}

async function openFindingsDetails(
  deps: SecurityToolDeps,
  args: FindingsArgs,
  defaultLimit: number,
): Promise<Record<string, unknown>> {
  const response = await deps.cerebro.listFindings(args.runtime_id, {
    status: normalizeFindingStatus(args.status),
    severity: args.severity,
    findingId: args.finding_id,
    ruleId: args.rule_id,
    order: normalizeFindingOrder(args.order),
    limit: limit(args.limit, defaultLimit),
  });
  return { findings: response };
}

async function findingEvidenceDetails(
  deps: SecurityToolDeps,
  args: { runtime_id: string; finding_id: string; limit?: number },
): Promise<Record<string, unknown>> {
  const response = await deps.cerebro.listFindingEvidence(args.runtime_id, args.finding_id, limit(args.limit, 8));
  const evidenceCasRefs = extractEvidenceCasRefs(response);
  return {
    evidence: response,
    evidence_cas_refs: evidenceCasRefs,
    note: evidenceCasRefs.length > 0
      ? "Use evidence_cas_resolve for these refs only when raw artifact metadata, digest matching, or manifest verification would change the answer."
      : "No EvidenceCAS refs were detected in these evidence rows.",
  };
}

async function findingReadDetails(
  deps: SecurityToolDeps,
  args: FindingReadArgs,
): Promise<Record<string, unknown>> {
  const depth = normalizeFindingDepth(args.depth);
  if (depth === "evidence") {
    const result = await runResilient<Record<string, unknown>>({
      name: "cerebro_finding[evidence]",
      run: () => findingEvidenceDetails(deps, {
        runtime_id: args.runtime_id,
        finding_id: args.finding_id,
        limit: args.evidence_limit,
      }),
    });
    return resilientDetails(result, { depth });
  }

  const result = await runResilient<Record<string, unknown>>({
    name: "cerebro_finding[full]",
    run: async () => findingInvestigation(deps, {
      runtimeId: args.runtime_id,
      findingId: args.finding_id,
      evidenceLimit: limit(args.evidence_limit, 12),
      relatedLimit: limit(args.related_limit, 8),
      includeGraph: args.include_graph !== false,
    }) as Promise<Record<string, unknown>>,
    fallbacks: [
      {
        name: "investigation_no_graph",
        run: async () => findingInvestigation(deps, {
          runtimeId: args.runtime_id,
          findingId: args.finding_id,
          evidenceLimit: limit(args.evidence_limit, 12),
          relatedLimit: limit(args.related_limit, 8),
          includeGraph: false,
        }) as Promise<Record<string, unknown>>,
      },
      {
        name: "evidence_rows",
        run: () => findingEvidenceDetails(deps, {
          runtime_id: args.runtime_id,
          finding_id: args.finding_id,
          limit: args.evidence_limit,
        }),
      },
    ],
  });
  return resilientDetails(result, { depth });
}

function normalizeFindingDepth(depth: string | undefined): "evidence" | "full" {
  return depth === "evidence" ? "evidence" : "full";
}

export async function findingInvestigation(deps: SecurityToolDeps, input: {
  runtimeId: string;
  findingId: string;
  evidenceLimit: number;
  relatedLimit: number;
  includeGraph: boolean;
}) {
  const [findings, evidence, health] = await Promise.all([
    deps.cerebro.listFindings(input.runtimeId, { findingId: input.findingId, limit: 5 }),
    deps.cerebro.listFindingEvidence(input.runtimeId, input.findingId, input.evidenceLimit).catch((error) => ({ error: shortError(error), rows: [] as FindingEvidence[] })),
    deps.cerebro.listRuntimeHealth({ runtimeId: input.runtimeId, limit: 1 }).catch((error) => ({ error: shortError(error), runtimes: [] })),
  ]);
  const finding = findings.find((item) => item.id === input.findingId) ?? findings[0];
  const evidenceRows = Array.isArray(evidence) ? evidence : evidence.rows;
  const runtimeHealth = Array.isArray(health) ? health : health.runtimes;
  const resourceUrn = stringValue(finding?.primary_resource_urn ?? finding?.resource_urn)
    ?? evidenceRows.map((row) => stringValue(row.graph_root_urn ?? row.graph_path_urn)).find(Boolean);
  const [relatedFindings, neighborhood] = await Promise.all([
    finding?.rule_id
      ? deps.cerebro.listFindings(input.runtimeId, { ruleId: finding.rule_id, status: "open", limit: input.relatedLimit })
        .catch((error) => ({ error: shortError(error), findings: [] as Finding[] }))
      : Promise.resolve(undefined),
    input.includeGraph && resourceUrn
      ? deps.cerebro.graphNeighborhood(resourceUrn, 20).catch((error) => ({ error: shortError(error) }))
      : Promise.resolve(undefined),
  ]);
  const related = Array.isArray(relatedFindings) ? relatedFindings : relatedFindings?.findings;
  const evidenceCasRefs = extractEvidenceCasRefs(evidenceRows);
  const gaps = investigationGaps(finding, evidenceRows, runtimeHealth, resourceUrn);
  const claimVerification = await deps.cerebro.verifyAgentClaim({
    claim: investigationClaim(input.findingId, finding),
    claim_type: "finding_triage",
    scope_urn: resourceUrn,
    supporting_evidence_urns: evidenceVerificationUrns(evidenceRows, resourceUrn),
    missing_evidence: gaps,
    freshness_state: findingEvidenceFreshness(finding, evidenceRows),
    requested_action_stage: "recommend",
  }).catch((error) => ({ error: shortError(error) }));
  return {
    runtime_id: input.runtimeId,
    finding_id: input.findingId,
    finding_found: Boolean(finding),
    finding: finding ? findingInvestigationFindingSummary(deps.config, input.runtimeId, finding) : undefined,
    runtime_health: runtimeHealth,
    evidence: evidenceRows.map(compactEvidenceRow).slice(0, input.evidenceLimit),
    evidence_cas_refs: evidenceCasRefs,
    related_findings: related?.map((item) => findingSummary(deps.config, input.runtimeId, item)).slice(0, input.relatedLimit),
    resource_neighborhood: neighborhood,
    proved_facts: provedFacts(finding, evidenceRows, resourceUrn),
    gaps,
    claim_verification: claimVerification,
    safe_next_actions: safeFindingNextActions(finding, evidenceRows, evidenceCasRefs, resourceUrn),
    note: "This is read-only investigation context. Do not resolve, suppress, assign, revoke, suspend, deploy, or change infrastructure from this packet alone; use a dedicated approved execution path.",
  };
}

function findingInvestigationFindingSummary(config: AppConfig, runtimeId: string, finding: Finding) {
  return {
    ...findingSummary(config, runtimeId, finding),
    rule_id: stringValue(finding.rule_id),
    summary: stringValue(finding.summary),
    due_at: stringValue(finding.due_at),
    tickets: finding.tickets,
    external_refs: finding.external_refs,
  };
}

function compactEvidenceRow(row: FindingEvidence): Record<string, unknown> {
  return {
    id: row.id,
    finding_id: row.finding_id,
    rule_id: row.rule_id,
    claim_id: row.claim_id,
    event_id: row.event_id,
    summary: row.summary,
    evidence_type: row.evidence_type,
    graph_root_urn: row.graph_root_urn,
    graph_path_urn: row.graph_path_urn,
    observed_at: row.observed_at,
    attributes: row.attributes,
  };
}

function provedFacts(finding: Finding | undefined, evidence: FindingEvidence[], resourceUrn: string | undefined): string[] {
  const facts = [
    finding ? `Cerebro returned finding ${finding.id ?? "unknown"} with status ${finding.status ?? "unknown"} and severity ${finding.severity ?? "unknown"}.` : "",
    finding?.rule_id ? `Rule ${finding.rule_id} produced the finding.` : "",
    resourceUrn ? `Primary resource context is ${resourceUrn}.` : "",
    evidence.length > 0 ? `${evidence.length} evidence row(s) were returned for the finding.` : "",
    evidence.some((row) => row.observed_at) ? `Evidence includes observed_at timestamps.` : "",
  ].filter(Boolean);
  return facts.slice(0, 8);
}

function investigationGaps(finding: Finding | undefined, evidence: FindingEvidence[], runtimeHealth: unknown[], resourceUrn: string | undefined): string[] {
  const gaps: string[] = [];
  if (!finding) gaps.push("Finding lookup did not return a matching record.");
  if (evidence.length === 0) gaps.push("No evidence rows were returned; verify ingestion coverage before making a confidence claim.");
  if (runtimeHealth.length === 0) gaps.push("Runtime health was unavailable for this runtime.");
  if (!resourceUrn) gaps.push("No primary resource URN or graph root was available for neighborhood expansion.");
  if (finding && !finding.last_observed_at && !finding.observed_at) gaps.push("Finding does not include a returned observation timestamp.");
  return gaps;
}

function investigationClaim(findingId: string, finding: Finding | undefined): string {
  const rule = stringValue(finding?.rule_id) ?? "its rule";
  const status = stringValue(finding?.status) ?? "unknown status";
  const severity = stringValue(finding?.severity) ?? "unknown severity";
  return `Finding ${findingId} is an actionable ${severity} ${rule} finding with ${status} status.`;
}

function evidenceVerificationUrns(evidence: FindingEvidence[], resourceUrn: string | undefined): string[] | undefined {
  const urns = unique([
    resourceUrn,
    ...evidence.flatMap((row) => [
      stringValue(row.graph_root_urn),
      stringValue(row.graph_path_urn),
    ]),
  ].filter((value): value is string => typeof value === "string" && value.startsWith("urn:cerebro:")));
  return urns.length > 0 ? urns.slice(0, 8) : undefined;
}

function findingEvidenceFreshness(finding: Finding | undefined, evidence: FindingEvidence[]): "fresh" | "unknown" {
  return finding?.last_observed_at || finding?.observed_at || evidence.some((row) => row.observed_at) ? "fresh" : "unknown";
}

function safeFindingNextActions(finding: Finding | undefined, evidence: FindingEvidence[], evidenceCasRefs: EvidenceCasReference[], resourceUrn: string | undefined): string[] {
  const actions = [
    evidenceCasRefs.length > 0 ? "Resolve EvidenceCAS refs only if artifact metadata or digest verification would change the decision." : "",
    resourceUrn ? "Use the resource neighborhood to check owning identity, path, and adjacent blast radius before recommending remediation." : "",
    finding?.tickets?.length ? "Check linked tickets before opening duplicate work." : "Open or link a tracking ticket if this remains actionable after evidence review.",
    evidence.length > 0 ? "Compare evidence timestamps with runtime health before calling the finding stale or current." : "Re-run source ingestion or request missing evidence before resolving.",
    "Use dry-run or approval-required execution for any response action.",
  ].filter(Boolean);
  return unique(actions).slice(0, 6);
}
