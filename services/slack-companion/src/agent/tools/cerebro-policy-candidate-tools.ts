import { createHash } from "node:crypto";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import {
  cleanCandidateText,
  isPolicyCandidateStatus,
  type PolicyCandidate,
  type PolicyCandidateCreateRequest,
  type PolicyCandidateGraphEdge,
  type PolicyCandidateGraphEvidence,
  type PolicyCandidateGraphNode,
  type PolicyCandidateStatus,
} from "../../cerebro/policy-candidates.js";
import type { SecurityToolDeps } from "./types.js";
import { safeToolResult, toolResult } from "./tool-result.js";

const attributeParams = Type.Record(Type.String(), Type.String(), { maxProperties: 20 });
const graphNodeParams = Type.Object({
  ref: Type.String(),
  entity_urn: Type.String(),
  source_id: Type.String(),
  entity_type: Type.String(),
  attributes: Type.Optional(attributeParams),
});
const graphEdgeParams = Type.Object({
  from_ref: Type.String(),
  to_ref: Type.String(),
  source_id: Type.String(),
  relation: Type.String(),
  attributes: Type.Optional(attributeParams),
});
const criticalEdgeParams = Type.Object({
  from_ref: Type.String(),
  to_ref: Type.String(),
  relation: Type.String(),
});
const MAX_EXPORT_FILE_CHARS = 12_000;
const MAX_EXPORT_TOTAL_CHARS = 16_000;

export function createCerebroPolicyCandidateTools(deps: SecurityToolDeps): AgentTool[] {
  return [
    {
      name: "cerebro_policy_candidate_create",
      label: "Create policy discovery candidate",
      description: "Create a private Cerebro policy candidate from a current tenant-scoped graph path. Cerebro rehydrates every declared node, edge, relation, and risk attribute before storing the draft. The host derives the bounded semantic hypothesis and opaque Slack origin; Slack text is never an input. This tool cannot promote a rule, write the graph, open a pull request, or merge code.",
      parameters: Type.Object({
        domain: Type.String(),
        graph_nodes: Type.Array(graphNodeParams, { minItems: 3, maxItems: 16 }),
        graph_edges: Type.Array(graphEdgeParams, { minItems: 2, maxItems: 32 }),
        critical_edge: criticalEdgeParams,
        evidence_node_refs: Type.Array(Type.String(), { minItems: 1, maxItems: 25 }),
      }),
      execute: async (_toolCallId, params) => {
        const denied = requirePolicyCandidateDiscoveryContext(deps);
        if (denied) return toolResult(denied);
        return safeToolResult(async () => {
          const request = createRequest(deps, params as CreateCandidateArgs);
          return candidateToolResult(await deps.cerebro.createPolicyCandidate(request));
        });
      },
    },
    {
      name: "cerebro_policy_candidate_get",
      label: "Read policy discovery candidate",
      description: "Read one private policy candidate's lifecycle, safe graph shape, proof gates, shadow counts, and artifact digests. The result omits the Slack origin, graph handles, cloud identifiers, and generated file bodies.",
      parameters: Type.Object({ candidate_id: Type.String() }),
      execute: async (_toolCallId, params) => {
        const denied = requirePolicyCandidateOperator(deps);
        if (denied) return toolResult(denied);
        return safeToolResult(async () => {
          const candidateId = cleanCandidateId((params as { candidate_id: string }).candidate_id);
          return candidateToolResult(await deps.cerebro.getPolicyCandidate(candidateId));
        });
      },
    },
    {
      name: "cerebro_policy_candidate_list",
      label: "List policy discovery candidates",
      description: "List private Cerebro policy candidates by lifecycle state. Returns bounded review status only; it omits Slack origins, graph handles, cloud identifiers, and generated file bodies.",
      parameters: Type.Object({
        status: Type.Optional(Type.String()),
        limit: Type.Optional(Type.Number()),
      }),
      execute: async (_toolCallId, params) => {
        const denied = requirePolicyCandidateOperator(deps);
        if (denied) return toolResult(denied);
        return safeToolResult(async () => {
          const args = params as { status?: string; limit?: number };
          const status = args.status === undefined ? undefined : cleanStatus(args.status);
          const limit = Math.max(1, Math.min(25, Math.floor(args.limit ?? 10)));
          const candidates = await deps.cerebro.listPolicyCandidates({ status, limit });
          return {
            candidates: candidates.map(candidateSummary),
            count: candidates.length,
            boundaries: candidateBoundaries(),
          };
        });
      },
    },
    {
      name: "cerebro_policy_candidate_export",
      label: "Export reviewed policy candidate files",
      description: "Export exactly two bounded files from an operator-reviewed candidate that is proved, shadowed, safe, and ready for review. Use only in a code-change or explicit response-action workflow before the existing GitHub PR tool. This read does not open a pull request, write files, promote a policy, or merge code.",
      parameters: Type.Object({ candidate_id: Type.String() }),
      execute: async (_toolCallId, params) => {
        const denied = requirePolicyCandidateOperator(deps);
        if (denied) return toolResult(denied);
        return safeToolResult(async () => {
          const candidateId = cleanCandidateId((params as { candidate_id: string }).candidate_id);
          return exportCandidateFiles(await deps.cerebro.getPolicyCandidate(candidateId));
        });
      },
    },
    {
      name: "cerebro_policy_candidate_prove",
      label: "Ground, author, and prove policy candidate",
      description: "Ask Cerebro to author a grounded candidate's policy and paired tests, reject catalog-covered graph paths, and execute the proof battery. A successful result carries coverage-gap and proof receipts. This tool cannot promote, write the graph, open a pull request, or merge code.",
      parameters: Type.Object({ candidate_id: Type.String() }),
      execute: async (_toolCallId, params) => {
        const denied = requirePolicyCandidateDiscoveryContext(deps);
        if (denied) return toolResult(denied);
        return safeToolResult(async () => {
          const candidateId = cleanCandidateId((params as { candidate_id: string }).candidate_id);
          return candidateToolResult(await deps.cerebro.provePolicyCandidate(candidateId));
        });
      },
    },
    {
      name: "cerebro_policy_candidate_shadow",
      label: "Shadow policy candidate",
      description: "Run a proved candidate against the bounded current graph without creating findings. Returns only match count and an opaque receipt. A ready result may be reviewed for a draft PR, but this tool cannot promote, write the graph, open a pull request, or merge code.",
      parameters: Type.Object({ candidate_id: Type.String() }),
      execute: async (_toolCallId, params) => {
        const denied = requirePolicyCandidateDiscoveryContext(deps);
        if (denied) return toolResult(denied);
        return safeToolResult(async () => {
          const candidateId = cleanCandidateId((params as { candidate_id: string }).candidate_id);
          return candidateToolResult(await deps.cerebro.shadowPolicyCandidate(candidateId));
        });
      },
    },
  ];
}

interface CreateCandidateArgs {
  domain: string;
  graph_nodes: Array<{
    ref: string;
    entity_urn: string;
    source_id: string;
    entity_type: string;
    attributes?: Record<string, string>;
  }>;
  graph_edges: Array<{
    from_ref: string;
    to_ref: string;
    source_id: string;
    relation: string;
    attributes?: Record<string, string>;
  }>;
  critical_edge: { from_ref: string; to_ref: string; relation: string };
  evidence_node_refs: string[];
}

function createRequest(deps: SecurityToolDeps, args: CreateCandidateArgs): PolicyCandidateCreateRequest {
  const domain = cleanDomain(args.domain);
  const graphEvidence = buildGraphEvidence(args);
  return {
    hypothesis: graphHypothesis(domain, graphEvidence),
    domain,
    origin: { kind: "slack", external_ref: opaqueSlackOrigin(deps) },
    graph_evidence: graphEvidence,
    grounding: {
      bindings: args.graph_nodes.map((node) => ({
        node_id: cleanLocalRef(node.ref, "graph node ref"),
        entity_urn: cleanGroundingURN(deps.config.cerebro.tenantId, node.entity_urn),
      })),
    },
  };
}

function buildGraphEvidence(args: CreateCandidateArgs): PolicyCandidateGraphEvidence {
  if (args.graph_nodes.length < 3 || args.graph_edges.length < 2 || args.evidence_node_refs.length < 1) {
    throw new Error("Graph evidence requires at least three nodes, two edges, and one evidence node.");
  }
  const nodes: PolicyCandidateGraphNode[] = args.graph_nodes.map((node) => ({
    id: cleanLocalRef(node.ref, "graph node ref"),
    source_id: cleanSemantic(node.source_id, "graph node source_id", 80),
    entity_type: cleanSemantic(node.entity_type, "graph node entity_type", 120),
    attributes: cleanAttributes(node.attributes),
  }));
  const nodeRefs = new Set(nodes.map((node) => node.id));
  if (nodeRefs.size !== nodes.length) throw new Error("Graph node refs must be unique.");
  const edges: PolicyCandidateGraphEdge[] = args.graph_edges.map((edge) => ({
    from_id: referencedLocalRef(edge.from_ref, nodeRefs),
    to_id: referencedLocalRef(edge.to_ref, nodeRefs),
    source_id: cleanSemantic(edge.source_id, "graph edge source_id", 80),
    relation: cleanSemantic(edge.relation, "graph edge relation", 120),
    attributes: cleanAttributes(edge.attributes),
  }));
  const criticalEdge = {
    from_id: referencedLocalRef(args.critical_edge.from_ref, nodeRefs),
    to_id: referencedLocalRef(args.critical_edge.to_ref, nodeRefs),
    relation: cleanSemantic(args.critical_edge.relation, "critical edge relation", 120),
  };
  if (!edges.some((edge) => edge.from_id === criticalEdge.from_id && edge.to_id === criticalEdge.to_id && edge.relation === criticalEdge.relation)) {
    throw new Error("The critical edge must match a declared graph edge.");
  }
  return {
    nodes,
    edges,
    critical_edge: criticalEdge,
    evidence_node_ids: args.evidence_node_refs.map((ref) => referencedLocalRef(ref, nodeRefs)).slice(0, 25),
  };
}

function candidateToolResult(candidate: PolicyCandidate): Record<string, unknown> {
  return {
    candidate: candidateSummary(candidate),
    pr_ready: candidateReadyForPr(candidate),
    next_action: candidateNextAction(candidate),
    boundaries: candidateBoundaries(),
  };
}

function exportCandidateFiles(candidate: PolicyCandidate): Record<string, unknown> {
  if (candidate.status !== "ready_for_review" || !candidate.pr_ready || !candidate.proof || !candidate.coverage_gap || !candidate.shadow
    || candidate.shadow.match_count < 1 || candidate.shadow.truncated) {
    throw new Error("Policy candidate must be proved, shadowed, and ready_for_review before export.");
  }
  const artifacts = candidate.artifacts;
  if (!artifacts?.safe_for_review
    || !artifacts.policy_path || !artifacts.policy_yaml || !artifacts.policy_digest
    || !artifacts.test_path || !artifacts.test_yaml || !artifacts.test_digest) {
    throw new Error("Policy candidate artifacts are incomplete or not safe for review.");
  }
  const totalChars = artifacts.policy_yaml.length + artifacts.test_yaml.length;
  if (artifacts.policy_yaml.length > MAX_EXPORT_FILE_CHARS
    || artifacts.test_yaml.length > MAX_EXPORT_FILE_CHARS
    || totalChars > MAX_EXPORT_TOTAL_CHARS) {
    throw new Error("Policy candidate artifacts exceed the bounded export size.");
  }
  return {
    candidate_id: candidate.id,
    files: [
      { path: artifacts.policy_path, content: artifacts.policy_yaml },
      { path: artifacts.test_path, content: artifacts.test_yaml },
    ],
    digests: {
      policy: artifacts.policy_digest,
      test: artifacts.test_digest,
    },
  };
}

function candidateSummary(candidate: PolicyCandidate): Record<string, unknown> {
  return {
    id: candidate.id,
    status: candidate.status,
    revision: candidate.revision,
    domain: candidate.domain,
    hypothesis: cleanCandidateText(candidate.hypothesis, 2_000),
    graph: candidate.graph,
    grounding: candidate.grounding,
    coverage_gap: candidate.coverage_gap,
    proof: candidate.proof,
    shadow: candidate.shadow,
    artifacts: candidate.artifacts ? {
      policy_path: candidate.artifacts.policy_path,
      test_path: candidate.artifacts.test_path,
      policy_digest: candidate.artifacts.policy_digest,
      test_digest: candidate.artifacts.test_digest,
      safe_for_review: candidate.artifacts.safe_for_review,
    } : undefined,
    created_at: candidate.created_at,
    updated_at: candidate.updated_at,
  };
}

function candidateReadyForPr(candidate: PolicyCandidate): boolean {
  return candidate.pr_ready
    && candidate.status === "ready_for_review"
    && Boolean(candidate.proof)
    && Boolean(candidate.coverage_gap)
    && Boolean(candidate.shadow)
    && (candidate.shadow?.match_count ?? 0) > 0
    && candidate.shadow?.truncated === false
    && candidate.artifacts?.safe_for_review === true;
}

function candidateNextAction(candidate: PolicyCandidate): Record<string, unknown> {
  if (candidate.status === "grounded") {
    return { tool: "cerebro_policy_candidate_prove", candidate_id: candidate.id };
  }
  if (candidate.status === "proved") {
    if (!candidate.coverage_gap) {
      return { state: "coverage_blocked", reason: "Cerebro did not return a graph-rule catalog coverage-gap receipt." };
    }
    if (candidate.shadow?.truncated) {
      return { state: "shadow_blocked", reason: "The current graph result exceeded the bounded review limit." };
    }
    if (candidate.shadow && candidate.shadow.match_count === 0) {
      return { state: "shadow_blocked", reason: "The authored rule has no current graph matches." };
    }
    return { tool: "cerebro_policy_candidate_shadow", candidate_id: candidate.id };
  }
  if (candidateReadyForPr(candidate)) {
    return {
      state: "review_candidate_artifacts",
      note: "Open a draft only through the existing reviewed code-change path. A security-answer turn cannot call the GitHub write tool.",
    };
  }
  return { state: candidate.status, note: "Inspect the candidate proof gates before taking another action." };
}

function candidateBoundaries(): Record<string, unknown> {
  return {
    source_authority: "Cerebro evidence and current-state graph",
    duplicate_authority: "Cerebro graph-rule catalog",
    slack_role: "private untrusted hypothesis only",
    creates_findings: false,
    writes_graph: false,
    promotes_policy: false,
    opens_pull_request: false,
    merges_code: false,
  };
}

function requirePolicyCandidateOperator(deps: SecurityToolDeps): Record<string, unknown> | undefined {
  const userId = deps.requestContext?.userId;
  if (userId && deps.config.slack.operatorUserIds.has(userId)) return undefined;
  return {
    ok: false,
    error: "trusted_operator_required",
    message: "Policy discovery candidates are private and available only to a configured Cerebro operator.",
  };
}

function requirePolicyCandidateDiscoveryContext(deps: SecurityToolDeps): Record<string, unknown> | undefined {
  const userId = deps.requestContext?.userId;
  const channelId = deps.requestContext?.channelId;
  if ((userId && deps.config.slack.operatorUserIds.has(userId))
    || (channelId && deps.config.slack.triageChannelIds.has(channelId))) {
    return undefined;
  }
  return {
    ok: false,
    error: "policy_discovery_context_required",
    message: "Policy discovery can run only for a configured operator or in a configured security-triage channel.",
  };
}

function opaqueSlackOrigin(deps: SecurityToolDeps): string {
  const context = deps.requestContext;
  if (!context?.channelId) throw new Error("Slack request context is required to create a policy candidate.");
  const digest = createHash("sha256")
    .update([deps.config.cerebro.tenantId, context.channelId, context.threadTs ?? "root"].join("\u0000"))
    .digest("hex")
    .slice(0, 32);
  return `slack-origin-${digest}`;
}

function cleanCandidateId(value: string): string {
  const cleaned = value.trim();
  if (!/^[A-Za-z][A-Za-z0-9_-]{2,119}$/.test(cleaned)) throw new Error("candidate_id must be an opaque candidate reference.");
  return cleaned;
}

function cleanGroundingURN(tenantId: string, value: string): string {
  const cleaned = value.trim();
  const prefix = `urn:cerebro:${tenantId.trim()}:`;
  if (!tenantId.trim() || !cleaned.startsWith(prefix) || cleaned.length > 2_048 || /[\s\u0000-\u001f\u007f]/.test(cleaned)) {
    throw new Error("entity_urn must be a current tenant-scoped Cerebro graph URN.");
  }
  return cleaned;
}

function cleanStatus(value: string): PolicyCandidateStatus {
  const cleaned = value.trim();
  if (!isPolicyCandidateStatus(cleaned)) throw new Error("status is not a policy candidate lifecycle state.");
  return cleaned;
}

function cleanLocalRef(value: string, field: string): string {
  const cleaned = value.trim();
  if (!/^[A-Za-z][A-Za-z0-9_-]{1,119}$/.test(cleaned)) throw new Error(`${field} must be an opaque local reference.`);
  return cleaned;
}

function referencedLocalRef(value: string, refs: Set<string>): string {
  const cleaned = cleanLocalRef(value, "graph reference");
  if (!refs.has(cleaned)) throw new Error(`Graph reference ${cleaned} does not name a declared node.`);
  return cleaned;
}

function cleanSemantic(value: string, field: string, max: number): string {
  const cleaned = value.trim();
  if (!cleaned || cleaned.length > max || !/^[A-Za-z][A-Za-z0-9_.-]*$/.test(cleaned)) {
    throw new Error(`${field} must contain identifier-safe semantic text.`);
  }
  return cleaned;
}

function cleanDomain(value: string): string {
  const cleaned = value.trim();
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(cleaned)) {
    throw new Error("domain must be a lowercase policy domain slug.");
  }
  return cleaned;
}

function graphHypothesis(domain: string, graph: PolicyCandidateGraphEvidence): string {
  const entityTypes = [...new Set(graph.nodes.map((node) => node.entity_type))];
  const relations = [...new Set(graph.edges.map((edge) => edge.relation))];
  const states = [...new Set(graph.nodes.flatMap((node) => Object.entries(node.attributes ?? {}).map(([key, value]) => `${key}=${value}`))
    .concat(graph.edges.flatMap((edge) => Object.entries(edge.attributes ?? {}).map(([key, value]) => `${key}=${value}`))))];
  return cleanCandidateText([
    `${domain} policy candidate`,
    `entity types: ${entityTypes.join(", ")}`,
    `relations: ${relations.join(", ")}`,
    states.length ? `risk states: ${states.join(", ")}` : undefined,
    `critical relation: ${graph.critical_edge.relation}`,
  ].filter((value): value is string => Boolean(value)).join("; "), 2_000);
}

function cleanAttributes(attributes: Record<string, string> | undefined): Record<string, string> | undefined {
  if (!attributes) return undefined;
  const entries = Object.entries(attributes).slice(0, 20).map(([rawKey, rawValue]) => {
    const key = cleanSemantic(rawKey, "graph attribute name", 80);
    if (/(?:^|_)(?:id|arn|name|endpoint|address|email|session|secret_ref|secret_name)(?:$|_)/i.test(key)) {
      throw new Error(`Graph attribute ${key} may contain a live identifier and is not allowed.`);
    }
    const value = cleanCandidateText(rawValue, 120);
    if (!value || value !== rawValue.trim() || !/^[A-Za-z0-9_.:, -]+$/.test(value)) {
      throw new Error(`Graph attribute ${key} must contain bounded risk semantics, not source identifiers.`);
    }
    return [key, value] as const;
  });
  return entries.length ? Object.fromEntries(entries) : undefined;
}
