import { redactSecurityText } from "../security/redaction.js";

export const POLICY_CANDIDATE_STATUSES = [
  "grounded",
  "proved",
  "ready_for_review",
  "blocked",
] as const;

export type PolicyCandidateStatus = typeof POLICY_CANDIDATE_STATUSES[number];

export interface PolicyCandidateOrigin {
  kind: "slack";
  external_ref: string;
}

export interface PolicyCandidateGraphNode {
  id: string;
  source_id: string;
  entity_type: string;
  attributes?: Record<string, string>;
}

export interface PolicyCandidateGraphEdge {
  from_id: string;
  to_id: string;
  source_id: string;
  relation: string;
  attributes?: Record<string, string>;
}

export interface PolicyCandidateGraphEvidence {
  nodes: PolicyCandidateGraphNode[];
  edges: PolicyCandidateGraphEdge[];
  critical_edge: Pick<PolicyCandidateGraphEdge, "from_id" | "to_id" | "relation">;
  evidence_node_ids: string[];
}

export interface PolicyCandidateCreateRequest {
  hypothesis: string;
  domain: string;
  origin: PolicyCandidateOrigin;
  graph_evidence: PolicyCandidateGraphEvidence;
  grounding: {
    bindings: Array<{ node_id: string; entity_urn: string }>;
  };
}

export interface PolicyCandidateGrounding {
  execution: string;
  node_count: number;
  edge_count: number;
  receipt_id: string;
  observed_at: string;
}

export interface PolicyCandidateCoverageGap {
  execution: string;
  catalog_digest: string;
  compared_rule_count: number;
  candidate_signature: string;
  observed_at: string;
}

export interface PolicyCandidateArtifacts {
  policy_path?: string;
  policy_yaml?: string;
  policy_digest?: string;
  test_path?: string;
  test_yaml?: string;
  test_digest?: string;
  safe_for_review: boolean;
}

export interface PolicyCandidateProof {
  policy_id?: string;
  policy_digest?: string;
  test_digest?: string;
  receipts: Array<{ gate: string; passed: boolean; execution: string }>;
}

export interface PolicyCandidateShadow {
  execution: string;
  match_count: number;
  truncated: boolean;
  receipt_id: string;
  observed_at: string;
}

export interface PolicyCandidate {
  id: string;
  tenant_id: string;
  status: PolicyCandidateStatus;
  revision: number;
  hypothesis: string;
  domain: string;
  origin_kind: string;
  graph: {
    node_count: number;
    edge_count: number;
    entity_types: string[];
    relations: string[];
  };
  grounding?: PolicyCandidateGrounding;
  coverage_gap?: PolicyCandidateCoverageGap;
  artifacts?: PolicyCandidateArtifacts;
  proof?: PolicyCandidateProof;
  shadow?: PolicyCandidateShadow;
  pr_ready: boolean;
  created_at: string;
  updated_at: string;
}

export function isPolicyCandidateStatus(value: unknown): value is PolicyCandidateStatus {
  return typeof value === "string" && POLICY_CANDIDATE_STATUSES.includes(value as PolicyCandidateStatus);
}

export function parsePolicyCandidate(value: unknown): PolicyCandidate {
  const root = objectValue(value);
  if (!root) throw new Error("Cerebro policy candidate response must be an object.");
  const id = requiredString(root.id, "id");
  const tenantId = requiredString(root.tenant_id, "tenant_id");
  const status = root.status;
  if (!isPolicyCandidateStatus(status)) throw new Error("Cerebro policy candidate response has an invalid status.");
  return {
    id,
    tenant_id: tenantId,
    status,
    revision: finitePositiveInteger(root.revision, "revision"),
    hypothesis: cleanCandidateText(requiredString(root.hypothesis ?? root.prompt, "hypothesis"), 2_000),
    domain: requiredString(root.domain, "domain"),
    origin_kind: requiredString(root.origin_kind, "origin_kind"),
    graph: graphEvidenceSummary(root.graph),
    grounding: parseGrounding(root.grounding),
    coverage_gap: parseCoverageGap(root.coverage_gap),
    artifacts: parseArtifacts(root.artifacts),
    proof: parseProof(root.proof),
    shadow: parseShadow(root.shadow),
    pr_ready: requiredBoolean(root.pr_ready, "pr_ready"),
    created_at: requiredString(root.created_at, "created_at"),
    updated_at: requiredString(root.updated_at, "updated_at"),
  };
}

function parseCoverageGap(value: unknown): PolicyCandidateCoverageGap | undefined {
  const coverage = objectValue(value);
  if (!coverage) return undefined;
  return {
    execution: requiredString(coverage.execution, "coverage_gap.execution"),
    catalog_digest: requiredString(coverage.catalog_digest, "coverage_gap.catalog_digest"),
    compared_rule_count: finiteNonNegativeInteger(coverage.compared_rule_count, "coverage_gap.compared_rule_count"),
    candidate_signature: requiredString(coverage.candidate_signature, "coverage_gap.candidate_signature"),
    observed_at: requiredString(coverage.observed_at, "coverage_gap.observed_at"),
  };
}

function parseGrounding(value: unknown): PolicyCandidateGrounding | undefined {
  const grounding = objectValue(value);
  if (!grounding) return undefined;
  return {
    execution: requiredString(grounding.execution, "grounding.execution"),
    node_count: finitePositiveInteger(grounding.node_count, "grounding.node_count"),
    edge_count: finitePositiveInteger(grounding.edge_count, "grounding.edge_count"),
    receipt_id: requiredString(grounding.receipt_id, "grounding.receipt_id"),
    observed_at: requiredString(grounding.observed_at, "grounding.observed_at"),
  };
}

export function parsePolicyCandidateList(value: unknown): PolicyCandidate[] {
  const root = objectValue(value);
  const values = Array.isArray(value) ? value : root?.candidates;
  if (!Array.isArray(values)) throw new Error("Cerebro policy candidate list response must contain candidates.");
  return values.map(parsePolicyCandidate);
}

export function cleanCandidateText(value: string, max: number): string {
  return redactSecurityText(value)
    .replace(/\barn:(?:aws|aws-us-gov|aws-cn):[^\s,;]+/gi, "[redacted_cloud_ref]")
    .replace(/\b\d{12}\b/g, "[redacted_account_id]")
    .replace(/https?:\/\/[^\s)]+/gi, "[redacted_endpoint]")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[redacted_address]")
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[redacted_identity]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

export function candidateTextContainsSensitiveData(value: string): boolean {
  return redactSecurityText(value) !== value
    || /\barn:(?:aws|aws-us-gov|aws-cn):[^\s,;]+/i.test(value)
    || /\b\d{12}\b/.test(value)
    || /https?:\/\/[^\s)]+/i.test(value)
    || /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(value)
    || /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(value);
}

function graphEvidenceSummary(value: unknown): PolicyCandidate["graph"] {
  const graph = objectValue(value);
  if (!graph) throw new Error("Cerebro policy candidate response requires graph.");
  return {
    node_count: finiteNonNegativeInteger(graph.node_count, "graph.node_count"),
    edge_count: finiteNonNegativeInteger(graph.edge_count, "graph.edge_count"),
    entity_types: uniqueSafeSemantics(arrayValue(graph.entity_types)),
    relations: uniqueSafeSemantics(arrayValue(graph.relations)),
  };
}

function uniqueSafeSemantics(values: unknown[]): string[] {
  return [...new Set(values.flatMap((value) => {
    const text = optionalString(value);
    return text && /^[A-Za-z][A-Za-z0-9_.-]{0,99}$/.test(text) ? [text] : [];
  }))].slice(0, 25);
}

function parseArtifacts(value: unknown): PolicyCandidateArtifacts | undefined {
  const artifacts = objectValue(value);
  if (!artifacts) return undefined;
  const policyPath = optionalString(artifacts.policy_path);
  const policyYaml = optionalRawString(artifacts.policy_yaml);
  const testPath = optionalString(artifacts.test_path);
  const testYaml = optionalRawString(artifacts.test_yaml);
  const policyDigest = optionalString(artifacts.policy_digest);
  const testDigest = optionalString(artifacts.test_digest);
  const strings = [policyPath, policyYaml, testPath, testYaml, policyDigest, testDigest].filter((item): item is string => Boolean(item));
  const safeForReview = strings.every((item) => !candidateTextContainsSensitiveData(item));
  return {
    policy_path: safeForReview ? policyPath : undefined,
    policy_yaml: safeForReview ? policyYaml : undefined,
    policy_digest: policyDigest,
    test_path: safeForReview ? testPath : undefined,
    test_yaml: safeForReview ? testYaml : undefined,
    test_digest: testDigest,
    safe_for_review: safeForReview && Boolean(policyPath && policyYaml && testPath && testYaml),
  };
}

function parseProof(value: unknown): PolicyCandidateProof | undefined {
  const proof = objectValue(value);
  if (!proof) return undefined;
  return {
    policy_id: optionalString(proof.policy_id),
    policy_digest: optionalString(proof.policy_digest),
    test_digest: optionalString(proof.test_digest),
    receipts: arrayValue(proof.receipts).flatMap((value) => {
      const receipt = objectValue(value);
      const gate = optionalString(receipt?.gate);
      const execution = optionalString(receipt?.execution);
      return gate && execution && typeof receipt?.passed === "boolean"
        ? [{ gate, passed: receipt.passed, execution }]
        : [];
    }).slice(0, 50),
  };
}

function parseShadow(value: unknown): PolicyCandidateShadow | undefined {
  const shadow = objectValue(value);
  if (!shadow) return undefined;
  return {
    execution: requiredString(shadow.execution, "shadow.execution"),
    match_count: finiteNonNegativeInteger(shadow.match_count, "shadow.match_count"),
    truncated: shadow.truncated === true,
    receipt_id: requiredString(shadow.receipt_id, "shadow.receipt_id"),
    observed_at: requiredString(shadow.observed_at, "shadow.observed_at"),
  };
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function requiredString(value: unknown, field: string): string {
  const parsed = optionalString(value);
  if (!parsed) throw new Error(`Cerebro policy candidate response requires ${field}.`);
  return parsed;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function optionalRawString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function finiteNonNegativeInteger(value: unknown, field: string): number {
  const parsed = optionalNonNegativeInteger(value);
  if (parsed === undefined) throw new Error(`Cerebro policy candidate response requires ${field}.`);
  return parsed;
}

function optionalNonNegativeInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function finitePositiveInteger(value: unknown, field: string): number {
  const parsed = finiteNonNegativeInteger(value, field);
  if (parsed < 1) throw new Error(`Cerebro policy candidate response requires a positive ${field}.`);
  return parsed;
}

function requiredBoolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") throw new Error(`Cerebro policy candidate response requires ${field}.`);
  return value;
}
