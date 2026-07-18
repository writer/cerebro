import { randomUUID } from "node:crypto";
import { z } from "zod";
import { redactSecurityText } from "../security/redaction.js";

export const agentResourceKindSchema = z.enum([
  "cerebro",
  "github",
  "slack",
  "jira",
  "linear",
  "aws",
  "panther",
  "evidence",
  "artifact",
  "person",
  "service",
  "generic",
]);

export const agentResourceLinkSchema = z.object({
  relation: z.string().trim().min(1).max(80),
  targetUri: z.string().trim().min(1).max(500),
});

export const agentResourceRefSchema = z.object({
  id: z.string().trim().min(1).max(240),
  uri: z.string().trim().min(1).max(500),
  kind: agentResourceKindSchema,
  source: z.string().trim().min(1).max(120),
  label: z.string().trim().min(1).max(240).optional(),
  observedAt: z.string().datetime().optional(),
  validUntil: z.string().datetime().optional(),
  evidenceReceipt: z.string().trim().min(1).max(240).optional(),
  confidence: z.number().min(0).max(1).default(1),
  links: z.array(agentResourceLinkSchema).max(20).default([]),
});

export const agentArtifactSchema = z.object({
  id: z.string().trim().min(1).max(160),
  kind: z.enum(["file", "report", "patch", "commit", "pull_request", "ticket", "evidence_packet", "decision", "other"]),
  title: z.string().trim().min(1).max(300),
  status: z.enum(["draft", "ready", "verified", "superseded"]).default("ready"),
  path: z.string().trim().min(1).max(500).optional(),
  url: z.string().trim().min(1).max(800).optional(),
  contentHash: z.string().trim().min(1).max(160).optional(),
  sourceRefs: z.array(z.string().trim().min(1).max(500)).max(24).default([]),
  createdAt: z.string().datetime(),
});

export const agentAcceptanceCriterionSchema = z.object({
  id: z.string().trim().min(1).max(160),
  description: z.string().trim().min(1).max(500),
  kind: z.enum(["tool_success", "field_present", "field_equals", "resource_ref", "artifact", "manual"]),
  field: z.string().trim().min(1).max(160).optional(),
  expected: z.union([z.string(), z.number(), z.boolean()]).optional(),
  status: z.enum(["pending", "passed", "failed"]).default("pending"),
  evidenceRefs: z.array(z.string().trim().min(1).max(500)).max(24).default([]),
  checkedAt: z.string().datetime().optional(),
  result: z.string().trim().min(1).max(600).optional(),
});

export const agentCorrectionSchema = z.object({
  id: z.string().trim().min(1).max(160),
  previousClaim: z.string().trim().min(1).max(1000),
  replacement: z.string().trim().min(1).max(1000),
  reason: z.string().trim().min(1).max(1000),
  sourceRefs: z.array(z.string().trim().min(1).max(500)).min(1).max(24),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime().optional(),
});

const agentToolArgumentsSchema = z.record(z.string().min(1).max(160), z.unknown()).superRefine((value, context) => {
  const serialized = JSON.stringify(value);
  if (Object.keys(value).length > 40) context.addIssue({ code: "custom", message: "Agent tool arguments exceed 40 fields." });
  if (serialized.length > 20_000) context.addIssue({ code: "custom", message: "Agent tool arguments exceed 20000 characters." });
  if (redactSecurityText(serialized) !== serialized || containsSecretArgumentKey(value)) {
    context.addIssue({ code: "custom", message: "Agent tool arguments contain secret-like input." });
  }
});

export const agentStepExecutionSchema = z.object({
  toolName: z.string().trim().min(1).max(160),
  arguments: agentToolArgumentsSchema.default({}),
  verificationToolName: z.string().trim().min(1).max(160).optional(),
  verificationArguments: agentToolArgumentsSchema.default({}),
  approvalRequired: z.boolean().default(false),
  idempotencyKey: z.string().trim().min(1).max(240).optional(),
  rollback: z.string().trim().min(1).max(1000).optional(),
  maxAttempts: z.number().int().min(1).max(3).default(1),
  attempts: z.number().int().min(0).max(3).default(0),
});

export const agentCompletionReceiptSchema = z.object({
  status: z.enum(["complete", "partial", "blocked"]),
  summary: z.string().trim().min(1).max(1200),
  verifiedAt: z.string().datetime(),
  verifier: z.string().trim().min(1).max(160),
  criteriaPassed: z.array(z.string().trim().min(1).max(160)).max(40),
  criteriaFailed: z.array(z.string().trim().min(1).max(160)).max(40),
  evidenceRefs: z.array(z.string().trim().min(1).max(500)).max(40),
});

export const agentResourceRefsSchema = z.array(agentResourceRefSchema).max(80);
export const agentArtifactsSchema = z.array(agentArtifactSchema).max(80);
export const agentAcceptanceCriteriaSchema = z.array(agentAcceptanceCriterionSchema).max(80);
export const agentCorrectionsSchema = z.array(agentCorrectionSchema).max(40);

export type AgentResourceKind = z.infer<typeof agentResourceKindSchema>;
export type AgentResourceRef = z.infer<typeof agentResourceRefSchema>;
export type AgentArtifact = z.infer<typeof agentArtifactSchema>;
export type AgentAcceptanceCriterion = z.infer<typeof agentAcceptanceCriterionSchema>;
export type AgentCorrection = z.infer<typeof agentCorrectionSchema>;
export type AgentStepExecution = z.infer<typeof agentStepExecutionSchema>;
export type AgentCompletionReceipt = z.infer<typeof agentCompletionReceiptSchema>;

export interface CanonicalResourceInput {
  kind: AgentResourceKind;
  id: string;
  source?: string;
  label?: string;
  observedAt?: string;
  validUntil?: string;
  evidenceReceipt?: string;
  confidence?: number;
  links?: Array<{ relation: string; targetUri: string }>;
}

export function canonicalResourceRef(input: CanonicalResourceInput): AgentResourceRef {
  const id = clean(input.id, 240);
  const kind = agentResourceKindSchema.parse(input.kind);
  return agentResourceRefSchema.parse({
    id,
    uri: `${kind}://${encodeURIComponent(id)}`,
    kind,
    source: clean(input.source ?? kind, 120),
    label: optionalClean(input.label, 240),
    observedAt: validDate(input.observedAt),
    validUntil: validDate(input.validUntil),
    evidenceReceipt: optionalClean(input.evidenceReceipt, 240),
    confidence: input.confidence ?? 1,
    links: (input.links ?? []).map((link) => ({ relation: clean(link.relation, 80), targetUri: clean(link.targetUri, 500) })),
  });
}

export function createAgentArtifact(input: Omit<AgentArtifact, "id" | "createdAt">, now = new Date()): AgentArtifact {
  return agentArtifactSchema.parse({
    ...input,
    title: clean(input.title, 300),
    path: optionalClean(input.path, 500),
    url: optionalClean(input.url, 800),
    contentHash: optionalClean(input.contentHash, 160),
    sourceRefs: input.sourceRefs.map((ref) => clean(ref, 500)),
    id: `artifact-${randomUUID()}`,
    createdAt: now.toISOString(),
  });
}

export function createAgentCorrection(input: Omit<AgentCorrection, "id" | "createdAt">, now = new Date()): AgentCorrection {
  return agentCorrectionSchema.parse({
    ...input,
    previousClaim: clean(input.previousClaim, 1000),
    replacement: clean(input.replacement, 1000),
    reason: clean(input.reason, 1000),
    sourceRefs: input.sourceRefs.map((ref) => clean(ref, 500)),
    expiresAt: validDate(input.expiresAt),
    id: `correction-${randomUUID()}`,
    createdAt: now.toISOString(),
  });
}

export function mergeResourceRefs(current: AgentResourceRef[], additions: AgentResourceRef[]): AgentResourceRef[] {
  const byUri = new Map(current.map((item) => [item.uri, item]));
  for (const item of additions) {
    const existing = byUri.get(item.uri);
    byUri.set(item.uri, existing ? {
      ...existing,
      ...item,
      links: uniqueLinks([...existing.links, ...item.links]),
      confidence: Math.max(existing.confidence, item.confidence),
    } : item);
  }
  return [...byUri.values()].slice(-80);
}

export function sanitizeAgentAcceptanceCriteria(input: AgentAcceptanceCriterion[]): AgentAcceptanceCriterion[] {
  return agentAcceptanceCriteriaSchema.parse(input).map((criterion) => agentAcceptanceCriterionSchema.parse({
    ...criterion,
    description: clean(criterion.description, 500),
    field: optionalClean(criterion.field, 160),
    expected: typeof criterion.expected === "string" ? clean(criterion.expected, 500) : criterion.expected,
    evidenceRefs: criterion.evidenceRefs.map((ref) => clean(ref, 500)),
    result: optionalClean(criterion.result, 600),
  }));
}

export function parseAgentStepExecution(value: unknown): AgentStepExecution | undefined {
  const parsed = agentStepExecutionSchema.safeParse(value);
  return parsed.success ? parsed.data : undefined;
}

function clean(value: string, max: number): string {
  const cleaned = redactSecurityText(value).replace(/\s+/g, " ").trim().slice(0, max);
  if (!cleaned) throw new Error("Agent run value is required.");
  return cleaned;
}

function optionalClean(value: string | undefined, max: number): string | undefined {
  return value?.trim() ? clean(value, max) : undefined;
}

function validDate(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : undefined;
}

function uniqueLinks(links: AgentResourceRef["links"]): AgentResourceRef["links"] {
  return [...new Map(links.map((link) => [`${link.relation}\u0000${link.targetUri}`, link])).values()].slice(0, 20);
}

function containsSecretArgumentKey(value: unknown, depth = 0): boolean {
  if (depth > 8 || !value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some((item) => containsSecretArgumentKey(item, depth + 1));
  return Object.entries(value as Record<string, unknown>).some(([key, item]) => {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]+/g, "_");
    return /^(authorization|cookie|password|private_key|secret|token|api_key)$/.test(normalized)
      || containsSecretArgumentKey(item, depth + 1);
  });
}
