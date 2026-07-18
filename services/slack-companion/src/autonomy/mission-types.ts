import { z } from "zod";

export const securityMissionPackIdSchema = z.enum([
  "appsec.remediation",
  "identity.access-risk",
  "detection.response",
]);

export const securityMissionInputIdSchema = z.enum([
  "alert_ref",
  "evidence_receipt",
  "finding_id",
  "identity_ref",
  "pull_request",
  "repository",
  "risk_ref",
  "rule_ref",
  "runtime_id",
  "target_slack_user_id",
]);

export const securityMissionStepKindSchema = z.enum([
  "observe",
  "compare",
  "verify",
  "decide",
  "act",
  "monitor",
  "rollback",
]);

export const securityMissionActionStageSchema = z.enum([
  "observe",
  "explain",
  "recommend",
  "dry_run",
  "approve",
  "execute",
  "verify",
  "close_loop",
]);

export const securityMissionToolSelectorSchema = z.object({
  names: z.array(z.string().trim().min(1).max(160)).max(20).default([]),
  prefixes: z.array(z.string().trim().min(1).max(120)).max(12).default([]),
  families: z.array(z.string().trim().min(1).max(80)).max(12).default([]),
  authorities: z.array(z.string().trim().min(1).max(80)).max(12).default([]),
});

export const securityMissionStepReceiptSchema = z.object({
  packStepId: z.string().trim().min(1).max(160),
  kind: securityMissionStepKindSchema,
  actionStage: securityMissionActionStageSchema,
  requiredInputIds: z.array(securityMissionInputIdSchema).max(12),
  toolSelector: securityMissionToolSelectorSchema,
  bindingState: z.enum(["bound", "missing_input", "needs_tool", "operator_decision"]),
  approvalRequired: z.boolean(),
  verificationRequired: z.boolean(),
  rollback: z.string().trim().min(1).max(1000).optional(),
});

export const securityMissionBindingSchema = z.object({
  id: securityMissionInputIdSchema,
  value: z.string().trim().min(1).max(500),
  source: z.enum(["explicit", "objective", "resource"]),
});

export const securityMissionReceiptSchema = z.object({
  packId: securityMissionPackIdSchema,
  packVersion: z.string().trim().min(1).max(80),
  compilerVersion: z.string().trim().min(1).max(80),
  compiledAt: z.string().datetime(),
  status: z.enum(["ready", "needs_input", "needs_tool"]),
  trigger: z.string().trim().min(1).max(160),
  owner: z.string().trim().min(1).max(160),
  objectiveDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  planDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  bindings: z.array(securityMissionBindingSchema).max(20),
  missingInputIds: z.array(securityMissionInputIdSchema).max(20),
  requiredEvidence: z.array(z.string().trim().min(1).max(300)).max(30),
  acceptanceCriteriaIds: z.array(z.string().trim().min(1).max(160)).max(40),
  actionStepIds: z.array(z.string().trim().min(1).max(160)).max(20),
  serviceLevel: z.object({
    firstCheckpointMinutes: z.number().int().min(1).max(10_080),
    staleAfterMinutes: z.number().int().min(1).max(43_200),
    targetCompletionHours: z.number().int().min(1).max(8_760),
  }),
});

export type SecurityMissionPackId = z.infer<typeof securityMissionPackIdSchema>;
export type SecurityMissionInputId = z.infer<typeof securityMissionInputIdSchema>;
export type SecurityMissionStepKind = z.infer<typeof securityMissionStepKindSchema>;
export type SecurityMissionActionStage = z.infer<typeof securityMissionActionStageSchema>;
export type SecurityMissionToolSelector = z.infer<typeof securityMissionToolSelectorSchema>;
export type SecurityMissionStepReceipt = z.infer<typeof securityMissionStepReceiptSchema>;
export type SecurityMissionBinding = z.infer<typeof securityMissionBindingSchema>;
export type SecurityMissionReceipt = z.infer<typeof securityMissionReceiptSchema>;
