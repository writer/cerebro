import { z } from "zod";

export const securityCaseKindSchema = z.enum(["github_security_alert", "cerebro_work_item"]);

const securityCaseBase = {
  id: z.string().trim().min(1).max(160),
  title: z.string().trim().min(1).max(300),
  owner: z.string().trim().min(1).max(240).optional(),
  desiredOutcome: z.string().trim().min(1).max(500),
};

export const githubSecurityCaseContextSchema = z.object({
  ...securityCaseBase,
  kind: z.literal("github_security_alert"),
  alertRef: z.string().trim().min(1).max(500),
  repository: z.string().trim().min(1).max(240),
  runtimeId: z.string().trim().min(1).max(240),
  findingId: z.string().trim().min(1).max(240),
});

export const cerebroWorkItemCaseContextSchema = z.object({
  ...securityCaseBase,
  kind: z.literal("cerebro_work_item"),
  workItemId: z.string().trim().min(1).max(160),
  workItemVersion: z.number().int().positive(),
  workItemState: z.enum(["open", "in_progress", "blocked", "resolved", "accepted", "snoozed", "superseded"]),
  programId: z.string().trim().min(1).max(240),
  scopeRevisionId: z.string().trim().min(1).max(240),
  controlId: z.string().trim().min(1).max(240),
  objectiveId: z.string().trim().min(1).max(240),
  subjectId: z.string().trim().min(1).max(500),
  sourceId: z.string().trim().min(1).max(240),
  findingIds: z.array(z.string().trim().min(1).max(240)).max(100),
  assuranceDecisionId: z.string().trim().min(1).max(240).optional(),
});

export const securityCaseContextSchema = z.discriminatedUnion("kind", [
  githubSecurityCaseContextSchema,
  cerebroWorkItemCaseContextSchema,
]);

export type SecurityCaseKind = z.infer<typeof securityCaseKindSchema>;
export type SecurityCaseContext = z.infer<typeof securityCaseContextSchema>;
export type GithubSecurityCaseContext = z.infer<typeof githubSecurityCaseContextSchema>;
export type CerebroWorkItemCaseContext = z.infer<typeof cerebroWorkItemCaseContextSchema>;

export type SecurityCaseState =
  | "investigating"
  | "needs_evidence"
  | "needs_decision"
  | "ready_to_act"
  | "waiting_on_owner"
  | "verifying"
  | "closed"
  | "blocked";
