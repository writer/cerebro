import { z } from "zod";

export const securityCaseKindSchema = z.enum(["github_security_alert"]);

export const securityCaseContextSchema = z.object({
  id: z.string().trim().min(1).max(160),
  kind: securityCaseKindSchema,
  title: z.string().trim().min(1).max(300),
  alertRef: z.string().trim().min(1).max(500),
  repository: z.string().trim().min(1).max(240),
  runtimeId: z.string().trim().min(1).max(240),
  findingId: z.string().trim().min(1).max(240),
  owner: z.string().trim().min(1).max(240).optional(),
  desiredOutcome: z.string().trim().min(1).max(500),
});

export type SecurityCaseKind = z.infer<typeof securityCaseKindSchema>;
export type SecurityCaseContext = z.infer<typeof securityCaseContextSchema>;

export type SecurityCaseState =
  | "investigating"
  | "needs_evidence"
  | "needs_decision"
  | "ready_to_act"
  | "waiting_on_owner"
  | "verifying"
  | "closed"
  | "blocked";
