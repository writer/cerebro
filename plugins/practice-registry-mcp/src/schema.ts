import { z } from "zod";

export const practiceStatuses = [
  "preferred",
  "allowed",
  "allowed_with_context",
  "discouraged",
  "banned",
  "legacy_accepted",
  "needs_review",
] as const;

export const enforcementLevels = ["advisory", "blocking", "review"] as const;

export const approvalMethods = ["owner", "research"] as const;

export const approvalSourceSchema = z.object({
  title: z.string().min(3),
  publisher: z.string().min(2),
  url: z.string().url(),
  direct_support: z.string().min(8),
});

export const practiceApprovalSchema = z.object({
  method: z.enum(approvalMethods),
  approved_by: z.string().min(2),
  approved_at: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  conclusion: z.string().min(8),
  sources: z.array(approvalSourceSchema).default([]),
});

export const practiceSchema = z.object({
  id: z.string().min(3),
  title: z.string().min(3),
  status: z.enum(practiceStatuses),
  enforcement: z.enum(enforcementLevels).default("advisory"),
  summary: z.string().min(8),
  rationale: z.string().min(8),
  scope: z
    .object({
      languages: z.array(z.string().min(1)).default([]),
      frameworks: z.array(z.string().min(1)).default([]),
      paths: z
        .object({
          include: z.array(z.string().min(1)).default([]),
          exclude: z.array(z.string().min(1)).default([]),
        })
        .default({ include: [], exclude: [] }),
    })
    .default({ languages: [], frameworks: [], paths: { include: [], exclude: [] } }),
  applies_when: z
    .object({
      intents: z.array(z.string().min(1)).default([]),
      keywords: z.array(z.string().min(1)).default([]),
    })
    .default({ intents: [], keywords: [] }),
  avoid: z.array(z.string().min(1)).default([]),
  use_instead: z.array(z.string().min(1)).default([]),
  good_examples: z.array(z.string().min(1)).default([]),
  bad_examples: z.array(z.string().min(1)).default([]),
  semgrep: z
    .object({
      rule_id: z.string().min(3).optional(),
      severity: z.enum(["ERROR", "WARNING", "INFO"]).optional(),
      pattern: z.string().min(1).optional(),
      pattern_regex: z.string().min(1).optional(),
      languages: z.array(z.string().min(1)).optional(),
    })
    .optional(),
  owner: z.string().min(2),
  last_reviewed: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  approval: practiceApprovalSchema.optional(),
});

export type PracticeRecord = z.infer<typeof practiceSchema> & {
  source_file: string;
};

export type PracticeStatus = (typeof practiceStatuses)[number];
export type EnforcementLevel = (typeof enforcementLevels)[number];
export type ApprovalMethod = (typeof approvalMethods)[number];
export type ApprovalSource = z.infer<typeof approvalSourceSchema>;
export type PracticeApproval = z.infer<typeof practiceApprovalSchema>;

export type PracticeCheckInput = {
  repo?: string;
  intent?: string;
  language?: string;
  framework?: string;
  files?: string[];
  planned_approach?: string;
  proposed_code?: string;
  diff?: string;
  dependencies?: string[];
};

export type PracticeGuardrailInput = Pick<
  PracticeCheckInput,
  "repo" | "intent" | "language" | "framework" | "files" | "dependencies"
> & {
  topic?: string;
  max_practices?: number;
};

export type PracticeMatch = {
  id: string;
  title: string;
  status: PracticeStatus;
  enforcement: EnforcementLevel;
  summary: string;
  rationale: string;
  owner: string;
  source_file: string;
  use_instead: string[];
  avoid: string[];
  confidence: "low" | "medium" | "high";
  score: number;
  reasons: string[];
};

export type PracticeGuardrail = {
  id: string;
  title: string;
  status: PracticeStatus;
  enforcement: EnforcementLevel;
  relevance: "high" | "medium" | "low";
  summary: string;
  owner: string;
  source_file: string;
  scope: PracticeRecord["scope"];
  avoid: string[];
  use_instead: string[];
  reasons: string[];
};

export type PracticeGuardrailResult = {
  summary: string;
  next_steps: string[];
  agent_contract: string[];
  practices: PracticeGuardrail[];
};

export type PracticePreflightInput = PracticeGuardrailInput & {
  planned_approach?: string;
  proposed_code?: string;
};

export type PracticeDecision =
  | "allowed"
  | "follow_guidance"
  | "revise_or_justify"
  | "change_code"
  | "ask_owner"
  | "needs_review";

export type PracticeOutcome = {
  passed: boolean;
  action_required: boolean;
  rerun_required: boolean;
};

export type PracticeObservedResult = {
  observation_id?: number;
};

export type PracticeCheckResult = PracticeOutcome & PracticeObservedResult & {
  decision: PracticeDecision;
  blocking: boolean;
  summary: string;
  next_steps: string[];
  matched_practices: PracticeMatch[];
};

export type PracticePreflightResult = PracticeOutcome & PracticeObservedResult & {
  decision: PracticeDecision;
  blocking: boolean;
  summary: string;
  next_steps: string[];
  required_calls: string[];
  guardrails: PracticeGuardrailResult;
  plan_check: PracticeCheckResult | null;
};

export type PracticeFinding = {
  rule_id: string;
  practice_id: string;
  title: string;
  status: PracticeStatus;
  enforcement: EnforcementLevel;
  blocking: boolean;
  severity: "ERROR" | "WARNING" | "INFO";
  message: string;
  path: string;
  line: number | null;
  code: string;
  engine: "semgrep" | "semgrep-rule-fallback";
  source_file: string;
  owner: string;
  use_instead: string[];
};

export type PracticeScanResult = PracticeOutcome & PracticeObservedResult & {
  decision: PracticeDecision;
  blocking: boolean;
  summary: string;
  next_steps: string[];
  findings: PracticeFinding[];
  engine: {
    semgrep_available: boolean;
    semgrep_used: boolean;
    fallback_used: boolean;
    rules_path: string;
  };
};

export type PracticeObservation = PracticeOutcome & {
  id: number;
  kind: string;
  decision: PracticeDecision | null;
  blocking: boolean;
  practice_ids: string[];
  summary: string | null;
  created_at: string;
};

export type PracticeObservationDetail = PracticeObservation & {
  input: Record<string, unknown>;
  result: Record<string, unknown>;
};

export type PracticeObservationStats = {
  total: number;
  passed: number;
  action_required: number;
  rerun_required: number;
  by_decision: Record<string, number>;
  by_kind: Record<string, number>;
  top_practices: Array<{ practice_id: string; count: number }>;
};

export type PracticeFinalizeInput = {
  diff: string;
  repo?: string;
  language?: string;
  framework?: string;
  files?: string[];
  dependencies?: string[];
  rules_path?: string;
  use_semgrep?: boolean;
  require_plan_check?: boolean;
  plan_observation_id?: number;
};

export type PracticePlanCheckReference = {
  required: boolean;
  provided_observation_id: number | null;
  matched_observation_id: number | null;
  match_type: "provided" | "recent_context" | "missing";
  passed: boolean;
  reason: string;
  final_files: string[];
  final_language: string | null;
  plan_files: string[];
  plan_language: string | null;
};

export type PracticeFinalizeResult = PracticeOutcome & PracticeObservedResult & {
  decision: PracticeDecision;
  blocking: boolean;
  summary: string;
  next_steps: string[];
  scan_diff: PracticeScanResult;
  observations: {
    required_plan_check: boolean;
    passing_plan_found: boolean;
    plan_check: PracticePlanCheckReference;
    recent: PracticeObservation[];
    stats: PracticeObservationStats;
  };
};

export type PracticeLintFinding = {
  practice_id: string;
  source_file: string;
  severity: "error" | "warning";
  message: string;
};

export type PracticeLintResult = PracticeOutcome & {
  decision: PracticeDecision;
  summary: string;
  next_steps: string[];
  findings: PracticeLintFinding[];
};

export type PracticeProposalInput = {
  title: string;
  summary: string;
  owner?: string;
  language?: string;
  framework?: string;
  files?: string[];
  evidence?: string;
  suggested_status?: PracticeStatus;
  suggested_enforcement?: EnforcementLevel;
  avoid?: string[];
  use_instead?: string[];
};

export type PracticeProposalResult = PracticeOutcome & PracticeObservedResult & {
  decision: PracticeDecision;
  blocking: false;
  summary: string;
  next_steps: string[];
  proposal: {
    title: string;
    owner: string;
    language: string | null;
    framework: string | null;
    files: string[];
    suggested_status: PracticeStatus;
    suggested_enforcement: EnforcementLevel;
    evidence: string | null;
  };
};

export type PracticeExceptionInput = {
  practice_id: string;
  reason: string;
  accepted_context: string;
  owner?: string;
  expires_at?: string;
  language?: string;
  files?: string[];
  evidence?: string;
  replacement_plan?: string;
};

export type PracticeExceptionResult = PracticeOutcome & PracticeObservedResult & {
  decision: PracticeDecision;
  blocking: false;
  summary: string;
  next_steps: string[];
  exception: {
    practice_id: string;
    owner: string;
    accepted_context: string;
    expires_at: string | null;
    files: string[];
    evidence: string | null;
    replacement_plan: string | null;
  };
};

export type PracticeApprovalInput = {
  practice_id: string;
  method: ApprovalMethod;
  approved_by: string;
  conclusion: string;
  related_observation_ids?: number[];
  sources?: ApprovalSource[];
};

export type PracticeApprovalResult = PracticeOutcome & PracticeObservedResult & {
  decision: PracticeDecision;
  blocking: false;
  summary: string;
  next_steps: string[];
  approval: {
    practice_id: string;
    owner: string | null;
    method: ApprovalMethod;
    approved_by: string;
    conclusion: string;
    related_observation_ids: number[];
    sources: ApprovalSource[];
  };
};

export type PracticeReviewQueueItem = {
  key: string;
  kind: "needs_review_observation" | "practice_proposal" | "practice_exception" | "owner_decision";
  title: string;
  summary: string;
  owner: string | null;
  practice_ids: string[];
  files: string[];
  language: string | null;
  count: number;
  latest_observation_id: number;
  observation_ids: number[];
  created_at: string;
  evidence: string | null;
  expires_at: string | null;
  next_step: string;
};

export type PracticeReviewQueueResult = PracticeOutcome & PracticeObservedResult & {
  decision: PracticeDecision;
  blocking: false;
  summary: string;
  next_steps: string[];
  stats: {
    total: number;
    needs_review: number;
    proposals: number;
    exceptions: number;
    owner_decisions: number;
  };
  items: PracticeReviewQueueItem[];
};
