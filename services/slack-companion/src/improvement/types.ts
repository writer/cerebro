import { z } from "zod";
import type { AssistantHardCorpusCase } from "../learning/assistant-hillclimb.js";

export const improvementRunStatusSchema = z.enum([
  "observed",
  "queued",
  "candidate_ready",
  "evaluating",
  "shadowing",
  "canary",
  "awaiting_promotion",
  "promoted",
  "rolled_back",
  "blocked",
]);

export const improvementSignalSourceSchema = z.enum([
  "answer_gap",
  "runtime_failure",
  "feedback_downvote",
  "operator",
]);

export const improvementArtifactSchema = z.object({
  kind: z.enum(["interaction", "feedback", "context_exposure", "outcome", "signal", "candidate_intent", "candidate", "ci", "corpus", "evaluation", "shadow", "canary", "rollback"]),
  uri: z.string().regex(/^s3:\/\//),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  createdAt: z.string().datetime(),
});

const corpusArtifactSchema = improvementArtifactSchema.extend({ kind: z.literal("corpus") });
const ciArtifactSchema = improvementArtifactSchema.extend({ kind: z.literal("ci") });
const evaluationArtifactSchema = improvementArtifactSchema.extend({ kind: z.literal("evaluation") });
const signalArtifactSchema = improvementArtifactSchema.extend({ kind: z.literal("signal") });
const candidateIntentArtifactSchema = improvementArtifactSchema.extend({ kind: z.literal("candidate_intent") });

export const improvementHumanAssistanceSchema = z.object({
  channelId: z.string().regex(/^[CDG][A-Z0-9]+$/),
  intendedUserId: z.string().regex(/^[UW][A-Z0-9]+$/),
  expiresAt: z.string().datetime(),
  deliveryStatus: z.enum(["pending", "enqueued", "answered"]),
  deliveryId: z.string().min(1).max(240).optional(),
  outcomeArtifact: signalArtifactSchema.optional(),
  refinementStatus: z.enum(["pending", "completed"]).optional(),
});

export const improvementPullRequestSchema = z.object({
  repo: z.string().min(3).max(200),
  number: z.number().int().positive(),
  url: z.string().url(),
  branch: z.string().min(1).max(240),
});

export const improvementCiCheckSchema = z.object({
  name: z.string().min(1).max(200),
  source: z.enum(["check_run", "commit_status"]),
  status: z.string().min(1).max(80),
  conclusion: z.string().min(1).max(80),
});

export const improvementCandidateReceiptSchema = z.object({
  schemaVersion: z.literal(1),
  repo: z.string().min(3).max(200),
  pullRequestNumber: z.number().int().positive(),
  pullRequestUrl: z.string().url(),
  state: z.string().min(1).max(80),
  draft: z.boolean(),
  merged: z.boolean(),
  headRepo: z.string().min(3).max(200),
  headRef: z.string().min(1).max(240),
  headSha: z.string().regex(/^[a-f0-9]{40}$/),
  baseRef: z.string().min(1).max(240),
  baseSha: z.string().regex(/^[a-f0-9]{40}$/),
  requiredChecks: z.array(z.string().trim().min(1).max(200)).min(1).max(50)
    .refine((checks) => new Set(checks).size === checks.length, "Required GitHub check names must be unique."),
  checks: z.array(improvementCiCheckSchema).min(1).max(100),
  observedAt: z.string().datetime(),
}).strict();

export const improvementDelegationRolloutModeSchema = z.enum(["disabled", "shadow", "canary", "active"]);

export const improvementDelegationManifestSchema = z.object({
  schemaVersion: z.literal(1),
  manifestId: z.string().regex(/^delegation-[a-f0-9]{32}$/),
  issuer: z.literal("cerebro-improvement-control-plane"),
  runId: z.string().regex(/^improvement-[a-f0-9]{24}$/),
  generation: z.number().int().positive(),
  jobKind: z.enum(["author_candidate", "open_candidate_pr"]),
  inputSignalShas: z.array(z.string().regex(/^[a-f0-9]{64}$/)).min(1).max(6)
    .refine((shas) => new Set(shas).size === shas.length, "Delegated signal SHA values must be unique."),
  repo: z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/).max(200),
  baseRef: z.string().min(1).max(200),
  baseSha: z.string().regex(/^[a-f0-9]{40}$/),
  sourceSha: z.string().regex(/^[a-f0-9]{40}$/),
  authority: z.tuple([z.literal("repository:read"), z.literal("pull_request:draft")]),
  budgets: z.object({
    maxFiles: z.number().int().min(1).max(12),
    maxFileBytes: z.number().int().min(1).max(120_000),
    maxTotalBytes: z.number().int().min(1).max(200_000),
    maxSourceCalls: z.number().int().min(2).max(8),
    maxRuntimeMs: z.number().int().min(30_000).max(600_000),
  }).strict(),
  policyVersion: z.string().min(1).max(100),
  toolsetVersion: z.string().min(1).max(100),
  rollout: z.object({
    mode: improvementDelegationRolloutModeSchema,
    cohortBucket: z.number().int().min(0).max(9_999),
    canaryBasisPoints: z.number().int().min(0).max(10_000),
  }).strict(),
  issuedAt: z.string().datetime(),
  notBefore: z.string().datetime(),
  expiresAt: z.string().datetime(),
}).strict().superRefine((manifest, context) => {
  const issuedAt = Date.parse(manifest.issuedAt);
  const notBefore = Date.parse(manifest.notBefore);
  const expiresAt = Date.parse(manifest.expiresAt);
  if (notBefore < issuedAt - 60_000 || notBefore > issuedAt) {
    context.addIssue({ code: "custom", message: "Delegation notBefore must be within one minute before issuance.", path: ["notBefore"] });
  }
  if (expiresAt <= issuedAt || expiresAt - issuedAt > 3_600_000) {
    context.addIssue({ code: "custom", message: "Delegation lifetime must be positive and at most one hour.", path: ["expiresAt"] });
  }
});

export const signedImprovementDelegationSchema = z.object({
  manifest: improvementDelegationManifestSchema,
  signature: z.string().min(40).max(4_000),
}).strict();

export const improvementCiReceiptSchema = z.object({
  repo: z.string().min(3).max(200),
  pullRequestNumber: z.number().int().positive(),
  headSha: z.string().regex(/^[a-f0-9]{40}$/),
  requiredChecks: z.array(z.string().min(1).max(200)).min(1).max(50),
  checks: z.array(improvementCiCheckSchema).min(1).max(100),
  successful: z.boolean(),
  verifiedAt: z.string().datetime(),
  artifact: ciArtifactSchema,
});

export const improvementEvaluationSchema = z.object({
  corpusPartition: z.literal("held_out"),
  candidateVersion: z.string().regex(/^[a-f0-9]{40}$/),
  evaluatorVersion: z.string().min(1).max(200),
  releaseReady: z.boolean(),
  caseCount: z.number().int().nonnegative(),
  passRate: z.number().min(0).max(1),
  averageScore: z.number().min(0).max(1),
  correctionClosureRate: z.number().min(0).max(1),
  regressionRate: z.number().min(0).max(1).optional(),
  blockers: z.array(z.string().min(1).max(200)).max(100),
  artifact: evaluationArtifactSchema,
});

export const improvementOutcomeSchema = z.object({
  stage: z.enum(["shadow", "canary"]),
  success: z.boolean(),
  sampleSize: z.number().int().positive(),
  helpfulRate: z.number().min(0).max(1).optional(),
  errorRate: z.number().min(0).max(1),
  rollbackReason: z.string().min(1).max(500).optional(),
  artifact: improvementArtifactSchema,
});

export const improvementApprovalSchema = z.object({
  reviewedBy: z.string().min(1).max(200),
  reviewedAt: z.string().datetime(),
  sourceRef: z.string().min(1).max(500),
  reason: z.string().min(1).max(500),
  signingKeyId: z.string().min(1).max(500),
  signature: z.string().min(40).max(4_000),
});

export const improvementAuthorLeaseSchema = z.object({
  generation: z.number().int().positive(),
  token: z.string().uuid(),
  acquiredAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
});

export const improvementAuthorRequestSchema = z.object({
  generation: z.number().int().positive(),
  inputSignalShas: z.array(z.string().regex(/^[a-f0-9]{64}$/)).min(1).max(6)
    .refine((shas) => new Set(shas).size === shas.length, "Author input signal SHA values must be unique."),
  repo: z.string().min(3).max(200).optional(),
  baseRef: z.string().min(1).max(200),
  requestedAt: z.string().datetime(),
});

export const improvementAuthorDispatchSchema = z.object({
  generation: z.number().int().positive(),
  enqueuedAt: z.string().datetime(),
});

export const improvementCandidateBranchWriteSchema = z.object({
  generation: z.number().int().positive(),
  repo: z.string().min(3).max(200),
  baseRef: z.string().min(1).max(200),
  branch: z.string().min(1).max(240),
  pullRequestNumber: z.number().int().positive(),
  pullRequestUrl: z.string().url(),
  headSha: z.string().regex(/^[a-f0-9]{40}$/),
  recordedAt: z.string().datetime(),
});

export const improvementCandidateWriteIntentSchema = z.object({
  generation: z.number().int().positive(),
  repo: z.string().min(3).max(200),
  baseRef: z.string().min(1).max(200),
  branch: z.string().min(1).max(240),
  expectedBaseSha: z.string().regex(/^[a-f0-9]{40}$/),
  expectedHeadSha: z.string().regex(/^[a-f0-9]{40}$/),
  payloadSha256: z.string().regex(/^[a-f0-9]{64}$/),
  artifact: candidateIntentArtifactSchema,
  recordedAt: z.string().datetime(),
});

export const improvementRunSchema = z.object({
  id: z.string().regex(/^improvement-[a-f0-9]{24}$/),
  candidateKey: z.string().regex(/^[a-f0-9]{12}$/).optional(),
  signature: z.string().min(1).max(240),
  source: improvementSignalSourceSchema,
  issueKind: z.string().min(1).max(100),
  skillId: z.string().min(1).max(100),
  status: improvementRunStatusSchema,
  signalCount: z.number().int().positive(),
  authorGeneration: z.number().int().positive().optional(),
  authorInputSignalShas: z.array(z.string().regex(/^[a-f0-9]{64}$/)).min(1).max(6)
    .refine((shas) => new Set(shas).size === shas.length, "Author input signal SHA values must be unique.")
    .optional(),
  authorRequest: improvementAuthorRequestSchema.optional(),
  authorDispatch: improvementAuthorDispatchSchema.optional(),
  authorLease: improvementAuthorLeaseSchema.optional(),
  candidateWriteIntent: improvementCandidateWriteIntentSchema.optional(),
  candidateBranchWrite: improvementCandidateBranchWriteSchema.optional(),
  candidateGeneration: z.number().int().positive().optional(),
  candidateVersion: z.string().regex(/^[a-f0-9]{40}$/).optional(),
  refinementBaseVersion: z.string().regex(/^[a-f0-9]{40}$/).optional(),
  evaluatorVersion: z.string().min(1).max(200).optional(),
  pullRequest: improvementPullRequestSchema.optional(),
  ciReceipt: improvementCiReceiptSchema.optional(),
  evaluation: improvementEvaluationSchema.optional(),
  shadowOutcome: improvementOutcomeSchema.optional(),
  canaryOutcome: improvementOutcomeSchema.optional(),
  approval: improvementApprovalSchema.optional(),
  assistance: improvementHumanAssistanceSchema.optional(),
  artifacts: z.array(improvementArtifactSchema).max(100),
  blockers: z.array(z.string().min(1).max(500)).max(50),
  version: z.number().int().positive(),
  createdAt: z.string().datetime(),
  queuedAt: z.string().datetime().optional(),
  updatedAt: z.string().datetime(),
});

export const improvementSignalSchema = z.object({
  signature: z.string().min(1).max(240),
  source: improvementSignalSourceSchema,
  issueKind: z.string().min(1).max(100),
  skillId: z.string().min(1).max(100),
  occurredAt: z.string().datetime(),
  channelHash: z.string().regex(/^[a-f0-9]{16}$/).optional(),
  answerHash: z.string().regex(/^[a-f0-9]{16}$/).optional(),
  question: z.string().min(1).max(4_000).optional(),
  answer: z.string().min(1).max(12_000).optional(),
  reason: z.string().min(1).max(100).optional(),
  executionLane: z.string().min(1).max(80).optional(),
  answerSource: z.enum(["pi", "flue", "blocked"]).optional(),
  toolNames: z.array(z.string().min(1).max(160)).max(64).default([]),
  evidenceCount: z.number().int().nonnegative().default(0),
  actionCount: z.number().int().nonnegative().default(0),
  commitmentStates: z.array(z.string().min(1).max(80)).max(24).default([]),
  deliveryComplete: z.boolean().optional(),
  providedBy: z.object({
    slackUserId: z.string().min(1).max(160),
    displayName: z.string().min(1).max(160).optional(),
  }).optional(),
});

export const improvementInteractionSchema = z.object({
  interactionId: z.string().regex(/^[a-f0-9]{16}$/),
  answerHash: z.string().regex(/^[a-f0-9]{16}$/),
  channelHash: z.string().regex(/^[a-f0-9]{16}$/),
  threadHash: z.string().regex(/^[a-f0-9]{16}$/),
  requester: z.object({
    slackUserId: z.string().min(1).max(160),
  }).optional(),
  occurredAt: z.string().datetime(),
  question: z.string().min(1).max(4_000),
  answer: z.string().min(1).max(12_000),
  executionLane: z.string().min(1).max(80).optional(),
  answerSource: z.enum(["pi", "flue", "blocked"]),
  toolNames: z.array(z.string().min(1).max(160)).max(64).default([]),
  evidenceCount: z.number().int().nonnegative(),
  actionCount: z.number().int().nonnegative(),
  commitmentStates: z.array(z.string().min(1).max(80)).max(24).default([]),
  deliveryComplete: z.boolean(),
  queueLatencyMs: z.number().int().nonnegative().optional(),
  totalLatencyMs: z.number().int().nonnegative().optional(),
  sourceSubjectCount: z.number().int().nonnegative().optional(),
  followsInteractionId: z.string().regex(/^[a-f0-9]{16}$/).optional(),
});

export const improvementFeedbackOutcomeSchema = z.object({
  interactionId: z.string().regex(/^[a-f0-9]{16}$/),
  answerHash: z.string().regex(/^[a-f0-9]{16}$/),
  occurredAt: z.string().datetime(),
  vote: z.enum(["up", "down"]),
  reason: z.string().min(1).max(100),
  providedBy: z.object({
    slackUserId: z.string().min(1).max(160),
    displayName: z.string().min(1).max(160).optional(),
  }),
  requester: z.object({
    slackUserId: z.string().min(1).max(160),
  }).optional(),
});

export const improvementContextExposureSchema = z.object({
  interactionId: z.string().regex(/^[a-f0-9]{16}$/),
  occurredAt: z.string().datetime(),
  requester: z.object({ slackUserId: z.string().min(1).max(160) }).optional(),
  channelHash: z.string().regex(/^[a-f0-9]{16}$/),
  threadHash: z.string().regex(/^[a-f0-9]{16}$/),
  selectorVersion: z.string().min(1).max(80),
  treatment: z.enum(["context", "holdout"]),
  candidateClaimIds: z.array(z.string().min(1).max(80)).max(50),
  selectedClaims: z.array(z.object({
    claimId: z.string().min(1).max(80),
    kind: z.enum(["task_correction", "personal_preference", "personal_strength", "successful_example", "team_preference", "team_strength"]),
    scope: z.enum(["same_thread", "related_task", "personal", "team"]),
    relevanceScore: z.number().int().nonnegative(),
  })).max(12),
  promptIncluded: z.boolean(),
  promptCharCount: z.number().int().nonnegative(),
});

export const improvementOutcomeEventSchema = z.object({
  interactionId: z.string().regex(/^[a-f0-9]{16}$/),
  answerHash: z.string().regex(/^[a-f0-9]{16}$/).optional(),
  occurredAt: z.string().datetime(),
  type: z.enum(["delivery", "explicit_feedback", "follow_up", "implicit_correction", "action_closure", "mission_completion"]),
  result: z.string().min(1).max(100),
  confidence: z.number().min(0).max(1),
});

export const improvementEventSchema = z.object({
  id: z.string().min(1).max(240),
  runId: z.string().regex(/^improvement-[a-f0-9]{24}$/),
  type: z.string().min(1).max(100),
  fromStatus: improvementRunStatusSchema.optional(),
  toStatus: improvementRunStatusSchema,
  at: z.string().datetime(),
  actor: z.enum(["companion", "worker", "evaluator", "promotion_controller", "operator"]),
  detail: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])).default({}),
});

export const candidatePullRequestJobSchema = z.object({
  repo: z.string().min(3).max(200).optional(),
  title: z.string().min(1).max(240),
  body: z.string().max(12_000).optional(),
  files: z.array(z.object({ path: z.string().min(1).max(500), content: z.string().max(120_000) })).min(1).max(12),
  branch: z.string().min(1).max(240).optional(),
  base: z.string().min(1).max(240).optional(),
  expectedBaseSha: z.string().regex(/^[a-f0-9]{40}$/).optional(),
  expectedHeadSha: z.string().regex(/^[a-f0-9]{40}$/).optional(),
  draft: z.boolean().default(true),
  draftBoundReuse: z.boolean().optional(),
}).superRefine((value, context) => {
  const totalBytes = value.files.reduce((total, file) => total + Buffer.byteLength(file.content, "utf8"), 0);
  if (totalBytes > 200_000) {
    context.addIssue({ code: "custom", message: "Candidate files exceed the 200000-byte queue payload limit.", path: ["files"] });
  }
});

const openCandidateJobSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal("open_candidate_pr"),
  runId: z.string().regex(/^improvement-[a-f0-9]{24}$/),
  generation: z.number().int().positive().optional(),
  inputSignalShas: z.array(z.string().regex(/^[a-f0-9]{64}$/)).min(1).max(6)
    .refine((shas) => new Set(shas).size === shas.length, "Author input signal SHA values must be unique.")
    .optional(),
  delegation: signedImprovementDelegationSchema.optional(),
  pullRequest: candidatePullRequestJobSchema,
});

const authorCandidateJobSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal("author_candidate"),
  runId: z.string().regex(/^improvement-[a-f0-9]{24}$/),
  generation: z.number().int().positive().optional(),
  inputSignalShas: z.array(z.string().regex(/^[a-f0-9]{64}$/)).min(1).max(6)
    .refine((shas) => new Set(shas).size === shas.length, "Author input signal SHA values must be unique.")
    .optional(),
  delegation: signedImprovementDelegationSchema.optional(),
  repo: z.string().min(3).max(200).optional(),
  baseRef: z.string().min(1).max(200).default("main"),
});

const evaluateCandidateJobSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal("evaluate_candidate"),
  runId: z.string().regex(/^improvement-[a-f0-9]{24}$/),
  candidateVersion: z.string().regex(/^[a-f0-9]{40}$/),
  evaluatorVersion: z.string().min(1).max(200),
  requiredChecks: z.array(z.string().trim().min(1).max(200)).min(1).max(50)
    .refine((checks) => new Set(checks).size === checks.length, "Required GitHub check names must be unique."),
  corpusArtifact: corpusArtifactSchema,
  candidateReceipt: improvementCandidateReceiptSchema,
  receiptSignature: z.string().min(40).max(4_000),
});

const shadowOutcomeJobSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal("record_shadow"),
  runId: z.string().regex(/^improvement-[a-f0-9]{24}$/),
  candidateVersion: z.string().regex(/^[a-f0-9]{40}$/).optional(),
  outcome: improvementOutcomeSchema,
});

const canaryOutcomeJobSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal("record_canary"),
  runId: z.string().regex(/^improvement-[a-f0-9]{24}$/),
  candidateVersion: z.string().regex(/^[a-f0-9]{40}$/).optional(),
  outcome: improvementOutcomeSchema,
});

export const promotionPayloadSchema = z.object({
  runId: z.string().regex(/^improvement-[a-f0-9]{24}$/),
  candidateVersion: z.string().regex(/^[a-f0-9]{40}$/).optional(),
  decision: z.enum(["promote", "rollback"]),
  reason: z.string().min(1).max(500),
  reviewedBy: z.string().min(1).max(200),
  reviewedAt: z.string().datetime(),
  sourceRef: z.string().min(1).max(500),
  candidateReceipt: improvementCandidateReceiptSchema,
});

const promotionJobSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal("promotion_decision"),
  payload: promotionPayloadSchema,
  signature: z.string().min(40).max(4_000),
});

const sweepJobSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal("sweep_stale_runs"),
});

export const improvementJobSchema = z.discriminatedUnion("kind", [
  authorCandidateJobSchema,
  openCandidateJobSchema,
  evaluateCandidateJobSchema,
  shadowOutcomeJobSchema,
  canaryOutcomeJobSchema,
  promotionJobSchema,
  sweepJobSchema,
]);

export type ImprovementRunStatus = z.infer<typeof improvementRunStatusSchema>;
export type ImprovementSignalSource = z.infer<typeof improvementSignalSourceSchema>;
export type ImprovementArtifact = z.infer<typeof improvementArtifactSchema>;
export type ImprovementPullRequest = z.infer<typeof improvementPullRequestSchema>;
export type ImprovementCiCheck = z.infer<typeof improvementCiCheckSchema>;
export type ImprovementCiReceipt = z.infer<typeof improvementCiReceiptSchema>;
export type ImprovementCandidateReceipt = z.infer<typeof improvementCandidateReceiptSchema>;
export type ImprovementDelegationRolloutMode = z.infer<typeof improvementDelegationRolloutModeSchema>;
export type ImprovementDelegationManifest = z.infer<typeof improvementDelegationManifestSchema>;
export type SignedImprovementDelegation = z.infer<typeof signedImprovementDelegationSchema>;
export type ImprovementEvaluation = z.infer<typeof improvementEvaluationSchema>;
export type ImprovementOutcome = z.infer<typeof improvementOutcomeSchema>;
export type ImprovementApproval = z.infer<typeof improvementApprovalSchema>;
export type ImprovementAuthorRequest = z.infer<typeof improvementAuthorRequestSchema>;
export type ImprovementHumanAssistance = z.infer<typeof improvementHumanAssistanceSchema>;
export type ImprovementRun = z.infer<typeof improvementRunSchema>;
export type ImprovementSignal = z.infer<typeof improvementSignalSchema>;
export type ImprovementInteraction = z.infer<typeof improvementInteractionSchema>;
export type ImprovementFeedbackOutcome = z.infer<typeof improvementFeedbackOutcomeSchema>;
export type ImprovementContextExposure = z.infer<typeof improvementContextExposureSchema>;
export type ImprovementOutcomeEvent = z.infer<typeof improvementOutcomeEventSchema>;
export type ImprovementEvent = z.infer<typeof improvementEventSchema>;
export type ImprovementJob = z.infer<typeof improvementJobSchema>;
export type PromotionPayload = z.infer<typeof promotionPayloadSchema>;

export interface ImprovementCandidate {
  repo?: string;
  baseRef?: string;
}

export interface ImprovementHumanAssistanceContext {
  channelId: string;
  intendedUserId: string;
}

export interface ImprovementObserveOptions {
  humanAssistance?: ImprovementHumanAssistanceContext;
}

export interface ImprovementSignalRecorder {
  observe(signal: ImprovementSignal, candidate: ImprovementCandidate, options?: ImprovementObserveOptions): Promise<ImprovementRun | undefined>;
  recordHumanAssistanceOutcome?(input: {
    runId: string;
    channelId: string;
    intendedUserId: string;
    outcome: string;
  }): Promise<ImprovementRun | undefined>;
  recordInteraction?(interaction: ImprovementInteraction): Promise<ImprovementArtifact>;
  recordFeedbackOutcome?(outcome: ImprovementFeedbackOutcome): Promise<ImprovementArtifact>;
  recordContextExposure?(exposure: ImprovementContextExposure): Promise<ImprovementArtifact>;
  recordOutcomeEvent?(outcome: ImprovementOutcomeEvent): Promise<ImprovementArtifact>;
  recordConversationCase?(conversationCase: AssistantHardCorpusCase): Promise<ImprovementArtifact>;
}
