import type { ClaimVerificationActionStage } from "../cerebro/types.js";
import type {
  AgentAcceptanceCriterion,
  AgentArtifact,
  AgentCompletionReceipt,
  AgentCorrection,
  AgentResourceRef,
  AgentStepExecution,
} from "./agent-run.js";
import type { SecurityCaseContext } from "../security-cases/types.js";
import type { SecurityMissionReceipt, SecurityMissionStepReceipt } from "./mission-types.js";

export interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

export interface AutonomyGoalStoreOptions {
  dynamo?: CommandSender;
  now?: () => Date;
}

export type AutonomyGoalStatus =
  | "active"
  | "waiting"
  | "approval_needed"
  | "blocked"
  | "paused"
  | "completed"
  | "cancelled";

export type AutonomyCapabilityId =
  | "triage"
  | "investigation"
  | "planner"
  | "executor"
  | "remediation"
  | "identity_response"
  | "detection_response"
  | "self_repair";

export type AutonomyToolRunStatus =
  | "planned"
  | "completed"
  | "failed"
  | "skipped"
  | "approval_requested";

export type AutonomyApprovalStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "executed"
  | "failed"
  | "cancelled";

export type AutonomyWorkLogKind =
  | "goal_created"
  | "plan_updated"
  | "step_started"
  | "tool_called"
  | "artifact_changed"
  | "check_result"
  | "assumption_made"
  | "blocker_found"
  | "approval_requested"
  | "decision_made"
  | "step_completed"
  | "goal_completed";

export interface AutonomyActor {
  slackUserId?: string;
  actorId?: string;
  displayName?: string;
}

export interface AutonomyPlanStep {
  id: string;
  title: string;
  status: "pending" | "active" | "waiting" | "completed" | "failed" | "skipped";
  dependsOn: string[];
  summary?: string;
  execution?: AgentStepExecution;
  acceptanceCriteriaIds?: string[];
  mission?: SecurityMissionStepReceipt;
}

export interface AutonomyWorkLogEntry {
  id: string;
  kind: AutonomyWorkLogKind;
  createdAt: string;
  summary: string;
  details?: string;
  artifactUrl?: string;
}

export type AutonomyGoalLedgerEventType =
  | "goal_created"
  | "goal_updated"
  | "work_log_appended"
  | "claim_acquired"
  | "claim_released";

export interface AutonomyGoalLedgerEvent {
  id: string;
  goalId: string;
  type: AutonomyGoalLedgerEventType;
  occurredAt: string;
  revision: number;
  previousRevision?: number;
  changedFields?: string[];
  workLog?: AutonomyWorkLogEntry;
  workerId?: string;
}

export interface AutonomyToolRunRecord {
  id: string;
  toolId: string;
  toolName?: string;
  status: AutonomyToolRunStatus;
  requestSummary?: string;
  responseSummary?: string;
  reason?: string;
  error?: string;
  artifactUrl?: string;
  startedAt: string;
  completedAt?: string;
}

export interface AutonomyApprovalRecord {
  id: string;
  status: AutonomyApprovalStatus;
  stepId?: string;
  toolId: string;
  toolName?: string;
  actionSummary: string;
  reason: string;
  risk: string;
  requestSummary?: string;
  createdAt: string;
  decidedAt?: string;
  decidedBy?: AutonomyActor;
  resultSummary?: string;
  error?: string;
}

export interface AutonomyGoalClaim {
  workerId: string;
  claimedAt: string;
  leaseExpiresAt: string;
  attempt: number;
}

export type AutonomyExecutionContractSource = "cerebro" | "local_default";

export interface AutonomyExecutionContract {
  source: AutonomyExecutionContractSource;
  version: string;
  capabilityId: AutonomyCapabilityId;
  profileId: string;
  maxActionStage: ClaimVerificationActionStage;
  requestedActionStage: ClaimVerificationActionStage;
  requiredVerifierIds: string[];
  selectedAt: string;
}

export interface AutonomousGoalRecord {
  id: string;
  status: AutonomyGoalStatus;
  capabilityId: AutonomyCapabilityId;
  objective: string;
  channelId?: string;
  threadTs?: string;
  createdBy: AutonomyActor;
  createdAt: string;
  updatedAt: string;
  currentPlan: AutonomyPlanStep[];
  activeStepId?: string | null;
  assumptions: string[];
  blockers: string[];
  artifactUrls: string[];
  resourceRefs: AgentResourceRef[];
  artifacts: AgentArtifact[];
  acceptanceCriteria: AgentAcceptanceCriterion[];
  corrections: AgentCorrection[];
  completionReceipt?: AgentCompletionReceipt;
  securityCase?: SecurityCaseContext;
  nextWakeAt?: string;
  completionSummary?: string;
  claim?: AutonomyGoalClaim;
  executionContract?: AutonomyExecutionContract;
  mission?: SecurityMissionReceipt;
  toolRuns: AutonomyToolRunRecord[];
  approvals: AutonomyApprovalRecord[];
  workLog: AutonomyWorkLogEntry[];
}

export interface CreateAutonomyGoalInput {
  objective: string;
  capabilityId?: AutonomyCapabilityId;
  channelId?: string;
  threadTs?: string;
  createdBy: AutonomyActor;
  assumptions?: string[];
  plan?: AutonomyPlanStep[];
  nextWakeAt?: string;
  executionContract?: AutonomyExecutionContract;
  mission?: SecurityMissionReceipt;
  resourceRefs?: AgentResourceRef[];
  artifacts?: AgentArtifact[];
  acceptanceCriteria?: AgentAcceptanceCriterion[];
  corrections?: AgentCorrection[];
  securityCase?: SecurityCaseContext;
}

export interface UpdateAutonomyGoalInput {
  status?: AutonomyGoalStatus;
  capabilityId?: AutonomyCapabilityId;
  currentPlan?: AutonomyPlanStep[];
  activeStepId?: string | null;
  assumptions?: string[];
  blockers?: string[];
  artifactUrls?: string[];
  nextWakeAt?: string | null;
  completionSummary?: string | null;
  claim?: AutonomyGoalClaim | null;
  executionContract?: AutonomyExecutionContract | null;
  mission?: SecurityMissionReceipt | null;
  toolRuns?: AutonomyToolRunRecord[];
  approvals?: AutonomyApprovalRecord[];
  resourceRefs?: AgentResourceRef[];
  artifacts?: AgentArtifact[];
  acceptanceCriteria?: AgentAcceptanceCriterion[];
  corrections?: AgentCorrection[];
  completionReceipt?: AgentCompletionReceipt | null;
  securityCase?: SecurityCaseContext | null;
}

export interface AutonomyGoalStore {
  create(input: CreateAutonomyGoalInput): Promise<AutonomousGoalRecord>;
  get(goalId: string): Promise<AutonomousGoalRecord | undefined>;
  getRevision(goalId: string): Promise<number | undefined>;
  list(status?: AutonomyGoalStatus): Promise<AutonomousGoalRecord[]>;
  listDue(now: Date, limit: number): Promise<AutonomousGoalRecord[]>;
  listEvents(goalId: string, limit?: number): Promise<AutonomyGoalLedgerEvent[]>;
  update(goalId: string, input: UpdateAutonomyGoalInput): Promise<AutonomousGoalRecord>;
  appendLog(goalId: string, entry: Omit<AutonomyWorkLogEntry, "id" | "createdAt">): Promise<AutonomousGoalRecord>;
  tryClaim(goalId: string, input: { workerId: string; leaseExpiresAt: string; expectedRevision?: number }): Promise<AutonomousGoalRecord | undefined>;
  releaseClaim(goalId: string, workerId: string): Promise<AutonomousGoalRecord>;
}
