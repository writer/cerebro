import type { FlueSecurityAssistantCompleteInput, FlueSecurityAssistantCompleteOutput } from "./flue-security-assistant.js";
import type { AutonomyGoalService } from "../autonomy/goal-service.js";
import type { SecurityMemoryFreshness, SecurityMemoryQuality, SecurityMemoryWriteInput } from "../learning/memory-types.js";
import type { AssistantExecutionLane, SecurityDomainLens } from "./operational-intelligence.js";
import type { AssistantThreadStateStore } from "./thread-intelligence-store.js";
import type { AssistantTeammateUpdate } from "./teammate-state.js";
import type { AssistantFeedbackService } from "../learning/assistant-feedback.js";
import type { EvidenceGovernanceService } from "./evidence-governance.js";
import type { RiskAttestationService } from "../slack/risk-attestation.js";
import type { SecurityToolFactory } from "./tools/types.js";
import type { CerebroEnsembleService } from "./cerebro-ensemble.js";
import type { CerebroDistributedWorkService } from "./distributed-work.js";
import type { SharedRateLimitCoordinator } from "../a2a/rate-limit.js";

export interface SecurityAssistantInput {
  interactionId?: string;
  channelId: string;
  userId?: string;
  senderKind?: "human" | "bot";
  question: string;
  ts: string;
  threadTs?: string;
}

export interface SecurityAssistantAnswer {
  answer: string;
  messages: string[];
  reaction?: string;
  keyPoints: string[];
  evidence: string[];
  actionsTaken: string[];
  nextActions: string[];
  research: string[];
  memoryUpdates: SecurityMemoryWriteInput[];
  memoryCitationIds?: string[];
  memoryCitations?: SecurityAssistantMemoryCitation[];
  claimEvidenceBindings?: SecurityAssistantClaimEvidenceBinding[];
  claimEvidence?: SecurityAssistantClaimEvidencePacket[];
  source: "pi" | "flue" | "blocked";
  executionLane?: AssistantExecutionLane;
  domainLenses?: SecurityDomainLens[];
  presentationReady?: boolean;
  delivery?: "respond" | "suppress";
  dispositionReason?: string;
  contractRecovery?: "qualified_uncertainty";
  teammate?: AssistantTeammateUpdate;
}

export type SecurityAssistantEvidenceKind = "memory" | "company_library" | "live_source";
export type SecurityAssistantEvidenceBasis = "historical" | "live" | "inferred";
export type SecurityAssistantEvidenceAccess = "allowed" | "restricted";
export type SecurityAssistantClaimTemporalScope = "historical" | "current";
export type SecurityAssistantClaimVerification = "verified" | "historical_only" | "contradicted" | "unverified" | "blocked";

export interface SecurityAssistantEvidenceRef {
  id: string;
  kind: SecurityAssistantEvidenceKind;
  title: string;
  basis: SecurityAssistantEvidenceBasis;
  access: SecurityAssistantEvidenceAccess;
  sourceTool?: string;
  sourceRef?: string;
  subjectId?: string;
  subjectKind?: string;
  subjectLabel?: string;
  channelId?: string;
  sourceTs?: string;
  createdAt?: string;
  verifiedAt?: string;
  verifiedBy: string[];
  sourceArtifacts: string[];
  quality?: SecurityMemoryQuality;
  freshness?: SecurityMemoryFreshness;
  permalink?: string;
  version?: number | string;
  conflicted?: boolean;
}

export interface SecurityAssistantClaimEvidenceBinding {
  claimId: string;
  claimText: string;
  temporalScope: SecurityAssistantClaimTemporalScope;
  evidenceIds: string[];
}

export interface SecurityAssistantClaimEvidencePacket {
  claimId: string;
  claimText: string;
  temporalScope: SecurityAssistantClaimTemporalScope;
  verification: SecurityAssistantClaimVerification;
  sourceTools: string[];
  evidenceReceipts: string[];
  evidence: SecurityAssistantEvidenceRef[];
  visible: boolean;
}

export interface SecurityAssistantMemoryCitation {
  id: string;
  topic: string;
  kind?: string;
  channelId?: string;
  sourceTs?: string;
  sourceKind?: string;
  createdAt: string;
  verifiedAt?: string;
  verifiedBy: string[];
  sourceArtifacts: string[];
  quality?: SecurityMemoryQuality;
  freshness?: SecurityMemoryFreshness;
  permalink?: string;
}

export interface SecurityAssistantRepairCompleteInput {
  systemPrompt: string;
  userPrompt: string;
  rawOutput: string;
  researchTrail: string[];
  transcript: string;
}

export interface SecurityAssistantPresentationCompleteInput {
  systemPrompt: string;
  userPrompt: string;
  answer: SecurityAssistantAnswer;
}

export interface SecurityAssistantServiceOptions {
  goals?: Pick<AutonomyGoalService,
    "createFromText" | "createFromPlan" | "get" | "appendArtifact" | "appendResourceRefs" | "appendCorrection"
  >;
  threadState?: AssistantThreadStateStore;
  repairComplete?: (input: SecurityAssistantRepairCompleteInput) => Promise<string>;
  presentationComplete?: (input: SecurityAssistantPresentationCompleteInput) => Promise<string>;
  flueComplete?: (input: FlueSecurityAssistantCompleteInput) => Promise<FlueSecurityAssistantCompleteOutput>;
  feedback?: Pick<AssistantFeedbackService, "promptBlockFor">;
  evidenceGovernance?: Pick<EvidenceGovernanceService, "promptBlockForThread">;
  riskAttestations?: Pick<RiskAttestationService, "request" | "status">;
  toolFactory?: SecurityToolFactory;
  additionalReadOnlyToolNames?: ReadonlySet<string>;
  evaluationInstructions?: readonly string[];
  ensemble?: Pick<CerebroEnsembleService, "refine">;
  distributedWork?: Pick<CerebroDistributedWorkService, "coordinate">;
  rateLimits?: Pick<SharedRateLimitCoordinator, "withPermit">;
}
