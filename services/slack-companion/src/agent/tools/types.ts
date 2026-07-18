import type { AgentTool } from "@earendil-works/pi-agent-core";
import type { AutonomyGoalService } from "../../autonomy/goal-service.js";
import type { CerebroClient } from "../../cerebro/client.js";
import type { ComplianceContextService } from "../../compliance/context.js";
import type { CompliancePacketStore } from "../../compliance/packet-store.js";
import type { AppConfig } from "../../config/index.js";
import type { InfisicalClient } from "../../infisical/client.js";
import type { SecurityMemoryStore } from "../../learning/security-memory/index.js";
import type { ScheduledJobService } from "../../schedules/scheduled-jobs/index.js";
import type { RiskAttestationService } from "../../slack/risk-attestation.js";
import type { SecurityResearchState } from "../research-state.js";

export interface SecurityToolDeps {
  config: AppConfig;
  cerebro: CerebroClient;
  memory: SecurityMemoryStore;
  infisical?: InfisicalClient;
  complianceContext?: ComplianceContextService;
  compliancePacketStore?: Pick<CompliancePacketStore, "put" | "get" | "list" | "storageMode">;
  scheduler?: Pick<ScheduledJobService, "createFromDraft">;
  riskAttestations?: Pick<RiskAttestationService, "request" | "status">;
  autonomyGoals?: Pick<AutonomyGoalService, "createFromText"> & Partial<Pick<AutonomyGoalService,
    "createFromPlan" | "get" | "list" | "replacePlan" | "update" | "appendArtifact" | "appendResourceRefs" | "appendCorrection" | "bindMissionStep" | "recordMissionDecision"
  >>;
  researchState?: SecurityResearchState;
  requestContext?: {
    channelId: string;
    userId?: string;
    threadTs?: string;
  };
}

export type SecurityToolFactory = (deps: SecurityToolDeps) => AgentTool[];
