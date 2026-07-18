import { DynamoAutonomyGoalStore } from "./goal-store-dynamo.js";
import { InMemoryAutonomyGoalStore } from "./goal-store-memory.js";
import type { AutonomyGoalStore, AutonomyGoalStoreOptions } from "./goal-types.js";
import type { AppConfig } from "../config/index.js";

export { isAutonomyCapabilityId, isAutonomyGoalStatus } from "./goal-codec.js";
export { DynamoAutonomyGoalStore } from "./goal-store-dynamo.js";
export { InMemoryAutonomyGoalStore } from "./goal-store-memory.js";
export type {
  AutonomyActor,
  AutonomyApprovalRecord,
  AutonomyApprovalStatus,
  AutonomyCapabilityId,
  AutonomyExecutionContract,
  AutonomyExecutionContractSource,
  AutonomyGoalClaim,
  AutonomyGoalLedgerEvent,
  AutonomyGoalLedgerEventType,
  AutonomyGoalStatus,
  AutonomyGoalStore,
  AutonomyGoalStoreOptions,
  AutonomyPlanStep,
  AutonomyToolRunRecord,
  AutonomyToolRunStatus,
  AutonomyWorkLogEntry,
  AutonomyWorkLogKind,
  AutonomousGoalRecord,
  CreateAutonomyGoalInput,
  UpdateAutonomyGoalInput,
} from "./goal-types.js";
export type { SecurityCaseContext, SecurityCaseKind, SecurityCaseState } from "../security-cases/types.js";
export type {
  AgentAcceptanceCriterion,
  AgentArtifact,
  AgentCompletionReceipt,
  AgentCorrection,
  AgentResourceKind,
  AgentResourceRef,
  AgentStepExecution,
} from "./agent-run.js";
export type {
  SecurityMissionActionStage,
  SecurityMissionBinding,
  SecurityMissionInputId,
  SecurityMissionPackId,
  SecurityMissionReceipt,
  SecurityMissionStepKind,
  SecurityMissionStepReceipt,
  SecurityMissionToolSelector,
} from "./mission-types.js";

export function createAutonomyGoalStore(config: AppConfig, options: AutonomyGoalStoreOptions = {}): AutonomyGoalStore {
  if (config.autonomy.goalsEnabled && config.autonomy.goalsTableName) {
    return new DynamoAutonomyGoalStore(config, config.autonomy.goalsTableName, options);
  }
  return new InMemoryAutonomyGoalStore(options.now);
}
