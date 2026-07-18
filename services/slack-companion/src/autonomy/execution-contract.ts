import type { AgentControlPlane, ClaimVerificationActionStage } from "../cerebro/types.js";
import type { AutonomyCapabilityId, AutonomyExecutionContract } from "./goal-types.js";

const ACTION_STAGE_ORDER: Record<ClaimVerificationActionStage, number> = {
  observe: 1,
  explain: 2,
  recommend: 3,
  dry_run: 4,
  approve: 5,
  execute: 6,
  verify: 7,
  close_loop: 8,
};

const REQUESTED_STAGE_BY_CAPABILITY: Record<AutonomyCapabilityId, ClaimVerificationActionStage> = {
  triage: "observe",
  investigation: "recommend",
  planner: "dry_run",
  self_repair: "dry_run",
  remediation: "execute",
  identity_response: "execute",
  detection_response: "execute",
  executor: "execute",
};

const PROFILE_TERMS_BY_CAPABILITY: Record<AutonomyCapabilityId, RegExp[]> = {
  triage: [/triage/i, /analyst/i, /exposure/i],
  investigation: [/investig/i, /analyst/i, /exposure/i],
  planner: [/planner/i, /remediation/i],
  self_repair: [/self[-_ ]?repair/i, /code/i],
  remediation: [/remediat/i, /appsec/i, /code/i],
  identity_response: [/identity/i, /enterprise/i, /access/i, /remediat/i],
  detection_response: [/detect/i, /panther/i, /response/i, /remediat/i],
  executor: [/executor/i, /execute/i, /remediation/i],
};

export interface AutonomyExecutionContractDecision {
  allowed: boolean;
  requestedActionStage: ClaimVerificationActionStage;
  reason?: string;
}

export function localAutonomyExecutionContract(capabilityId: AutonomyCapabilityId, selectedAt: string): AutonomyExecutionContract {
  const requestedActionStage = autonomyCapabilityRequestedActionStage(capabilityId);
  return {
    source: "local_default",
    version: "local",
    capabilityId,
    profileId: `${capabilityId}-local-default`,
    maxActionStage: requestedActionStage,
    requestedActionStage,
    requiredVerifierIds: [],
    selectedAt,
  };
}

export function autonomyExecutionContractFromControlPlane(
  capabilityId: AutonomyCapabilityId,
  controlPlane: AgentControlPlane,
  selectedAt: string,
): AutonomyExecutionContract {
  const requestedActionStage = autonomyCapabilityRequestedActionStage(capabilityId);
  const profile = selectProfile(capabilityId, controlPlane, requestedActionStage);
  if (!profile) return localAutonomyExecutionContract(capabilityId, selectedAt);
  return {
    source: "cerebro",
    version: controlPlane.version,
    capabilityId,
    profileId: profile.id,
    maxActionStage: profile.maxActionStage,
    requestedActionStage,
    requiredVerifierIds: [...profile.requiredVerifierIds],
    selectedAt,
  };
}

export function evaluateAutonomyExecutionContract(
  contract: AutonomyExecutionContract,
  capabilityId: AutonomyCapabilityId,
): AutonomyExecutionContractDecision {
  if (contract.capabilityId !== capabilityId) {
    return {
      allowed: false,
      requestedActionStage: autonomyCapabilityRequestedActionStage(capabilityId),
      reason: `Execution contract is for ${contract.capabilityId}, but this goal is ${capabilityId}.`,
    };
  }
  if (actionStageAllows(contract.maxActionStage, contract.requestedActionStage)) {
    return {
      allowed: true,
      requestedActionStage: contract.requestedActionStage,
    };
  }
  return {
    allowed: false,
    requestedActionStage: contract.requestedActionStage,
    reason: `Execution contract ${contract.profileId} allows ${contract.maxActionStage}, but ${capabilityId} needs ${contract.requestedActionStage}.`,
  };
}

export function autonomyCapabilityRequestedActionStage(capabilityId: AutonomyCapabilityId): ClaimVerificationActionStage {
  return REQUESTED_STAGE_BY_CAPABILITY[capabilityId];
}

function selectProfile(
  capabilityId: AutonomyCapabilityId,
  controlPlane: AgentControlPlane,
  requestedActionStage: ClaimVerificationActionStage,
): AgentControlPlane["agentProfiles"][number] | undefined {
  const terms = PROFILE_TERMS_BY_CAPABILITY[capabilityId];
  return controlPlane.agentProfiles.find((profile) => matchesAny(profile.id, terms) && actionStageAllows(profile.maxActionStage, requestedActionStage))
    ?? controlPlane.agentProfiles.find((profile) => matchesAny(profile.id, terms))
    ?? controlPlane.agentProfiles.find((profile) => profile.defaultOn && actionStageAllows(profile.maxActionStage, requestedActionStage))
    ?? controlPlane.agentProfiles.find((profile) => profile.defaultOn)
    ?? controlPlane.agentProfiles.find((profile) => actionStageAllows(profile.maxActionStage, requestedActionStage))
    ?? controlPlane.agentProfiles[0];
}

function actionStageAllows(maxActionStage: ClaimVerificationActionStage, requestedActionStage: ClaimVerificationActionStage): boolean {
  return ACTION_STAGE_ORDER[maxActionStage] >= ACTION_STAGE_ORDER[requestedActionStage];
}

function matchesAny(value: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(value));
}
