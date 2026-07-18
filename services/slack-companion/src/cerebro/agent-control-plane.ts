import {
  isClaimVerificationActionStage,
  type AgentControlPlane,
  type AgentControlPlaneActionStage,
  type AgentControlPlaneEvalScenario,
  type AgentControlPlaneProfile,
  type AgentControlPlaneSimulationHarness,
  type AgentControlPlaneVerifier,
  type ClaimVerificationActionStage,
} from "./types.js";

const SAFE_DEFAULT_STAGE: ClaimVerificationActionStage = "observe";

export function parseAgentControlPlaneResponse(value: unknown): AgentControlPlane {
  const root = objectValue(value);
  if (!root) throw new Error("Cerebro agent control plane response must be an object.");
  return {
    version: stringValue(root.version) ?? "unknown",
    agentProfiles: arrayOfObjects(root.agent_profiles ?? root.agentProfiles).map(toProfile).filter(isProfile),
    verifierLayer: arrayOfObjects(root.verifier_layer ?? root.verifierLayer).map(toVerifier).filter(isVerifier),
    actionLadder: arrayOfObjects(root.action_ladder ?? root.actionLadder).map(toActionStage).filter(isActionStage),
    evalScenarios: arrayOfObjects(objectValue(root.eval_suite ?? root.evalSuite)?.scenarios).map(toEvalScenario).filter(isEvalScenario),
    connectorToolGateIds: arrayOfObjects(root.connector_tool_gates ?? root.connectorToolGates)
      .map((gate) => stringValue(gate.id))
      .filter((id): id is string => Boolean(id)),
    simulationHarness: toSimulationHarness(root.simulation_harness ?? root.simulationHarness),
  };
}

function toProfile(value: Record<string, unknown>): AgentControlPlaneProfile | undefined {
  const id = stringValue(value.id);
  if (!id) return undefined;
  return {
    id,
    defaultOn: value.default_on === true || value.defaultOn === true,
    maxActionStage: actionStageValue(value.max_action_stage ?? value.maxActionStage),
    requiredVerifierIds: stringArray(value.required_verifiers ?? value.requiredVerifierIds),
  };
}

function toVerifier(value: Record<string, unknown>): AgentControlPlaneVerifier | undefined {
  const id = stringValue(value.id);
  return id ? { id } : undefined;
}

function toActionStage(value: Record<string, unknown>): AgentControlPlaneActionStage | undefined {
  const id = actionStageValue(value.id);
  return {
    id,
    order: numberValue(value.order) ?? stageFallbackOrder(id),
    mutating: value.mutating === true,
    requiresApproval: value.requires_approval === true || value.requiresApproval === true,
    verifierIds: stringArray(value.verifier_ids ?? value.verifierIds),
  };
}

function toEvalScenario(value: Record<string, unknown>): AgentControlPlaneEvalScenario | undefined {
  const id = stringValue(value.id);
  if (!id) return undefined;
  return {
    id,
    capability: stringValue(value.capability),
  };
}

function toSimulationHarness(value: unknown): AgentControlPlaneSimulationHarness | undefined {
  const harness = objectValue(value);
  if (!harness) return undefined;
  return {
    id: stringValue(harness.id),
    mode: stringValue(harness.mode),
    allowedInputs: stringArray(harness.allowed_inputs ?? harness.allowedInputs),
    forbiddenInputs: stringArray(harness.forbidden_inputs ?? harness.forbiddenInputs),
  };
}

function actionStageValue(value: unknown): ClaimVerificationActionStage {
  return isClaimVerificationActionStage(value) ? value : SAFE_DEFAULT_STAGE;
}

function stageFallbackOrder(stage: ClaimVerificationActionStage): number {
  const order: Record<ClaimVerificationActionStage, number> = {
    observe: 1,
    explain: 2,
    recommend: 3,
    dry_run: 4,
    approve: 5,
    execute: 6,
    verify: 7,
    close_loop: 8,
  };
  return order[stage];
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function arrayOfObjects(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.map(objectValue).filter((item): item is Record<string, unknown> => Boolean(item)) : [];
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map(stringValue).filter((item): item is string => Boolean(item)) : [];
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function isProfile(value: AgentControlPlaneProfile | undefined): value is AgentControlPlaneProfile {
  return Boolean(value);
}

function isVerifier(value: AgentControlPlaneVerifier | undefined): value is AgentControlPlaneVerifier {
  return Boolean(value);
}

function isActionStage(value: AgentControlPlaneActionStage | undefined): value is AgentControlPlaneActionStage {
  return Boolean(value);
}

function isEvalScenario(value: AgentControlPlaneEvalScenario | undefined): value is AgentControlPlaneEvalScenario {
  return Boolean(value);
}
