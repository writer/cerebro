import { createHash } from "node:crypto";
import { redactSecurityText } from "../security/redaction.js";
import type { AgentAcceptanceCriterion, AgentResourceRef, AgentStepExecution } from "./agent-run.js";
import type { AutonomyPlanStep } from "./goals.js";
import { securityMissionPack, securityMissionPacks, type SecurityMissionPack, type SecurityMissionPackStep } from "./mission-packs.js";
import {
  securityMissionPackIdSchema,
  securityMissionReceiptSchema,
  type SecurityMissionBinding,
  type SecurityMissionInputId,
  type SecurityMissionPackId,
  type SecurityMissionReceipt,
  type SecurityMissionStepReceipt,
} from "./mission-types.js";

export const SECURITY_MISSION_COMPILER_VERSION = "2026-07-16.1";

export interface CompileSecurityMissionInput {
  objective: string;
  requestedPackId?: SecurityMissionPackId;
  bindings?: Partial<Record<SecurityMissionInputId, string>>;
  resourceRefs?: AgentResourceRef[];
  now?: Date;
}

export interface SecurityMissionCompilation {
  pack: SecurityMissionPack;
  receipt: SecurityMissionReceipt;
  plan: AutonomyPlanStep[];
  acceptanceCriteria: AgentAcceptanceCriterion[];
}

interface ResolvedBinding {
  value: string;
  source: SecurityMissionBinding["source"];
}

export function compileSecurityMission(input: CompileSecurityMissionInput): SecurityMissionCompilation | undefined {
  const objective = clean(input.objective, 1200);
  const selection = selectPack(objective, input.requestedPackId);
  if (!selection) return undefined;
  const pack = selection.pack;
  const resolved = resolveBindings(pack, objective, input.bindings, input.resourceRefs ?? []);
  const plan = pack.steps.map((packStep) => compileStep(pack, packStep, objective, resolved));
  const includedCriterionIds = new Set(plan
    .filter((step) => step.status !== "skipped")
    .flatMap((step) => step.acceptanceCriteriaIds ?? []));
  const acceptanceCriteria = pack.acceptanceCriteria
    .filter((criterion) => includedCriterionIds.has(criterion.id))
    .map((criterion) => ({ ...criterion, evidenceRefs: [...criterion.evidenceRefs] }));
  const missingInputIds = pack.inputs
    .filter((definition) => definition.required && !resolved.has(definition.id))
    .map((definition) => definition.id);
  const needsTool = plan.some((step) => step.status !== "skipped"
    && step.mission?.bindingState === "needs_tool"
    && step.id !== "monitor-github-merge");
  const compiledAt = (input.now ?? new Date()).toISOString();
  const receipt = securityMissionReceiptSchema.parse({
    packId: pack.id,
    packVersion: pack.version,
    compilerVersion: SECURITY_MISSION_COMPILER_VERSION,
    compiledAt,
    status: missingInputIds.length > 0 ? "needs_input" : needsTool ? "needs_tool" : "ready",
    trigger: selection.trigger,
    owner: pack.owner,
    objectiveDigest: digest(objective),
    planDigest: missionPlanDigest(plan),
    bindings: [...resolved.entries()].map(([id, binding]) => ({ id, value: binding.value, source: binding.source })),
    missingInputIds,
    requiredEvidence: pack.requiredEvidence,
    acceptanceCriteriaIds: acceptanceCriteria.map((criterion) => criterion.id),
    actionStepIds: pack.steps.filter((step) => step.kind === "act" || step.actionStage === "approve").map((step) => step.id),
    serviceLevel: pack.serviceLevel,
  });
  return { pack, receipt, plan, acceptanceCriteria };
}

export function missionPlanDigest(plan: AutonomyPlanStep[]): string {
  return digest(JSON.stringify(plan.map((step) => ({
    id: step.id,
    title: step.title,
    dependsOn: step.dependsOn,
    acceptanceCriteriaIds: step.acceptanceCriteriaIds ?? [],
    mission: step.mission ? {
      packStepId: step.mission.packStepId,
      kind: step.mission.kind,
      actionStage: step.mission.actionStage,
      requiredInputIds: step.mission.requiredInputIds,
      toolSelector: step.mission.toolSelector,
      approvalRequired: step.mission.approvalRequired,
      verificationRequired: step.mission.verificationRequired,
      rollback: step.mission.rollback,
    } : undefined,
  }))));
}

export function missionToolMatches(
  selector: SecurityMissionStepReceipt["toolSelector"],
  tool: { name: string; family: string; authority: string },
): boolean {
  const nameMatches = selector.names.length === 0 && selector.prefixes.length === 0
    ? true
    : selector.names.includes(tool.name) || selector.prefixes.some((prefix) => tool.name.startsWith(prefix));
  const familyMatches = selector.families.length === 0 || selector.families.includes(tool.family);
  const authorityMatches = selector.authorities.length === 0 || selector.authorities.includes(tool.authority);
  return nameMatches && familyMatches && authorityMatches;
}

function selectPack(objective: string, requestedPackId: SecurityMissionPackId | undefined): { pack: SecurityMissionPack; trigger: string } | undefined {
  if (requestedPackId) {
    const id = securityMissionPackIdSchema.parse(requestedPackId);
    return { pack: securityMissionPack(id), trigger: `explicit:${id}` };
  }
  const normalized = objective.toLowerCase();
  if (!/\b(handle|remediate|resolve|fix|close|revoke|disable|remove|deploy|rollout|tune|change|update|respond|work through|carry)\b/.test(normalized)) {
    return undefined;
  }
  const ranked = securityMissionPacks().flatMap((pack) => {
    const signals = pack.objectiveSignals.filter((signal) => normalized.includes(signal));
    const score = signals.reduce((total, signal) => total + Math.max(1, signal.split(/\s+/).length), 0);
    return score > 0 ? [{ pack, score, trigger: signals.sort((left, right) => right.length - left.length)[0]! }] : [];
  }).sort((left, right) => right.score - left.score || left.pack.id.localeCompare(right.pack.id));
  return ranked[0] ? { pack: ranked[0].pack, trigger: ranked[0].trigger } : undefined;
}

function resolveBindings(
  pack: SecurityMissionPack,
  objective: string,
  explicit: Partial<Record<SecurityMissionInputId, string>> | undefined,
  resources: AgentResourceRef[],
): Map<SecurityMissionInputId, ResolvedBinding> {
  const resolved = new Map<SecurityMissionInputId, ResolvedBinding>();
  const allowed = new Set(pack.inputs.map((definition) => definition.id));
  for (const [id, value] of Object.entries(explicit ?? {}) as Array<[SecurityMissionInputId, string | undefined]>) {
    if (allowed.has(id) && value?.trim()) resolved.set(id, { value: clean(value, 500), source: "explicit" });
  }
  for (const binding of resourceBindings(resources)) {
    if (allowed.has(binding.id) && !resolved.has(binding.id)) resolved.set(binding.id, { value: binding.value, source: "resource" });
  }
  for (const binding of objectiveBindings(objective)) {
    if (allowed.has(binding.id) && !resolved.has(binding.id)) resolved.set(binding.id, { value: binding.value, source: "objective" });
  }
  return resolved;
}

function compileStep(
  pack: SecurityMissionPack,
  packStep: SecurityMissionPackStep,
  objective: string,
  bindings: Map<SecurityMissionInputId, ResolvedBinding>,
): AutonomyPlanStep {
  const missing = packStep.requiredInputIds.filter((id) => !bindings.has(id));
  const skipForOptionalInput = missing.length > 0 && missing.every((id) => pack.inputs.find((definition) => definition.id === id)?.whenMissing === "skip_step");
  const execution = missing.length === 0 && packStep.autoBind ? autoExecution(pack.id, packStep.id, objective, bindings) : undefined;
  const noTool = packStep.toolSelector.names.length === 0
    && packStep.toolSelector.prefixes.length === 0
    && packStep.toolSelector.families.length === 0;
  const mission: SecurityMissionStepReceipt = {
    packStepId: packStep.id,
    kind: packStep.kind,
    actionStage: packStep.actionStage,
    requiredInputIds: [...packStep.requiredInputIds],
    toolSelector: {
      names: [...packStep.toolSelector.names], prefixes: [...packStep.toolSelector.prefixes],
      families: [...packStep.toolSelector.families], authorities: [...packStep.toolSelector.authorities],
    },
    bindingState: execution ? "bound" : missing.length > 0 ? "missing_input" : noTool ? "operator_decision" : "needs_tool",
    approvalRequired: packStep.approvalRequired,
    verificationRequired: packStep.verificationRequired,
    rollback: packStep.rollback,
  };
  return {
    id: packStep.id,
    title: packStep.title,
    status: skipForOptionalInput ? "skipped" : "pending",
    dependsOn: [...packStep.dependsOn],
    summary: skipForOptionalInput ? `Skipped because optional input was not supplied: ${missing.join(", ")}.` : undefined,
    execution,
    acceptanceCriteriaIds: skipForOptionalInput ? [] : [...packStep.acceptanceCriteriaIds],
    mission,
  };
}

function autoExecution(
  packId: SecurityMissionPackId,
  stepId: string,
  objective: string,
  bindings: Map<SecurityMissionInputId, ResolvedBinding>,
): AgentStepExecution | undefined {
  const value = (id: SecurityMissionInputId): string => bindings.get(id)!.value;
  if (packId === "appsec.remediation") {
    if (stepId === "investigate-finding") return execution("cerebro_finding_investigation", { runtime_id: value("runtime_id"), finding_id: value("finding_id"), include_graph: true });
    if (stepId === "resolve-owner") return execution("owner_resolve", { runtime_id: value("runtime_id"), finding_id: value("finding_id") });
    if (stepId === "verify-pr-gate") {
      const pullNumber = pullRequestNumber(value("pull_request"));
      return pullNumber ? execution("cerebro_code_github_pr_status", { repo: value("repository"), pull_number: pullNumber, include_checks: true }) : undefined;
    }
    if (stepId === "rerun-source") return execution(
      "source_run_trigger",
      { runtime_id: value("runtime_id"), action: "finding_evaluate", reason: "Verify deployed application security remediation.", execute: true, approved: true },
      {
        approvalRequired: true,
        idempotencyKey: `mission:${digest(`${value("runtime_id")}:${value("finding_id")}`).slice(7, 31)}:finding-evaluate`,
        rollback: "Stop further source runs and preserve the prior finding state.",
        verificationToolName: "source_run_status",
        verificationArguments: { runtime_id: value("runtime_id"), limit: 1 },
      },
    );
    if (stepId === "verify-finding-closure") return execution("finding_lookup", { runtime_id: value("runtime_id"), finding_id: value("finding_id"), limit: 1 });
  }
  if (packId === "identity.access-risk") {
    if (stepId === "collect-identity-evidence") return execution("cerebro_evidence_packet", {
      question: objective,
      entities: [value("identity_ref"), value("risk_ref")],
      capability_ids: ["identity-access-risk", "graph-reasoning"],
    });
    if (stepId === "correlate-access") return execution("cerebro_graph_reason", {
      question: `Identify current effective access paths and contradictions for ${value("identity_ref")}.`,
      scope_urn: value("identity_ref"),
    });
  }
  if (packId === "detection.response" && stepId === "check-detection-provider") {
    return execution("panther_mcp_status", { check_connection: true });
  }
  return undefined;
}

function execution(
  toolName: string,
  argumentsValue: Record<string, unknown>,
  overrides: Partial<AgentStepExecution> = {},
): AgentStepExecution {
  return {
    toolName,
    arguments: argumentsValue,
    verificationArguments: {},
    approvalRequired: false,
    maxAttempts: 2,
    attempts: 0,
    ...overrides,
  };
}

function resourceBindings(resources: AgentResourceRef[]): Array<{ id: SecurityMissionInputId; value: string }> {
  return resources.flatMap((resource): Array<{ id: SecurityMissionInputId; value: string }> => {
    const normalized = `${resource.source} ${resource.kind} ${resource.label ?? ""} ${resource.id}`.toLowerCase();
    if (resource.kind === "github" && /^[-\w.]+\/[-\w.]+$/.test(resource.id)) return [{ id: "repository", value: resource.id }];
    if (resource.kind === "person") return [{ id: "identity_ref", value: resource.uri }];
    if (resource.kind === "panther" && /rule/.test(normalized)) return [{ id: "rule_ref", value: resource.id }];
    if (resource.kind === "panther") return [{ id: "alert_ref", value: resource.id }];
    if (resource.kind === "cerebro" && /runtime|source/.test(normalized)) return [{ id: "runtime_id", value: resource.id }];
    if (resource.kind === "cerebro" && /finding/.test(normalized)) return [{ id: "finding_id", value: resource.id }, { id: "risk_ref", value: resource.uri }];
    if (resource.kind === "generic" && /risk|case|alert|finding/.test(normalized)) return [{ id: "risk_ref", value: resource.uri }];
    return [];
  });
}

function objectiveBindings(objective: string): Array<{ id: SecurityMissionInputId; value: string }> {
  const bindings: Array<{ id: SecurityMissionInputId; value: string }> = [];
  addMatch(bindings, "repository", objective, /https?:\/\/github\.com\/([-\w.]+\/[-\w.]+)/i, 1);
  addMatch(bindings, "repository", objective, /\b(WriterInternal\/[-\w.]+)\b/i, 1);
  addMatch(bindings, "pull_request", objective, /https?:\/\/github\.com\/[-\w.]+\/[-\w.]+\/pull\/(\d+)/i, 1);
  addMatch(bindings, "pull_request", objective, /\b(?:pull request|pr)\s*#?\s*(\d+)\b/i, 1);
  addMatch(bindings, "runtime_id", objective, /\bruntime(?:_id)?\s*[:=#]?\s*([-\w.]+)\b/i, 1);
  addMatch(bindings, "finding_id", objective, /\b(finding[-_:][A-Za-z0-9][\w.:-]*)\b/i, 1);
  addMatch(bindings, "finding_id", objective, /\bfinding(?:_id)?\s*[:=#]\s*([-\w.]+)\b/i, 1);
  addMatch(bindings, "identity_ref", objective, /\bidentity(?:_ref)?\s*[:=#]\s*([^\s,;]+)/i, 1);
  addMatch(bindings, "risk_ref", objective, /\b(?:risk|case)(?:_ref)?\s*[:=#]\s*([^\s,;]+)/i, 1);
  addMatch(bindings, "alert_ref", objective, /\b(alert[-_:][A-Za-z0-9][\w.:-]*)\b/i, 1);
  addMatch(bindings, "alert_ref", objective, /\balert(?:_ref)?\s*[:=#]\s*([^\s,;]+)/i, 1);
  addMatch(bindings, "rule_ref", objective, /\b(rule[-_:][A-Za-z0-9][\w.:-]*)\b/i, 1);
  addMatch(bindings, "rule_ref", objective, /\brule(?:_ref)?\s*[:=#]\s*([^\s,;]+)/i, 1);
  addMatch(bindings, "target_slack_user_id", objective, /\b(U[A-Z0-9]{8,})\b/, 1);
  addMatch(bindings, "evidence_receipt", objective, /\b(evidence:[A-Za-z0-9._:-]+)\b/i, 1);
  const finding = bindings.find((binding) => binding.id === "finding_id");
  if (finding && !bindings.some((binding) => binding.id === "risk_ref")) bindings.push({ id: "risk_ref", value: finding.value });
  return bindings;
}

function addMatch(
  bindings: Array<{ id: SecurityMissionInputId; value: string }>,
  id: SecurityMissionInputId,
  input: string,
  pattern: RegExp,
  group: number,
): void {
  const matched = input.match(pattern)?.[group];
  if (matched?.trim()) bindings.push({ id, value: clean(matched, 500) });
}

function pullRequestNumber(value: string): number | undefined {
  const matched = value.match(/(?:\/pull\/|#)?(\d+)$/)?.[1];
  const parsed = matched ? Number(matched) : NaN;
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}

function clean(value: string, max: number): string {
  const cleaned = redactSecurityText(value).replace(/\s+/g, " ").trim().slice(0, max);
  if (!cleaned) throw new Error("Security mission value is required.");
  return cleaned;
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
