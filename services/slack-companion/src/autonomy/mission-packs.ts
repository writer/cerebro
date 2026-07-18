import type { AgentAcceptanceCriterion } from "./agent-run.js";
import {
  securityMissionPackIdSchema,
  type SecurityMissionActionStage,
  type SecurityMissionInputId,
  type SecurityMissionPackId,
  type SecurityMissionStepKind,
  type SecurityMissionToolSelector,
} from "./mission-types.js";

export interface SecurityMissionInputDefinition {
  id: SecurityMissionInputId;
  label: string;
  required: boolean;
  whenMissing: "wait" | "skip_step";
  description: string;
}

export interface SecurityMissionPackStep {
  id: string;
  kind: SecurityMissionStepKind;
  title: string;
  dependsOn: string[];
  actionStage: SecurityMissionActionStage;
  requiredInputIds: SecurityMissionInputId[];
  toolSelector: SecurityMissionToolSelector;
  autoBind: boolean;
  approvalRequired: boolean;
  verificationRequired: boolean;
  rollback?: string;
  acceptanceCriteriaIds: string[];
}

export interface SecurityMissionPack {
  id: SecurityMissionPackId;
  version: string;
  title: string;
  purpose: string;
  capabilityId: "remediation" | "identity_response" | "detection_response";
  domain: "appsec" | "identity" | "detection";
  owner: string;
  escalationPath: string;
  objectiveSignals: string[];
  eventTriggers: string[];
  inputs: SecurityMissionInputDefinition[];
  requiredEvidence: string[];
  allowedActions: string[];
  serviceLevel: {
    firstCheckpointMinutes: number;
    staleAfterMinutes: number;
    targetCompletionHours: number;
  };
  acceptanceCriteria: AgentAcceptanceCriterion[];
  steps: SecurityMissionPackStep[];
}

const readTool = (names: string[], families: string[] = []): SecurityMissionToolSelector => ({
  names,
  prefixes: [],
  families,
  authorities: ["read"],
});

const noTool = (): SecurityMissionToolSelector => ({ names: [], prefixes: [], families: [], authorities: [] });

export const SECURITY_MISSION_PACKS: readonly SecurityMissionPack[] = Object.freeze([
  {
    id: "appsec.remediation",
    version: "2026-07-16.1",
    title: "Application security remediation",
    purpose: "Carry one source-backed application security finding through a bounded patch, pull request, merge gate, source rerun, and verified closure.",
    capabilityId: "remediation",
    domain: "appsec",
    owner: "@writer/security-platform",
    escalationPath: "slack:#security-investigations",
    objectiveSignals: ["codeql", "dependabot", "secret scanning", "github security alert", "application security", "appsec", "vulnerability", "security finding"],
    eventTriggers: ["github.code_scanning_alert", "github.dependabot_alert", "github.secret_scanning_alert", "cerebro.finding_opened"],
    inputs: [
      { id: "runtime_id", label: "Cerebro runtime", required: true, whenMissing: "wait", description: "Runtime that owns the finding and fresh verification run." },
      { id: "finding_id", label: "Finding", required: true, whenMissing: "wait", description: "Exact source-backed finding identifier." },
      { id: "repository", label: "Repository", required: true, whenMissing: "wait", description: "Exact owner/name repository that contains the affected source." },
      { id: "pull_request", label: "Pull request", required: false, whenMissing: "wait", description: "Pull request number after the bounded fix exists." },
    ],
    requiredEvidence: ["finding record", "source evidence", "affected resource scope", "repository owner", "pull request checks", "fresh source evaluation"],
    allowedActions: ["read finding evidence", "read repository source", "write bounded patch", "open pull request", "read checks", "request source rerun approval", "verify closure"],
    serviceLevel: { firstCheckpointMinutes: 15, staleAfterMinutes: 60, targetCompletionHours: 24 },
    acceptanceCriteria: [
      criterion("appsec-evidence-collected", "The finding, evidence, and affected resources were read from the owning sources.", "tool_success"),
      criterion("appsec-owner-resolved", "A repository or service owner was resolved from current evidence.", "tool_success"),
      criterion("appsec-source-inspected", "The affected repository source was read at an exact ref.", "tool_success"),
      criterion("appsec-patch-ready", "A bounded patch and local validation result are attached.", "tool_success"),
      criterion("appsec-pr-created", "A reviewable pull request contains the bounded fix and validation evidence.", "tool_success"),
      criterion("appsec-checks-passed", "Required pull request checks passed on the exact head.", "tool_success"),
      criterion("appsec-source-rerun", "The finding source completed a fresh post-merge evaluation.", "tool_success"),
      criterion("appsec-finding-closed", "The fresh finding lookup reports the finding as resolved.", "field_equals", "findings.0.status", "resolved"),
    ],
    steps: [
      step("investigate-finding", "observe", "Read the finding, evidence, and affected resources", [], "observe", ["runtime_id", "finding_id"], readTool(["cerebro_finding_investigation"]), ["appsec-evidence-collected"], true),
      step("resolve-owner", "observe", "Resolve the repository and service owner", ["investigate-finding"], "explain", ["runtime_id", "finding_id"], readTool(["owner_resolve"]), ["appsec-owner-resolved"], true),
      step("inspect-repository", "observe", "Read affected repository source at an exact ref", ["resolve-owner"], "observe", ["repository"], {
        names: ["cerebro_code_github_source_list", "cerebro_code_github_source_read", "cerebro_code_workspace_search", "cerebro_code_workspace_read_many"],
        prefixes: [], families: ["runtime_code"], authorities: ["read"],
      }, ["appsec-source-inspected"], false),
      step("prepare-fix", "act", "Prepare a bounded patch and run local validation", ["inspect-repository"], "dry_run", ["repository"], {
        names: ["cerebro_code_workspace_patch", "cerebro_code_workspace_write", "cerebro_code_shell_run"],
        prefixes: [], families: ["runtime_code"], authorities: ["workspace_write", "bounded_shell"],
      }, ["appsec-patch-ready"], false, false, true, "Revert the bounded workspace change."),
      step("open-fix-pr", "act", "Open a reviewable pull request for the bounded fix", ["prepare-fix"], "dry_run", ["repository"], {
        names: ["cerebro_code_github_pr"], prefixes: [], families: ["runtime_code"], authorities: ["github_write"],
      }, ["appsec-pr-created"], false, false, true, "Close the draft pull request and revert the bounded workspace change."),
      step("verify-pr-gate", "verify", "Read checks on the exact pull request head", ["open-fix-pr"], "verify", ["repository", "pull_request"], readTool(["cerebro_code_github_pr_status", "cerebro_code_github_checks"], ["runtime_code"]), ["appsec-checks-passed"], true),
      step("monitor-github-merge", "monitor", "Wait for checks, review, and merge policy to complete", ["verify-pr-gate"], "approve", ["pull_request"], noTool(), [], false),
      step("rerun-source", "act", "Run a fresh finding evaluation after merge", ["monitor-github-merge"], "execute", ["runtime_id"], {
        names: ["source_run_trigger"], prefixes: [], families: ["cerebro"], authorities: ["cerebro_write"],
      }, ["appsec-source-rerun"], true, true, true, "Stop further source runs and preserve the prior finding state."),
      step("verify-finding-closure", "verify", "Read the fresh finding state and verify closure", ["rerun-source"], "close_loop", ["runtime_id", "finding_id"], readTool(["finding_lookup"]), ["appsec-finding-closed"], true),
    ],
  },
  {
    id: "identity.access-risk",
    version: "2026-07-16.1",
    title: "Identity and SaaS access risk",
    purpose: "Correlate one identity risk across people, IdP, SaaS access, and activity evidence before an approval-gated revocation and independent access check.",
    capabilityId: "identity_response",
    domain: "identity",
    owner: "@writer/enterprise-security",
    escalationPath: "slack:#security-investigations",
    objectiveSignals: ["okta", "identity", "offboarding", "former worker", "former employee", "access path", "saas access", "sso", "mfa"],
    eventTriggers: ["cerebro.identity_anomaly", "cerebro.offboarding_gap", "okta.risk_event"],
    inputs: [
      { id: "identity_ref", label: "Identity", required: true, whenMissing: "wait", description: "Canonical person or identity reference." },
      { id: "risk_ref", label: "Risk", required: true, whenMissing: "wait", description: "Finding, alert, or case reference that explains the access concern." },
      { id: "target_slack_user_id", label: "Slack user", required: false, whenMissing: "skip_step", description: "Evidence-linked Slack user for a bounded self-attestation request." },
      { id: "evidence_receipt", label: "Evidence receipt", required: false, whenMissing: "skip_step", description: "Current receipt that supports the identity-to-risk link." },
    ],
    requiredEvidence: ["HR or lifecycle state", "IdP account state", "effective SaaS access", "recent activity", "identity correlation", "post-action access state"],
    allowedActions: ["read identity evidence", "read graph access paths", "request self-attestation", "prepare revocation", "request revocation approval", "execute one bounded revocation", "verify access removal"],
    serviceLevel: { firstCheckpointMinutes: 10, staleAfterMinutes: 30, targetCompletionHours: 8 },
    acceptanceCriteria: [
      criterion("identity-evidence-collected", "Lifecycle, IdP, SaaS access, and activity evidence were collected.", "tool_success"),
      criterion("identity-access-correlated", "The identity-to-access path was correlated from current graph evidence.", "tool_success"),
      criterion("identity-attestation-recorded", "A bounded self-attestation state was recorded when an evidence-linked person was available.", "tool_success"),
      criterion("identity-revocation-approved", "The exact revocation target and rollback received reviewed approval.", "manual"),
      criterion("identity-access-revoked", "The approved access change completed successfully.", "tool_success"),
      criterion("identity-access-verified", "An independent read reports that the targeted access path is absent.", "tool_success"),
    ],
    steps: [
      step("collect-identity-evidence", "observe", "Collect lifecycle, IdP, SaaS access, and activity evidence", [], "observe", ["identity_ref", "risk_ref"], readTool(["cerebro_evidence_packet"]), ["identity-evidence-collected"], true),
      step("correlate-access", "compare", "Correlate the identity, account, and effective access paths", ["collect-identity-evidence"], "explain", ["identity_ref"], readTool(["cerebro_graph_reason"]), ["identity-access-correlated"], true),
      step("request-attestation", "observe", "Request bounded self-attestation when the identity link is current", ["correlate-access"], "recommend", ["target_slack_user_id", "risk_ref", "evidence_receipt"], {
        names: ["slack_risk_attestation_request", "slack_risk_attestation_status"], prefixes: [], families: ["slack"], authorities: ["slack_write", "read"],
      }, ["identity-attestation-recorded"], false),
      step("revoke-access", "act", "Execute one approved access revocation", ["correlate-access"], "execute", ["identity_ref", "risk_ref"], {
        names: [], prefixes: ["okta_", "identity_"], families: ["cerebro", "other"], authorities: ["security_write"],
      }, ["identity-revocation-approved", "identity-access-revoked"], false, true, true, "Restore the prior assignment or account state from the pre-action snapshot."),
      step("verify-access-removed", "verify", "Read the identity again and verify the targeted access is absent", ["revoke-access"], "close_loop", ["identity_ref"], {
        names: ["cerebro_evidence_packet", "cerebro_graph_reason"], prefixes: ["okta_", "identity_"], families: ["cerebro", "graph", "other"], authorities: ["read"],
      }, ["identity-access-verified"], false),
    ],
  },
  {
    id: "detection.response",
    version: "2026-07-16.1",
    title: "Detection response and rule improvement",
    purpose: "Carry one detection alert through enrichment, incident or noise disposition, rule change, backtest, canary, deployment approval, and effectiveness verification.",
    capabilityId: "detection_response",
    domain: "detection",
    owner: "@writer/detection-engineering",
    escalationPath: "slack:#security-incidents",
    objectiveSignals: ["panther", "detection", "security alert", "false positive", "detection rule", "backtest", "canary"],
    eventTriggers: ["panther.alert_opened", "cerebro.detection_alert", "cerebro.rule_regression"],
    inputs: [
      { id: "alert_ref", label: "Alert", required: true, whenMissing: "wait", description: "Exact alert reference from the detection source." },
      { id: "rule_ref", label: "Rule", required: true, whenMissing: "wait", description: "Exact rule reference that produced the alert." },
    ],
    requiredEvidence: ["raw alert", "entity enrichment", "historical matches", "incident or noise decision", "backtest result", "canary result", "post-deployment effectiveness"],
    allowedActions: ["read alert", "enrich entities", "record disposition", "prepare rule change", "run backtest", "run canary", "request deployment approval", "deploy rule", "verify effectiveness"],
    serviceLevel: { firstCheckpointMinutes: 5, staleAfterMinutes: 15, targetCompletionHours: 12 },
    acceptanceCriteria: [
      criterion("detection-provider-ready", "The configured detection provider returned its current tool and connection state.", "tool_success"),
      criterion("detection-alert-enriched", "The alert and affected entities were enriched from current source evidence.", "tool_success"),
      criterion("detection-disposition-recorded", "The alert was classified as an incident or noise with evidence.", "manual"),
      criterion("detection-rule-change-ready", "A bounded rule change and rollback were prepared.", "tool_success"),
      criterion("detection-backtest-passed", "The changed rule passed the defined historical backtest.", "tool_success"),
      criterion("detection-canary-passed", "The changed rule passed the canary window without a blocking regression.", "tool_success"),
      criterion("detection-deployment-approved", "The exact rule deployment received reviewed approval.", "manual"),
      criterion("detection-rule-deployed", "The approved rule revision was deployed successfully.", "tool_success"),
      criterion("detection-effectiveness-verified", "A post-deployment read confirmed the expected detection behavior.", "tool_success"),
    ],
    steps: [
      step("check-detection-provider", "observe", "Read the detection provider connection and tool state", [], "observe", [], readTool(["panther_mcp_status"], ["panther_mcp"]), ["detection-provider-ready"], true),
      step("enrich-alert", "observe", "Read the alert and enrich affected entities", ["check-detection-provider"], "explain", ["alert_ref"], {
        names: ["cerebro_evidence_packet"], prefixes: ["panther_mcp_"], families: ["panther_mcp", "cerebro"], authorities: ["read"],
      }, ["detection-alert-enriched"], false),
      step("record-disposition", "decide", "Record the incident or noise decision with evidence", ["enrich-alert"], "recommend", ["alert_ref"], noTool(), ["detection-disposition-recorded"], false),
      step("prepare-rule-change", "act", "Prepare a bounded rule change and rollback", ["record-disposition"], "dry_run", ["rule_ref"], {
        names: [], prefixes: ["panther_mcp_"], families: ["panther_mcp"], authorities: ["security_write"],
      }, ["detection-rule-change-ready"], false, true, true, "Restore the prior rule revision."),
      step("backtest-rule", "verify", "Run the changed rule against the defined historical window", ["prepare-rule-change"], "verify", ["rule_ref"], {
        names: [], prefixes: ["panther_mcp_"], families: ["panther_mcp"], authorities: ["read"],
      }, ["detection-backtest-passed"], false),
      step("canary-rule", "monitor", "Run the changed rule in a bounded canary", ["backtest-rule"], "verify", ["rule_ref"], {
        names: [], prefixes: ["panther_mcp_"], families: ["panther_mcp"], authorities: ["read", "security_write"],
      }, ["detection-canary-passed"], false, true, true, "Disable the canary and restore the prior rule revision."),
      step("deploy-rule", "act", "Deploy the approved rule revision", ["canary-rule"], "execute", ["rule_ref"], {
        names: [], prefixes: ["panther_mcp_"], families: ["panther_mcp"], authorities: ["security_write"],
      }, ["detection-deployment-approved", "detection-rule-deployed"], false, true, true, "Restore the prior rule revision and disable the new revision."),
      step("verify-detection-effectiveness", "verify", "Read post-deployment alerts and verify rule effectiveness", ["deploy-rule"], "close_loop", ["rule_ref"], {
        names: [], prefixes: ["panther_mcp_"], families: ["panther_mcp"], authorities: ["read"],
      }, ["detection-effectiveness-verified"], false),
    ],
  },
] satisfies SecurityMissionPack[]);

const packById = new Map(SECURITY_MISSION_PACKS.map((pack) => [pack.id, pack]));

export function securityMissionPacks(): SecurityMissionPack[] {
  return SECURITY_MISSION_PACKS.map(clonePack);
}

export function securityMissionPack(id: SecurityMissionPackId): SecurityMissionPack {
  const pack = packById.get(id);
  if (!pack) throw new Error(`Unknown security mission pack ${id}.`);
  return clonePack(pack);
}

export function validateSecurityMissionPacks(packs: readonly SecurityMissionPack[] = SECURITY_MISSION_PACKS): void {
  const packIds = new Set<string>();
  for (const pack of packs) {
    securityMissionPackIdSchema.parse(pack.id);
    if (packIds.has(pack.id)) throw new Error(`Duplicate security mission pack ${pack.id}.`);
    packIds.add(pack.id);
    if (!pack.version.trim() || !pack.owner.trim() || !pack.escalationPath.trim()) throw new Error(`Mission pack ${pack.id} needs version, owner, and escalation path.`);
    if (pack.inputs.filter((input) => input.required).length === 0) throw new Error(`Mission pack ${pack.id} needs at least one required input.`);
    const inputIds = new Set(pack.inputs.map((input) => input.id));
    const criterionIds = new Set(pack.acceptanceCriteria.map((criterion) => criterion.id));
    const stepIds = new Set<string>();
    for (const missionStep of pack.steps) {
      if (stepIds.has(missionStep.id)) throw new Error(`Duplicate mission step ${pack.id}/${missionStep.id}.`);
      stepIds.add(missionStep.id);
      const unknownInputs = missionStep.requiredInputIds.filter((id) => !inputIds.has(id));
      if (unknownInputs.length) throw new Error(`Mission step ${pack.id}/${missionStep.id} has unknown inputs: ${unknownInputs.join(", ")}.`);
      const unknownCriteria = missionStep.acceptanceCriteriaIds.filter((id) => !criterionIds.has(id));
      if (unknownCriteria.length) throw new Error(`Mission step ${pack.id}/${missionStep.id} has unknown acceptance criteria: ${unknownCriteria.join(", ")}.`);
      const selectsTool = missionStep.toolSelector.names.length > 0 || missionStep.toolSelector.prefixes.length > 0 || missionStep.toolSelector.families.length > 0;
      if (selectsTool && missionStep.acceptanceCriteriaIds.length === 0) throw new Error(`Mission tool step ${pack.id}/${missionStep.id} needs an acceptance criterion.`);
      if (missionStep.actionStage === "execute" && (!missionStep.approvalRequired || !missionStep.verificationRequired || !missionStep.rollback)) {
        throw new Error(`Executable mission step ${pack.id}/${missionStep.id} needs approval, verification, and rollback.`);
      }
      if (missionStep.toolSelector.authorities.includes("security_write")
        && (!missionStep.approvalRequired || !missionStep.verificationRequired || !missionStep.rollback)) {
        throw new Error(`Security write mission step ${pack.id}/${missionStep.id} needs approval, verification, and rollback.`);
      }
    }
    for (const missionStep of pack.steps) {
      const unknownDependencies = missionStep.dependsOn.filter((id) => !stepIds.has(id));
      if (unknownDependencies.length) throw new Error(`Mission step ${pack.id}/${missionStep.id} has unknown dependencies: ${unknownDependencies.join(", ")}.`);
    }
    assertAcyclicMissionPlan(pack);
  }
}

function assertAcyclicMissionPlan(pack: SecurityMissionPack): void {
  const dependencies = new Map(pack.steps.map((missionStep) => [missionStep.id, missionStep.dependsOn]));
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (stepId: string, path: string[]): void => {
    if (visited.has(stepId)) return;
    if (visiting.has(stepId)) {
      const cycleStart = path.indexOf(stepId);
      const cycle = [...path.slice(Math.max(0, cycleStart)), stepId];
      throw new Error(`Mission pack ${pack.id} has a dependency cycle: ${cycle.join(" -> ")}.`);
    }
    visiting.add(stepId);
    for (const dependency of dependencies.get(stepId) ?? []) visit(dependency, [...path, stepId]);
    visiting.delete(stepId);
    visited.add(stepId);
  };
  for (const missionStep of pack.steps) visit(missionStep.id, []);
}

function criterion(
  id: string,
  description: string,
  kind: AgentAcceptanceCriterion["kind"],
  field?: string,
  expected?: string | number | boolean,
): AgentAcceptanceCriterion {
  return { id, description, kind, field, expected, status: "pending", evidenceRefs: [] };
}

function step(
  id: string,
  kind: SecurityMissionStepKind,
  title: string,
  dependsOn: string[],
  actionStage: SecurityMissionActionStage,
  requiredInputIds: SecurityMissionInputId[],
  toolSelector: SecurityMissionToolSelector,
  acceptanceCriteriaIds: string[],
  autoBind: boolean,
  approvalRequired = false,
  verificationRequired = false,
  rollback?: string,
): SecurityMissionPackStep {
  return { id, kind, title, dependsOn, actionStage, requiredInputIds, toolSelector, acceptanceCriteriaIds, autoBind, approvalRequired, verificationRequired, rollback };
}

function clonePack(pack: SecurityMissionPack): SecurityMissionPack {
  return {
    ...pack,
    objectiveSignals: [...pack.objectiveSignals], eventTriggers: [...pack.eventTriggers],
    inputs: pack.inputs.map((input) => ({ ...input })), requiredEvidence: [...pack.requiredEvidence], allowedActions: [...pack.allowedActions],
    serviceLevel: { ...pack.serviceLevel },
    acceptanceCriteria: pack.acceptanceCriteria.map((criterion) => ({ ...criterion, evidenceRefs: [...criterion.evidenceRefs] })),
    steps: pack.steps.map((missionStep) => ({
      ...missionStep, dependsOn: [...missionStep.dependsOn], requiredInputIds: [...missionStep.requiredInputIds],
      toolSelector: {
        names: [...missionStep.toolSelector.names], prefixes: [...missionStep.toolSelector.prefixes],
        families: [...missionStep.toolSelector.families], authorities: [...missionStep.toolSelector.authorities],
      },
      acceptanceCriteriaIds: [...missionStep.acceptanceCriteriaIds],
    })),
  };
}

validateSecurityMissionPacks();
