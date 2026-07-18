import type { AutonomyCapabilityId } from "./goals.js";

export type AutonomyBlastRadius = "read-only" | "single-user" | "tenant" | "org";

export interface AutonomyCapabilityDefinition {
  id: AutonomyCapabilityId;
  name: string;
  purpose: string;
  stage: "triage" | "investigation" | "planning" | "execution" | "self-repair";
  surface: "appsec" | "entsec" | "cloudsec" | "detection" | "vuln-mgmt" | "threat-modeling" | "saas-posture" | "cross-cutting";
  owner: string;
  dataSources: string[];
  allowedActions: string[];
  blastRadius: AutonomyBlastRadius;
  escalationPath: string;
  requiresApproval: boolean;
}

export const AUTONOMY_CAPABILITIES: readonly AutonomyCapabilityDefinition[] = Object.freeze([
  {
    id: "remediation",
    name: "Security Case Remediation",
    purpose: "Carry a security finding through a reviewable code fix, merge, source reevaluation, and verified closure.",
    stage: "execution",
    surface: "appsec",
    owner: "@writer/security-platform",
    dataSources: ["cerebro", "github", "slack"],
    allowedActions: [
      "read:cerebro_findings",
      "read:cerebro_graph",
      "write:github.pr",
      "read:github.pr_status",
      "read:github.checks",
      "write:cerebro_source_run_with_approval",
    ],
    blastRadius: "single-user",
    escalationPath: "slack:#security-investigations",
    requiresApproval: false,
  },
  {
    id: "executor",
    name: "Remediation Executor",
    purpose: "Execute approved security or code-remediation work and write compact evidence back to Cerebro.",
    stage: "execution",
    surface: "cross-cutting",
    owner: "@writer/security-platform",
    dataSources: ["cerebro", "github", "slack"],
    allowedActions: [
      "read:cerebro_execution_status",
      "read:github.pr_status",
      "read:github.checks",
      "write:cerebro_outcome",
    ],
    blastRadius: "tenant",
    escalationPath: "slack:#security-incidents",
    requiresApproval: true,
  },
  {
    id: "identity_response",
    name: "Identity Response Agent",
    purpose: "Correlate identity and SaaS access evidence, checkpoint an exact revocation target, execute only the approved action, and verify access independently.",
    stage: "execution",
    surface: "entsec",
    owner: "@writer/enterprise-security",
    dataSources: ["cerebro", "okta", "slack"],
    allowedActions: [
      "read:identity_lifecycle",
      "read:identity_access_graph",
      "write:slack_attestation",
      "write:identity_revocation_with_approval",
      "read:identity_access_verification",
    ],
    blastRadius: "tenant",
    escalationPath: "slack:#security-investigations",
    requiresApproval: false,
  },
  {
    id: "detection_response",
    name: "Detection Response Agent",
    purpose: "Enrich one alert, record its disposition, carry a bounded rule change through backtest and canary, and deploy only after reviewed approval.",
    stage: "execution",
    surface: "detection",
    owner: "@writer/detection-engineering",
    dataSources: ["panther", "cerebro", "slack"],
    allowedActions: [
      "read:detection_alert",
      "read:detection_history",
      "write:detection_rule_candidate",
      "run:detection_backtest",
      "run:detection_canary",
      "write:detection_rule_with_approval",
      "read:detection_effectiveness",
    ],
    blastRadius: "tenant",
    escalationPath: "slack:#security-incidents",
    requiresApproval: false,
  },
  {
    id: "investigation",
    name: "Investigation Agent",
    purpose: "Expand scope, gather supporting evidence, and map related entities across Cerebro, GitHub, and Slack.",
    stage: "investigation",
    surface: "cross-cutting",
    owner: "@writer/security-platform",
    dataSources: ["cerebro", "github", "slack"],
    allowedActions: [
      "read:cerebro_context",
      "read:cerebro_graph",
      "read:cerebro_findings",
      "read:github.search",
      "read:slack.context",
    ],
    blastRadius: "read-only",
    escalationPath: "slack:#security-investigations",
    requiresApproval: false,
  },
  {
    id: "planner",
    name: "Remediation Planner",
    purpose: "Create safe remediation plans, run read-only checks, and package approval-ready proposals.",
    stage: "planning",
    surface: "cross-cutting",
    owner: "@writer/security-platform",
    dataSources: ["cerebro", "github", "slack"],
    allowedActions: [
      "read:cerebro_context",
      "read:cerebro_graph",
      "read:github.pr_status",
      "read:github.checks",
      "propose:approval_request",
    ],
    blastRadius: "read-only",
    escalationPath: "slack:#security-investigations",
    requiresApproval: false,
  },
  {
    id: "self_repair",
    name: "Self-Repair Agent",
    purpose: "Inspect Cerebro companion behavior gaps, prepare reviewable code fixes, open PRs, and watch checks.",
    stage: "self-repair",
    surface: "cross-cutting",
    owner: "@writer/security-platform",
    dataSources: ["github", "slack", "cerebro"],
    allowedActions: [
      "read:github.pr_status",
      "read:github.checks",
      "write:github.pr",
      "write:runtime_code_workspace",
      "run:bounded_shell",
    ],
    blastRadius: "single-user",
    escalationPath: "slack:#security-team-agents",
    requiresApproval: false,
  },
  {
    id: "triage",
    name: "Triage Agent",
    purpose: "Summarize incoming security signals, retrieve context, and route work to a specialist capability.",
    stage: "triage",
    surface: "cross-cutting",
    owner: "@writer/security-platform",
    dataSources: ["cerebro", "github", "slack"],
    allowedActions: [
      "read:cerebro_context",
      "read:cerebro_findings",
      "read:github.issue",
      "read:slack.context",
    ],
    blastRadius: "read-only",
    escalationPath: "slack:#security-triage",
    requiresApproval: false,
  },
] satisfies AutonomyCapabilityDefinition[]);

const capabilityById = new Map(AUTONOMY_CAPABILITIES.map((capability) => [capability.id, capability]));
const allowedSurfaces = new Set<AutonomyCapabilityDefinition["surface"]>([
  "appsec",
  "entsec",
  "cloudsec",
  "detection",
  "vuln-mgmt",
  "threat-modeling",
  "saas-posture",
  "cross-cutting",
]);
const allowedBlastRadii = new Set<AutonomyBlastRadius>(["read-only", "single-user", "tenant", "org"]);

export function autonomyCapabilities(): AutonomyCapabilityDefinition[] {
  return AUTONOMY_CAPABILITIES.map(cloneCapability);
}

export function autonomyCapability(id: AutonomyCapabilityId): AutonomyCapabilityDefinition {
  const capability = capabilityById.get(id);
  if (!capability) throw new Error(`Unknown autonomy capability ${id}.`);
  return cloneCapability(capability);
}

export function inferAutonomyCapability(objective: string): AutonomyCapabilityId {
  const normalized = objective.toLowerCase();
  if (/\b(security alert|security case|dependabot|codeql|secret scanning|vulnerabilit(?:y|ies))\b/.test(normalized)
    && /\b(handle|fix|patch|remediat|resolve)\w*\b/.test(normalized)) return "remediation";
  if (/\b(self[- ]?repair|fix|patch|pr|pull request|ci|test|code|repo|merge)\b/.test(normalized)) return "self_repair";
  if (/\b(execute|remediate|resolve|suppress|deploy|rollout|apply|close out)\b/.test(normalized)) return "executor";
  if (/\b(investigate|debug|root cause|evidence|blast radius|trace)\b/.test(normalized)) return "investigation";
  if (/\b(triage|classify|route|prioritize)\b/.test(normalized)) return "triage";
  return "planner";
}

export function validateAutonomyCapabilities(capabilities: readonly AutonomyCapabilityDefinition[] = AUTONOMY_CAPABILITIES): void {
  const ids = new Set<string>();
  for (const capability of capabilities) {
    if (!capability.id.trim()) throw new Error("Autonomy capability id is required.");
    if (ids.has(capability.id)) throw new Error(`Autonomy capability ${capability.id} is duplicated.`);
    ids.add(capability.id);
    if (!capability.name.trim()) throw new Error(`Autonomy capability ${capability.id} name is required.`);
    if (!allowedSurfaces.has(capability.surface)) throw new Error(`Autonomy capability ${capability.id} surface is invalid.`);
    if (!capability.owner.trim()) throw new Error(`Autonomy capability ${capability.id} owner is required.`);
    if (capability.dataSources.length === 0) throw new Error(`Autonomy capability ${capability.id} needs at least one data source.`);
    if (capability.allowedActions.length === 0) throw new Error(`Autonomy capability ${capability.id} needs at least one allowed action.`);
    if (!allowedBlastRadii.has(capability.blastRadius)) throw new Error(`Autonomy capability ${capability.id} blast radius is invalid.`);
    if (!capability.escalationPath.trim()) throw new Error(`Autonomy capability ${capability.id} escalation path is required.`);
    if (capability.requiresApproval && capability.blastRadius !== "tenant" && capability.blastRadius !== "org") {
      throw new Error(`Autonomy capability ${capability.id} can require approval only for tenant or org blast radius.`);
    }
  }
}

function cloneCapability(capability: AutonomyCapabilityDefinition): AutonomyCapabilityDefinition {
  return {
    ...capability,
    dataSources: [...capability.dataSources],
    allowedActions: [...capability.allowedActions],
  };
}

validateAutonomyCapabilities();
