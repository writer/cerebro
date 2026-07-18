import { trimForSlack } from "../slack/format.js";
import type { AutonomyCapabilityDefinition } from "./capabilities.js";
import type { AutonomyPlanStep, AutonomousGoalRecord } from "./goals.js";

export function playbookToolId(capability: AutonomyCapabilityDefinition): string {
  switch (capability.id) {
    case "investigation":
      return "autonomy.investigation_playbook";
    case "planner":
      return "autonomy.planning_playbook";
    case "triage":
      return "autonomy.triage_playbook";
    case "self_repair":
      return "autonomy.self_repair_playbook";
    case "remediation":
      return "autonomy.security_case_remediation_playbook";
    case "identity_response":
      return "autonomy.identity_response_playbook";
    case "detection_response":
      return "autonomy.detection_response_playbook";
    case "executor":
      return "autonomy.execution_playbook";
  }
}

export function playbookSummary(capability: AutonomyCapabilityDefinition, goal: AutonomousGoalRecord, step: AutonomyPlanStep): string {
  const objective = trimForSlack(goal.objective, 500);
  switch (capability.id) {
    case "investigation":
      return [
        `Objective: ${objective}`,
        `Step: ${step.title}.`,
        "Use cerebro_finding_investigation when a runtime and finding id are known.",
        "Otherwise use cerebro_recent_scary_findings, cerebro_open_findings, cerebro_graph_cypher_investigate, slack_thread_context, and evidence_cas_resolve only for returned refs.",
        "Return proved facts, gaps, blast-radius clues, confidence, and safe next actions. Do not execute response actions.",
      ].join(" ");
    case "planner":
      return [
        `Objective: ${objective}`,
        "Build a reviewable plan with evidence, owner, checks, rollback path, approval need, and blocked sources.",
      ].join(" ");
    case "triage":
      return [
        `Objective: ${objective}`,
        "Classify severity and confidence, identify the owner and required evidence, and route without changing production state.",
      ].join(" ");
    case "self_repair":
      return [
        `Objective: ${objective}`,
        "Use code workspace search/read-many before patching, run bounded checks, then open a reviewable PR if code changes are needed.",
      ].join(" ");
    case "remediation":
      return [
        `Objective: ${objective}`,
        "Keep the security case attached to current Cerebro evidence, a reviewable pull request, and fresh post-merge verification.",
      ].join(" ");
    case "identity_response":
      return [
        `Objective: ${objective}`,
        "Bind current identity and access evidence, isolate one revocation target, require reviewed approval, then verify with an independent read.",
      ].join(" ");
    case "detection_response":
      return [
        `Objective: ${objective}`,
        "Bind the current alert and rule, record the disposition, require backtest and canary evidence, then gate deployment and effectiveness verification.",
      ].join(" ");
    case "executor":
      return [
        `Objective: ${objective}`,
        "Execution remains approval-gated. Consume approval, then use the dedicated approved response tool path.",
      ].join(" ");
  }
}

export function playbookStepSummary(capability: AutonomyCapabilityDefinition, step: AutonomyPlanStep): string {
  if (capability.id === "investigation") {
    return `Investigation checkpoint recorded for ${step.title}.`;
  }
  if (capability.id === "self_repair") {
    return `Self-repair checkpoint recorded for ${step.title}.`;
  }
  if (capability.id === "remediation") {
    return `Security case checkpoint recorded for ${step.title}.`;
  }
  if (capability.id === "identity_response" || capability.id === "detection_response") {
    return `Security mission checkpoint recorded for ${step.title}.`;
  }
  return `Capability checkpoint recorded for ${step.title}.`;
}
