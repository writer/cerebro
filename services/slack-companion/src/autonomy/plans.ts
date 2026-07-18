import type { AutonomyCapabilityId, AutonomyPlanStep } from "./goals.js";

export function defaultAutonomyPlan(capabilityId: AutonomyCapabilityId): AutonomyPlanStep[] {
  switch (capabilityId) {
    case "investigation":
      return [
        {
          id: "inspect-context",
          title: "Identify finding, runtime, entity, and source coverage",
          status: "pending",
          dependsOn: [],
        },
        {
          id: "collect-evidence",
          title: "Build evidence ledger and related-entity scope",
          status: "pending",
          dependsOn: ["inspect-context"],
        },
        {
          id: "assess-safe-next-step",
          title: "Separate proved facts, gaps, and safe next actions",
          status: "pending",
          dependsOn: ["collect-evidence"],
        },
      ];
    case "planner":
      return [
        {
          id: "inspect-context",
          title: "Identify objective, constraints, and available evidence",
          status: "pending",
          dependsOn: [],
        },
        {
          id: "plan-reviewable-work",
          title: "Prepare a reviewable plan with checks and rollback path",
          status: "pending",
          dependsOn: ["inspect-context"],
        },
      ];
    case "triage":
      return [
        {
          id: "classify-signal",
          title: "Classify signal and identify required evidence",
          status: "pending",
          dependsOn: [],
        },
        {
          id: "route-owner",
          title: "Route to owner with confidence and missing context",
          status: "pending",
          dependsOn: ["classify-signal"],
        },
      ];
    case "self_repair":
      return [
        {
          id: "inspect-context",
          title: "Inspect current context and choose the next action",
          status: "pending",
          dependsOn: [],
        },
        {
          id: "prepare-reviewable-change",
          title: "Prepare bounded change, checks, and PR path",
          status: "pending",
          dependsOn: ["inspect-context"],
        },
        {
          id: "monitor-github-checks",
          title: "Watch GitHub PR checks until they pass, fail, or need review",
          status: "pending",
          dependsOn: ["prepare-reviewable-change"],
        },
      ];
    case "remediation":
      return [
        {
          id: "investigate-finding",
          title: "Investigate the finding and affected resources",
          status: "pending",
          dependsOn: [],
        },
        {
          id: "prepare-reviewable-fix",
          title: "Prepare the reviewable fix",
          status: "pending",
          dependsOn: ["investigate-finding"],
        },
        {
          id: "verify-finding-resolved",
          title: "Verify the finding is resolved",
          status: "pending",
          dependsOn: ["prepare-reviewable-fix"],
        },
      ];
    case "identity_response":
      return [
        { id: "collect-identity-evidence", title: "Collect lifecycle, IdP, SaaS access, and activity evidence", status: "pending", dependsOn: [] },
        { id: "approve-revocation", title: "Approve the exact access revocation target and rollback", status: "pending", dependsOn: ["collect-identity-evidence"] },
        { id: "verify-access-removed", title: "Verify the targeted access path is absent", status: "pending", dependsOn: ["approve-revocation"] },
      ];
    case "detection_response":
      return [
        { id: "enrich-alert", title: "Read the alert and enrich affected entities", status: "pending", dependsOn: [] },
        { id: "backtest-rule", title: "Run the changed rule against the historical window", status: "pending", dependsOn: ["enrich-alert"] },
        { id: "verify-detection-effectiveness", title: "Verify post-deployment detection behavior", status: "pending", dependsOn: ["backtest-rule"] },
      ];
    case "executor":
      return [{
        id: "execute",
        title: "Execute approved remediation",
        status: "pending",
        dependsOn: [],
      }];
  }
}
