import { describe, expect, it } from "vitest";

import {
  ATTACK_SIMULATION_SCENARIOS,
  attackSimulationRequest,
  attackSimulationResult,
  attackSimulationScenarioFor,
  signedChange,
  simulationRuntimeIDs,
  simulationTargetForPath,
  tenantIDFromURN,
} from "./attack-simulation";

describe("simulationTargetForPath", () => {
  const internet = { urn: "urn:cerebro:t1:internet:any", role: "public_principal" };
  const exposed = { urn: "urn:cerebro:t1:service:api", role: "exposed_resource" };
  const principal = { urn: "urn:cerebro:t1:identity:admin", role: "principal" };

  it("never targets the internet pseudo-entity that starts an exposure path", () => {
    expect(simulationTargetForPath([internet, exposed, principal], "remove_public_exposure")).toBe(exposed);
    expect(simulationTargetForPath([{ urn: "urn:cerebro:t1:internet:any" }, { urn: "urn:cerebro:t1:bucket:b" }], "remove_public_exposure")?.urn)
      .toBe("urn:cerebro:t1:bucket:b");
  });

  it("targets the privileged principal when removing privilege", () => {
    expect(simulationTargetForPath([internet, exposed, principal], "remove_privilege")).toBe(principal);
  });

  it("returns nothing when only the public principal is on the path", () => {
    expect(simulationTargetForPath([internet], "remove_public_exposure")).toBeUndefined();
  });
});

describe("attack simulation scenarios", () => {
  it("offers exactly the scenarios the risk-delta report accepts", () => {
    expect(ATTACK_SIMULATION_SCENARIOS.map((scenario) => scenario.id)).toEqual([
      "remove_public_exposure",
      "remove_privilege",
      "patch_vulnerability",
      "compromise_identity",
    ]);
    expect(attackSimulationScenarioFor(" remove_privilege ")?.label).toBe("Remove Privilege");
    expect(attackSimulationScenarioFor("drop_table")).toBeUndefined();
    expect(attackSimulationScenarioFor("compromise_identity")?.intent).toBe("attack");
  });
});

describe("attackSimulationRequest", () => {
  it("runs the risk-delta report with the parameters it requires", () => {
    expect(attackSimulationRequest({
      runtimeIDs: ["rt-a", "rt-b"],
      scenario: "remove_public_exposure",
      targetURN: "urn:cerebro:acme:aws.ec2.instance:i-1",
      tenantID: "acme",
    })).toEqual({
      path: "/reports/risk-delta/runs",
      body: {
        parameters: {
          tenant_id: "acme",
          runtime_ids: "rt-a,rt-b",
          scenario_type: "remove_public_exposure",
          target_urn: "urn:cerebro:acme:aws.ec2.instance:i-1",
        },
      },
    });
  });
});

describe("tenantIDFromURN", () => {
  it("reads the tenant segment of a Cerebro URN only", () => {
    expect(tenantIDFromURN("urn:cerebro:acme:repository:demo")).toBe("acme");
    expect(tenantIDFromURN("urn:other:acme:repository:demo")).toBe("");
    expect(tenantIDFromURN("urn:cerebro:acme")).toBe("");
    expect(tenantIDFromURN("")).toBe("");
  });
});

describe("simulationRuntimeIDs", () => {
  it("accepts both the fixture and service runtime shapes and deduplicates", () => {
    expect(simulationRuntimeIDs({ source_runtimes: [{ runtime_id: "b" }, { id: "a" }, { id: "b" }, {}, null] })).toEqual(["a", "b"]);
    expect(simulationRuntimeIDs({})).toEqual([]);
    expect(simulationRuntimeIDs(null)).toEqual([]);
  });
});

describe("attackSimulationResult", () => {
  const response = {
    run: {
      id: "run-1",
      result: {
        graph_evidence_status: "included",
        risk_delta: {
          scenario_type: "remove_public_exposure",
          target_urn: "urn:cerebro:acme:service:api",
          before: { finding_count: 3, total_risk_score: "180", attack_path_count: 2, total_attack_path_score: 140 },
          after: { finding_count: 3, total_risk_score: 120, attack_path_count: 1, total_attack_path_score: 60 },
          risk_score_change: -60,
          attack_path_count_change: -1,
          attack_path_score_change: "-80",
          affected_findings: [
            { finding_id: "f-1", rule_id: "public-admin", before_risk_score: 90, after_risk_score: 30, reduction: 60, removed_reasons: ["public_exposure"] },
            { rule_id: "orphan" },
          ],
          removed_attack_paths: [
            { pattern: "public_to_admin", score: 80, finding_id: "f-1", steps: [{ from_urn: "urn:a", relation: "can_reach", to_urn: "urn:b" }, { from_urn: "", to_urn: "urn:c" }] },
          ],
          remaining_attack_paths: [{ pattern: "secret_exposure", score: 60, steps: [] }],
          reasons: ["removed_graph_relation:can_reach"],
        },
      },
    },
  };

  it("normalizes the report payload, including Struct numbers sent as strings", () => {
    const result = attackSimulationResult(response);
    expect(result).toMatchObject({
      runID: "run-1",
      scenario: "remove_public_exposure",
      targetURN: "urn:cerebro:acme:service:api",
      graphEvidenceStatus: "included",
      before: { findingCount: 3, totalRiskScore: 180, attackPathCount: 2, totalAttackPathScore: 140 },
      after: { attackPathCount: 1, totalAttackPathScore: 60 },
      riskScoreChange: -60,
      attackPathCountChange: -1,
      attackPathScoreChange: -80,
      addedPaths: [],
      reasons: ["removed_graph_relation:can_reach"],
    });
    expect(result?.affectedFindings).toEqual([
      { findingID: "f-1", ruleID: "public-admin", before: 90, after: 30, reduction: 60, addedReasons: [], removedReasons: ["public_exposure"] },
    ]);
    expect(result?.removedPaths[0].steps).toEqual([{ from: "urn:a", relation: "can_reach", to: "urn:b" }]);
  });

  it("returns nothing when the run carries no risk delta", () => {
    expect(attackSimulationResult({ run: { result: {} } })).toBeNull();
    expect(attackSimulationResult(null)).toBeNull();
  });
});

describe("signedChange", () => {
  it("prefixes increases so a growing attack surface reads as one", () => {
    expect(signedChange(3)).toBe("+3");
    expect(signedChange(-3)).toBe("-3");
    expect(signedChange(0)).toBe("0");
  });
});
