import { describe, expect, it } from "vitest";

import {
  controlRefMatchesFramework,
  controlViolations,
  enabledFrameworks,
  frameworkViolationSummary,
  selectableFrameworks,
  toggleFrameworkName,
} from "./compliance-frameworks";
import type { GRCFinding, GRCFramework } from "./grc";

const finding = (id: string, severity: string, ruleID: string, controls: GRCFinding["controls"], extra: Partial<GRCFinding> = {}): GRCFinding => ({
  id,
  title: id,
  severity,
  status: "open",
  rule_id: ruleID,
  controls,
  evidence_count: 0,
  owner: "",
  sla_status: "",
  ...extra,
});

const soc2 = { id: "soc2", name: "SOC 2" };

describe("controlViolations", () => {
  it("groups open findings by the framework controls they violate", () => {
    const violations = controlViolations([
      finding("f1", "HIGH", "aws.s3_public", [{ framework_name: "SOC 2", control_id: "CC6.1" }, { framework_name: "ISO 27001:2022", control_id: "A.8.3" }]),
      finding("f2", "CRITICAL", "okta.admin_no_mfa", [{ framework_name: "soc 2", control_id: "CC6.1" }]),
      finding("f3", "MEDIUM", "aws.s3_public", [{ framework_name: "SOC 2", control_id: "CC6.10" }]),
      finding("f4", "LOW", "aws.s3_public", [{ framework_name: "SOC 2", control_id: "CC7.2" }], { status: "resolved" }),
    ], soc2);

    expect(violations.map((violation) => violation.controlID)).toEqual(["CC6.1", "CC6.10"]);
    expect(violations[0].findings.map((item) => item.id)).toEqual(["f2", "f1"]);
    expect(violations[0].rules).toEqual([
      { ruleID: "aws.s3_public", findings: 1 },
      { ruleID: "okta.admin_no_mfa", findings: 1 },
    ]);
    expect(violations[0]).toMatchObject({ critical: 1, high: 1 });
  });

  it("matches control refs by framework id when names differ", () => {
    expect(controlRefMatchesFramework({ framework_name: "SOC2 Type II", framework_id: "SOC2" }, soc2)).toBe(true);
    expect(controlRefMatchesFramework({ framework_name: "SOC 3" }, soc2)).toBe(false);
    expect(controlRefMatchesFramework({ framework_name: "x", framework_id: "" }, { name: "y" })).toBe(false);
  });

  it("orders controls with equal severity naturally", () => {
    const violations = controlViolations([
      finding("a", "LOW", "r", [{ framework_name: "CIS", control_id: "2.10" }]),
      finding("b", "LOW", "r", [{ framework_name: "CIS", control_id: "2.1.4" }]),
    ], { name: "CIS" });
    expect(violations.map((violation) => violation.controlID)).toEqual(["2.1.4", "2.10"]);
  });

  it("counts a finding once in the summary even when it violates several controls", () => {
    const violations = controlViolations([
      finding("f1", "CRITICAL", "r1", [{ framework_name: "SOC 2", control_id: "CC6.1" }, { framework_name: "SOC 2", control_id: "CC6.2" }]),
      finding("f2", "LOW", "r2", [{ framework_name: "SOC 2", control_id: "CC6.2" }]),
    ], soc2);
    expect(frameworkViolationSummary(violations)).toEqual({ controls: 2, findings: 2, rules: 2, critical: 1 });
  });
});

describe("framework selection helpers", () => {
  const catalog = [
    { name: "SOC 2", lifecycle: "active" },
    { name: "ISO 27001:2022", lifecycle: "active" },
    { name: "CSA CCM v4.0", lifecycle: "upcoming" },
  ] as GRCFramework[];

  it("resolves saved names in catalog order and drops names the catalog no longer has", () => {
    expect(enabledFrameworks(catalog, ["iso 27001:2022", "SOC 2", "Retired Framework"]).map((framework) => framework.name))
      .toEqual(["SOC 2", "ISO 27001:2022"]);
  });

  it("only offers active frameworks", () => {
    expect(selectableFrameworks(catalog).map((framework) => framework.name)).toEqual(["SOC 2", "ISO 27001:2022"]);
  });

  it("toggles names case-insensitively", () => {
    expect(toggleFrameworkName(["SOC 2"], "soc 2")).toEqual([]);
    expect(toggleFrameworkName(["SOC 2"], "ISO 27001:2022")).toEqual(["SOC 2", "ISO 27001:2022"]);
  });
});
