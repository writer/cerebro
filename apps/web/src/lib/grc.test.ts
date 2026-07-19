import { describe, expect, it } from "vitest";

import { humanize } from "./grc";
import {
  connectorScopeOptionMatchesFrameworkSegment,
  controlMatchesFrameworkSegment,
  findingMatchesFrameworkSegment,
  findSupportedGRCFramework,
  frameworkOptionLabel,
  frameworkMatchesRouteSegment,
  frameworkRouteSegment,
  inventoryAssetMatchesFrameworkSegment,
  isUpcomingGRCFramework,
  supportedGRCFrameworkNames,
  upcomingGRCFrameworkNames,
} from "./grc-frameworks";

describe("humanize", () => {
  it("preserves infrastructure acronyms", () => {
    expect(humanize("aws_sso")).toBe("AWS SSO");
    expect(humanize("gcp_api_url")).toBe("GCP API URL");
    expect(humanize("account_id")).toBe("Account ID");
  });
});

describe("supported GRC frameworks", () => {
  it("includes the regulatory framework support mirrored from cerebro", () => {
    expect(supportedGRCFrameworkNames).toEqual(expect.arrayContaining([
      "DORA",
      "FedRAMP Rev. 5",
      "NIS2",
      "CMMC 2.0",
      "CJIS Security Policy",
      "NIST CSF 2.0",
      "GDPR",
      "CCPA",
      "ISO 27701:2025",
      "ISO 42001",
      "NIST AI RMF 1.0",
      "CSA CCM v4.0",
    ]));
  });

  it("resolves common framework aliases for controls navigation", () => {
    expect(findSupportedGRCFramework("fedramp")?.name).toBe("FedRAMP Rev. 5");
    expect(findSupportedGRCFramework("cjis")?.name).toBe("CJIS Security Policy");
    expect(findSupportedGRCFramework("nist csf")?.name).toBe("NIST CSF 2.0");
    expect(findSupportedGRCFramework("soc2")?.name).toBe("SOC 2");
  });

  it("does not duplicate framework names", () => {
    expect(new Set(supportedGRCFrameworkNames).size).toBe(supportedGRCFrameworkNames.length);
  });

  it("marks upcoming frameworks as discoverable but separately labeled", () => {
    expect(upcomingGRCFrameworkNames).toEqual(expect.arrayContaining(["NIST AI RMF 1.0", "CSA CCM v4.0"]));
    expect(isUpcomingGRCFramework("nist ai rmf")).toBe(true);
    expect(frameworkOptionLabel("NIST AI RMF 1.0")).toBe("NIST AI RMF 1.0 (Upcoming)");
    expect(isUpcomingGRCFramework("SOC 2")).toBe(false);
  });

  it("builds stable framework detail route segments", () => {
    const framework = { id: "soc2", name: "SOC 2" };
    expect(frameworkRouteSegment(framework)).toBe("soc2");
    expect(frameworkMatchesRouteSegment(framework, "soc2")).toBe(true);
    expect(frameworkMatchesRouteSegment({ name: "ISO 27001:2022" }, "iso-27001-2022")).toBe(true);
  });

  it("filters alert findings by direct and overlapping framework mappings", () => {
    expect(findingMatchesFrameworkSegment({
      id: "finding-1",
      title: "Third-party ICT provider lacks exit plan",
      severity: "HIGH",
      status: "open",
      source_id: "grc",
      policy_name: "ICT third-party resilience",
      controls: [{ framework_name: "DORA", control_id: "Art.28" }],
      evidence_count: 1,
      owner: "risk",
      sla_status: "active",
    }, "DORA")).toBe(true);

    expect(findingMatchesFrameworkSegment({
      id: "finding-2",
      title: "Repository missing CODEOWNERS",
      severity: "MEDIUM",
      status: "open",
      source_id: "github",
      rule_id: "github-automated-checks",
      controls: [{ framework_name: "CIS GitHub Benchmark", control_id: "1.1" }],
      evidence_count: 1,
      owner: "appsec",
      sla_status: "active",
    }, "CIS GitHub")).toBe(true);

    expect(findingMatchesFrameworkSegment({
      id: "finding-3",
      title: "Generated source coverage blind spot",
      severity: "HIGH",
      status: "open",
      source_id: "custom_identity",
      source_coverage_refs: [{
        source_id: "custom_identity",
        dimension_id: "custom_identity.users",
        dimension_type: "app_entitlement",
        support_level: "partial",
        evidence_types: ["identity_configuration"],
        matched_control_refs: [{ framework_name: "SOC 2", control_id: "CC6.1" }],
      }],
      evidence_count: 1,
      owner: "identity",
      sla_status: "active",
    }, "SOC 2")).toBe(true);

    expect(findingMatchesFrameworkSegment({
      id: "finding-4",
      title: "Coverage metadata only",
      severity: "MEDIUM",
      status: "open",
      source_id: "custom_source",
      source_coverage_refs: [{
        source_id: "custom_source",
        dimension_id: "custom_source.users",
        dimension_type: "app_entitlement",
        support_level: "partial",
        families: ["users"],
        evidence_types: ["identity_configuration"],
        control_domains: ["identity_access"],
      }],
      evidence_count: 0,
      owner: "identity",
      sla_status: "active",
    }, "identity configuration")).toBe(true);
  });

  it("maps framework segmentation onto inventory assets", () => {
    expect(inventoryAssetMatchesFrameworkSegment({
      urn: "urn:cerebro:tenant:aws_bedrock_agent:agent-1",
      label: "Production support agent",
      entity_type: "aws.bedrock_agent",
      source_id: "aws",
      attributes: { resource_type: "bedrock_agent", owner: "ai-platform" },
    }, "ISO 42001")).toBe(true);

    expect(inventoryAssetMatchesFrameworkSegment({
      urn: "urn:cerebro:tenant:github_repository:app",
      label: "Application repository",
      entity_type: "github.repository",
      source_id: "github",
      attributes: { resource_type: "repository" },
    }, "CIS Google Workspace Benchmark")).toBe(false);
  });

  it("maps framework segmentation onto connector collection families", () => {
    expect(connectorScopeOptionMatchesFrameworkSegment({
      id: "aws.bedrock_agent",
      label: "Bedrock agents",
      families: ["aws.bedrock_agent"],
    }, "EU AI Act", "aws")).toBe(true);

    expect(connectorScopeOptionMatchesFrameworkSegment({
      id: "google_workspace.group",
      label: "Workspace groups",
      families: ["google_workspace.group"],
    }, "CIS Google Workspace Benchmark", "google_workspace")).toBe(true);

    expect(connectorScopeOptionMatchesFrameworkSegment({
      id: "github.repository",
      label: "Repositories",
      families: ["github.repository"],
    }, "CIS Google Workspace Benchmark", "github")).toBe(false);

    expect(connectorScopeOptionMatchesFrameworkSegment({
      id: "custom.users.identity",
      label: "Custom identity entitlements",
      families: ["custom.user"],
      evidence_types: ["identity_configuration"],
      control_domains: ["identity_and_access"],
      control_refs: [{ framework_name: "SOC 2", control_id: "CC6.1" }],
    }, "SOC 2", "custom_identity")).toBe(true);
  });

  it("falls back to text matching for custom framework filters", () => {
    expect(findingMatchesFrameworkSegment({
      id: "finding-3",
      title: "Repository default branch is unprotected",
      severity: "MEDIUM",
      status: "open",
      source_id: "github",
      controls: [{ framework_name: "CIS GitHub Benchmark", control_id: "2.1" }],
      evidence_count: 1,
      owner: "appsec",
      sla_status: "active",
    }, "repository")).toBe(true);

    expect(inventoryAssetMatchesFrameworkSegment({
      urn: "urn:cerebro:tenant:github_repository:app",
      label: "Application repository",
      entity_type: "github.repository",
      source_id: "github",
      attributes: { resource_type: "repository" },
    }, "github")).toBe(true);

    expect(connectorScopeOptionMatchesFrameworkSegment({
      id: "google_workspace.group",
      label: "Workspace groups",
      families: ["google_workspace.group"],
    }, "group", "google_workspace")).toBe(true);

    expect(controlMatchesFrameworkSegment({
      framework_name: "SOC 2",
      control_id: "CC6.1",
      status: "passing",
      open_findings: 0,
      critical_findings: 0,
      high_findings: 0,
      evidence_items: 1,
    }, "unmapped custom filter")).toBe(false);
  });

  it("matches controls and asset tests through aliases", () => {
    expect(controlMatchesFrameworkSegment({
      framework_name: "FedRAMP Rev. 5",
      control_id: "AC-2",
      status: "failing",
      open_findings: 1,
      critical_findings: 0,
      high_findings: 1,
      evidence_items: 2,
    }, "fedramp")).toBe(true);

    expect(controlMatchesFrameworkSegment({
      name: "Privileged access review",
      owner: "security",
      status: "open",
      framework: "NIST CSF 2.0",
      control_id: "GV.RM",
    }, "nist csf")).toBe(true);
  });
});
