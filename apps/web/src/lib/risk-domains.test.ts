import { describe, expect, it } from "vitest";

import type { GRCFinding } from "@/lib/grc";
import {
  groupFindingsByRule,
  groupFindingsBySource,
  riskDomainForRuleID,
  riskDomainSummary,
} from "./risk-domains";

const finding = (overrides: Partial<GRCFinding>): GRCFinding => ({
  evidence_count: 0,
  id: overrides.id ?? "finding",
  owner: "Unassigned",
  severity: "LOW",
  sla_status: "on_track",
  status: "open",
  title: "Finding",
  ...overrides,
});

describe("risk domains", () => {
  it("maps the four cloud providers onto the cloud posture domain", () => {
    for (const ruleID of ["aws-s3-bucket-public", "gcp-storage-public", "azure-blob-public", "k8s-privileged-pod"]) {
      expect(riskDomainForRuleID(ruleID), ruleID).toBe("cloud");
    }
  });

  it("separates SaaS posture from identity", () => {
    expect(riskDomainForRuleID("github-branch-protection-missing")).toBe("saas");
    expect(riskDomainForRuleID("m365-sharing-anonymous")).toBe("saas");
    expect(riskDomainForRuleID("identity-mfa-missing")).toBe("identity");
    expect(riskDomainForRuleID("okta-admin-no-mfa")).toBe("identity");
  });

  it("falls back to other rather than guessing an unknown prefix", () => {
    expect(riskDomainForRuleID("hipaa-164-312-audit")).toBe("other");
    expect(riskDomainForRuleID("")).toBe("other");
    expect(riskDomainForRuleID(undefined)).toBe("other");
  });

  it("is case and whitespace insensitive on the rule prefix", () => {
    expect(riskDomainForRuleID("  AWS-Public-Bucket ")).toBe("cloud");
  });

  it("reads a dot delimited rule id the same way as a hyphenated one", () => {
    expect(riskDomainForRuleID("identity.admin_without_mfa")).toBe("identity");
    expect(riskDomainForRuleID("storage.bucket_policy_review")).toBe("cloud");
    expect(riskDomainForRuleID("repo.public_sensitive")).toBe("saas");
    expect(riskDomainForRuleID("aws.open_security_group")).toBe(riskDomainForRuleID("aws-open-security-group"));
  });

  it("treats cloud resource classes as cloud posture", () => {
    for (const ruleID of ["db-backup-disabled", "network-acl-open", "backup-retention-short", "bucket-public-read"]) {
      expect(riskDomainForRuleID(ruleID), ruleID).toBe("cloud");
    }
  });

  it("counts severity and ownership per domain", () => {
    const summary = riskDomainSummary([
      finding({ id: "a", rule_id: "aws-public-bucket", severity: "CRITICAL" }),
      finding({ id: "b", rule_id: "aws-open-sg", severity: "HIGH", owner: "platform" }),
      finding({ id: "c", rule_id: "github-no-2fa", severity: "HIGH" }),
      finding({ id: "d", rule_id: "hipaa-audit-log", severity: "LOW", owner: "grc" }),
    ]);

    expect(summary.cloud.findings).toHaveLength(2);
    expect(summary.cloud.critical).toBe(1);
    expect(summary.cloud.high).toBe(1);
    expect(summary.cloud.unowned).toBe(1);
    expect(summary.saas.findings).toHaveLength(1);
    expect(summary.other.findings).toHaveLength(1);
    expect(summary.endpoint.findings).toHaveLength(0);
  });

  it("ranks rule groups by critical, then high, then top risk", () => {
    const groups = groupFindingsByRule([
      finding({ id: "a", rule_id: "aws-low", policy_name: "Low rule", severity: "LOW", risk_score: 10 }),
      finding({ id: "b", rule_id: "aws-high", policy_name: "High rule", severity: "HIGH", risk_score: 70 }),
      finding({ id: "c", rule_id: "aws-crit", policy_name: "Critical rule", severity: "CRITICAL", risk_score: 95 }),
    ]);

    expect(groups.map((group) => group.label)).toEqual(["Critical rule", "High rule", "Low rule"]);
    expect(groups[0]?.topRisk).toBe(95);
  });

  it("labels a rule group by policy name and falls back to the rule id", () => {
    const groups = groupFindingsByRule([
      finding({ id: "a", rule_id: "aws-open-sg" }),
      finding({ id: "b" }),
    ]);

    expect(groups.map((group) => group.id).sort()).toEqual(["aws-open-sg", "unclassified"]);
    expect(groups.find((group) => group.id === "unclassified")?.label).toBe("Unclassified rule");
  });

  it("groups by source and names the unattributed bucket", () => {
    const groups = groupFindingsBySource([
      finding({ id: "a", source_id: "aws", severity: "CRITICAL" }),
      finding({ id: "b", source_id: "aws" }),
      finding({ id: "c" }),
    ]);

    expect(groups[0]?.id).toBe("aws");
    expect(groups[0]?.findings).toHaveLength(2);
    expect(groups[1]?.label).toBe("Unattributed source");
  });
});
