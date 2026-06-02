package findings

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestSimulateRiskDeltaRemovePublicExposure(t *testing.T) {
	finding := compoundRiskFinding("cloud-public-prod-secrets", cloudPublicResourceExposureRuleID, "HIGH", "", "", "urn:cerebro:writer:aws_secret_store:prod-secrets", "public_network_ingress")
	finding.Attributes["internet_exposed"] = "true"
	finding.Attributes["crown_jewel"] = "true"
	report := SimulateRiskDelta([]*ports.FindingRecord{finding}, RiskDeltaSimulationOptions{
		ScenarioType: RiskDeltaScenarioRemovePublicExposure,
		TargetURN:    "urn:cerebro:writer:aws_secret_store:prod-secrets",
		Limit:        10,
		GraphNeighborhoods: map[string]*ports.EntityNeighborhood{
			"cloud": {
				Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
				Neighbors: []*ports.NeighborhoodNode{
					{URN: "urn:cerebro:writer:aws_public_principal:public_internet", EntityType: "aws.public_principal", Label: "public internet"},
					{URN: "urn:cerebro:writer:aws_role:admin", EntityType: "aws.role", Label: "admin"},
					{URN: "urn:cerebro:writer:finding:cloud-public-prod-secrets", EntityType: "finding", Label: "cloud-public-prod-secrets"},
				},
				Relations: []*ports.NeighborhoodRelation{
					{FromURN: "urn:cerebro:writer:aws_public_principal:public_internet", Relation: "can_reach", ToURN: "urn:cerebro:writer:aws_secret_store:prod-secrets"},
					{FromURN: "urn:cerebro:writer:aws_role:admin", Relation: "can_admin", ToURN: "urn:cerebro:writer:aws_secret_store:prod-secrets"},
					{FromURN: "urn:cerebro:writer:aws_secret_store:prod-secrets", Relation: "has_finding", ToURN: "urn:cerebro:writer:finding:cloud-public-prod-secrets"},
				},
			},
		},
	})

	if report.RiskScoreReduction <= 0 {
		t.Fatalf("RiskScoreReduction = %d, want positive reduction", report.RiskScoreReduction)
	}
	if report.AttackPathScoreReduction <= 0 {
		t.Fatalf("AttackPathScoreReduction = %d, want positive reduction", report.AttackPathScoreReduction)
	}
	if report.AttackPathCountReduction <= 0 {
		t.Fatalf("AttackPathCountReduction = %d, want public exposure path count reduction", report.AttackPathCountReduction)
	}
	if len(report.RemovedAttackPaths) == 0 || !riskSimulationAttackPathContainsRelation(report.RemovedAttackPaths, "can_reach") {
		t.Fatalf("RemovedAttackPaths = %#v, want removed can_reach path", report.RemovedAttackPaths)
	}
	if len(report.AffectedFindings) != 1 {
		t.Fatalf("AffectedFindings = %#v, want one affected finding", report.AffectedFindings)
	}
	if !stringSliceContains(report.AffectedFindings[0].RemovedReasons, "external_exposure") {
		t.Fatalf("RemovedReasons = %#v, want external_exposure", report.AffectedFindings[0].RemovedReasons)
	}
}

func riskSimulationAttackPathContainsRelation(paths []FindingAttackPath, relation string) bool {
	for _, path := range paths {
		for _, step := range path.Steps {
			if step.Relation == relation {
				return true
			}
		}
	}
	return false
}

func TestSimulateRiskDeltaPatchVulnerability(t *testing.T) {
	now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	finding := compoundRiskFinding("runtime-kev", githubDependabotOpenAlertRuleID, "HIGH", "", "writer/cerebro", "urn:cerebro:writer:container_image:sha256:abc", "scan.detected")
	finding.LastObservedAt = now
	finding.Attributes["is_kev"] = "true"
	finding.Attributes["epss_score"] = "0.91"
	finding.Attributes["cvss_score"] = "9.8"
	finding.Attributes["exploit_available"] = "true"
	finding.Attributes["internet_exposed"] = "true"
	finding.Attributes["environment"] = "production"
	finding.Attributes["crown_jewel"] = "true"

	report := SimulateRiskDelta([]*ports.FindingRecord{finding}, RiskDeltaSimulationOptions{
		ScenarioType: RiskDeltaScenarioPatchVulnerability,
		TargetURN:    "urn:cerebro:writer:container_image:sha256:abc",
		Now:          now,
	})

	if report.RiskScoreReduction <= 0 {
		t.Fatalf("RiskScoreReduction = %d, want positive reduction", report.RiskScoreReduction)
	}
	if len(report.AffectedFindings) != 1 {
		t.Fatalf("AffectedFindings = %#v, want one affected finding", report.AffectedFindings)
	}
	for _, reason := range []string{"known_exploited", "epss_high", "cvss_critical", "exploit_available"} {
		if !stringSliceContains(report.AffectedFindings[0].RemovedReasons, reason) {
			t.Fatalf("RemovedReasons = %#v, want %q", report.AffectedFindings[0].RemovedReasons, reason)
		}
	}
}

func TestSimulateRiskDeltaRemovePrivilege(t *testing.T) {
	finding := compoundRiskFinding("privileged-role", cloudPrivilegePathGrantedRuleID, "HIGH", "", "", "urn:cerebro:writer:aws_role:admin", "can_admin")
	finding.Attributes["privileged"] = "true"
	finding.Attributes["can_admin"] = "true"
	finding.Attributes["has_admin_path"] = "true"
	report := SimulateRiskDelta([]*ports.FindingRecord{finding}, RiskDeltaSimulationOptions{
		ScenarioType: RiskDeltaScenarioRemovePrivilege,
		TargetURN:    "urn:cerebro:writer:aws_role:admin",
		Limit:        10,
		GraphNeighborhoods: map[string]*ports.EntityNeighborhood{
			"iam": {
				Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:aws_role:admin", EntityType: "aws.role", Label: "admin"},
				Neighbors: []*ports.NeighborhoodNode{
					{URN: "urn:cerebro:writer:aws_user:operator", EntityType: "aws.user", Label: "operator"},
					{URN: "urn:cerebro:writer:finding:privileged-role", EntityType: "finding", Label: "privileged-role"},
				},
				Relations: []*ports.NeighborhoodRelation{
					{FromURN: "urn:cerebro:writer:aws_user:operator", Relation: "can_admin", ToURN: "urn:cerebro:writer:aws_role:admin"},
					{FromURN: "urn:cerebro:writer:aws_role:admin", Relation: "has_finding", ToURN: "urn:cerebro:writer:finding:privileged-role"},
				},
			},
		},
	})

	if report.RiskScoreReduction <= 0 {
		t.Fatalf("RiskScoreReduction = %d, want positive reduction", report.RiskScoreReduction)
	}
	if report.AttackPathScoreReduction <= 0 {
		t.Fatalf("AttackPathScoreReduction = %d, want positive reduction", report.AttackPathScoreReduction)
	}
	if len(report.RemovedAttackPaths) == 0 || !riskSimulationAttackPathContainsRelation(report.RemovedAttackPaths, "can_admin") {
		t.Fatalf("RemovedAttackPaths = %#v, want removed can_admin path", report.RemovedAttackPaths)
	}
	if len(report.AffectedFindings) != 1 || !stringSliceContains(report.AffectedFindings[0].RemovedReasons, "privileged_actor") {
		t.Fatalf("AffectedFindings = %#v, want privilege reason removed", report.AffectedFindings)
	}
}

func TestSimulateRiskDeltaCompromiseIdentity(t *testing.T) {
	finding := compoundRiskFinding("sensitive-data", dataSensitiveAssetRiskRuleID, "HIGH", "", "", "urn:cerebro:writer:aws_secret_store:prod-secrets", "data_access")
	finding.Attributes["data_classification"] = "restricted"
	report := SimulateRiskDelta([]*ports.FindingRecord{finding}, RiskDeltaSimulationOptions{
		ScenarioType: RiskDeltaScenarioCompromiseIdentity,
		TargetURN:    "urn:cerebro:writer:okta_user:admin@example.com",
		Limit:        10,
		GraphNeighborhoods: map[string]*ports.EntityNeighborhood{
			"identity": {
				Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:okta_user:admin@example.com", EntityType: "okta.user", Label: "admin@example.com"},
				Neighbors: []*ports.NeighborhoodNode{
					{URN: "urn:cerebro:writer:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
					{URN: "urn:cerebro:writer:finding:sensitive-data", EntityType: "finding", Label: "sensitive-data"},
				},
				Relations: []*ports.NeighborhoodRelation{
					{FromURN: "urn:cerebro:writer:okta_user:admin@example.com", Relation: "can_admin", ToURN: "urn:cerebro:writer:aws_secret_store:prod-secrets"},
					{FromURN: "urn:cerebro:writer:aws_secret_store:prod-secrets", Relation: "has_finding", ToURN: "urn:cerebro:writer:finding:sensitive-data"},
				},
			},
		},
	})

	if report.RiskScoreChange <= 0 {
		t.Fatalf("RiskScoreChange = %d, want positive risk increase", report.RiskScoreChange)
	}
	if report.RiskScoreReduction >= 0 {
		t.Fatalf("RiskScoreReduction = %d, want negative reduction for compromise scenario", report.RiskScoreReduction)
	}
	if report.AttackPathScoreChange <= 0 {
		t.Fatalf("AttackPathScoreChange = %d, want positive attack-path risk increase", report.AttackPathScoreChange)
	}
	if len(report.AffectedFindings) != 1 {
		t.Fatalf("AffectedFindings = %#v, want one affected downstream finding", report.AffectedFindings)
	}
	if report.AffectedFindings[0].Reduction >= 0 {
		t.Fatalf("AffectedFindings[0].Reduction = %d, want negative reduction", report.AffectedFindings[0].Reduction)
	}
	for _, reason := range []string{"active_threat", "blast_radius", "privilege_or_control_plane"} {
		if !stringSliceContains(report.AffectedFindings[0].AddedReasons, reason) {
			t.Fatalf("AddedReasons = %#v, want %q", report.AffectedFindings[0].AddedReasons, reason)
		}
	}
	if !stringSliceContains(report.Reasons, "modeled_identity_blast_radius") {
		t.Fatalf("Reasons = %#v, want modeled_identity_blast_radius", report.Reasons)
	}
}
