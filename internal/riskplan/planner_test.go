package riskplan

import (
	"testing"
	"time"

	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

func TestAnalyzeRanksSimulatedCandidatesWithFirstClassSignals(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	findings := []*ports.FindingRecord{
		{
			ID:           "cloud-public-prod-secrets",
			TenantID:     "writer",
			RuntimeID:    "writer-aws",
			RuleID:       "cloud-public-resource-exposure",
			Title:        "Cloud Public Resource Exposure",
			Severity:     "HIGH",
			Status:       "open",
			ResourceURNs: []string{"urn:cerebro:writer:aws_secret_store:prod-secrets"},
			EventIDs:     []string{"evt-public"},
			FindingWorkflow: ports.FindingWorkflow{
				Assignee: "cloud-platform",
			},
			FindingRisk: ports.FindingRisk{
				RiskScore:       90,
				ConfidenceScore: 92,
				RiskReasons:     []string{"external_exposure", "crown_jewel"},
				RiskFactors: []ports.FindingRiskFactor{
					{FactorID: "external_exposure", Category: "likelihood", Weight: 35, SeverityContribution: "high", EvidenceRefs: []string{"attribute:internet_exposed"}},
					{FactorID: "crown_jewel", Category: "impact", Weight: 35, SeverityContribution: "high", EvidenceRefs: []string{"attribute:crown_jewel"}},
				},
			},
			Attributes: map[string]string{
				"action":               "public_network_ingress",
				"crown_jewel":          "true",
				"internet_exposed":     "true",
				"primary_resource_urn": "urn:cerebro:writer:aws_secret_store:prod-secrets",
				"resource_name":        "prod-secrets",
			},
			LastObservedAt: now.Add(-2 * time.Hour),
		},
		{
			ID:           "repo-kev-package",
			TenantID:     "writer",
			RuntimeID:    "writer-github",
			RuleID:       "vulnerability-known-exploited",
			Title:        "Known exploited dependency",
			Severity:     "HIGH",
			Status:       "open",
			ResourceURNs: []string{"urn:cerebro:writer:github_repository:payments-api"},
			FindingRisk: ports.FindingRisk{
				RiskScore:       78,
				ConfidenceScore: 88,
				RiskReasons:     []string{"known_exploited", "cvss_high"},
				RiskFactors: []ports.FindingRiskFactor{
					{FactorID: "known_exploited", Category: "likelihood", Weight: 35, SeverityContribution: "high", EvidenceRefs: []string{"attribute:is_kev"}},
				},
			},
			Attributes: map[string]string{
				"cvss_score":           "8.7",
				"is_kev":               "true",
				"package":              "example-lib",
				"primary_resource_urn": "urn:cerebro:writer:github_repository:payments-api",
			},
			LastObservedAt: now.Add(-24 * time.Hour),
		},
	}
	graphNeighborhoods := map[string]*ports.EntityNeighborhood{
		"urn:cerebro:writer:aws_secret_store:prod-secrets": {
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
			Neighbors: []*ports.NeighborhoodNode{
				{URN: "urn:cerebro:writer:aws_public_principal:public_internet", EntityType: "aws.public_principal", Label: "public internet"},
				{URN: "urn:cerebro:writer:finding:cloud-public-prod-secrets", EntityType: "finding", Label: "cloud-public-prod-secrets"},
				{URN: "urn:cerebro:writer:action:block-public-prod-secrets", EntityType: "workflow_action", Label: "block public access"},
			},
			Relations: []*ports.NeighborhoodRelation{
				{FromURN: "urn:cerebro:writer:aws_public_principal:public_internet", Relation: "can_reach", ToURN: "urn:cerebro:writer:aws_secret_store:prod-secrets"},
				{FromURN: "urn:cerebro:writer:aws_secret_store:prod-secrets", Relation: "has_finding", ToURN: "urn:cerebro:writer:finding:cloud-public-prod-secrets"},
				{FromURN: "urn:cerebro:writer:action:block-public-prod-secrets", Relation: "completed_action", ToURN: "urn:cerebro:writer:aws_secret_store:prod-secrets", Attributes: map[string]string{"outcome": "resolved"}},
			},
		},
		"urn:cerebro:writer:github_repository:payments-api": {
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:github_repository:payments-api", EntityType: "github.repository", Label: "payments-api"},
		},
	}

	plan := Analyze(findings, Options{
		TenantID:           "writer",
		RuntimeIDs:         []string{"writer-aws", "writer-github"},
		CandidateLimit:     2,
		GraphNeighborhoods: graphNeighborhoods,
		Now:                now,
	})

	if plan.ModelVersion != ModelVersion {
		t.Fatalf("ModelVersion = %q, want %q", plan.ModelVersion, ModelVersion)
	}
	if plan.TotalFindings != 2 || plan.TotalCandidates != 2 || plan.SimulatedCandidateCount != 2 {
		t.Fatalf("plan counts = %#v, want two simulated candidates", plan)
	}
	top := plan.ActionCandidates[0]
	if top.ScenarioType != findinganalysis.RiskDeltaScenarioRemovePublicExposure {
		t.Fatalf("top scenario = %q, want remove public exposure", top.ScenarioType)
	}
	if top.TargetURN != "urn:cerebro:writer:aws_secret_store:prod-secrets" {
		t.Fatalf("top target = %q, want prod secrets", top.TargetURN)
	}
	if top.PriorityScore != top.ScoreBreakdown.Total || top.ScoreBreakdown.AttackPathCountReductionPoints <= 0 {
		t.Fatalf("score breakdown = %#v, priority = %d, want auditable attack-path contribution", top.ScoreBreakdown, top.PriorityScore)
	}
	if top.ExpectedReduction.RiskScore != top.ExpectedRiskScoreReduction || top.ExpectedAttackPathScoreReduction <= 0 {
		t.Fatalf("expected reduction = %#v, legacy reduction = %d", top.ExpectedReduction, top.ExpectedRiskScoreReduction)
	}
	if top.Ownership.Owner != "cloud-platform" || top.Owner != "cloud-platform" || top.Ownership.Missing {
		t.Fatalf("ownership = %#v, owner = %q, want cloud-platform", top.Ownership, top.Owner)
	}
	if top.Effort.Level == "" || !top.Effort.ApprovalRequired {
		t.Fatalf("effort = %#v, want explicit approval-aware estimate", top.Effort)
	}
	if top.Evidence.Status != "ready" || top.Evidence.Freshness != "current" {
		t.Fatalf("evidence = %#v, want current ready evidence", top.Evidence)
	}
	if top.OutcomeLearning.Status != "learned_from_prior_outcomes" || top.OutcomeLearning.PositiveOutcomeCount == 0 {
		t.Fatalf("outcome learning = %#v, want learned positive outcome", top.OutcomeLearning)
	}
	var payments Candidate
	for _, candidate := range plan.ActionCandidates {
		if candidate.TargetURN == "urn:cerebro:writer:github_repository:payments-api" {
			payments = candidate
			break
		}
	}
	if payments.ID == "" {
		t.Fatalf("action candidates = %#v, want payments-api candidate", plan.ActionCandidates)
	}
	if payments.OutcomeLearning.Status != "no_prior_outcomes" || payments.OutcomeLearning.PriorActionCount != 0 || payments.OutcomeLearning.PositiveOutcomeCount != 0 {
		t.Fatalf("payments outcome learning = %#v, want no leaked prior outcomes", payments.OutcomeLearning)
	}
}

func TestOutcomeLearningDeduplicatesMirroredRelations(t *testing.T) {
	targetURN := "urn:cerebro:writer:service:payments"
	actionURN := "urn:cerebro:writer:workflow_action:patch-payments"
	relation := &ports.NeighborhoodRelation{
		FromURN:    actionURN,
		Relation:   "completed_action",
		ToURN:      targetURN,
		Attributes: map[string]string{"outcome": "resolved"},
	}
	neighborhoods := map[string]*ports.EntityNeighborhood{
		targetURN: {
			Root: &ports.NeighborhoodNode{URN: targetURN, EntityType: "service", Label: "payments"},
			Relations: []*ports.NeighborhoodRelation{
				relation,
			},
		},
		actionURN: {
			Root: &ports.NeighborhoodNode{URN: actionURN, EntityType: "workflow_action", Label: "patch payments"},
			Relations: []*ports.NeighborhoodRelation{
				{
					FromURN:    " " + actionURN + " ",
					Relation:   " completed_action ",
					ToURN:      " " + targetURN + " ",
					Attributes: map[string]string{"outcome": "resolved"},
				},
			},
		},
	}

	learning := outcomeLearningForTarget(targetURN, neighborhoods)

	if learning.PositiveOutcomeCount != 1 {
		t.Fatalf("PositiveOutcomeCount = %d, want mirrored relations counted once", learning.PositiveOutcomeCount)
	}
	if learning.NegativeOutcomeCount != 0 || learning.PriorityAdjustment != 10 {
		t.Fatalf("outcome learning = %#v, want one positive outcome adjustment", learning)
	}
}

func TestAnalyzeDeduplicatesStoredAndRecomputedRiskFactorsPerFinding(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	plan := Analyze([]*ports.FindingRecord{{
		ID:           "cloud-public-prod-secrets",
		TenantID:     "writer",
		RuntimeID:    "writer-aws",
		RuleID:       "cloud-public-resource-exposure",
		Title:        "Cloud Public Resource Exposure",
		Severity:     "HIGH",
		Status:       "open",
		ResourceURNs: []string{"urn:cerebro:writer:aws_secret_store:prod-secrets"},
		FindingRisk: ports.FindingRisk{
			RiskScore:       90,
			ConfidenceScore: 92,
			RiskReasons:     []string{"external_exposure"},
			RiskFactors: []ports.FindingRiskFactor{
				{FactorID: "external_exposure", Category: "likelihood", Weight: 35, SeverityContribution: "high", EvidenceRefs: []string{"attribute:internet_exposed"}},
			},
		},
		Attributes: map[string]string{
			"action":               "public_network_ingress",
			"internet_exposed":     "true",
			"primary_resource_urn": "urn:cerebro:writer:aws_secret_store:prod-secrets",
			"resource_name":        "prod-secrets",
		},
		LastObservedAt: now.Add(-2 * time.Hour),
	}}, Options{
		TenantID:   "writer",
		RuntimeIDs: []string{"writer-aws"},
		Now:        now,
	})

	if len(plan.ActionCandidates) == 0 {
		t.Fatalf("ActionCandidates = nil, want public exposure candidate")
	}
	factors := plan.ActionCandidates[0].RiskFactors
	for _, factor := range factors {
		if factor.FactorID != "external_exposure" {
			continue
		}
		if factor.Count != 1 || factor.WeightTotal != 35 {
			t.Fatalf("external_exposure factor = %#v, want one contribution from the finding", factor)
		}
		return
	}
	t.Fatalf("risk factors = %#v, want external_exposure factor", factors)
}

func TestAddRiskFactorCountsUniqueEvidenceRefs(t *testing.T) {
	seed := newAggregatedSeed("candidate", CandidateSeed{})
	seed.addRiskFactor(ports.FindingRiskFactor{
		FactorID:     "external_exposure",
		EvidenceRefs: []string{"attribute:internet_exposed", " attribute:internet_exposed ", "attribute:public"},
	})

	if seed.EvidenceRefCount != 2 {
		t.Fatalf("EvidenceRefCount = %d, want 2 unique evidence refs", seed.EvidenceRefCount)
	}
	factor := seed.RiskFactors["external_exposure"]
	if factor == nil || len(factor.EvidenceRefs) != 2 {
		t.Fatalf("factor evidence refs = %#v, want two unique refs", factor)
	}
}

func TestAnalyzeCanIncludeUnscoredPlanningBlockers(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	plan := Analyze([]*ports.FindingRecord{{
		ID:           "ownerless-control-gap",
		TenantID:     "writer",
		RuntimeID:    "writer-grc",
		RuleID:       "control-owner-missing",
		Title:        "High risk control gap",
		Status:       "open",
		ResourceURNs: []string{"urn:cerebro:writer:service:payments"},
		FindingRisk: ports.FindingRisk{
			RiskScore:       82,
			ConfidenceScore: 42,
			RiskReasons:     []string{"crown_jewel"},
		},
		Attributes: map[string]string{
			"primary_resource_urn": "urn:cerebro:writer:service:payments",
			"resource_name":        "payments",
		},
		LastObservedAt: now.Add(-45 * 24 * time.Hour),
	}}, Options{
		TenantID:        "writer",
		RuntimeIDs:      []string{"writer-grc"},
		IncludeUnscored: true,
		Now:             now,
	})

	if plan.SimulatedCandidateCount != 0 || plan.UnscoredCandidateCount != 2 {
		t.Fatalf("candidate counts = simulated %d unscored %d, want two unscored blockers", plan.SimulatedCandidateCount, plan.UnscoredCandidateCount)
	}
	byType := map[string]Candidate{}
	for _, candidate := range plan.ActionCandidates {
		byType[candidate.ActionType] = candidate
		if candidate.SimulationStatus != SimulationStatusUnsupported {
			t.Fatalf("candidate %s status = %q, want unsupported", candidate.ActionType, candidate.SimulationStatus)
		}
		if candidate.ScoreBreakdown.SimulationPenaltyPoints == 0 {
			t.Fatalf("candidate %s score breakdown = %#v, want simulation penalty", candidate.ActionType, candidate.ScoreBreakdown)
		}
	}
	if owner := byType[ActionTypeAssignOwner]; !owner.Ownership.Missing || owner.Effort.PrimaryConstraint != "routing" {
		t.Fatalf("assign owner candidate = %#v, want missing ownership routing blocker", owner)
	}
	if evidence := byType[ActionTypeRefreshEvidence]; evidence.Evidence.Status != "limited" || evidence.Evidence.Freshness != "stale" {
		t.Fatalf("refresh evidence candidate = %#v, want limited stale evidence", evidence)
	}
}

func TestAnalyzeCredentialGovernanceActionsPreferRecentPrivilegedUse(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	recentCredentialURN := "urn:cerebro:writer:openai_credential:admin-runtime"     // #nosec G101 -- test credential identifier, not credential material.
	staleCredentialURN := "urn:cerebro:writer:anthropic_credential:analytics-stale" // #nosec G101 -- test credential identifier, not credential material.
	plan := Analyze([]*ports.FindingRecord{
		{
			ID:           "openai-admin-runtime",
			TenantID:     "writer",
			RuntimeID:    "writer-openai",
			RuleID:       "openai-orphaned-privileged-api-key",
			Title:        "OpenAI Orphaned Privileged API Key",
			Severity:     "HIGH",
			Status:       "open",
			ResourceURNs: []string{recentCredentialURN},
			EventIDs:     []string{"evt-openai-admin-runtime"},
			FindingRisk: ports.FindingRisk{
				RiskScore:       88,
				ConfidenceScore: 92,
				RiskReasons:     []string{"privileged_actor", "active_threat"},
			},
			Attributes: map[string]string{
				"credential_use":        "true",
				"has_owner":             "false",
				"last_used_at":          now.Add(-2 * time.Hour).Format(time.RFC3339),
				"name":                  "admin-runtime",
				"openai_credential_urn": recentCredentialURN,
				"primary_resource_urn":  recentCredentialURN,
				"privileged":            "true",
				"status":                "active",
			},
			LastObservedAt: now.Add(-2 * time.Hour),
		},
		{
			ID:           "anthropic-stale-runtime",
			TenantID:     "writer",
			RuntimeID:    "writer-anthropic",
			RuleID:       "anthropic-unmanaged-active-api-key",
			Title:        "Anthropic Unmanaged Active API Key",
			Severity:     "MEDIUM",
			Status:       "open",
			ResourceURNs: []string{staleCredentialURN},
			EventIDs:     []string{"evt-anthropic-stale-runtime"},
			FindingRisk: ports.FindingRisk{
				RiskScore:       62,
				ConfidenceScore: 84,
				RiskReasons:     []string{"active"},
			},
			Attributes: map[string]string{
				"anthropic_credential_urn": staleCredentialURN,
				"has_owner":                "false",
				"last_used_at":             now.Add(-120 * 24 * time.Hour).Format(time.RFC3339),
				"name":                     "analytics-stale",
				"primary_resource_urn":     staleCredentialURN,
				"status":                   "active",
			},
			LastObservedAt: now.Add(-48 * time.Hour),
		},
	}, Options{
		TenantID:        "writer",
		RuntimeIDs:      []string{"writer-openai", "writer-anthropic"},
		IncludeUnscored: true,
		Now:             now,
	})

	if len(plan.ActionCandidates) == 0 {
		t.Fatalf("ActionCandidates = nil, want credential governance candidates")
	}
	top := plan.ActionCandidates[0]
	if top.ActionType != ActionTypeRotateCredential || top.TargetURN != recentCredentialURN {
		t.Fatalf("top candidate = %#v, want rotate recent privileged credential", top)
	}
	if top.SimulationStatus != SimulationStatusSimulated || top.ExpectedRiskScoreReduction <= 0 {
		t.Fatalf("top simulation = %q reduction = %d, want simulated risk reduction", top.SimulationStatus, top.ExpectedRiskScoreReduction)
	}
	if top.Effort.PrimaryConstraint != "access_review" || !top.Effort.ApprovalRequired {
		t.Fatalf("top effort = %#v, want approval-aware credential rotation", top.Effort)
	}
	byActionTarget := map[string]Candidate{}
	for _, candidate := range plan.ActionCandidates {
		byActionTarget[candidate.ActionType+"|"+candidate.TargetURN] = candidate
		if candidate.ActionType == findinganalysis.RiskDeltaScenarioRemovePrivilege && candidate.TargetURN == recentCredentialURN {
			t.Fatalf("generic privilege candidate duplicated credential rotation: %#v", candidate)
		}
	}
	stale := byActionTarget[ActionTypeRevokeCredential+"|"+staleCredentialURN]
	if stale.ID == "" {
		t.Fatalf("action candidates = %#v, want stale credential revoke recommendation", plan.ActionCandidates)
	}
	if stale.SimulationStatus != SimulationStatusUnsupported || stale.Effort.PrimaryConstraint != "usage_validation" {
		t.Fatalf("stale credential candidate = %#v, want usage-validation recommendation", stale)
	}
	if top.PriorityScore <= stale.PriorityScore {
		t.Fatalf("priority scores top=%d stale=%d, want recent privileged use ranked higher", top.PriorityScore, stale.PriorityScore)
	}
}

func TestCompareCandidatesRanksNonSimulatedStatusesByScore(t *testing.T) {
	unsupportedHigh := diffTestCandidate("unsupported-high", "Unsupported high", 100, 0, 0, SimulationStatusUnsupported)
	noReductionLow := diffTestCandidate("no-reduction-low", "No reduction low", 10, 0, 0, SimulationStatusNoExpectedRisk)
	unsupportedMid := diffTestCandidate("unsupported-mid", "Unsupported mid", 50, 0, 0, SimulationStatusUnsupported)
	simulatedLow := diffTestCandidate("simulated-low", "Simulated low", 1, 0, 0, SimulationStatusSimulated)

	if got := compareCandidates(unsupportedHigh, noReductionLow); got >= 0 {
		t.Fatalf("compareCandidates(high unsupported, low no-reduction) = %d, want high priority first", got)
	}
	if got := compareCandidates(noReductionLow, unsupportedMid); got <= 0 {
		t.Fatalf("compareCandidates(low no-reduction, mid unsupported) = %d, want priority tie-breaker across non-simulated statuses", got)
	}
	if got := compareCandidates(simulatedLow, unsupportedHigh); got >= 0 {
		t.Fatalf("compareCandidates(simulated, unsupported) = %d, want simulated first", got)
	}
}

func TestDiffCandidatesReportsAddedRemovedAndChanged(t *testing.T) {
	diff := DiffCandidates(
		[]Candidate{
			diffTestCandidate("a", "A", 100, 5, 1, SimulationStatusSimulated),
			diffTestCandidate("c", "C", 70, 0, 0, ""),
		},
		[]Candidate{
			diffTestCandidate("a", "A", 115, 8, 2, SimulationStatusSimulated),
			diffTestCandidate("b", "B", 20, 0, 0, ""),
		},
	)

	if len(diff.Added) != 1 || diff.Added[0].ID != "b" || diff.Added[0].ChangeType != "added" {
		t.Fatalf("added diff = %#v, want b added", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0].ID != "c" || diff.Removed[0].ChangeType != "removed" {
		t.Fatalf("removed diff = %#v, want c removed", diff.Removed)
	}
	if len(diff.Changed) != 1 || diff.Changed[0].ID != "a" || diff.Changed[0].PriorityScoreDelta != 15 || diff.Changed[0].ExpectedRiskScoreReductionDelta != 3 {
		t.Fatalf("changed diff = %#v, want a changed with deltas", diff.Changed)
	}
	if diff.UnchangedCount != 0 {
		t.Fatalf("UnchangedCount = %d, want 0", diff.UnchangedCount)
	}
}

func diffTestCandidate(id string, title string, priorityScore int, riskReduction int, pathCountReduction int, simulationStatus string) Candidate {
	return Candidate{
		CandidateIdentity: CandidateIdentity{
			ID:               id,
			Title:            title,
			SimulationStatus: simulationStatus,
		},
		CandidateScoring: CandidateScoring{
			PriorityScore:                    priorityScore,
			ExpectedRiskScoreReduction:       riskReduction,
			ExpectedAttackPathCountReduction: pathCountReduction,
		},
	}
}
