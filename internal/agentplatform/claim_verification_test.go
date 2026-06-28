package agentplatform

import "testing"

func TestBuildClaimVerificationGatesWeakClaims(t *testing.T) {
	verification := BuildClaimVerification(ClaimVerificationRequest{
		TenantID:               "tenant-1",
		ActorID:                "analyst-1",
		Claim:                  "This finding is exploitable through a public endpoint.",
		ClaimType:              "exposure",
		ScopeURN:               "urn:cerebro:tenant-1:finding:finding-1",
		SupportingEvidenceURNs: []string{"urn:cerebro:tenant-1:evidence:evidence-1"},
		MissingEvidence:        []string{"fresh identity graph"},
		FreshnessState:         "stale",
		RequestedActionStage:   ActionStageDryRun,
		CoverageContext: &AgentCoverageContext{
			Version:        ContractVersion,
			TenantID:       "tenant-1",
			BlindSpotCount: 1,
			StaleCount:     1,
		},
	})

	if verification.Verdict != ClaimVerdictWeaklySupported {
		t.Fatalf("verdict = %q, want weakly_supported", verification.Verdict)
	}
	if verification.AllowedNextStage != ActionStageExplain {
		t.Fatalf("allowed_next_stage = %q, want explain", verification.AllowedNextStage)
	}
	if !claimVerificationHasBlocker(verification, "stage_skip") {
		t.Fatalf("blockers = %+v, want stage_skip", verification.Blockers)
	}
	if !claimVerificationHasVerifierStatus(verification, "freshness", "warning") || !claimVerificationHasVerifierStatus(verification, "coverage", "warning") {
		t.Fatalf("verifier results = %+v, want freshness and coverage warnings", verification.VerifierResults)
	}
	if len(verification.SupportingEvidence) != 1 || verification.SupportingEvidence[0].CitationStatus != "required" {
		t.Fatalf("supporting evidence = %+v", verification.SupportingEvidence)
	}

	unrecognizedFreshness := BuildClaimVerification(ClaimVerificationRequest{
		TenantID:               "tenant-1",
		Claim:                  "This claim has evidence but an unrecognized freshness state.",
		ScopeURN:               "urn:cerebro:tenant-1:finding:finding-1",
		SupportingEvidenceURNs: []string{"urn:cerebro:tenant-1:evidence:evidence-1"},
		FreshnessState:         "maybe",
	})
	if unrecognizedFreshness.Verdict != ClaimVerdictWeaklySupported || !claimVerificationHasVerifierStatus(unrecognizedFreshness, "freshness", "warning") {
		t.Fatalf("unrecognized freshness verification = %+v, want weak verdict with freshness warning", unrecognizedFreshness)
	}
}

func TestBuildClaimVerificationBlocksCounterevidenceAndPrefersTenantScope(t *testing.T) {
	verification := BuildClaimVerification(ClaimVerificationRequest{
		TenantID:               "tenant-1",
		Claim:                  "This finding can be resolved.",
		ScopeURN:               "urn:cerebro:other:finding:finding-1",
		SupportingEvidenceURNs: []string{"urn:cerebro:tenant-1:evidence:evidence-1"},
		CounterEvidenceURNs:    []string{"urn:cerebro:tenant-1:evidence:evidence-2"},
		FreshnessState:         "fresh",
		RequestedActionStage:   ActionStageRecommend,
	})

	if verification.Verdict != ClaimVerdictUnknown {
		t.Fatalf("verdict = %q, want unknown", verification.Verdict)
	}
	if !claimVerificationHasBlocker(verification, "tenant-scope") || !claimVerificationHasBlocker(verification, "counterevidence") {
		t.Fatalf("blockers = %+v, want tenant-scope and counterevidence", verification.Blockers)
	}
	if verification.AllowedNextStage != ActionStageObserve {
		t.Fatalf("allowed_next_stage = %q, want observe", verification.AllowedNextStage)
	}

	counterevidenceOnly := BuildClaimVerification(ClaimVerificationRequest{
		TenantID:               "tenant-1",
		Claim:                  "This finding can be resolved.",
		ScopeURN:               "urn:cerebro:tenant-1:finding:finding-1",
		SupportingEvidenceURNs: []string{"urn:cerebro:tenant-1:evidence:evidence-1"},
		CounterEvidenceURNs:    []string{"urn:cerebro:tenant-1:evidence:evidence-2"},
		FreshnessState:         "fresh",
		RequestedActionStage:   ActionStageExplain,
	})
	if counterevidenceOnly.Verdict != ClaimVerdictContradicted {
		t.Fatalf("counterevidence verdict = %q, want contradicted", counterevidenceOnly.Verdict)
	}
	if counterevidenceOnly.AllowedNextStage != ActionStageObserve {
		t.Fatalf("counterevidence allowed_next_stage = %q, want observe", counterevidenceOnly.AllowedNextStage)
	}
	if !claimVerificationHasBlocker(counterevidenceOnly, "stage_skip") {
		t.Fatalf("counterevidence blockers = %+v, want stage_skip", counterevidenceOnly.Blockers)
	}

	crossTenantOnly := BuildClaimVerification(ClaimVerificationRequest{
		TenantID:               "tenant-1",
		Claim:                  "This finding can be resolved.",
		ScopeURN:               "urn:cerebro:other:finding:finding-1",
		SupportingEvidenceURNs: []string{"urn:cerebro:tenant-1:evidence:evidence-1"},
		FreshnessState:         "fresh",
		RequestedActionStage:   ActionStageRecommend,
	})
	if crossTenantOnly.Verdict != ClaimVerdictUnknown {
		t.Fatalf("cross-tenant verdict = %q, want unknown", crossTenantOnly.Verdict)
	}
	if !claimVerificationHasBlocker(crossTenantOnly, "tenant-scope") {
		t.Fatalf("cross-tenant blockers = %+v, want tenant-scope", crossTenantOnly.Blockers)
	}
}

func TestBuildClaimVerificationApprovalFollowsMutatingActionStages(t *testing.T) {
	for _, stage := range []string{ActionStageVerify, ActionStageCloseLoop} {
		t.Run(stage, func(t *testing.T) {
			verification := BuildClaimVerification(ClaimVerificationRequest{
				TenantID:               "tenant-1",
				Claim:                  "This finding has verified evidence.",
				ScopeURN:               "urn:cerebro:tenant-1:finding:finding-1",
				SupportingEvidenceURNs: []string{"urn:cerebro:tenant-1:evidence:evidence-1"},
				FreshnessState:         "fresh",
				RequestedActionStage:   stage,
				CoverageContext: &AgentCoverageContext{
					Version:  ContractVersion,
					TenantID: "tenant-1",
				},
			})

			if !claimVerificationHasBlocker(verification, "stage_skip") {
				t.Fatalf("blockers = %+v, want stage_skip", verification.Blockers)
			}
			if claimVerificationHasBlocker(verification, "unapproved_mutation") {
				t.Fatalf("blockers = %+v, did not want unapproved_mutation for read-only stage %q", verification.Blockers, stage)
			}
		})
	}

	execute := BuildClaimVerification(ClaimVerificationRequest{
		TenantID:               "tenant-1",
		Claim:                  "This finding has verified evidence.",
		ScopeURN:               "urn:cerebro:tenant-1:finding:finding-1",
		SupportingEvidenceURNs: []string{"urn:cerebro:tenant-1:evidence:evidence-1"},
		FreshnessState:         "fresh",
		RequestedActionStage:   ActionStageExecute,
		CoverageContext: &AgentCoverageContext{
			Version:  ContractVersion,
			TenantID: "tenant-1",
		},
	})
	if !claimVerificationHasBlocker(execute, "unapproved_mutation") {
		t.Fatalf("execute blockers = %+v, want unapproved_mutation", execute.Blockers)
	}
}

func TestClaimVerificationAndAgentWorkContractsAreInControlPlane(t *testing.T) {
	snapshot := SecurityControlPlaneSnapshot()
	if snapshot.ClaimVerification.ID != "agent-claim-verification" {
		t.Fatalf("claim verification contract = %+v", snapshot.ClaimVerification)
	}
	if snapshot.AgentWork.ID != "agent-work-ledger" {
		t.Fatalf("agent work contract = %+v", snapshot.AgentWork)
	}
	for _, required := range []string{"claim", "verdict", "allowed_next_stage"} {
		if !containsString(snapshot.ClaimVerification.RequiredFields, required) {
			t.Fatalf("claim verification missing required field %q: %+v", required, snapshot.ClaimVerification.RequiredFields)
		}
	}
	for _, required := range []string{"work_id", "claim_ids", "closure_reason"} {
		if !containsString(snapshot.AgentWork.RequiredFields, required) {
			t.Fatalf("agent work missing required field %q: %+v", required, snapshot.AgentWork.RequiredFields)
		}
	}
}

func claimVerificationHasBlocker(verification ClaimVerification, code string) bool {
	for _, blocker := range verification.Blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}

func claimVerificationHasVerifierStatus(verification ClaimVerification, id string, status string) bool {
	for _, result := range verification.VerifierResults {
		if result.ID == id && result.Status == status {
			return true
		}
	}
	return false
}
