package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceimprovement"
)

var demoNow = time.Date(2026, 7, 16, 18, 0, 0, 0, time.UTC)

type demoVerifier struct{}

func (demoVerifier) VerifyInputRevisions(context.Context, string, []complianceimprovement.InputRevision) ([]complianceimprovement.VerificationResult, error) {
	return []complianceimprovement.VerificationResult{{
		VerifierID: "exact-input-revisions", Status: complianceimprovement.VerificationPass,
		Message: "All program, assessment, and source revisions still match.",
	}}, nil
}

func (demoVerifier) VerifyRepositoryChange(context.Context, complianceimprovement.RepositoryPatch) ([]complianceimprovement.VerificationResult, error) {
	return []complianceimprovement.VerificationResult{{
		VerifierID: "repository-data-policy", Status: complianceimprovement.VerificationPass,
		Message: "The bounded patch contains no private program data or secrets.",
	}}, nil
}

type demoPublisher struct {
	request complianceimprovement.OpenDraftPullRequestRequest
}

func (publisher *demoPublisher) OpenDraftPullRequest(_ context.Context, request complianceimprovement.OpenDraftPullRequestRequest) (complianceimprovement.DraftPullRequestReceipt, error) {
	publisher.request = request
	return complianceimprovement.DraftPullRequestReceipt{
		Repository: request.Repository, Number: 101, URL: "https://github.example/compliance/program/pull/101",
		HeadCommitSHA: strings.Repeat("c", 40), BaseCommitSHA: request.BaseCommitSHA,
		Draft: true, ProposalDigest: request.ProposalDigest, OpenedAt: demoNow,
	}, nil
}

type demoOutbox struct {
	update complianceimprovement.TeamUpdate
}

func (outbox *demoOutbox) EnqueueTeamUpdate(_ context.Context, _, _ string, update complianceimprovement.TeamUpdate) (complianceimprovement.TeamUpdateReceipt, error) {
	outbox.update = update
	return complianceimprovement.TeamUpdateReceipt{OutboxID: "team-update-101", ProposalDigest: update.ProposalDigest, QueuedAt: demoNow}, nil
}

type demoResult struct {
	CustomerOutcome  string          `json:"customer_outcome"`
	UncitedResearch  gateResult      `json:"uncited_research"`
	ScopeWeakening   gateResult      `json:"scope_weakening"`
	ValidatedChange  validatedResult `json:"validated_change"`
	DraftPullRequest draftResult     `json:"draft_pull_request"`
	TeamUpdate       teamResult      `json:"team_update"`
}

type gateResult struct {
	Blocked    bool   `json:"blocked"`
	StateAfter string `json:"state_after"`
	Reason     string `json:"reason"`
}

type validatedResult struct {
	CurrentValue float64 `json:"current_value"`
	TargetValue  float64 `json:"target_value"`
	Unit         string  `json:"unit"`
	Guardrail    string  `json:"guardrail"`
	ChecksPassed int     `json:"checks_passed"`
}

type draftResult struct {
	State           string `json:"state"`
	URL             string `json:"url"`
	Draft           bool   `json:"draft"`
	MergeCapability bool   `json:"merge_capability"`
}

type teamResult struct {
	Queued          bool   `json:"queued"`
	DecisionOwner   string `json:"decision_owner"`
	RequiredAction  string `json:"required_action"`
	SupportingFacts int    `json:"supporting_facts"`
	Counterevidence int    `json:"counterevidence"`
	Unknowns        int    `json:"unknowns"`
}

func main() {
	result, err := runDemo(context.Background())
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runDemo(ctx context.Context) (demoResult, error) {
	publisher := &demoPublisher{}
	outbox := &demoOutbox{}
	service := complianceimprovement.New(complianceimprovement.NewMemoryStore(), demoVerifier{}, demoVerifier{}, publisher, outbox)
	detected, _, err := service.Detect(ctx, complianceimprovement.DetectRequest{
		TenantID: "demo-tenant", ProgramID: "access-review-program", DecisionOwner: "grc-team-owner",
		IdempotencyKey: "incomplete-quarterly-access-evidence", ActorID: "compliance-refiner",
		Inputs: []complianceimprovement.InputRevision{{Kind: "program_scope", Ref: demoRevision("scope", "scope-r7", "a")}},
		Gap: complianceimprovement.ProgramGap{
			Kind: "evidence_coverage", Summary: "Quarterly privileged-access review evidence does not cover the full in-scope population.",
			Current:    complianceimprovement.Measurement{Name: "evidence_coverage", Value: 60, Unit: "percent"},
			Target:     complianceimprovement.TargetMeasurement{Name: "evidence_coverage", Comparator: ">=", Value: 95, Unit: "percent"},
			Guardrails: []complianceimprovement.Guardrail{{Name: "in_scope_subjects", Comparator: ">=", Value: 100, Unit: "count"}},
			DetectedBy: "compliance-refiner", DetectedAt: demoNow,
		},
	})
	if err != nil {
		return demoResult{}, err
	}
	uncited := demoResearch()
	uncited.Claims[0].CitationIDs = nil
	_, uncitedErr := service.RecordResearch(ctx, detected.Run.TenantID, detected.Run.ID, complianceimprovement.ResearchRequest{
		ExpectedVersion: detected.Run.AggregateVersion, Research: uncited, ActorID: "compliance-researcher",
	})
	if !errors.Is(uncitedErr, complianceimprovement.ErrVerification) {
		return demoResult{}, fmt.Errorf("uncited research was not blocked: %w", uncitedErr)
	}
	afterUncited, err := service.Get(ctx, detected.Run.TenantID, detected.Run.ID)
	if err != nil {
		return demoResult{}, err
	}
	researched, err := service.RecordResearch(ctx, detected.Run.TenantID, detected.Run.ID, complianceimprovement.ResearchRequest{
		ExpectedVersion: detected.Run.AggregateVersion, Research: demoResearch(), ActorID: "compliance-researcher",
	})
	if err != nil {
		return demoResult{}, err
	}
	weakening, err := service.Propose(ctx, researched.Run.TenantID, researched.Run.ID, complianceimprovement.ProposeRequest{
		ExpectedVersion: researched.Run.AggregateVersion, ActorID: "compliance-author",
		Impact: complianceimprovement.ExpectedProgramImpact{ScopeSubjectsRemoved: 40, ExpectedBenefit: "Raise readiness by excluding subjects without evidence."},
		Patch:  demoPatch(),
	})
	if err != nil {
		return demoResult{}, err
	}
	weakening, weakeningErr := service.Validate(ctx, weakening.Run.TenantID, weakening.Run.ID, complianceimprovement.ValidateRequest{
		ExpectedVersion: weakening.Run.AggregateVersion, ActorID: "compliance-verifier",
	})
	if !errors.Is(weakeningErr, complianceimprovement.ErrVerification) {
		return demoResult{}, fmt.Errorf("scope weakening was not blocked: %w", weakeningErr)
	}
	proposed, err := service.Propose(ctx, weakening.Run.TenantID, weakening.Run.ID, complianceimprovement.ProposeRequest{
		ExpectedVersion: weakening.Run.AggregateVersion, ActorID: "compliance-author",
		Impact: complianceimprovement.ExpectedProgramImpact{ExpectedBenefit: "Increase evidence coverage from 60 percent to at least 95 percent without reducing scope."},
		Patch:  demoPatch(),
	})
	if err != nil {
		return demoResult{}, err
	}
	validated, err := service.Validate(ctx, proposed.Run.TenantID, proposed.Run.ID, complianceimprovement.ValidateRequest{
		ExpectedVersion: proposed.Run.AggregateVersion, ActorID: "compliance-verifier",
	})
	if err != nil {
		return demoResult{}, err
	}
	published, err := service.PublishDraft(ctx, validated.Run.TenantID, validated.Run.ID, complianceimprovement.PublishDraftRequest{
		ExpectedVersion: validated.Run.AggregateVersion, ActorID: "compliance-draft-publisher",
	})
	if err != nil {
		return demoResult{}, err
	}
	passingChecks := 0
	for _, check := range validated.Revision.Proposal.Verification.Results {
		if check.Status == complianceimprovement.VerificationPass {
			passingChecks++
		}
	}
	return demoResult{
		CustomerOutcome: "A measured program gap became a cited, verified draft change and a team decision record without changing the active program.",
		UncitedResearch: gateResult{Blocked: true, StateAfter: afterUncited.Run.State, Reason: "Every claim needs a source citation."},
		ScopeWeakening:  gateResult{Blocked: true, StateAfter: weakening.Run.State, Reason: "Removing in-scope subjects cannot use the automated path."},
		ValidatedChange: validatedResult{
			CurrentValue: validated.Revision.Proposal.Gap.Current.Value, TargetValue: validated.Revision.Proposal.Gap.Target.Value,
			Unit: validated.Revision.Proposal.Gap.Target.Unit, Guardrail: "In-scope subject count cannot decrease.", ChecksPassed: passingChecks,
		},
		DraftPullRequest: draftResult{
			State: published.Run.State, URL: published.Revision.Proposal.DraftPullRequest.URL,
			Draft: publisher.request.Draft, MergeCapability: false,
		},
		TeamUpdate: teamResult{
			Queued: outbox.update.ProposalDigest != "", DecisionOwner: outbox.update.DecisionOwner,
			RequiredAction: outbox.update.RequiredAction, SupportingFacts: len(outbox.update.Supporting),
			Counterevidence: len(outbox.update.Counterevidence), Unknowns: len(outbox.update.Unknowns),
		},
	}, nil
}

func demoResearch() complianceimprovement.ResearchPacket {
	return complianceimprovement.ResearchPacket{
		Claims: []complianceimprovement.ResearchClaim{{
			ID: "coverage-gap", Statement: "The current review evidence omits part of the in-scope population.", CitationIDs: []string{"assessment-result"},
		}},
		Counterevidence: []complianceimprovement.ResearchClaim{{
			ID: "recent-period-current", Statement: "The latest interval has current evidence.", CitationIDs: []string{"assessment-result"},
		}},
		Citations: []complianceimprovement.Citation{{
			ID: "assessment-result", SourceURN: "urn:cerebro:demo:assessment-result:coverage-gap",
			SnapshotRevision: demoRevision("assessment-result", "assessment-result-r3", "d"), CapturedAt: demoNow.Add(-time.Hour), ExpiresAt: demoNow.Add(24 * time.Hour),
		}},
		Unknowns:     []string{"Whether an additional source covers the earlier interval."},
		ResearchedBy: "compliance-researcher", ResearchedAt: demoNow,
	}
}

func demoPatch() complianceimprovement.RepositoryPatch {
	return complianceimprovement.RepositoryPatch{
		Repository: "example/compliance-program", BaseBranch: "main", BaseCommitSHA: strings.Repeat("b", 40),
		ProposalBranch: "cerebro/improvement/access-review-evidence", ChangeKind: complianceimprovement.ChangeKindAssessmentTest,
		Changes: []complianceimprovement.FileChange{{
			Path: "controls/access_review/evidence_test.yaml", Operation: complianceimprovement.FileOperationUpdate,
			Content: "minimum_coverage_percent: 95\nrequire_full_period: true\n",
		}},
		ValidationSteps: []string{"Run the access-review assessment fixtures."}, RollbackSteps: []string{"Revert the proposal commit."},
	}
}

func demoRevision(id, revisionID, digestCharacter string) compliance.RevisionRef {
	return compliance.RevisionRef{
		ID: id, RevisionID: revisionID, Version: 1,
		ContentDigest: compliance.ContentDigest("sha256:" + strings.Repeat(digestCharacter, 64)), LastModified: demoNow.Add(-time.Hour),
	}
}
