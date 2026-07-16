package complianceimprovement

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

var testNow = time.Date(2026, 7, 16, 18, 0, 0, 0, time.UTC)

type testInputVerifier struct {
	results []VerificationResult
	inputs  []InputRevision
}

func (v *testInputVerifier) VerifyInputRevisions(_ context.Context, _ string, inputs []InputRevision) ([]VerificationResult, error) {
	v.inputs = append([]InputRevision(nil), inputs...)
	if v.results != nil {
		return append([]VerificationResult(nil), v.results...), nil
	}
	return []VerificationResult{{VerifierID: "exact-input-revisions", Status: VerificationPass, Message: "All input revisions still match."}}, nil
}

type testRepositoryVerifier struct {
	results []VerificationResult
	patch   RepositoryPatch
}

func (v *testRepositoryVerifier) VerifyRepositoryChange(_ context.Context, patch RepositoryPatch) ([]VerificationResult, error) {
	v.patch = patch
	if v.results != nil {
		return append([]VerificationResult(nil), v.results...), nil
	}
	return []VerificationResult{{VerifierID: "repository-data-policy", Status: VerificationPass, Message: "The patch is safe for the repository."}}, nil
}

type testDraftPublisher struct {
	request OpenDraftPullRequestRequest
	calls   int
	receipt *DraftPullRequestReceipt
}

func (p *testDraftPublisher) OpenDraftPullRequest(_ context.Context, request OpenDraftPullRequestRequest) (DraftPullRequestReceipt, error) {
	p.calls++
	p.request = request
	if p.receipt != nil {
		return *p.receipt, nil
	}
	return DraftPullRequestReceipt{
		Repository: request.Repository, Number: 42, URL: "https://example.invalid/pulls/42",
		HeadCommitSHA: strings.Repeat("c", 40), BaseCommitSHA: request.BaseCommitSHA,
		Draft: true, ProposalDigest: request.ProposalDigest, OpenedAt: testNow,
	}, nil
}

type testTeamOutbox struct {
	update TeamUpdate
	calls  int
}

func (o *testTeamOutbox) EnqueueTeamUpdate(_ context.Context, _, _ string, update TeamUpdate) (TeamUpdateReceipt, error) {
	o.calls++
	o.update = update
	return TeamUpdateReceipt{OutboxID: "outbox-1", ProposalDigest: update.ProposalDigest, QueuedAt: testNow}, nil
}

func TestGovernedImprovementLoopPublishesDraftAndWaitsForHumanDecision(t *testing.T) {
	ctx := context.Background()
	inputVerifier := &testInputVerifier{}
	repositoryVerifier := &testRepositoryVerifier{}
	publisher := &testDraftPublisher{}
	outbox := &testTeamOutbox{}
	service := newTestService(inputVerifier, repositoryVerifier, publisher, outbox)

	record, created, err := service.Detect(ctx, detectedRequest())
	if err != nil || !created {
		t.Fatalf("Detect() = created %t, err %v", created, err)
	}
	initialDigest := record.Revision.Proposal.ContentDigest
	record, err = service.RecordResearch(ctx, record.Run.TenantID, record.Run.ID, ResearchRequest{
		ExpectedVersion: record.Run.AggregateVersion, Research: validResearch(), ActorID: "researcher-agent",
	})
	if err != nil {
		t.Fatalf("RecordResearch() error = %v", err)
	}
	if record.Run.State != StateResearching || record.Revision.Proposal.ContentDigest == initialDigest {
		t.Fatalf("research state/digest = %q/%q", record.Run.State, record.Revision.Proposal.ContentDigest)
	}
	record, err = service.Propose(ctx, record.Run.TenantID, record.Run.ID, ProposeRequest{
		ExpectedVersion: record.Run.AggregateVersion, ActorID: "author-agent",
		Impact: ExpectedProgramImpact{ExpectedBenefit: "Increase current evidence coverage from 60 percent to at least 95 percent without reducing scope."},
		Patch:  validPatch(),
	})
	if err != nil {
		t.Fatalf("Propose() error = %v", err)
	}
	record, err = service.Validate(ctx, record.Run.TenantID, record.Run.ID, ValidateRequest{ExpectedVersion: record.Run.AggregateVersion, ActorID: "verifier-agent"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if record.Run.State != StateValidated || hasBlockingResult(record.Revision.Proposal.Verification.Results) {
		t.Fatalf("validation state/results = %q/%+v", record.Run.State, record.Revision.Proposal.Verification.Results)
	}
	validatedDigest := record.Revision.Proposal.ContentDigest
	if len(inputVerifier.inputs) != 2 {
		t.Fatalf("input verifier saw %d revisions, want program input plus research source", len(inputVerifier.inputs))
	}

	record, err = service.PublishDraft(ctx, record.Run.TenantID, record.Run.ID, PublishDraftRequest{ExpectedVersion: record.Run.AggregateVersion, ActorID: "publisher-agent"})
	if err != nil {
		t.Fatalf("PublishDraft() error = %v", err)
	}
	if record.Run.State != StateDraftPROpened || publisher.calls != 1 || outbox.calls != 1 {
		t.Fatalf("publication state/calls = %q/%d/%d", record.Run.State, publisher.calls, outbox.calls)
	}
	if !publisher.request.Draft {
		t.Fatal("publisher request was not draft")
	}
	if strings.Contains(publisher.request.Title, record.Run.TenantID) || strings.Contains(publisher.request.Body, record.Revision.Proposal.Gap.Summary) {
		t.Fatalf("public metadata contains internal program data: %q\n%s", publisher.request.Title, publisher.request.Body)
	}
	if outbox.update.GapSummary != record.Revision.Proposal.Gap.Summary || outbox.update.DecisionOwner != "grc-owner" {
		t.Fatalf("team update omitted decision context: %+v", outbox.update)
	}
	if record.Revision.Proposal.ContentDigest != validatedDigest {
		t.Fatalf("validated proposal digest changed after publication: got %q want %q", record.Revision.Proposal.ContentDigest, validatedDigest)
	}

	_, err = service.RecordHumanDecision(ctx, record.Run.TenantID, record.Run.ID, DecisionRequest{
		ExpectedVersion: record.Run.AggregateVersion, Decision: DecisionAccept, Rationale: "Reviewed the cited evidence and checks.",
		ActorID: "not-the-owner", ProposalDigest: string(validatedDigest),
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RecordHumanDecision(non-owner) error = %v, want ErrInvalidRequest", err)
	}
	record, err = service.RecordHumanDecision(ctx, record.Run.TenantID, record.Run.ID, DecisionRequest{
		ExpectedVersion: record.Run.AggregateVersion, Decision: DecisionAccept, Rationale: "Reviewed the cited evidence and checks.",
		ActorID: "grc-owner", ProposalDigest: string(validatedDigest),
	})
	if err != nil {
		t.Fatalf("RecordHumanDecision(owner) error = %v", err)
	}
	if record.Run.State != StateAccepted || publisher.calls != 1 {
		t.Fatalf("human decision state/publisher calls = %q/%d", record.Run.State, publisher.calls)
	}
}

func TestResearcherBlocksUncitedClaims(t *testing.T) {
	service := newTestService(&testInputVerifier{}, &testRepositoryVerifier{}, &testDraftPublisher{}, &testTeamOutbox{})
	record, _, err := service.Detect(context.Background(), detectedRequest())
	if err != nil {
		t.Fatal(err)
	}
	research := validResearch()
	research.Claims[0].CitationIDs = nil
	_, err = service.RecordResearch(context.Background(), record.Run.TenantID, record.Run.ID, ResearchRequest{
		ExpectedVersion: record.Run.AggregateVersion, Research: research, ActorID: "researcher-agent",
	})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("RecordResearch() error = %v, want ErrVerification", err)
	}
	current, getErr := service.Get(context.Background(), record.Run.TenantID, record.Run.ID)
	if getErr != nil || current.Run.AggregateVersion != record.Run.AggregateVersion || current.Run.State != StateDetected {
		t.Fatalf("uncited research changed durable state: %+v, err %v", current.Run, getErr)
	}
}

func TestVerifierRecordsAndBlocksScopeWeakening(t *testing.T) {
	publisher := &testDraftPublisher{}
	service := newTestService(&testInputVerifier{}, &testRepositoryVerifier{}, publisher, &testTeamOutbox{})
	record := advanceToProposal(t, service, ExpectedProgramImpact{
		ScopeSubjectsRemoved: 3, ExpectedBenefit: "Raise the readiness score by removing unsupported subjects.",
	})
	record, err := service.Validate(context.Background(), record.Run.TenantID, record.Run.ID, ValidateRequest{
		ExpectedVersion: record.Run.AggregateVersion, ActorID: "verifier-agent",
	})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Validate() error = %v, want ErrVerification", err)
	}
	if record.Run.State != StateProposed || !hasBlockingResult(record.Revision.Proposal.Verification.Results) {
		t.Fatalf("blocked validation was not recorded: state %q results %+v", record.Run.State, record.Revision.Proposal.Verification.Results)
	}
	_, err = service.PublishDraft(context.Background(), record.Run.TenantID, record.Run.ID, PublishDraftRequest{
		ExpectedVersion: record.Run.AggregateVersion, ActorID: "publisher-agent",
	})
	if !errors.Is(err, ErrInvalidState) || publisher.calls != 0 {
		t.Fatalf("PublishDraft(blocked) = calls %d, err %v", publisher.calls, err)
	}
}

func TestRepositoryPolicyCanBlockPublication(t *testing.T) {
	repositoryVerifier := &testRepositoryVerifier{results: []VerificationResult{{
		VerifierID: "repository-data-policy", Status: VerificationBlock, Message: "Patch contains data that cannot be published.",
	}}}
	service := newTestService(&testInputVerifier{}, repositoryVerifier, &testDraftPublisher{}, &testTeamOutbox{})
	record := advanceToProposal(t, service, ExpectedProgramImpact{ExpectedBenefit: "Increase evidence coverage."})
	record, err := service.Validate(context.Background(), record.Run.TenantID, record.Run.ID, ValidateRequest{
		ExpectedVersion: record.Run.AggregateVersion, ActorID: "verifier-agent",
	})
	if !errors.Is(err, ErrVerification) || record.Run.State != StateProposed {
		t.Fatalf("Validate() = state %q, err %v", record.Run.State, err)
	}
}

func TestPublisherRejectsNonDraftReceipt(t *testing.T) {
	publisher := &testDraftPublisher{receipt: &DraftPullRequestReceipt{
		Repository: "writer/cerebro", Number: 42, URL: "https://example.invalid/pulls/42",
		HeadCommitSHA: strings.Repeat("c", 40), BaseCommitSHA: strings.Repeat("b", 40), Draft: false,
		OpenedAt: testNow,
	}}
	service := newTestService(&testInputVerifier{}, &testRepositoryVerifier{}, publisher, &testTeamOutbox{})
	record := advanceToProposal(t, service, ExpectedProgramImpact{ExpectedBenefit: "Increase evidence coverage."})
	var err error
	record, err = service.Validate(context.Background(), record.Run.TenantID, record.Run.ID, ValidateRequest{ExpectedVersion: record.Run.AggregateVersion, ActorID: "verifier-agent"})
	if err != nil {
		t.Fatal(err)
	}
	publisher.receipt.ProposalDigest = string(record.Revision.Proposal.ContentDigest)
	_, err = service.PublishDraft(context.Background(), record.Run.TenantID, record.Run.ID, PublishDraftRequest{ExpectedVersion: record.Run.AggregateVersion, ActorID: "publisher-agent"})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("PublishDraft() error = %v, want ErrVerification", err)
	}
}

func TestDraftPublisherCapabilityHasNoMergeOperation(t *testing.T) {
	typeOfPort := reflect.TypeOf((*DraftPullRequestPublisher)(nil)).Elem()
	if typeOfPort.NumMethod() != 1 || typeOfPort.Method(0).Name != "OpenDraftPullRequest" {
		t.Fatalf("DraftPullRequestPublisher methods = %v", typeOfPort.NumMethod())
	}
	serviceType := reflect.TypeOf((*Service)(nil))
	for index := 0; index < serviceType.NumMethod(); index++ {
		name := strings.ToLower(serviceType.Method(index).Name)
		if strings.Contains(name, "merge") || strings.Contains(name, "approve") || strings.Contains(name, "force") {
			t.Fatalf("Service exposes forbidden repository action %q", serviceType.Method(index).Name)
		}
	}
}

func TestDetectIsIdempotentAndConflictsOnStaleVersion(t *testing.T) {
	service := newTestService(&testInputVerifier{}, &testRepositoryVerifier{}, &testDraftPublisher{}, &testTeamOutbox{})
	first, created, err := service.Detect(context.Background(), detectedRequest())
	if err != nil || !created {
		t.Fatalf("first Detect() = created %t, err %v", created, err)
	}
	second, created, err := service.Detect(context.Background(), detectedRequest())
	if err != nil || created || second.Run.ID != first.Run.ID {
		t.Fatalf("second Detect() = id %q, created %t, err %v", second.Run.ID, created, err)
	}
	_, err = service.RecordResearch(context.Background(), first.Run.TenantID, first.Run.ID, ResearchRequest{
		ExpectedVersion: first.Run.AggregateVersion + 1, Research: validResearch(), ActorID: "researcher-agent",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("RecordResearch(stale) error = %v, want ErrConflict", err)
	}
}

func BenchmarkProposalDigestAtLimits(b *testing.B) {
	proposal := benchmarkProposal()
	b.ReportAllocs()
	b.SetBytes(MaxPatchBytes)
	for range b.N {
		if _, err := proposalDigest(proposal); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIntrinsicVerification(b *testing.B) {
	proposal := benchmarkProposal()
	b.ReportAllocs()
	for range b.N {
		if results := intrinsicVerification(proposal); len(results) == 0 {
			b.Fatal("no verifier results")
		}
	}
}

func newTestService(input InputRevisionVerifier, repository RepositoryChangeVerifier, publisher DraftPullRequestPublisher, outbox TeamUpdateOutbox) *Service {
	service := New(NewMemoryStore(), input, repository, publisher, outbox)
	service.now = func() time.Time { return testNow }
	return service
}

func detectedRequest() DetectRequest {
	return DetectRequest{
		TenantID: "tenant-private", ProgramID: "program-private", DecisionOwner: "grc-owner", IdempotencyKey: "evidence-gap-1", ActorID: "refiner-agent",
		Inputs: []InputRevision{{Kind: "program_scope", Ref: testRevision("scope", "scope-r4", "a")}},
		Gap: ProgramGap{
			Kind: "evidence_coverage", Summary: "Production access evidence is incomplete for one control family.",
			Current:    Measurement{Name: "evidence_coverage", Value: 60, Unit: "percent"},
			Target:     TargetMeasurement{Name: "evidence_coverage", Comparator: ">=", Value: 95, Unit: "percent"},
			Guardrails: []Guardrail{{Name: "in_scope_subjects", Comparator: ">=", Value: 100, Unit: "count"}},
			DetectedBy: "refiner-agent", DetectedAt: testNow,
		},
	}
}

func validResearch() ResearchPacket {
	return ResearchPacket{
		Claims:          []ResearchClaim{{ID: "claim-1", Statement: "The current evidence does not cover the full review period.", CitationIDs: []string{"citation-1"}}},
		Counterevidence: []ResearchClaim{{ID: "counter-1", Statement: "The source was current for the most recent interval.", CitationIDs: []string{"citation-1"}}},
		Citations: []Citation{{
			ID: "citation-1", SourceURN: "urn:cerebro:source-snapshot:one", SnapshotRevision: testRevision("snapshot", "snapshot-r9", "d"),
			CapturedAt: testNow.Add(-time.Hour), ExpiresAt: testNow.Add(24 * time.Hour),
		}},
		Unknowns: []string{"Whether an additional source covers the earlier interval."}, ResearchedBy: "researcher-agent", ResearchedAt: testNow,
	}
}

func validPatch() RepositoryPatch {
	return RepositoryPatch{
		Repository: "writer/cerebro", BaseBranch: "main", BaseCommitSHA: strings.Repeat("b", 40),
		ProposalBranch: "cerebro/improvement/evidence-gap-1", ChangeKind: ChangeKindAssessmentTest,
		Changes:         []FileChange{{Path: "internal/example/evidence_test.go", Operation: FileOperationUpdate, Content: "package example\n"}},
		ValidationSteps: []string{"go test ./internal/example"}, RollbackSteps: []string{"Revert the proposal commit."},
	}
}

func testRevision(id, revisionID, digestCharacter string) compliance.RevisionRef {
	return compliance.RevisionRef{
		ID: id, RevisionID: revisionID, Version: 1,
		ContentDigest: compliance.ContentDigest("sha256:" + strings.Repeat(digestCharacter, 64)), LastModified: testNow.Add(-time.Hour),
	}
}

func advanceToProposal(t *testing.T, service *Service, impact ExpectedProgramImpact) ImprovementRecord {
	t.Helper()
	record, _, err := service.Detect(context.Background(), detectedRequest())
	if err != nil {
		t.Fatal(err)
	}
	record, err = service.RecordResearch(context.Background(), record.Run.TenantID, record.Run.ID, ResearchRequest{
		ExpectedVersion: record.Run.AggregateVersion, Research: validResearch(), ActorID: "researcher-agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err = service.Propose(context.Background(), record.Run.TenantID, record.Run.ID, ProposeRequest{
		ExpectedVersion: record.Run.AggregateVersion, Impact: impact, Patch: validPatch(), ActorID: "author-agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func benchmarkProposal() ImprovementProposal {
	request := detectedRequest()
	proposal := ImprovementProposal{Inputs: request.Inputs, Gap: request.Gap, Research: validResearch()}
	for index := 1; index < MaxClaims; index++ {
		proposal.Research.Claims = append(proposal.Research.Claims, ResearchClaim{
			ID: fmt.Sprintf("claim-%03d", index+1), Statement: "A source-backed statement used to evaluate the proposed program change.", CitationIDs: []string{"citation-1"},
		})
	}
	proposal.Impact = ExpectedProgramImpact{ExpectedBenefit: "Increase verified evidence coverage without reducing program scope."}
	proposal.Patch = validPatch()
	proposal.Patch.Changes = nil
	bytesPerFile := MaxPatchBytes / MaxFileChanges
	for index := 0; index < MaxFileChanges; index++ {
		proposal.Patch.Changes = append(proposal.Patch.Changes, FileChange{
			Path: fmt.Sprintf("internal/generated/change_%02d.go", index), Operation: FileOperationUpdate, Content: strings.Repeat("x", bytesPerFile),
		})
	}
	return normalizeProposal(proposal)
}
