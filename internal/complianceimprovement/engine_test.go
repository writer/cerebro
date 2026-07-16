package complianceimprovement

import (
	"context"
	"testing"
)

type engineRoleFixtures struct {
	refinerCalls    int
	researcherCalls int
	authorCalls     int
}

func (fixtures *engineRoleFixtures) FindProgramGap(context.Context, RefinementContext) (ProgramGap, error) {
	fixtures.refinerCalls++
	return detectedRequest().Gap, nil
}

func (fixtures *engineRoleFixtures) ResearchProgramGap(context.Context, ResearchAssignment) (ResearchPacket, error) {
	fixtures.researcherCalls++
	return validResearch(), nil
}

func (fixtures *engineRoleFixtures) AuthorProgramChange(context.Context, AuthorAssignment) (ExpectedProgramImpact, RepositoryPatch, error) {
	fixtures.authorCalls++
	return ExpectedProgramImpact{ExpectedBenefit: "Increase verified evidence coverage without reducing scope."}, validPatch(), nil
}

func TestRefinementEngineRunsRolesThroughDraftAndStopsBeforeMerge(t *testing.T) {
	publisher := &testDraftPublisher{}
	outbox := &testTeamOutbox{}
	service := newTestService(&testInputVerifier{}, &testRepositoryVerifier{}, publisher, outbox)
	roles := &engineRoleFixtures{}
	engine := NewRefinementEngine(service, roles, roles, roles)
	request := RunRefinementRequest{
		Context:       RefinementContext{TenantID: "tenant-private", ProgramID: "program-private", Inputs: detectedRequest().Inputs},
		DecisionOwner: "grc-owner", IdempotencyKey: "engine-run-1", PublishDraft: true,
		Actors: EngineActors{
			Refiner: "compliance-refiner", Researcher: "compliance-researcher", Author: "compliance-author",
			Verifier: "compliance-verifier", Publisher: "compliance-draft-publisher",
		},
	}
	result, err := engine.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Record.Run.State != StateDraftPROpened || result.Record.Revision.Proposal.Decision != nil || !publisher.request.Draft || publisher.calls != 1 {
		t.Fatalf("engine result = %+v publisher = %+v", result, publisher)
	}
	if roles.refinerCalls != 1 || roles.researcherCalls != 1 || roles.authorCalls != 1 {
		t.Fatalf("role calls = %d/%d/%d", roles.refinerCalls, roles.researcherCalls, roles.authorCalls)
	}
	if result.HumanDecision == "" {
		t.Fatal("engine omitted human decision handoff")
	}

	retried, err := engine.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if retried.Record.Run.AggregateVersion != result.Record.Run.AggregateVersion || publisher.calls != 1 || roles.refinerCalls != 1 || roles.researcherCalls != 1 || roles.authorCalls != 1 {
		t.Fatalf("retry reran completed work: result %+v calls publisher=%d research=%d author=%d", retried.Record.Run, publisher.calls, roles.researcherCalls, roles.authorCalls)
	}
}

func TestRefinementEngineCanStopAtValidatedProposal(t *testing.T) {
	service := newTestService(&testInputVerifier{}, &testRepositoryVerifier{}, &testDraftPublisher{}, &testTeamOutbox{})
	roles := &engineRoleFixtures{}
	engine := NewRefinementEngine(service, roles, roles, roles)
	result, err := engine.Run(context.Background(), RunRefinementRequest{
		Context:       RefinementContext{TenantID: "tenant-private", ProgramID: "program-private", Inputs: detectedRequest().Inputs},
		DecisionOwner: "grc-owner", IdempotencyKey: "engine-run-validated", PublishDraft: false,
		Actors: EngineActors{Refiner: "refiner", Researcher: "researcher", Author: "author", Verifier: "verifier"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Record.Run.State != StateValidated || result.Record.Revision.Proposal.DraftPullRequest != nil {
		t.Fatalf("engine result = %+v", result.Record)
	}
}
