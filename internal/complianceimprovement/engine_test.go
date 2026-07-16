package complianceimprovement

import (
	"context"
	"reflect"
	"testing"
)

type engineRoleFixtures struct {
	refinerCalls    int
	researcherCalls int
	authorCalls     int
	research        ResearchAssignment
	author          AuthorAssignment
}

func (fixtures *engineRoleFixtures) FindProgramGap(context.Context, RefinementContext) (ProgramGap, error) {
	fixtures.refinerCalls++
	return detectedRequest().Gap, nil
}

func (fixtures *engineRoleFixtures) ResearchProgramGap(_ context.Context, assignment ResearchAssignment) (ResearchPacket, error) {
	fixtures.researcherCalls++
	fixtures.research = assignment
	return validResearch(), nil
}

func (fixtures *engineRoleFixtures) AuthorProgramChange(_ context.Context, assignment AuthorAssignment) (ExpectedProgramImpact, RepositoryPatch, error) {
	fixtures.authorCalls++
	fixtures.author = assignment
	return ExpectedProgramImpact{ExpectedBenefit: "Increase verified evidence coverage without reducing scope."}, validPatch(), nil
}

func TestRefinementEngineResumesWithDurableInputsAndCompleteStages(t *testing.T) {
	service := newTestService(&testInputVerifier{}, &testRepositoryVerifier{}, &testDraftPublisher{}, &testTeamOutbox{})
	original := detectedRequest()
	original.IdempotencyKey = "engine-resume-durable"
	if _, _, err := service.Detect(context.Background(), original); err != nil {
		t.Fatal(err)
	}

	roles := &engineRoleFixtures{}
	engine := NewRefinementEngine(service, roles, roles, roles)
	retryInputs := []InputRevision{{Kind: "program_scope", Ref: testRevision("scope", "scope-r5", "f")}}
	result, err := engine.Run(context.Background(), RunRefinementRequest{
		Context: RefinementContext{
			TenantID: original.TenantID, ProgramID: original.ProgramID, Inputs: retryInputs,
		},
		DecisionOwner: original.DecisionOwner, IdempotencyKey: original.IdempotencyKey,
		Actors: EngineActors{Refiner: "refiner", Researcher: "researcher", Author: "author", Verifier: "verifier"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantStages := []string{StateDetected, StateResearching, StateProposed, StateValidated}
	if !reflect.DeepEqual(result.CompletedStages, wantStages) {
		t.Fatalf("completed stages = %v, want %v", result.CompletedStages, wantStages)
	}
	if roles.refinerCalls != 0 || roles.researcherCalls != 1 || roles.authorCalls != 1 {
		t.Fatalf("role calls = %d/%d/%d", roles.refinerCalls, roles.researcherCalls, roles.authorCalls)
	}
	if !reflect.DeepEqual(roles.research.Context.Inputs, original.Inputs) || !reflect.DeepEqual(roles.author.Context.Inputs, original.Inputs) {
		t.Fatalf("role inputs = research %+v author %+v, want durable %+v", roles.research.Context.Inputs, roles.author.Context.Inputs, original.Inputs)
	}
}

func TestRefinementEngineReportsCompletedStagesWhenResumingProposedRun(t *testing.T) {
	service := newTestService(&testInputVerifier{}, &testRepositoryVerifier{}, &testDraftPublisher{}, &testTeamOutbox{})
	record := advanceToProposal(t, service, ExpectedProgramImpact{ExpectedBenefit: "Increase evidence coverage without reducing scope."})
	roles := &engineRoleFixtures{}
	result, err := NewRefinementEngine(service, roles, roles, roles).Run(context.Background(), RunRefinementRequest{
		Context: RefinementContext{
			TenantID: record.Run.TenantID, ProgramID: record.Run.ProgramID, Inputs: record.Revision.Proposal.Inputs,
		},
		DecisionOwner: record.Run.DecisionOwner, IdempotencyKey: record.Run.IdempotencyKey,
		Actors: EngineActors{Refiner: "refiner", Researcher: "researcher", Author: "author", Verifier: "verifier"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{StateDetected, StateResearching, StateProposed, StateValidated}
	if !reflect.DeepEqual(result.CompletedStages, want) {
		t.Fatalf("completed stages = %v, want %v", result.CompletedStages, want)
	}
	if roles.refinerCalls != 0 || roles.researcherCalls != 0 || roles.authorCalls != 0 {
		t.Fatalf("resume reran completed roles = %d/%d/%d", roles.refinerCalls, roles.researcherCalls, roles.authorCalls)
	}
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
