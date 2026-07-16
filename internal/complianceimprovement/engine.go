package complianceimprovement

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ProgramRefiner selects one measurable gap from exact program inputs. It does
// not author a patch or change program state.
type ProgramRefiner interface {
	FindProgramGap(context.Context, RefinementContext) (ProgramGap, error)
}

// ProgramResearcher builds the cited case for and against the selected gap.
type ProgramResearcher interface {
	ResearchProgramGap(context.Context, ResearchAssignment) (ResearchPacket, error)
}

// ProgramChangeAuthor creates a bounded repository patch and declares its
// expected program impact. It cannot publish or merge the patch.
type ProgramChangeAuthor interface {
	AuthorProgramChange(context.Context, AuthorAssignment) (ExpectedProgramImpact, RepositoryPatch, error)
}

type RefinementContext struct {
	TenantID  string          `json:"tenant_id"`
	ProgramID string          `json:"program_id"`
	Inputs    []InputRevision `json:"inputs"`
}

type ResearchAssignment struct {
	Context RefinementContext `json:"context"`
	Gap     ProgramGap        `json:"gap"`
}

type AuthorAssignment struct {
	Context  RefinementContext `json:"context"`
	Gap      ProgramGap        `json:"gap"`
	Research ResearchPacket    `json:"research"`
}

type EngineActors struct {
	Refiner    string `json:"refiner"`
	Researcher string `json:"researcher"`
	Author     string `json:"author"`
	Verifier   string `json:"verifier"`
	Publisher  string `json:"publisher"`
}

type RunRefinementRequest struct {
	Context        RefinementContext `json:"context"`
	DecisionOwner  string            `json:"decision_owner"`
	IdempotencyKey string            `json:"idempotency_key"`
	Actors         EngineActors      `json:"actors"`
	PublishDraft   bool              `json:"publish_draft"`
}

type RunRefinementResult struct {
	Record          ImprovementRecord `json:"record"`
	CompletedStages []string          `json:"completed_stages"`
	HumanDecision   string            `json:"human_decision"`
}

// RefinementEngine runs the bounded agent roles and resumes from durable state
// after a retry. The terminal automated action is opening a draft pull request.
type RefinementEngine struct {
	service    *Service
	refiner    ProgramRefiner
	researcher ProgramResearcher
	author     ProgramChangeAuthor
}

func NewRefinementEngine(service *Service, refiner ProgramRefiner, researcher ProgramResearcher, author ProgramChangeAuthor) *RefinementEngine {
	return &RefinementEngine{service: service, refiner: refiner, researcher: researcher, author: author}
}

func (engine *RefinementEngine) Run(ctx context.Context, request RunRefinementRequest) (RunRefinementResult, error) {
	if engine == nil || engine.service == nil || engine.refiner == nil || engine.researcher == nil || engine.author == nil {
		return RunRefinementResult{}, ErrUnavailable
	}
	request = normalizeRunRefinementRequest(request)
	if err := validateRunRefinementRequest(request); err != nil {
		return RunRefinementResult{}, err
	}
	runID := improvementRunID(request.Context.TenantID, request.Context.ProgramID, request.IdempotencyKey)
	record, err := engine.service.Get(ctx, request.Context.TenantID, runID)
	if errors.Is(err, ErrNotFound) {
		gap, refineErr := engine.refiner.FindProgramGap(ctx, request.Context)
		if refineErr != nil {
			return RunRefinementResult{}, fmt.Errorf("refine compliance program: %w", refineErr)
		}
		record, _, err = engine.service.Detect(ctx, DetectRequest{
			TenantID: request.Context.TenantID, ProgramID: request.Context.ProgramID,
			DecisionOwner: request.DecisionOwner, IdempotencyKey: request.IdempotencyKey,
			Inputs: request.Context.Inputs, Gap: gap, ActorID: request.Actors.Refiner,
		})
	}
	if err != nil {
		return RunRefinementResult{}, err
	}
	completed := []string{StateDetected}
	for {
		switch record.Run.State {
		case StateDetected:
			research, researchErr := engine.researcher.ResearchProgramGap(ctx, ResearchAssignment{Context: request.Context, Gap: record.Revision.Proposal.Gap})
			if researchErr != nil {
				return RunRefinementResult{Record: record, CompletedStages: completed}, fmt.Errorf("research compliance program gap: %w", researchErr)
			}
			record, err = engine.service.RecordResearch(ctx, record.Run.TenantID, record.Run.ID, ResearchRequest{
				ExpectedVersion: record.Run.AggregateVersion, Research: research, ActorID: request.Actors.Researcher,
			})
			if err != nil {
				return RunRefinementResult{Record: record, CompletedStages: completed}, err
			}
			completed = append(completed, StateResearching)
		case StateResearching:
			impact, patch, authorErr := engine.author.AuthorProgramChange(ctx, AuthorAssignment{
				Context: request.Context, Gap: record.Revision.Proposal.Gap, Research: record.Revision.Proposal.Research,
			})
			if authorErr != nil {
				return RunRefinementResult{Record: record, CompletedStages: completed}, fmt.Errorf("author compliance program change: %w", authorErr)
			}
			record, err = engine.service.Propose(ctx, record.Run.TenantID, record.Run.ID, ProposeRequest{
				ExpectedVersion: record.Run.AggregateVersion, Impact: impact, Patch: patch, ActorID: request.Actors.Author,
			})
			if err != nil {
				return RunRefinementResult{Record: record, CompletedStages: completed}, err
			}
			completed = append(completed, StateProposed)
		case StateProposed:
			record, err = engine.service.Validate(ctx, record.Run.TenantID, record.Run.ID, ValidateRequest{
				ExpectedVersion: record.Run.AggregateVersion, ActorID: request.Actors.Verifier,
			})
			if err != nil {
				return RunRefinementResult{Record: record, CompletedStages: append(completed, StateProposed)}, err
			}
			completed = append(completed, StateValidated)
		case StateValidated:
			if !request.PublishDraft {
				return RunRefinementResult{Record: record, CompletedStages: completed, HumanDecision: "A human GRC owner can review the validated proposal before draft publication."}, nil
			}
			record, err = engine.service.PublishDraft(ctx, record.Run.TenantID, record.Run.ID, PublishDraftRequest{
				ExpectedVersion: record.Run.AggregateVersion, ActorID: request.Actors.Publisher,
			})
			if err != nil {
				return RunRefinementResult{Record: record, CompletedStages: completed}, err
			}
			completed = append(completed, StateDraftPROpened)
		case StateDraftPROpened:
			return RunRefinementResult{
				Record: record, CompletedStages: completed,
				HumanDecision: "The assigned human GRC owner must review the evidence and decide whether to merge or reject the draft pull request.",
			}, nil
		case StateAccepted, StateRejected, StateExpired, StateSuperseded:
			return RunRefinementResult{Record: record, CompletedStages: completed, HumanDecision: "The improvement run is in a human or terminal state."}, nil
		default:
			return RunRefinementResult{Record: record, CompletedStages: completed}, fmt.Errorf("%w: unknown state %q", ErrInvalidState, record.Run.State)
		}
	}
}

func normalizeRunRefinementRequest(request RunRefinementRequest) RunRefinementRequest {
	request.Context.TenantID = strings.TrimSpace(request.Context.TenantID)
	request.Context.ProgramID = strings.TrimSpace(request.Context.ProgramID)
	request.DecisionOwner = strings.TrimSpace(request.DecisionOwner)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.Actors.Refiner = strings.TrimSpace(request.Actors.Refiner)
	request.Actors.Researcher = strings.TrimSpace(request.Actors.Researcher)
	request.Actors.Author = strings.TrimSpace(request.Actors.Author)
	request.Actors.Verifier = strings.TrimSpace(request.Actors.Verifier)
	request.Actors.Publisher = strings.TrimSpace(request.Actors.Publisher)
	return request
}

func validateRunRefinementRequest(request RunRefinementRequest) error {
	if request.Context.TenantID == "" || request.Context.ProgramID == "" || request.DecisionOwner == "" || request.IdempotencyKey == "" || len(request.Context.Inputs) == 0 {
		return fmt.Errorf("%w: tenant, program, exact inputs, decision owner, and idempotency key are required", ErrInvalidRequest)
	}
	if request.Actors.Refiner == "" || request.Actors.Researcher == "" || request.Actors.Author == "" || request.Actors.Verifier == "" || (request.PublishDraft && request.Actors.Publisher == "") {
		return fmt.Errorf("%w: every enabled improvement role requires an actor", ErrInvalidRequest)
	}
	return nil
}
