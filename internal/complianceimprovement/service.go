package complianceimprovement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

type Service struct {
	store              Store
	inputVerifier      InputRevisionVerifier
	repositoryVerifier RepositoryChangeVerifier
	draftPublisher     DraftPullRequestPublisher
	teamOutbox         TeamUpdateOutbox
	now                func() time.Time
}

func New(store Store, inputVerifier InputRevisionVerifier, repositoryVerifier RepositoryChangeVerifier, draftPublisher DraftPullRequestPublisher, teamOutbox TeamUpdateOutbox) *Service {
	return &Service{
		store: store, inputVerifier: inputVerifier, repositoryVerifier: repositoryVerifier,
		draftPublisher: draftPublisher, teamOutbox: teamOutbox,
		now: func() time.Time { return time.Now().UTC() },
	}
}

type DetectRequest struct {
	TenantID       string          `json:"tenant_id"`
	ProgramID      string          `json:"program_id"`
	DecisionOwner  string          `json:"decision_owner"`
	IdempotencyKey string          `json:"idempotency_key"`
	Inputs         []InputRevision `json:"inputs"`
	Gap            ProgramGap      `json:"gap"`
	ActorID        string          `json:"actor_id"`
}

func (s *Service) Detect(ctx context.Context, request DetectRequest) (ImprovementRecord, bool, error) {
	if err := s.coreReady(); err != nil {
		return ImprovementRecord{}, false, err
	}
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.ProgramID = strings.TrimSpace(request.ProgramID)
	request.DecisionOwner = strings.TrimSpace(request.DecisionOwner)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.ActorID = strings.TrimSpace(request.ActorID)
	if request.TenantID == "" || request.ProgramID == "" || request.DecisionOwner == "" || request.IdempotencyKey == "" || request.ActorID == "" {
		return ImprovementRecord{}, false, fmt.Errorf("%w: tenant, program, decision owner, idempotency key, and actor are required", ErrInvalidRequest)
	}
	now := canonicalTime(s.now())
	if request.Gap.DetectedAt.IsZero() {
		request.Gap.DetectedAt = now
	}
	proposal := normalizeProposal(ImprovementProposal{Inputs: request.Inputs, Gap: request.Gap})
	if err := validateDetectedProposal(proposal); err != nil {
		return ImprovementRecord{}, false, err
	}
	digest, err := proposalDigest(proposal)
	if err != nil {
		return ImprovementRecord{}, false, err
	}
	proposal.ContentDigest = digest
	runID := improvementRunID(request.TenantID, request.ProgramID, request.IdempotencyKey)
	run := ImprovementRun{
		TenantID: request.TenantID, ID: runID, ProgramID: request.ProgramID, State: StateDetected,
		DecisionOwner: request.DecisionOwner, AggregateVersion: 1, CurrentRevisionID: revisionID(runID, 1),
		IdempotencyKey: request.IdempotencyKey, CreatedAt: now, UpdatedAt: now,
	}
	revision, err := buildRevision(run, proposal, request.ActorID, "")
	if err != nil {
		return ImprovementRecord{}, false, err
	}
	return s.store.CreateComplianceImprovement(ctx, CreateRecordRequest{Run: run, Revision: revision})
}

type ResearchRequest struct {
	ExpectedVersion uint64         `json:"expected_version"`
	Research        ResearchPacket `json:"research"`
	ActorID         string         `json:"actor_id"`
}

func (s *Service) RecordResearch(ctx context.Context, tenantID, runID string, request ResearchRequest) (ImprovementRecord, error) {
	record, err := s.getForTransition(ctx, tenantID, runID, request.ExpectedVersion, StateDetected, StateResearching, StateProposed)
	if err != nil {
		return ImprovementRecord{}, err
	}
	request.Research = normalizeResearch(request.Research)
	if request.Research.ResearchedAt.IsZero() {
		request.Research.ResearchedAt = canonicalTime(s.now())
	}
	if request.Research.ResearchedBy == "" {
		request.Research.ResearchedBy = strings.TrimSpace(request.ActorID)
	}
	if err := validateResearch(request.Research, canonicalTime(s.now())); err != nil {
		return ImprovementRecord{}, err
	}
	proposal := record.Revision.Proposal
	proposal.Research = request.Research
	proposal.Patch = RepositoryPatch{}
	proposal.Impact = ExpectedProgramImpact{}
	proposal.Verification = VerificationRecord{}
	proposal.DraftPullRequest = nil
	proposal.TeamUpdate = nil
	proposal.Decision = nil
	return s.append(ctx, record, StateResearching, proposal, request.ActorID)
}

type ProposeRequest struct {
	ExpectedVersion uint64                `json:"expected_version"`
	Impact          ExpectedProgramImpact `json:"impact"`
	Patch           RepositoryPatch       `json:"patch"`
	ActorID         string                `json:"actor_id"`
}

func (s *Service) Propose(ctx context.Context, tenantID, runID string, request ProposeRequest) (ImprovementRecord, error) {
	record, err := s.getForTransition(ctx, tenantID, runID, request.ExpectedVersion, StateResearching, StateProposed)
	if err != nil {
		return ImprovementRecord{}, err
	}
	proposal := record.Revision.Proposal
	if err := validateResearch(proposal.Research, canonicalTime(s.now())); err != nil {
		return ImprovementRecord{}, err
	}
	proposal.Impact = request.Impact
	proposal.Patch = normalizePatch(request.Patch)
	proposal.Verification = VerificationRecord{}
	proposal.DraftPullRequest = nil
	proposal.TeamUpdate = nil
	proposal.Decision = nil
	if err := validatePatch(proposal.Patch); err != nil {
		return ImprovementRecord{}, err
	}
	return s.append(ctx, record, StateProposed, proposal, request.ActorID)
}

type ValidateRequest struct {
	ExpectedVersion uint64 `json:"expected_version"`
	ActorID         string `json:"actor_id"`
}

func (s *Service) Validate(ctx context.Context, tenantID, runID string, request ValidateRequest) (ImprovementRecord, error) {
	record, err := s.getForTransition(ctx, tenantID, runID, request.ExpectedVersion, StateProposed)
	if err != nil {
		return ImprovementRecord{}, err
	}
	if s.inputVerifier == nil || s.repositoryVerifier == nil {
		return ImprovementRecord{}, fmt.Errorf("%w: input and repository verifiers are required", ErrUnavailable)
	}
	proposal := normalizeProposal(record.Revision.Proposal)
	results := intrinsicVerification(proposal)
	if err := validateResearch(proposal.Research, canonicalTime(s.now())); err != nil {
		results = append(results, VerificationResult{VerifierID: "research-citations", Status: VerificationBlock, Message: err.Error()})
	}
	if err := validatePatch(proposal.Patch); err != nil {
		results = append(results, VerificationResult{VerifierID: "bounded-repository-patch", Status: VerificationBlock, Message: err.Error()})
	}
	inputs := append([]InputRevision(nil), proposal.Inputs...)
	for _, citation := range proposal.Research.Citations {
		inputs = append(inputs, InputRevision{Kind: "research_source", Ref: citation.SnapshotRevision})
	}
	inputResults, err := s.inputVerifier.VerifyInputRevisions(ctx, record.Run.TenantID, inputs)
	if err != nil {
		return ImprovementRecord{}, fmt.Errorf("verify exact input revisions: %w", err)
	}
	repositoryResults, err := s.repositoryVerifier.VerifyRepositoryChange(ctx, proposal.Patch)
	if err != nil {
		return ImprovementRecord{}, fmt.Errorf("verify repository change: %w", err)
	}
	results = normalizeVerificationResults(append(results, append(inputResults, repositoryResults...)...))
	if err := validateVerificationResults(results); err != nil {
		return ImprovementRecord{}, err
	}
	proposal.Verification = VerificationRecord{Results: results, VerifiedBy: strings.TrimSpace(request.ActorID), VerifiedAt: canonicalTime(s.now())}
	nextState := StateValidated
	blocked := hasBlockingResult(results)
	if blocked {
		nextState = StateProposed
	}
	updated, appendErr := s.append(ctx, record, nextState, proposal, request.ActorID)
	if appendErr != nil {
		return ImprovementRecord{}, appendErr
	}
	if blocked {
		return updated, ErrVerification
	}
	return updated, nil
}

type PublishDraftRequest struct {
	ExpectedVersion uint64 `json:"expected_version"`
	ActorID         string `json:"actor_id"`
}

func (s *Service) PublishDraft(ctx context.Context, tenantID, runID string, request PublishDraftRequest) (ImprovementRecord, error) {
	record, err := s.getForTransition(ctx, tenantID, runID, request.ExpectedVersion, StateValidated)
	if err != nil {
		return ImprovementRecord{}, err
	}
	if s.draftPublisher == nil || s.teamOutbox == nil {
		return ImprovementRecord{}, fmt.Errorf("%w: draft publisher and team outbox are required", ErrUnavailable)
	}
	proposal := normalizeProposal(record.Revision.Proposal)
	digest, err := proposalDigest(proposal)
	if err != nil {
		return ImprovementRecord{}, err
	}
	if digest != proposal.ContentDigest {
		return ImprovementRecord{}, fmt.Errorf("%w: validated proposal digest does not match content", ErrVerification)
	}
	title, body := publicPullRequestMetadata(proposal.Patch.ChangeKind)
	openRequest := OpenDraftPullRequestRequest{
		ProposalDigest: string(digest), Repository: proposal.Patch.Repository,
		BaseBranch: proposal.Patch.BaseBranch, BaseCommitSHA: proposal.Patch.BaseCommitSHA,
		ProposalBranch: proposal.Patch.ProposalBranch, Title: title, Body: body,
		Changes:        append([]FileChange(nil), proposal.Patch.Changes...),
		IdempotencyKey: record.Run.ID + ":" + string(digest), Draft: true,
	}
	receipt, err := s.draftPublisher.OpenDraftPullRequest(ctx, openRequest)
	if err != nil {
		return ImprovementRecord{}, fmt.Errorf("open draft pull request: %w", err)
	}
	if err := validateDraftReceipt(openRequest, receipt); err != nil {
		return ImprovementRecord{}, err
	}
	update := TeamUpdate{
		ProposalDigest: string(digest), State: StateDraftPROpened, GapSummary: proposal.Gap.Summary,
		Current: proposal.Gap.Current, Target: proposal.Gap.Target, Guardrails: append([]Guardrail(nil), proposal.Gap.Guardrails...),
		Supporting: append([]ResearchClaim(nil), proposal.Research.Claims...), Counterevidence: append([]ResearchClaim(nil), proposal.Research.Counterevidence...),
		Unknowns: append([]string(nil), proposal.Research.Unknowns...), Verification: append([]VerificationResult(nil), proposal.Verification.Results...),
		PullRequest: receipt, DecisionOwner: record.Run.DecisionOwner,
		RequiredAction: "Review the evidence and draft changes. Merge or reject the pull request as the assigned human GRC owner.",
		CreatedAt:      canonicalTime(s.now()),
	}
	updateReceipt, err := s.teamOutbox.EnqueueTeamUpdate(ctx, record.Run.TenantID, openRequest.IdempotencyKey, update)
	if err != nil {
		return ImprovementRecord{}, fmt.Errorf("enqueue team update: %w", err)
	}
	if updateReceipt.ProposalDigest != string(digest) || updateReceipt.OutboxID == "" || updateReceipt.QueuedAt.IsZero() {
		return ImprovementRecord{}, fmt.Errorf("%w: team update outbox returned an invalid receipt", ErrVerification)
	}
	proposal.DraftPullRequest = &receipt
	proposal.TeamUpdate = &updateReceipt
	return s.append(ctx, record, StateDraftPROpened, proposal, request.ActorID)
}

type DecisionRequest struct {
	ExpectedVersion uint64    `json:"expected_version"`
	Decision        string    `json:"decision"`
	Rationale       string    `json:"rationale"`
	ActorID         string    `json:"actor_id"`
	ProposalDigest  string    `json:"proposal_digest"`
	DecidedAt       time.Time `json:"decided_at"`
}

// RecordHumanDecision records the GRC owner's decision. It does not call the
// repository provider and cannot merge, close, retarget, or approve a PR.
func (s *Service) RecordHumanDecision(ctx context.Context, tenantID, runID string, request DecisionRequest) (ImprovementRecord, error) {
	record, err := s.getForTransition(ctx, tenantID, runID, request.ExpectedVersion, StateDraftPROpened)
	if err != nil {
		return ImprovementRecord{}, err
	}
	request.ActorID = strings.TrimSpace(request.ActorID)
	request.Rationale = strings.TrimSpace(request.Rationale)
	request.ProposalDigest = strings.TrimSpace(request.ProposalDigest)
	request.Decision = strings.TrimSpace(request.Decision)
	if request.ActorID == "" || request.ActorID != record.Run.DecisionOwner || request.Rationale == "" {
		return ImprovementRecord{}, fmt.Errorf("%w: the assigned human GRC owner and rationale are required", ErrInvalidRequest)
	}
	proposal := record.Revision.Proposal
	if request.ProposalDigest == "" || request.ProposalDigest != string(proposal.ContentDigest) {
		return ImprovementRecord{}, fmt.Errorf("%w: decision must bind the validated proposal digest", ErrVerification)
	}
	var nextState string
	switch request.Decision {
	case DecisionAccept:
		nextState = StateAccepted
	case DecisionReject:
		nextState = StateRejected
	default:
		return ImprovementRecord{}, fmt.Errorf("%w: decision must be accept or reject", ErrInvalidRequest)
	}
	if request.DecidedAt.IsZero() {
		request.DecidedAt = canonicalTime(s.now())
	}
	proposal.Decision = &HumanDecision{
		Decision: request.Decision, ActorID: request.ActorID, Rationale: request.Rationale,
		ProposalDigest: request.ProposalDigest, DecidedAt: canonicalTime(request.DecidedAt),
	}
	return s.append(ctx, record, nextState, proposal, request.ActorID)
}

func (s *Service) Get(ctx context.Context, tenantID, runID string) (ImprovementRecord, error) {
	if err := s.coreReady(); err != nil {
		return ImprovementRecord{}, err
	}
	return s.store.GetComplianceImprovement(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(runID))
}

func (s *Service) coreReady() error {
	if s == nil || s.store == nil || s.now == nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) getForTransition(ctx context.Context, tenantID, runID string, expectedVersion uint64, allowedStates ...string) (ImprovementRecord, error) {
	if err := s.coreReady(); err != nil {
		return ImprovementRecord{}, err
	}
	record, err := s.store.GetComplianceImprovement(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(runID))
	if err != nil {
		return ImprovementRecord{}, err
	}
	if record.Run.AggregateVersion != expectedVersion {
		return ImprovementRecord{}, fmt.Errorf("%w: expected version %d, current version %d", ErrConflict, expectedVersion, record.Run.AggregateVersion)
	}
	for _, state := range allowedStates {
		if record.Run.State == state {
			return record, nil
		}
	}
	return ImprovementRecord{}, fmt.Errorf("%w: state %q does not allow this operation", ErrInvalidState, record.Run.State)
}

func (s *Service) append(ctx context.Context, current ImprovementRecord, state string, proposal ImprovementProposal, actorID string) (ImprovementRecord, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return ImprovementRecord{}, fmt.Errorf("%w: actor is required", ErrInvalidRequest)
	}
	proposal = normalizeProposal(proposal)
	digest, err := proposalDigest(proposal)
	if err != nil {
		return ImprovementRecord{}, err
	}
	proposal.ContentDigest = digest
	now := canonicalTime(s.now())
	next := current.Run
	next.State = state
	next.AggregateVersion++
	next.CurrentRevisionID = revisionID(next.ID, next.AggregateVersion)
	next.UpdatedAt = now
	revision, err := buildRevision(next, proposal, actorID, current.Revision.Version.RevisionID)
	if err != nil {
		return ImprovementRecord{}, err
	}
	return s.store.AppendComplianceImprovementRevision(ctx, AppendRevisionRequest{
		TenantID: next.TenantID, RunID: next.ID, ExpectedVersion: current.Run.AggregateVersion,
		Run: next, Revision: revision,
	})
}

func buildRevision(run ImprovementRun, proposal ImprovementProposal, actorID, predecessorID string) (ImprovementRevision, error) {
	digest, err := revisionDigest(run.State, proposal)
	if err != nil {
		return ImprovementRevision{}, err
	}
	return ImprovementRevision{
		TenantID: run.TenantID, RunID: run.ID,
		Version: compliance.VersionMetadata{
			ID: run.ID, RevisionID: run.CurrentRevisionID, Version: run.AggregateVersion,
			LastModified: run.UpdatedAt, ContentDigest: digest, CreatedBy: strings.TrimSpace(actorID), PredecessorID: predecessorID,
		},
		Proposal: proposal,
	}, nil
}

func improvementRunID(tenantID, programID, key string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(programID) + "\x00" + strings.TrimSpace(key)))
	return "improvement-" + hex.EncodeToString(digest[:12])
}

func revisionID(runID string, version uint64) string { return fmt.Sprintf("%s-r%d", runID, version) }

func validateDraftReceipt(request OpenDraftPullRequestRequest, receipt DraftPullRequestReceipt) error {
	if !request.Draft || !receipt.Draft {
		return fmt.Errorf("%w: repository publisher must return a draft pull request", ErrVerification)
	}
	if receipt.Repository != request.Repository || receipt.BaseCommitSHA != request.BaseCommitSHA || receipt.ProposalDigest != request.ProposalDigest {
		return fmt.Errorf("%w: draft pull-request receipt does not match the validated request", ErrVerification)
	}
	if receipt.Number == 0 || strings.TrimSpace(receipt.URL) == "" || !commitSHAPattern.MatchString(receipt.HeadCommitSHA) || receipt.OpenedAt.IsZero() {
		return fmt.Errorf("%w: draft pull-request receipt is incomplete", ErrVerification)
	}
	return nil
}

func IsVerificationBlocked(err error) bool { return errors.Is(err, ErrVerification) }
