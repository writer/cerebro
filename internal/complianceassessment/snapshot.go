package complianceassessment

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

var (
	ErrAssessmentSnapshotNotFound    = errors.New("assessment snapshot not found")
	ErrAssessmentSnapshotUnavailable = errors.New("assessment snapshot persistence is unavailable")
	ErrAssessmentLensNotFound        = errors.New("assessment lens not found")
)

const (
	AssessmentSnapshotVersion = "assessment-snapshot/v1"
	AssessmentLensVersion     = "assessment-lens/v1"
	defaultSnapshotLensLimit  = 50
	maxSnapshotLensLimit      = 200
)

type AssessmentSnapshot struct {
	ID                     string                   `json:"id"`
	TenantID               string                   `json:"tenant_id"`
	RunID                  string                   `json:"run_id"`
	ProgramID              string                   `json:"program_id"`
	ScopeRevisionID        string                   `json:"scope_revision_id"`
	PlanRevisionID         string                   `json:"plan_revision_id"`
	Version                string                   `json:"version"`
	InputManifest          InputManifest            `json:"input_manifest"`
	InputHash              string                   `json:"input_hash"`
	ResultSetHash          string                   `json:"result_set_hash"`
	ResultCount            uint64                   `json:"result_count"`
	ResultChunks           []SnapshotResultChunkRef `json:"result_chunks"`
	DecisionCutoff         time.Time                `json:"decision_cutoff"`
	DecisionSetDigest      string                   `json:"decision_set_digest"`
	DecisionCount          uint64                   `json:"decision_count"`
	QualifiedDecisionCount uint64                   `json:"qualified_decision_count"`
	MissingDecisionCount   uint64                   `json:"missing_decision_count"`
	EvidenceSetDigest      string                   `json:"evidence_set_digest"`
	EvidenceCount          uint64                   `json:"evidence_count"`
	RunCompletedAt         time.Time                `json:"run_completed_at"`
	CreatedAt              time.Time                `json:"created_at"`
	CreatedBy              string                   `json:"created_by"`
	RequestHash            string                   `json:"request_hash"`
	IdempotencyKey         string                   `json:"idempotency_key"`
	RecordDigest           string                   `json:"record_digest"`
}

type SnapshotResultChunkRef struct {
	Sequence       uint32 `json:"sequence"`
	FirstResultID  string `json:"first_result_id"`
	LastResultID   string `json:"last_result_id"`
	Count          uint32 `json:"count"`
	PreviousDigest string `json:"previous_digest,omitempty"`
	Digest         string `json:"digest"`
}

type SnapshotDecisionRef struct {
	ResultID       string    `json:"result_id"`
	DecisionID     string    `json:"decision_id"`
	DecisionDigest string    `json:"decision_digest"`
	RecordDigest   string    `json:"record_digest"`
	Qualified      bool      `json:"qualified"`
	AsOf           time.Time `json:"as_of"`
	RecordedAt     time.Time `json:"recorded_at"`
}

type AssessmentSnapshotRequest struct {
	TenantID       string
	RunID          string
	IdempotencyKey string
	CreatedBy      string
}

type AssessmentLensAudience string

const (
	LensAudienceSecurity   AssessmentLensAudience = "security"
	LensAudienceAudit      AssessmentLensAudience = "audit"
	LensAudiencePlatform   AssessmentLensAudience = "platform"
	LensAudienceLeadership AssessmentLensAudience = "leadership"
)

type AssessmentLensDefinition struct {
	ID               string                 `json:"id"`
	Version          string                 `json:"version"`
	Audience         AssessmentLensAudience `json:"audience"`
	FirstQuestion    string                 `json:"first_question"`
	PromotedSignals  []string               `json:"promoted_signals"`
	IncludedFields   []string               `json:"included_fields"`
	SuppressedFields []string               `json:"suppressed_fields"`
	WorkQueue        string                 `json:"work_queue"`
	NextActions      []string               `json:"next_actions"`
	QuestionStarters []string               `json:"question_starters"`
}

type AssessmentLensSummary struct {
	TotalResults       uint64 `json:"total_results"`
	InScopeResults     uint64 `json:"in_scope_results"`
	Satisfied          uint64 `json:"satisfied"`
	NotSatisfied       uint64 `json:"not_satisfied"`
	NotAssessed        uint64 `json:"not_assessed"`
	QualifiedDecisions uint64 `json:"qualified_decisions"`
	MissingDecisions   uint64 `json:"missing_decisions"`
	EvidenceGaps       uint64 `json:"evidence_gaps"`
	PendingReviews     uint64 `json:"pending_reviews"`
}

type AssessmentLensSignal struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Value uint64 `json:"value"`
	State string `json:"state"`
}

type AssessmentLensItem struct {
	ResultID                    string                      `json:"result_id"`
	ControlRef                  compliance.ControlRef       `json:"control_ref"`
	ObjectiveID                 string                      `json:"objective_id"`
	ScopeState                  ScopeState                  `json:"scope_state"`
	AutomatedOutcome            AutomatedOutcome            `json:"automated_outcome"`
	Assurance                   Assurance                   `json:"assurance"`
	EvidenceState               EvidenceState               `json:"evidence_state"`
	OperatingEffectivenessState OperatingEffectivenessState `json:"operating_effectiveness_state"`
	AuditorState                AuditorState                `json:"auditor_state"`
	DecisionState               string                      `json:"decision_state"`
	DecisionID                  string                      `json:"decision_id,omitempty"`
	DecisionAsOf                time.Time                   `json:"decision_as_of,omitempty"`
	ReasonCodes                 []ReasonCode                `json:"reason_codes,omitempty"`
	NextActions                 []NextAction                `json:"next_actions,omitempty"`
	EvidenceIDs                 []string                    `json:"evidence_ids,omitempty"`
	FindingIDs                  []string                    `json:"finding_ids,omitempty"`
	SourceRuntimeIDs            []string                    `json:"source_runtime_ids,omitempty"`
}

type AssessmentSnapshotLens struct {
	SnapshotID     string                   `json:"snapshot_id"`
	SnapshotDigest string                   `json:"snapshot_digest"`
	Lens           AssessmentLensDefinition `json:"lens"`
	Summary        AssessmentLensSummary    `json:"summary"`
	Signals        []AssessmentLensSignal   `json:"signals"`
	Items          []AssessmentLensItem     `json:"items"`
	NextCursor     string                   `json:"next_cursor,omitempty"`
	HasMore        bool                     `json:"has_more"`
}

func (s *Service) CreateAssessmentSnapshot(ctx context.Context, request AssessmentSnapshotRequest) (AssessmentSnapshot, bool, error) {
	store, ok := s.assessmentSnapshotStore()
	if !ok || s.log == nil {
		return AssessmentSnapshot{}, false, ErrAssessmentSnapshotUnavailable
	}
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.RunID = strings.TrimSpace(request.RunID)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.CreatedBy = strings.TrimSpace(request.CreatedBy)
	if request.TenantID == "" || request.RunID == "" || request.IdempotencyKey == "" || request.CreatedBy == "" {
		return AssessmentSnapshot{}, false, fmt.Errorf("%w: snapshot request identity is incomplete", ErrInvalidResult)
	}
	requestHash, err := semanticHash(struct {
		TenantID string `json:"tenant_id"`
		RunID    string `json:"run_id"`
	}{TenantID: request.TenantID, RunID: request.RunID})
	if err != nil {
		return AssessmentSnapshot{}, false, err
	}
	if existing, findErr := store.FindAssessmentSnapshotByIdempotency(ctx, request.TenantID, request.IdempotencyKey); findErr == nil {
		if existing.RequestHash != requestHash {
			return AssessmentSnapshot{}, false, ports.ErrJobIdempotencyConflict
		}
		return existing, false, nil
	} else if !errors.Is(findErr, ErrAssessmentSnapshotNotFound) {
		return AssessmentSnapshot{}, false, findErr
	}

	run, chunks, results, err := s.loadSnapshotRun(ctx, request.TenantID, request.RunID)
	if err != nil {
		return AssessmentSnapshot{}, false, err
	}
	createdAt := CanonicalTime(s.now())
	decisions, err := store.ListAssuranceDecisionsByRun(ctx, request.TenantID, request.RunID)
	if err != nil {
		return AssessmentSnapshot{}, false, err
	}
	decisionRefs, selected, err := snapshotDecisionSet(decisions, results, request.TenantID, request.RunID, createdAt)
	if err != nil {
		return AssessmentSnapshot{}, false, err
	}
	decisionSetDigest, err := semanticHash(decisionRefs)
	if err != nil {
		return AssessmentSnapshot{}, false, err
	}
	evidenceIDs := snapshotEvidenceIDs(results, selected)
	evidenceSetDigest, err := semanticHash(evidenceIDs)
	if err != nil {
		return AssessmentSnapshot{}, false, err
	}
	id, err := compliance.NewIdentifier(compliance.IdentifierSnapshot)
	if err != nil {
		return AssessmentSnapshot{}, false, err
	}
	qualified := uint64(0)
	decisionCount := uint64(0)
	for _, ref := range decisionRefs {
		decisionCount++
		if ref.Qualified {
			qualified++
		}
	}
	evidenceCount := uint64(0)
	for range evidenceIDs {
		evidenceCount++
	}
	snapshot := AssessmentSnapshot{
		ID: id, TenantID: run.TenantID, RunID: run.ID, ProgramID: run.ProgramID,
		ScopeRevisionID: run.ScopeRevisionID, PlanRevisionID: run.PlanRevisionID,
		Version: AssessmentSnapshotVersion, InputManifest: NormalizeManifest(*run.InputManifest),
		InputHash: run.InputHash, ResultSetHash: run.AutomatedResultHash, ResultCount: run.ResultCount,
		ResultChunks: snapshotChunkRefs(chunks), DecisionCutoff: createdAt,
		DecisionSetDigest: decisionSetDigest, DecisionCount: decisionCount,
		QualifiedDecisionCount: qualified, MissingDecisionCount: run.ResultCount - decisionCount,
		EvidenceSetDigest: evidenceSetDigest, EvidenceCount: evidenceCount,
		RunCompletedAt: CanonicalTime(run.CompletedAt), CreatedAt: createdAt, CreatedBy: request.CreatedBy,
		RequestHash: requestHash, IdempotencyKey: request.IdempotencyKey,
	}
	snapshot.RecordDigest, err = assessmentSnapshotDigest(snapshot)
	if err != nil {
		return AssessmentSnapshot{}, false, err
	}
	if err := validateAssessmentSnapshot(snapshot); err != nil {
		return AssessmentSnapshot{}, false, err
	}
	payload, err := canonicalBytes(snapshot)
	if err != nil {
		return AssessmentSnapshot{}, false, err
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind:     workflowevents.EventKindComplianceAssessmentSnapshotRecorded,
		TenantID: snapshot.TenantID, AggregateType: "assessment_snapshot", AggregateID: snapshot.ID,
		AggregateVersion: 1, Operation: "assessment_snapshot_recorded", ContentDigest: snapshot.RecordDigest,
		PayloadJSON: string(payload), ActorID: snapshot.CreatedBy, RecordedAt: snapshot.CreatedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		return AssessmentSnapshot{}, false, err
	}
	if err := s.log.Append(ctx, event); err != nil {
		return AssessmentSnapshot{}, false, fmt.Errorf("append assessment snapshot: %w", err)
	}
	if err := store.ApplyAssessmentSnapshot(ctx, event.GetId(), snapshot); err != nil {
		return AssessmentSnapshot{}, false, fmt.Errorf("project assessment snapshot: %w", err)
	}
	return snapshot, true, nil
}

func (s *Service) GetAssessmentSnapshot(ctx context.Context, tenantID, snapshotID string) (AssessmentSnapshot, error) {
	store, ok := s.assessmentSnapshotStore()
	if !ok {
		return AssessmentSnapshot{}, ErrAssessmentSnapshotUnavailable
	}
	snapshot, err := store.GetAssessmentSnapshot(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(snapshotID))
	if err != nil {
		return AssessmentSnapshot{}, err
	}
	if err := validateAssessmentSnapshot(snapshot); err != nil {
		return AssessmentSnapshot{}, fmt.Errorf("%w: persisted snapshot is invalid", ErrAssessmentConflict)
	}
	return snapshot, nil
}

func (s *Service) GetAssessmentSnapshotLens(ctx context.Context, tenantID, snapshotID string, audience AssessmentLensAudience, cursor string, limit uint32) (AssessmentSnapshotLens, error) {
	definition, ok := assessmentLensDefinition(audience)
	if !ok {
		return AssessmentSnapshotLens{}, ErrAssessmentLensNotFound
	}
	snapshot, err := s.GetAssessmentSnapshot(ctx, tenantID, snapshotID)
	if err != nil {
		return AssessmentSnapshotLens{}, err
	}
	store, _ := s.assessmentSnapshotStore()
	_, chunks, results, err := s.loadSnapshotRun(ctx, snapshot.TenantID, snapshot.RunID)
	if err != nil || !snapshotRunMatches(snapshot, chunks, results) {
		return AssessmentSnapshotLens{}, fmt.Errorf("%w: snapshot result commitment no longer verifies", ErrAssessmentConflict)
	}
	decisions, err := store.ListAssuranceDecisionsByRun(ctx, snapshot.TenantID, snapshot.RunID)
	if err != nil {
		return AssessmentSnapshotLens{}, err
	}
	refs, selected, err := snapshotDecisionSet(decisions, results, snapshot.TenantID, snapshot.RunID, snapshot.DecisionCutoff)
	if err != nil {
		return AssessmentSnapshotLens{}, err
	}
	decisionDigest, _ := semanticHash(refs)
	evidenceIDs := snapshotEvidenceIDs(results, selected)
	evidenceDigest, _ := semanticHash(evidenceIDs)
	if decisionDigest != snapshot.DecisionSetDigest || uint64(len(refs)) != snapshot.DecisionCount ||
		evidenceDigest != snapshot.EvidenceSetDigest || uint64(len(evidenceIDs)) != snapshot.EvidenceCount {
		return AssessmentSnapshotLens{}, fmt.Errorf("%w: snapshot decision or evidence commitment no longer verifies", ErrAssessmentConflict)
	}
	items := assessmentLensItems(definition.Audience, results, selected)
	summary := assessmentLensSummary(results, selected)
	start, err := decodeSnapshotLensCursor(cursor, snapshot)
	if err != nil || start > len(items) {
		return AssessmentSnapshotLens{}, fmt.Errorf("%w: invalid lens cursor", ErrInvalidResult)
	}
	if limit == 0 {
		limit = defaultSnapshotLensLimit
	}
	if limit > maxSnapshotLensLimit {
		return AssessmentSnapshotLens{}, fmt.Errorf("%w: lens limit exceeds %d", ErrInvalidResult, maxSnapshotLensLimit)
	}
	end := start + int(limit)
	if end > len(items) {
		end = len(items)
	}
	view := AssessmentSnapshotLens{
		SnapshotID: snapshot.ID, SnapshotDigest: snapshot.RecordDigest, Lens: definition,
		Summary: summary, Signals: assessmentLensSignals(definition.Audience, summary),
		Items: append([]AssessmentLensItem(nil), items[start:end]...), HasMore: end < len(items),
	}
	if view.HasMore {
		view.NextCursor = encodeSnapshotLensCursor(snapshot, end)
	}
	return view, nil
}

func ListAssessmentLenses() []AssessmentLensDefinition {
	result := make([]AssessmentLensDefinition, 0, len(assessmentLensDefinitions))
	for _, audience := range []AssessmentLensAudience{LensAudienceSecurity, LensAudienceAudit, LensAudiencePlatform, LensAudienceLeadership} {
		definition := assessmentLensDefinitions[audience]
		definition.PromotedSignals = append([]string(nil), definition.PromotedSignals...)
		definition.IncludedFields = append([]string(nil), definition.IncludedFields...)
		definition.SuppressedFields = append([]string(nil), definition.SuppressedFields...)
		definition.NextActions = append([]string(nil), definition.NextActions...)
		definition.QuestionStarters = append([]string(nil), definition.QuestionStarters...)
		result = append(result, definition)
	}
	return result
}

func (s *Service) assessmentSnapshotStore() (AssessmentSnapshotStore, bool) {
	if s == nil || s.store == nil {
		return nil, false
	}
	store, ok := s.store.(AssessmentSnapshotStore)
	return store, ok
}

func (s *Service) loadSnapshotRun(ctx context.Context, tenantID, runID string) (AssessmentRun, []ResultChunk, []ObjectiveResult, error) {
	run, err := s.store.GetRun(ctx, tenantID, runID)
	if err != nil {
		return AssessmentRun{}, nil, nil, err
	}
	if run.State != RunComplete || run.InputManifest == nil || run.InputHash == "" || run.AutomatedResultHash == "" || run.CompletedAt.IsZero() {
		return AssessmentRun{}, nil, nil, fmt.Errorf("%w: assessment run is not complete", ErrAssessmentConflict)
	}
	manifest := NormalizeManifest(*run.InputManifest)
	manifestDigest, err := CanonicalManifestDigest(manifest)
	if err != nil || manifestDigest != run.InputHash {
		return AssessmentRun{}, nil, nil, fmt.Errorf("%w: assessment manifest does not match the completed run", ErrAssessmentConflict)
	}
	chunks, results, err := s.loadVerifiedRunResults(ctx, tenantID, run.ID, run.AutomatedResultHash, run.ResultCount)
	return run, chunks, results, err
}

func snapshotDecisionSet(decisions []AssuranceDecision, results []ObjectiveResult, tenantID, runID string, cutoff time.Time) ([]SnapshotDecisionRef, map[string]AssuranceDecision, error) {
	resultIDs := make(map[string]struct{}, len(results))
	for _, result := range results {
		resultIDs[result.ID] = struct{}{}
	}
	selected := map[string]AssuranceDecision{}
	for _, decision := range decisions {
		if decision.RecordedAt.After(cutoff) {
			continue
		}
		if decision.TenantID != tenantID || decision.RunID != runID {
			return nil, nil, fmt.Errorf("%w: assurance decision tenant or run does not match the snapshot", ErrAssessmentConflict)
		}
		if _, ok := resultIDs[decision.ResultID]; !ok || validateAssuranceDecision(decision) != nil {
			return nil, nil, fmt.Errorf("%w: assurance decision does not match the snapshot run", ErrAssessmentConflict)
		}
		current, exists := selected[decision.ResultID]
		if !exists || decision.RecordedAt.After(current.RecordedAt) || (decision.RecordedAt.Equal(current.RecordedAt) && decision.ID > current.ID) {
			selected[decision.ResultID] = decision
		}
	}
	refs := make([]SnapshotDecisionRef, 0, len(selected))
	for resultID, decision := range selected {
		refs = append(refs, SnapshotDecisionRef{
			ResultID: resultID, DecisionID: decision.ID, DecisionDigest: decision.Decision.DecisionDigest,
			RecordDigest: decision.RecordDigest, Qualified: decision.Decision.Qualified,
			AsOf: decision.Decision.AsOf, RecordedAt: decision.RecordedAt,
		})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ResultID < refs[j].ResultID })
	return refs, selected, nil
}

func snapshotEvidenceIDs(results []ObjectiveResult, decisions map[string]AssuranceDecision) []string {
	values := []string{}
	for _, result := range results {
		values = append(values, result.EvidenceIDs...)
		if decision, ok := decisions[result.ID]; ok {
			for _, proof := range decision.InputSnapshot.EvidenceProofs {
				values = append(values, proof.EvidenceID)
			}
		}
	}
	return normalizedStrings(values)
}

func snapshotChunkRefs(chunks []ResultChunk) []SnapshotResultChunkRef {
	refs := make([]SnapshotResultChunkRef, 0, len(chunks))
	for _, chunk := range chunks {
		refs = append(refs, SnapshotResultChunkRef{
			Sequence: chunk.Sequence, FirstResultID: chunk.FirstResultID, LastResultID: chunk.LastResultID,
			Count: chunk.Count, PreviousDigest: chunk.PreviousDigest, Digest: chunk.Digest,
		})
	}
	return refs
}

func snapshotRunMatches(snapshot AssessmentSnapshot, chunks []ResultChunk, results []ObjectiveResult) bool {
	if uint64(len(results)) != snapshot.ResultCount || len(chunks) != len(snapshot.ResultChunks) {
		return false
	}
	setDigest, err := CanonicalResultSetDigest(results)
	if err != nil || setDigest != snapshot.ResultSetHash {
		return false
	}
	want := snapshotChunkRefs(chunks)
	wantBytes, _ := canonicalBytes(want)
	gotBytes, _ := canonicalBytes(snapshot.ResultChunks)
	return string(wantBytes) == string(gotBytes)
}

func assessmentSnapshotDigest(snapshot AssessmentSnapshot) (string, error) {
	snapshot.RecordDigest = ""
	return semanticHash(snapshot)
}

func validateAssessmentSnapshot(snapshot AssessmentSnapshot) error {
	if compliance.ValidateIdentifier(compliance.IdentifierSnapshot, snapshot.ID) != nil || snapshot.TenantID == "" || snapshot.RunID == "" ||
		snapshot.ProgramID == "" || snapshot.ScopeRevisionID == "" || snapshot.PlanRevisionID == "" || snapshot.Version != AssessmentSnapshotVersion ||
		snapshot.ResultCount == 0 || len(snapshot.ResultChunks) == 0 || snapshot.DecisionCutoff.IsZero() || snapshot.RunCompletedAt.IsZero() ||
		snapshot.CreatedAt.IsZero() || snapshot.CreatedBy == "" || snapshot.RequestHash == "" || snapshot.IdempotencyKey == "" || snapshot.RecordDigest == "" {
		return fmt.Errorf("%w: assessment snapshot is incomplete", ErrInvalidResult)
	}
	for _, digest := range []string{snapshot.InputHash, snapshot.ResultSetHash, snapshot.DecisionSetDigest, snapshot.EvidenceSetDigest, snapshot.RequestHash, snapshot.RecordDigest} {
		if compliance.ValidateContentDigest(compliance.ContentDigest(digest)) != nil {
			return fmt.Errorf("%w: assessment snapshot digest is invalid", ErrInvalidResult)
		}
	}
	manifestDigest, err := CanonicalManifestDigest(snapshot.InputManifest)
	if err != nil || manifestDigest != snapshot.InputHash || snapshot.InputManifest.ProgramID != snapshot.ProgramID ||
		snapshot.InputManifest.ScopeRevisionID != snapshot.ScopeRevisionID || snapshot.InputManifest.PlanRevisionID != snapshot.PlanRevisionID {
		return fmt.Errorf("%w: assessment snapshot manifest does not match its identity", ErrInvalidResult)
	}
	var count uint64
	previous := ""
	for index, chunk := range snapshot.ResultChunks {
		if chunk.Sequence != uint32(index+1) || chunk.PreviousDigest != previous || chunk.Count == 0 || chunk.FirstResultID == "" || chunk.LastResultID == "" {
			return fmt.Errorf("%w: assessment snapshot chunk chain is invalid", ErrInvalidResult)
		}
		if compliance.ValidateContentDigest(compliance.ContentDigest(chunk.Digest)) != nil {
			return fmt.Errorf("%w: assessment snapshot chunk digest is invalid", ErrInvalidResult)
		}
		previous = chunk.Digest
		count += uint64(chunk.Count)
	}
	if count != snapshot.ResultCount || snapshot.DecisionCount+snapshot.MissingDecisionCount != snapshot.ResultCount ||
		snapshot.QualifiedDecisionCount > snapshot.DecisionCount || !snapshot.DecisionCutoff.Equal(snapshot.CreatedAt) || snapshot.CreatedAt.Before(snapshot.RunCompletedAt) {
		return fmt.Errorf("%w: assessment snapshot counts or times are inconsistent", ErrInvalidResult)
	}
	digest, err := assessmentSnapshotDigest(snapshot)
	if err != nil || digest != snapshot.RecordDigest {
		return fmt.Errorf("%w: assessment snapshot record digest does not match", ErrInvalidResult)
	}
	return nil
}

var assessmentLensDefinitions = map[AssessmentLensAudience]AssessmentLensDefinition{
	LensAudienceSecurity: {
		ID: "security-action", Version: AssessmentLensVersion, Audience: LensAudienceSecurity,
		FirstQuestion:    "Which control failures need action first, who owns the related work, and what findings make them urgent?",
		PromotedSignals:  []string{"not_satisfied", "missing_decisions", "evidence_gaps"},
		IncludedFields:   []string{"control_ref", "objective_id", "automated_outcome", "assurance", "decision_state", "finding_ids", "next_actions"},
		SuppressedFields: []string{"evidence_ids", "source_runtime_ids"}, WorkQueue: "Unresolved results ordered by outcome, decision state, and control.",
		NextActions:      []string{"Open the canonical work item", "Inspect the affected finding", "Record remediation"},
		QuestionStarters: []string{"Why is this control failing?", "What changed since the prior run?", "Which work item should be handled first?"},
	},
	LensAudienceAudit: {
		ID: "audit-readiness", Version: AssessmentLensVersion, Audience: LensAudienceAudit,
		FirstQuestion:    "Which controls are provable, stale, blocked, or ready for review?",
		PromotedSignals:  []string{"evidence_gaps", "pending_reviews", "missing_decisions"},
		IncludedFields:   []string{"control_ref", "objective_id", "evidence_state", "auditor_state", "decision_id", "decision_as_of", "evidence_ids"},
		SuppressedFields: []string{"finding_ids", "source_runtime_ids"}, WorkQueue: "Evidence gaps and pending reviews ordered before supported controls.",
		NextActions:      []string{"Inspect evidence references", "Complete the required review", "Create an audit package from qualified decisions"},
		QuestionStarters: []string{"Which controls lack current evidence?", "Which decisions are not qualified?", "What is ready for auditor review?"},
	},
	LensAudiencePlatform: {
		ID: "platform-trust", Version: AssessmentLensVersion, Audience: LensAudiencePlatform,
		FirstQuestion:    "Are source runtimes and assessment inputs current enough for teams to trust this result?",
		PromotedSignals:  []string{"evidence_gaps", "not_assessed", "missing_decisions"},
		IncludedFields:   []string{"control_ref", "objective_id", "evidence_state", "source_runtime_ids", "decision_state"},
		SuppressedFields: []string{"evidence_ids", "finding_ids"}, WorkQueue: "Results with missing evidence or unresolved source coverage ordered first.",
		NextActions:      []string{"Inspect source runtime health", "Refresh stale source data", "Run the assessment again"},
		QuestionStarters: []string{"Which sources weakened this assessment?", "Where is evidence incomplete?", "Which results need a fresh run?"},
	},
	LensAudienceLeadership: {
		ID: "leadership-posture", Version: AssessmentLensVersion, Audience: LensAudienceLeadership,
		FirstQuestion:    "What material control exposure needs an owner or review decision?",
		PromotedSignals:  []string{"not_satisfied", "qualified_decisions", "missing_decisions"},
		IncludedFields:   []string{"control_ref", "objective_id", "automated_outcome", "assurance", "decision_state"},
		SuppressedFields: []string{"decision_id", "decision_as_of", "evidence_ids", "finding_ids", "source_runtime_ids", "reason_codes", "next_actions"},
		WorkQueue:        "Material unresolved controls ordered before supported controls.",
		NextActions:      []string{"Assign the follow-up owner", "Review unresolved control exposure", "Confirm the next assessment date"},
		QuestionStarters: []string{"What remains unresolved?", "Which controls lack a qualified decision?", "What needs leadership follow-up?"},
	},
}

func assessmentLensDefinition(audience AssessmentLensAudience) (AssessmentLensDefinition, bool) {
	definition, ok := assessmentLensDefinitions[AssessmentLensAudience(strings.TrimSpace(string(audience)))]
	return definition, ok
}

func assessmentLensSummary(results []ObjectiveResult, decisions map[string]AssuranceDecision) AssessmentLensSummary {
	summary := AssessmentLensSummary{TotalResults: uint64(len(results))}
	for _, result := range results {
		if result.ScopeState == ScopeInScope {
			summary.InScopeResults++
		}
		switch result.AutomatedOutcome {
		case OutcomeSatisfied:
			summary.Satisfied++
		case OutcomeNotSatisfied:
			summary.NotSatisfied++
		default:
			summary.NotAssessed++
		}
		if result.EvidenceState != EvidenceSufficient {
			summary.EvidenceGaps++
		}
		decision, ok := decisions[result.ID]
		if !ok {
			summary.MissingDecisions++
			continue
		}
		if decision.Decision.Qualified {
			summary.QualifiedDecisions++
		}
		for _, review := range decision.Decision.RequiredReviews {
			if review.Required && review.Status != ReviewApproved {
				summary.PendingReviews++
				break
			}
		}
	}
	return summary
}

func assessmentLensItems(audience AssessmentLensAudience, results []ObjectiveResult, decisions map[string]AssuranceDecision) []AssessmentLensItem {
	items := make([]AssessmentLensItem, 0, len(results))
	for _, result := range results {
		item := AssessmentLensItem{
			ResultID: result.ID, ControlRef: result.ControlRef, ObjectiveID: result.ObjectiveID,
			ScopeState: result.ScopeState, AutomatedOutcome: result.AutomatedOutcome, Assurance: result.Assurance,
			EvidenceState: result.EvidenceState, OperatingEffectivenessState: result.OperatingEffectivenessState,
			AuditorState: result.AuditorState, DecisionState: "missing",
		}
		decision, hasDecision := decisions[result.ID]
		if hasDecision {
			item.DecisionState = "unqualified"
			if decision.Decision.Qualified {
				item.DecisionState = "qualified"
			}
			item.DecisionID, item.DecisionAsOf = decision.ID, decision.Decision.AsOf
		}
		switch audience {
		case LensAudienceSecurity:
			item.FindingIDs, item.NextActions = append([]string(nil), result.FindingIDs...), append([]NextAction(nil), result.NextActions...)
		case LensAudienceAudit:
			item.EvidenceIDs = append([]string(nil), result.EvidenceIDs...)
			if hasDecision {
				for _, proof := range decision.InputSnapshot.EvidenceProofs {
					item.EvidenceIDs = append(item.EvidenceIDs, proof.EvidenceID)
				}
			}
			item.EvidenceIDs = normalizedStrings(item.EvidenceIDs)
		case LensAudiencePlatform:
			item.SourceRuntimeIDs = append([]string(nil), result.SourceRuntimeIDs...)
			if hasDecision {
				for _, proof := range decision.InputSnapshot.SourceProofs {
					item.SourceRuntimeIDs = append(item.SourceRuntimeIDs, proof.RuntimeID)
				}
			}
			item.SourceRuntimeIDs = normalizedStrings(item.SourceRuntimeIDs)
		case LensAudienceLeadership:
			item.DecisionID, item.DecisionAsOf = "", time.Time{}
		}
		if audience != LensAudienceLeadership {
			item.ReasonCodes = append([]ReasonCode(nil), result.ReasonCodes...)
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		left, right := lensItemRank(audience, items[i]), lensItemRank(audience, items[j])
		if left != right {
			return left < right
		}
		leftControl := items[i].ControlRef.FrameworkID + "\x00" + items[i].ControlRef.ControlID + "\x00" + items[i].ResultID
		rightControl := items[j].ControlRef.FrameworkID + "\x00" + items[j].ControlRef.ControlID + "\x00" + items[j].ResultID
		return leftControl < rightControl
	})
	return items
}

func lensItemRank(audience AssessmentLensAudience, item AssessmentLensItem) int {
	rank := 0
	switch item.AutomatedOutcome {
	case OutcomeSatisfied:
		rank += 20
	case OutcomeNotAssessed:
		rank += 10
	}
	switch item.DecisionState {
	case "missing":
		rank -= 4
	case "unqualified":
		rank -= 2
	}
	if (audience == LensAudienceAudit || audience == LensAudiencePlatform) && item.EvidenceState != EvidenceSufficient {
		rank -= 8
	}
	return rank
}

func assessmentLensSignals(audience AssessmentLensAudience, summary AssessmentLensSummary) []AssessmentLensSignal {
	values := map[string]uint64{
		"not_satisfied": summary.NotSatisfied, "not_assessed": summary.NotAssessed,
		"qualified_decisions": summary.QualifiedDecisions, "missing_decisions": summary.MissingDecisions,
		"evidence_gaps": summary.EvidenceGaps, "pending_reviews": summary.PendingReviews,
	}
	labels := map[string]string{
		"not_satisfied": "Controls not satisfied", "not_assessed": "Controls not assessed",
		"qualified_decisions": "Qualified decisions", "missing_decisions": "Results without decisions",
		"evidence_gaps": "Results with evidence gaps", "pending_reviews": "Required reviews pending",
	}
	definition, _ := assessmentLensDefinition(audience)
	result := make([]AssessmentLensSignal, 0, len(definition.PromotedSignals))
	for _, key := range definition.PromotedSignals {
		state := "clear"
		if values[key] > 0 && key != "qualified_decisions" {
			state = "attention"
		}
		result = append(result, AssessmentLensSignal{Key: key, Label: labels[key], Value: values[key], State: state})
	}
	return result
}

func encodeSnapshotLensCursor(snapshot AssessmentSnapshot, offset int) string {
	value := snapshot.ID + "\x00" + snapshot.RecordDigest + "\x00" + strconv.Itoa(offset)
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeSnapshotLensCursor(cursor string, snapshot AssessmentSnapshot) (int, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 0, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, err
	}
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) != 3 || parts[0] != snapshot.ID || parts[1] != snapshot.RecordDigest {
		return 0, errors.New("cursor does not match snapshot")
	}
	offset, err := strconv.Atoi(parts[2])
	if err != nil || offset < 0 {
		return 0, errors.New("cursor offset is invalid")
	}
	return offset, nil
}
