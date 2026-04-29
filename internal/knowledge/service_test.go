package knowledge

import (
	"context"
	"errors"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

type stubGraphStore struct {
	entities  map[string]*ports.ProjectedEntity
	links     map[string]*ports.ProjectedLink
	upsertErr error
}

func (s *stubGraphStore) Ping(context.Context) error { return nil }

func (s *stubGraphStore) GetEntityNeighborhood(_ context.Context, rootURN string, _ int) (*ports.EntityNeighborhood, error) {
	if entity, ok := s.entities[rootURN]; ok && entity != nil {
		return &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{
				URN:        entity.URN,
				EntityType: entity.EntityType,
				Label:      entity.Label,
			},
		}, nil
	}
	return nil, ports.ErrGraphEntityNotFound
}

func (s *stubGraphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if s.upsertErr != nil {
		return s.upsertErr
	}
	if entity == nil {
		return nil
	}
	if s.entities == nil {
		s.entities = make(map[string]*ports.ProjectedEntity)
	}
	attributes := make(map[string]string, len(entity.Attributes))
	for key, value := range entity.Attributes {
		attributes[key] = value
	}
	s.entities[entity.URN] = &ports.ProjectedEntity{
		URN:        entity.URN,
		TenantID:   entity.TenantID,
		SourceID:   entity.SourceID,
		EntityType: entity.EntityType,
		Label:      entity.Label,
		Attributes: attributes,
	}
	return nil
}

func (s *stubGraphStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if s.upsertErr != nil {
		return s.upsertErr
	}
	if link == nil {
		return nil
	}
	if s.links == nil {
		s.links = make(map[string]*ports.ProjectedLink)
	}
	attributes := make(map[string]string, len(link.Attributes))
	for key, value := range link.Attributes {
		attributes[key] = value
	}
	key := link.FromURN + "|" + link.Relation + "|" + link.ToURN
	s.links[key] = &ports.ProjectedLink{
		TenantID:   link.TenantID,
		SourceID:   link.SourceID,
		FromURN:    link.FromURN,
		ToURN:      link.ToURN,
		Relation:   link.Relation,
		Attributes: attributes,
	}
	return nil
}

type recordingAppendLog struct {
	err    error
	events []*cerebrov1.EventEnvelope
}

func (s *recordingAppendLog) Ping(context.Context) error { return s.err }

func (s *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, event)
	return nil
}

func TestWriteDecisionRecordsDecisionTargetsEvidenceAndActions(t *testing.T) {
	targetURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	store := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			targetURN: {
				URN:        targetURN,
				TenantID:   "writer",
				SourceID:   "okta",
				EntityType: "okta.resource",
				Label:      "Require MFA",
			},
		},
	}
	service := New(store, store)

	result, err := service.WriteDecision(context.Background(), DecisionWriteRequest{
		DecisionType:  "finding-triage",
		Status:        "approved",
		MadeBy:        "secops",
		Rationale:     "accepted risk pending longer-term remediation",
		TargetIDs:     []string{targetURN},
		EvidenceIDs:   []string{"finding-evidence-1"},
		ActionIDs:     []string{"ticket-ENG-123"},
		SourceSystem:  "findings",
		SourceEventID: "finding-1",
		ObservedAt:    time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("WriteDecision() error = %v", err)
	}
	if got := result.TargetCount; got != 1 {
		t.Fatalf("WriteDecision().TargetCount = %d, want 1", got)
	}
	decision, ok := store.entities[result.DecisionID]
	if !ok {
		t.Fatalf("decision entity %q missing", result.DecisionID)
	}
	if got := decision.EntityType; got != decisionEntityType {
		t.Fatalf("decision entity type = %q, want %q", got, decisionEntityType)
	}
	if _, ok := store.links[result.DecisionID+"|"+relationTargets+"|"+targetURN]; !ok {
		t.Fatal("decision target link missing")
	}
	evidenceURN := "urn:cerebro:writer:evidence:finding-evidence-1"
	if _, ok := store.links[result.DecisionID+"|"+relationBasedOn+"|"+evidenceURN]; !ok {
		t.Fatal("decision evidence link missing")
	}
	actionURN := "urn:cerebro:writer:action:ticket-ENG-123"
	if _, ok := store.links[result.DecisionID+"|"+relationExecutedBy+"|"+actionURN]; !ok {
		t.Fatal("decision action link missing")
	}
}

func TestWriteOutcomeRecordsOutcomeAgainstDecision(t *testing.T) {
	targetURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	store := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			targetURN: {
				URN:        targetURN,
				TenantID:   "writer",
				SourceID:   "okta",
				EntityType: "okta.resource",
				Label:      "Require MFA",
			},
		},
	}
	service := New(store, store)
	decision, err := service.WriteDecision(context.Background(), DecisionWriteRequest{
		ID:           "decision-1",
		DecisionType: "finding-triage",
		TargetIDs:    []string{targetURN},
	})
	if err != nil {
		t.Fatalf("WriteDecision() error = %v", err)
	}
	result, err := service.WriteOutcome(context.Background(), OutcomeWriteRequest{
		OutcomeType: "finding-resolution",
		Verdict:     "resolved",
		DecisionID:  decision.DecisionID,
		TargetIDs:   []string{targetURN},
	})
	if err != nil {
		t.Fatalf("WriteOutcome() error = %v", err)
	}
	if got := result.DecisionID; got != decision.DecisionID {
		t.Fatalf("WriteOutcome().DecisionID = %q, want %q", got, decision.DecisionID)
	}
	if _, ok := store.links[result.OutcomeID+"|"+relationEvaluates+"|"+decision.DecisionID]; !ok {
		t.Fatal("outcome evaluates link missing")
	}
	if _, ok := store.links[result.OutcomeID+"|"+relationTargets+"|"+targetURN]; !ok {
		t.Fatal("outcome target link missing")
	}
}

func TestWriteActionRecordsTargetsAndDecisionLink(t *testing.T) {
	targetURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	store := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			targetURN: {
				URN:        targetURN,
				TenantID:   "writer",
				SourceID:   "okta",
				EntityType: "okta.resource",
				Label:      "Require MFA",
			},
		},
	}
	service := New(store, store)
	decision, err := service.WriteDecision(context.Background(), DecisionWriteRequest{
		ID:           "decision-1",
		DecisionType: "finding-triage",
		TargetIDs:    []string{targetURN},
	})
	if err != nil {
		t.Fatalf("WriteDecision() error = %v", err)
	}
	result, err := service.WriteAction(context.Background(), ActionWriteRequest{
		ID:               "action-1",
		RecommendationID: "recommendation-1",
		InsightType:      "remediation",
		Title:            "Open remediation ticket",
		Summary:          "Track the fix in the owning team's backlog",
		DecisionID:       decision.DecisionID,
		TargetIDs:        []string{targetURN},
		SourceSystem:     "platform.recommendations",
		SourceEventID:    "recommendation-evt-1",
		ObservedAt:       time.Date(2026, 4, 27, 13, 0, 0, 0, time.UTC),
		AutoGenerated:    true,
	})
	if err != nil {
		t.Fatalf("WriteAction() error = %v", err)
	}
	if got := result.DecisionID; got != decision.DecisionID {
		t.Fatalf("WriteAction().DecisionID = %q, want %q", got, decision.DecisionID)
	}
	action, ok := store.entities[result.ActionID]
	if !ok {
		t.Fatalf("action entity %q missing", result.ActionID)
	}
	if got := action.Attributes["action_type"]; got != "remediation" {
		t.Fatalf("action type = %q, want remediation", got)
	}
	if got := action.Attributes["status"]; got != defaultActionStatus {
		t.Fatalf("action status = %q, want %q", got, defaultActionStatus)
	}
	if got := action.Attributes["auto_generated"]; got != "true" {
		t.Fatalf("auto_generated = %q, want true", got)
	}
	if _, ok := store.links[result.ActionID+"|"+relationTargets+"|"+targetURN]; !ok {
		t.Fatal("action target link missing")
	}
	if _, ok := store.links[decision.DecisionID+"|"+relationExecutedBy+"|"+result.ActionID]; !ok {
		t.Fatal("decision action link missing")
	}
}

func TestWriteDecisionAppendsWorkflowEventBeforeProjection(t *testing.T) {
	targetURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	store := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			targetURN: {
				URN:        targetURN,
				TenantID:   "writer",
				SourceID:   "okta",
				EntityType: "okta.resource",
				Label:      "Require MFA",
			},
		},
	}
	appendLog := &recordingAppendLog{}
	service := New(store, store).WithAppendLog(appendLog)
	result, err := service.WriteDecision(context.Background(), DecisionWriteRequest{
		ID:           "decision-1",
		DecisionType: "finding-triage",
		TargetIDs:    []string{targetURN},
	})
	if err != nil {
		t.Fatalf("WriteDecision() error = %v", err)
	}
	if len(appendLog.events) != 1 {
		t.Fatalf("len(appendLog.events) = %d, want 1", len(appendLog.events))
	}
	if got := appendLog.events[0].GetKind(); got != workflowevents.EventKindKnowledgeDecisionRecorded {
		t.Fatalf("appended event kind = %q, want %q", got, workflowevents.EventKindKnowledgeDecisionRecorded)
	}
	if got := appendLog.events[0].GetAttributes()[workflowevents.EventAttributeDecisionID]; got != result.DecisionID {
		t.Fatalf("appended decision_id = %q, want %q", got, result.DecisionID)
	}
}

func TestWriteDecisionAppendFailurePreventsGraphProjection(t *testing.T) {
	targetURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	store := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			targetURN: {
				URN:        targetURN,
				TenantID:   "writer",
				SourceID:   "okta",
				EntityType: "okta.resource",
				Label:      "Require MFA",
			},
		},
	}
	appendErr := errors.New("append failed")
	service := New(store, store).WithAppendLog(&recordingAppendLog{err: appendErr})
	if _, err := service.WriteDecision(context.Background(), DecisionWriteRequest{
		ID:           "decision-1",
		DecisionType: "finding-triage",
		TargetIDs:    []string{targetURN},
	}); !errors.Is(err, appendErr) {
		t.Fatalf("WriteDecision() error = %v, want %v", err, appendErr)
	}
	if _, ok := store.entities["urn:cerebro:writer:decision:decision-1"]; ok {
		t.Fatal("decision entity was projected despite append failure")
	}
}

func TestWriteActionProjectionFailureLeavesAppendedWorkflowEvent(t *testing.T) {
	targetURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	store := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			targetURN: {
				URN:        targetURN,
				TenantID:   "writer",
				SourceID:   "okta",
				EntityType: "okta.resource",
				Label:      "Require MFA",
			},
		},
	}
	service := New(store, store)
	decision, err := service.WriteDecision(context.Background(), DecisionWriteRequest{
		ID:           "decision-1",
		DecisionType: "finding-triage",
		TargetIDs:    []string{targetURN},
	})
	if err != nil {
		t.Fatalf("WriteDecision() error = %v", err)
	}
	upsertErr := errors.New("graph failed")
	store.upsertErr = upsertErr
	appendLog := &recordingAppendLog{}
	if _, err := service.WithAppendLog(appendLog).WriteAction(context.Background(), ActionWriteRequest{
		ID:          "action-1",
		InsightType: "remediation",
		Title:       "Open remediation ticket",
		DecisionID:  decision.DecisionID,
		TargetIDs:   []string{targetURN},
	}); !errors.Is(err, upsertErr) {
		t.Fatalf("WriteAction() error = %v, want %v", err, upsertErr)
	}
	if len(appendLog.events) != 1 {
		t.Fatalf("len(appendLog.events) = %d, want 1", len(appendLog.events))
	}
	if got := appendLog.events[0].GetKind(); got != workflowevents.EventKindKnowledgeActionRecorded {
		t.Fatalf("appended event kind = %q, want %q", got, workflowevents.EventKindKnowledgeActionRecorded)
	}
}

func TestWriteDecisionRequiresAvailableGraph(t *testing.T) {
	service := New(nil, nil)
	if _, err := service.WriteDecision(context.Background(), DecisionWriteRequest{
		DecisionType: "finding-triage",
		TargetIDs:    []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
	}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("WriteDecision() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}
