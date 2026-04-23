package claims

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type stubRuntimeStore struct {
	runtimes map[string]*cerebrov1.SourceRuntime
}

func (s *stubRuntimeStore) Ping(context.Context) error { return nil }

func (s *stubRuntimeStore) PutSourceRuntime(context.Context, *cerebrov1.SourceRuntime) error {
	return nil
}

func (s *stubRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return proto.Clone(runtime).(*cerebrov1.SourceRuntime), nil
}

type stubClaimStore struct {
	claims map[string]*ports.ClaimRecord
}

func (s *stubClaimStore) Ping(context.Context) error { return nil }

func (s *stubClaimStore) UpsertClaim(_ context.Context, claim *ports.ClaimRecord) (*ports.ClaimRecord, error) {
	if s.claims == nil {
		s.claims = make(map[string]*ports.ClaimRecord)
	}
	s.claims[claim.ID] = cloneClaimRecord(claim)
	return cloneClaimRecord(claim), nil
}

type projectionRecorder struct {
	entities map[string]*ports.ProjectedEntity
	links    map[string]*ports.ProjectedLink
}

func (r *projectionRecorder) Ping(context.Context) error { return nil }

func (r *projectionRecorder) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if r.entities == nil {
		r.entities = make(map[string]*ports.ProjectedEntity)
	}
	r.entities[entity.URN] = cloneProjectedEntity(entity)
	return nil
}

func (r *projectionRecorder) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if r.links == nil {
		r.links = make(map[string]*ports.ProjectedLink)
	}
	r.links[link.FromURN+"|"+link.Relation+"|"+link.ToURN] = cloneProjectedLink(link)
	return nil
}

func TestWriteClaimsPersistsClaimsAndProjectsRelations(t *testing.T) {
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-jira": {
					Id:       "writer-jira",
					SourceId: "sdk",
					TenantId: "writer",
				},
			},
		},
		&stubClaimStore{},
		&projectionRecorder{},
		&projectionRecorder{},
	)
	observedAt := timestamppb.Now()
	issue := &cerebrov1.EntityRef{
		Urn:        "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123",
		EntityType: "ticket",
		Label:      "ENG-123",
	}
	assignee := &cerebrov1.EntityRef{
		Urn:        "urn:cerebro:writer:runtime:writer-jira:user:acct:42",
		EntityType: "user",
		Label:      "Alice",
	}
	project := &cerebrov1.EntityRef{
		Urn:        "urn:cerebro:writer:runtime:writer-jira:project:ENG",
		EntityType: "project",
		Label:      "ENG",
	}

	result, err := service.WriteClaims(context.Background(), WriteRequest{
		RuntimeID: "writer-jira",
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef:    issue,
				Predicate:     "exists",
				ClaimType:     claimTypeExistence,
				ObservedAt:    observedAt,
				SourceEventId: "jira-event-1",
			},
			{
				SubjectRef:    issue,
				Predicate:     "status",
				ObjectValue:   "in_progress",
				ClaimType:     claimTypeAttribute,
				ObservedAt:    observedAt,
				SourceEventId: "jira-event-1",
			},
			{
				SubjectRef:    issue,
				Predicate:     "assigned_to",
				ObjectRef:     assignee,
				ClaimType:     claimTypeRelation,
				ObservedAt:    observedAt,
				SourceEventId: "jira-event-1",
			},
			{
				SubjectRef:    issue,
				Predicate:     "belongs_to",
				ObjectRef:     project,
				ClaimType:     claimTypeRelation,
				ObservedAt:    observedAt,
				SourceEventId: "jira-event-1",
			},
		},
	})
	if err != nil {
		t.Fatalf("WriteClaims() error = %v", err)
	}
	if got := result.ClaimsWritten; got != 4 {
		t.Fatalf("WriteClaims().ClaimsWritten = %d, want 4", got)
	}
	if got := result.EntitiesUpserted; got != 3 {
		t.Fatalf("WriteClaims().EntitiesUpserted = %d, want 3", got)
	}
	if got := result.RelationLinksProjected; got != 2 {
		t.Fatalf("WriteClaims().RelationLinksProjected = %d, want 2", got)
	}

	store := service.store.(*stubClaimStore)
	if len(store.claims) != 4 {
		t.Fatalf("len(claims) = %d, want 4", len(store.claims))
	}
	for _, claim := range store.claims {
		if claim.ID == "" {
			t.Fatal("stored claim id = empty, want non-empty")
		}
		if claim.RuntimeID != "writer-jira" {
			t.Fatalf("stored claim runtime_id = %q, want writer-jira", claim.RuntimeID)
		}
		if claim.TenantID != "writer" {
			t.Fatalf("stored claim tenant_id = %q, want writer", claim.TenantID)
		}
	}

	state := service.state.(*projectionRecorder)
	if len(state.entities) != 3 {
		t.Fatalf("len(state.entities) = %d, want 3", len(state.entities))
	}
	if len(state.links) != 2 {
		t.Fatalf("len(state.links) = %d, want 2", len(state.links))
	}
	link := state.links[issue.GetUrn()+"|assigned_to|"+assignee.GetUrn()]
	if link == nil {
		t.Fatalf("assigned_to link = nil, want non-nil")
	}
	if got := link.Attributes["claim_type"]; got != claimTypeRelation {
		t.Fatalf("assigned_to link claim_type = %q, want %q", got, claimTypeRelation)
	}
	if got := link.Attributes["status"]; got != claimStatusAsserted {
		t.Fatalf("assigned_to link status = %q, want %q", got, claimStatusAsserted)
	}
}

func TestWriteClaimsRequiresAvailableDependencies(t *testing.T) {
	service := New(nil, nil, nil, nil)
	if _, err := service.WriteClaims(context.Background(), WriteRequest{RuntimeID: "writer-jira"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("WriteClaims() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestWriteClaimsRejectsRelationWithoutObjectURN(t *testing.T) {
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-jira": {
					Id:       "writer-jira",
					SourceId: "sdk",
					TenantId: "writer",
				},
			},
		},
		&stubClaimStore{},
		nil,
		nil,
	)
	_, err := service.WriteClaims(context.Background(), WriteRequest{
		RuntimeID: "writer-jira",
		Claims: []*cerebrov1.Claim{
			{
				SubjectUrn: "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123",
				Predicate:  "assigned_to",
				ClaimType:  claimTypeRelation,
			},
		},
	})
	if err == nil {
		t.Fatal("WriteClaims() error = nil, want non-nil")
	}
}

func cloneClaimRecord(claim *ports.ClaimRecord) *ports.ClaimRecord {
	if claim == nil {
		return nil
	}
	attributes := make(map[string]string, len(claim.Attributes))
	for key, value := range claim.Attributes {
		attributes[key] = value
	}
	return &ports.ClaimRecord{
		ID:            claim.ID,
		RuntimeID:     claim.RuntimeID,
		TenantID:      claim.TenantID,
		SubjectURN:    claim.SubjectURN,
		SubjectRef:    cloneEntityRef(claim.SubjectRef),
		Predicate:     claim.Predicate,
		ObjectURN:     claim.ObjectURN,
		ObjectRef:     cloneEntityRef(claim.ObjectRef),
		ObjectValue:   claim.ObjectValue,
		ClaimType:     claim.ClaimType,
		Status:        claim.Status,
		SourceEventID: claim.SourceEventID,
		ObservedAt:    claim.ObservedAt,
		ValidFrom:     claim.ValidFrom,
		ValidTo:       claim.ValidTo,
		Attributes:    attributes,
	}
}

func cloneProjectedEntity(entity *ports.ProjectedEntity) *ports.ProjectedEntity {
	if entity == nil {
		return nil
	}
	return &ports.ProjectedEntity{
		URN:        entity.URN,
		TenantID:   entity.TenantID,
		SourceID:   entity.SourceID,
		EntityType: entity.EntityType,
		Label:      entity.Label,
	}
}

func cloneProjectedLink(link *ports.ProjectedLink) *ports.ProjectedLink {
	if link == nil {
		return nil
	}
	attributes := make(map[string]string, len(link.Attributes))
	for key, value := range link.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedLink{
		TenantID:   link.TenantID,
		SourceID:   link.SourceID,
		FromURN:    link.FromURN,
		Relation:   link.Relation,
		ToURN:      link.ToURN,
		Attributes: attributes,
	}
}
