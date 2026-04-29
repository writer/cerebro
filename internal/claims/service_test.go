package claims

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

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
	claims      map[string]*ports.ClaimRecord
	listRequest ports.ListClaimsRequest
	err         error
}

func (s *stubClaimStore) Ping(context.Context) error { return nil }

func (s *stubClaimStore) UpsertClaim(_ context.Context, claim *ports.ClaimRecord) (*ports.ClaimRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.claims == nil {
		s.claims = make(map[string]*ports.ClaimRecord)
	}
	s.claims[claim.ID] = cloneClaimRecord(claim)
	return cloneClaimRecord(claim), nil
}

func (s *stubClaimStore) ListClaims(_ context.Context, request ports.ListClaimsRequest) ([]*ports.ClaimRecord, error) {
	s.listRequest = request
	claims := make([]*ports.ClaimRecord, 0, len(s.claims))
	for _, claim := range s.claims {
		if !claimMatches(request, claim) {
			continue
		}
		claims = append(claims, cloneClaimRecord(claim))
	}
	sort.Slice(claims, func(i, j int) bool {
		left := claims[i]
		right := claims[j]
		switch {
		case left.ObservedAt.Equal(right.ObservedAt):
			return left.ID < right.ID
		case left.ObservedAt.IsZero():
			return false
		case right.ObservedAt.IsZero():
			return true
		default:
			return left.ObservedAt.After(right.ObservedAt)
		}
	})
	if request.Limit != 0 && len(claims) > int(request.Limit) {
		claims = claims[:int(request.Limit)]
	}
	return claims, nil
}

type projectionRecorder struct {
	entities     map[string]*ports.ProjectedEntity
	links        map[string]*ports.ProjectedLink
	deletedLinks map[string]*ports.ProjectedLink
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

func (r *projectionRecorder) DeleteProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if r.deletedLinks == nil {
		r.deletedLinks = make(map[string]*ports.ProjectedLink)
	}
	r.deletedLinks[link.FromURN+"|"+link.Relation+"|"+link.ToURN] = cloneProjectedLink(link)
	return nil
}

func TestClaimRecordAllowsNilTimestamps(t *testing.T) {
	record := claimRecord(&cerebrov1.SourceRuntime{
		Id:       "writer-jira",
		TenantId: "writer",
	}, &cerebrov1.Claim{
		Id:         "claim-1",
		SubjectUrn: "urn:cerebro:writer:ticket:ENG-123",
		Predicate:  "exists",
		ClaimType:  claimTypeExistence,
	})
	if record == nil {
		t.Fatal("claimRecord() = nil, want record")
	}
	if !record.ObservedAt.IsZero() || !record.ValidFrom.IsZero() || !record.ValidTo.IsZero() {
		t.Fatalf("claimRecord() timestamps = [%v %v %v], want zero values", record.ObservedAt, record.ValidFrom, record.ValidTo)
	}
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

func TestWriteClaimsReplaceExistingRetractsOmittedClaims(t *testing.T) {
	issueURN := "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123"
	assigneeURN := "urn:cerebro:writer:runtime:writer-jira:user:acct:42"
	observedAt := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)
	statusID := hashClaimID("writer-jira", claimTypeAttribute, issueURN, "status", "in_progress")
	assigneeID := hashClaimID("writer-jira", claimTypeRelation, issueURN, "assigned_to", assigneeURN)
	store := &stubClaimStore{
		claims: map[string]*ports.ClaimRecord{
			statusID: {
				ID:            statusID,
				RuntimeID:     "writer-jira",
				TenantID:      "writer",
				SubjectURN:    issueURN,
				Predicate:     "status",
				ObjectValue:   "in_progress",
				ClaimType:     claimTypeAttribute,
				Status:        claimStatusAsserted,
				SourceEventID: "jira-event-1",
				ObservedAt:    observedAt.Add(-time.Hour),
			},
			assigneeID: {
				ID:            assigneeID,
				RuntimeID:     "writer-jira",
				TenantID:      "writer",
				SubjectURN:    issueURN,
				Predicate:     "assigned_to",
				ObjectURN:     assigneeURN,
				ObjectRef:     &cerebrov1.EntityRef{Urn: assigneeURN, EntityType: "user", Label: "Alice"},
				ClaimType:     claimTypeRelation,
				Status:        claimStatusAsserted,
				SourceEventID: "jira-event-1",
				ObservedAt:    observedAt.Add(-time.Hour),
			},
		},
	}
	projection := &projectionRecorder{}
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
		store,
		projection,
		projection,
	)

	result, err := service.WriteClaims(context.Background(), WriteRequest{
		RuntimeID:       "writer-jira",
		ReplaceExisting: true,
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef: &cerebrov1.EntityRef{
					Urn:        issueURN,
					EntityType: "ticket",
					Label:      "ENG-123",
				},
				Predicate:     "status",
				ObjectValue:   "done",
				ClaimType:     claimTypeAttribute,
				ObservedAt:    timestamppb.New(observedAt),
				SourceEventId: "jira-event-2",
			},
		},
	})
	if err != nil {
		t.Fatalf("WriteClaims() error = %v", err)
	}
	if got := result.ClaimsWritten; got != 1 {
		t.Fatalf("WriteClaims().ClaimsWritten = %d, want 1", got)
	}
	if got := result.ClaimsRetracted; got != 2 {
		t.Fatalf("WriteClaims().ClaimsRetracted = %d, want 2", got)
	}
	if got := store.listRequest.RuntimeID; got != "writer-jira" {
		t.Fatalf("retract list runtime_id = %q, want writer-jira", got)
	}
	if got := store.listRequest.Status; got != claimStatusAsserted {
		t.Fatalf("retract list status = %q, want %q", got, claimStatusAsserted)
	}
	retracted := store.claims[assigneeID]
	if retracted == nil {
		t.Fatal("retracted claim = nil, want non-nil")
	}
	if got := retracted.Status; got != claimStatusRetracted {
		t.Fatalf("retracted claim status = %q, want %q", got, claimStatusRetracted)
	}
	if got := retracted.SourceEventID; got != "jira-event-2" {
		t.Fatalf("retracted claim source_event_id = %q, want jira-event-2", got)
	}
	if !retracted.ValidTo.Equal(observedAt) {
		t.Fatalf("retracted claim valid_to = %v, want %v", retracted.ValidTo, observedAt)
	}
	if _, ok := projection.deletedLinks[issueURN+"|assigned_to|"+assigneeURN]; !ok {
		t.Fatalf("deleted projected link missing for retracted relation")
	}
}

func TestWriteClaimsRetractedRelationDeletesProjectedLink(t *testing.T) {
	issueURN := "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123"
	assigneeURN := "urn:cerebro:writer:runtime:writer-jira:user:acct:42"
	projection := &projectionRecorder{}
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
		projection,
		projection,
	)

	result, err := service.WriteClaims(context.Background(), WriteRequest{
		RuntimeID: "writer-jira",
		Claims: []*cerebrov1.Claim{
			{
				SubjectUrn:    issueURN,
				Predicate:     "assigned_to",
				ObjectUrn:     assigneeURN,
				ClaimType:     claimTypeRelation,
				Status:        claimStatusRetracted,
				SourceEventId: "jira-event-3",
			},
		},
	})
	if err != nil {
		t.Fatalf("WriteClaims() error = %v", err)
	}
	if got := result.RelationLinksProjected; got != 0 {
		t.Fatalf("WriteClaims().RelationLinksProjected = %d, want 0", got)
	}
	if _, ok := projection.links[issueURN+"|assigned_to|"+assigneeURN]; ok {
		t.Fatal("projected link was upserted for retracted relation")
	}
	if _, ok := projection.deletedLinks[issueURN+"|assigned_to|"+assigneeURN]; !ok {
		t.Fatal("deleted projected link missing for explicitly retracted relation")
	}
}

func TestWriteClaimsRequiresAvailableDependencies(t *testing.T) {
	service := New(nil, nil, nil, nil)
	if _, err := service.WriteClaims(context.Background(), WriteRequest{RuntimeID: "writer-jira"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("WriteClaims() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestListClaimsReturnsFilteredProtoClaims(t *testing.T) {
	store := &stubClaimStore{
		claims: map[string]*ports.ClaimRecord{
			"claim-status": {
				ID:            "claim-status",
				RuntimeID:     "writer-jira",
				TenantID:      "writer",
				SubjectURN:    "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123",
				Predicate:     "status",
				ObjectValue:   "in_progress",
				ClaimType:     claimTypeAttribute,
				Status:        claimStatusAsserted,
				SourceEventID: "jira-event-1",
				ObservedAt:    timeFromProto(timestamppb.New(timestamppb.Now().AsTime().Add(-time.Minute))),
			},
			"claim-assignee": {
				ID:            "claim-assignee",
				RuntimeID:     "writer-jira",
				TenantID:      "writer",
				SubjectURN:    "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123",
				Predicate:     "assigned_to",
				ObjectURN:     "urn:cerebro:writer:runtime:writer-jira:user:acct:42",
				ClaimType:     claimTypeRelation,
				Status:        claimStatusAsserted,
				SourceEventID: "jira-event-2",
				ObservedAt:    timeFromProto(timestamppb.Now()),
			},
		},
	}
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
		store,
		nil,
		nil,
	)

	response, err := service.ListClaims(context.Background(), ListRequest{
		RuntimeID:     "writer-jira",
		Predicate:     "status",
		ObjectValue:   "in_progress",
		SourceEventID: "jira-event-1",
		Limit:         1,
	})
	if err != nil {
		t.Fatalf("ListClaims() error = %v", err)
	}
	if got := len(response.Claims); got != 1 {
		t.Fatalf("len(ListClaims().Claims) = %d, want 1", got)
	}
	if got := response.Claims[0].GetPredicate(); got != "status" {
		t.Fatalf("ListClaims().Claims[0].Predicate = %q, want status", got)
	}
	if got := response.Claims[0].GetObjectValue(); got != "in_progress" {
		t.Fatalf("ListClaims().Claims[0].ObjectValue = %q, want in_progress", got)
	}
	if got := store.listRequest.RuntimeID; got != "writer-jira" {
		t.Fatalf("ListClaims().RuntimeID = %q, want writer-jira", got)
	}
	if got := store.listRequest.Predicate; got != "status" {
		t.Fatalf("ListClaims().Predicate = %q, want status", got)
	}
	if got := store.listRequest.ObjectValue; got != "in_progress" {
		t.Fatalf("ListClaims().ObjectValue = %q, want in_progress", got)
	}
	if got := store.listRequest.SourceEventID; got != "jira-event-1" {
		t.Fatalf("ListClaims().SourceEventID = %q, want jira-event-1", got)
	}
	if got := store.listRequest.Limit; got != 1 {
		t.Fatalf("ListClaims().Limit = %d, want 1", got)
	}
}

func TestListClaimsRequiresAvailableDependencies(t *testing.T) {
	service := New(nil, nil, nil, nil)
	if _, err := service.ListClaims(context.Background(), ListRequest{RuntimeID: "writer-jira"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("ListClaims() error = %v, want %v", err, ErrRuntimeUnavailable)
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

func TestWriteClaimsDoesNotProjectWhenPersistenceFails(t *testing.T) {
	state := &projectionRecorder{}
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
		&stubClaimStore{err: errors.New("persist failed")},
		state,
		nil,
	)

	_, err := service.WriteClaims(context.Background(), WriteRequest{
		RuntimeID: "writer-jira",
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef: &cerebrov1.EntityRef{
					Urn:        "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123",
					EntityType: "ticket",
				},
				Predicate:   "status",
				ObjectValue: "in_progress",
				ClaimType:   claimTypeAttribute,
			},
		},
	})
	if err == nil {
		t.Fatal("WriteClaims() error = nil, want non-nil")
	}
	if len(state.entities) != 0 {
		t.Fatalf("len(state.entities) = %d, want 0", len(state.entities))
	}
	if len(state.links) != 0 {
		t.Fatalf("len(state.links) = %d, want 0", len(state.links))
	}
}

func TestNormalizeClaimIDIncludesObjectIdentity(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "writer-jira"}
	first, err := normalizeClaim(&cerebrov1.Claim{
		SubjectUrn: "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123",
		Predicate:  "assigned_to",
		ObjectUrn:  "urn:cerebro:writer:runtime:writer-jira:user:alice",
		ClaimType:  claimTypeRelation,
	}, runtime)
	if err != nil {
		t.Fatalf("normalizeClaim(first) error = %v", err)
	}
	second, err := normalizeClaim(&cerebrov1.Claim{
		SubjectUrn: "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123",
		Predicate:  "assigned_to",
		ObjectUrn:  "urn:cerebro:writer:runtime:writer-jira:user:bob",
		ClaimType:  claimTypeRelation,
	}, runtime)
	if err != nil {
		t.Fatalf("normalizeClaim(second) error = %v", err)
	}
	if first.GetId() == second.GetId() {
		t.Fatalf("relation claim ids collided: %q", first.GetId())
	}

	attrFirst, err := normalizeClaim(&cerebrov1.Claim{
		SubjectUrn:  "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123",
		Predicate:   "status",
		ObjectValue: "open",
		ClaimType:   claimTypeAttribute,
	}, runtime)
	if err != nil {
		t.Fatalf("normalizeClaim(attrFirst) error = %v", err)
	}
	attrSecond, err := normalizeClaim(&cerebrov1.Claim{
		SubjectUrn:  "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123",
		Predicate:   "status",
		ObjectValue: "closed",
		ClaimType:   claimTypeAttribute,
	}, runtime)
	if err != nil {
		t.Fatalf("normalizeClaim(attrSecond) error = %v", err)
	}
	if attrFirst.GetId() == attrSecond.GetId() {
		t.Fatalf("attribute claim ids collided: %q", attrFirst.GetId())
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

func claimMatches(request ports.ListClaimsRequest, claim *ports.ClaimRecord) bool {
	if claim == nil {
		return false
	}
	if strings.TrimSpace(claim.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.ClaimID != "" && strings.TrimSpace(claim.ID) != strings.TrimSpace(request.ClaimID) {
		return false
	}
	if request.SubjectURN != "" && strings.TrimSpace(claim.SubjectURN) != strings.TrimSpace(request.SubjectURN) {
		return false
	}
	if request.Predicate != "" && strings.TrimSpace(claim.Predicate) != strings.TrimSpace(request.Predicate) {
		return false
	}
	if request.ObjectURN != "" && strings.TrimSpace(claim.ObjectURN) != strings.TrimSpace(request.ObjectURN) {
		return false
	}
	if request.ObjectValue != "" && strings.TrimSpace(claim.ObjectValue) != strings.TrimSpace(request.ObjectValue) {
		return false
	}
	if request.ClaimType != "" && strings.TrimSpace(claim.ClaimType) != strings.TrimSpace(request.ClaimType) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(claim.Status) != strings.TrimSpace(request.Status) {
		return false
	}
	if request.SourceEventID != "" && strings.TrimSpace(claim.SourceEventID) != strings.TrimSpace(request.SourceEventID) {
		return false
	}
	return true
}

func timeFromProto(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.AsTime().UTC()
}
