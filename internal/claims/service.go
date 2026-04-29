package claims

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	claimTypeExistence      = "existence"
	claimTypeAttribute      = "attribute"
	claimTypeRelation       = "relation"
	claimTypeClassification = "classification"
	claimStatusAsserted     = "asserted"
)

// ErrRuntimeUnavailable indicates that the runtime or claim store boundary is unavailable.
var ErrRuntimeUnavailable = errors.New("claim runtime is unavailable")

// Service reads and writes runtime-scoped claims into the state store and optional projections.
type Service struct {
	runtimeStore ports.SourceRuntimeStore
	store        ports.ClaimStore
	state        ports.ProjectionStateStore
	graph        ports.ProjectionGraphStore
}

// WriteRequest scopes one runtime-scoped claim batch.
type WriteRequest struct {
	RuntimeID string
	Claims    []*cerebrov1.Claim
}

// WriteResult reports one claim batch write.
type WriteResult struct {
	ClaimsWritten          uint32
	EntitiesUpserted       uint32
	RelationLinksProjected uint32
}

// ListRequest scopes one runtime-scoped claim query.
type ListRequest struct {
	RuntimeID   string
	ClaimID     string
	SubjectURN  string
	Predicate   string
	ObjectURN   string
	ObjectValue string
	ClaimType   string
	Status      string
	Limit       uint32
}

// ListResult reports one runtime-scoped claim query.
type ListResult struct {
	Claims []*cerebrov1.Claim
}

// New constructs a claim write service.
func New(runtimeStore ports.SourceRuntimeStore, store ports.ClaimStore, state ports.ProjectionStateStore, graph ports.ProjectionGraphStore) *Service {
	return &Service{
		runtimeStore: runtimeStore,
		store:        store,
		state:        state,
		graph:        graph,
	}
}

// WriteClaims persists one runtime-scoped claim batch.
func (s *Service) WriteClaims(ctx context.Context, request WriteRequest) (*WriteResult, error) {
	if s == nil || s.runtimeStore == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("source runtime id is required")
	}
	runtime, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return nil, err
	}
	result := &WriteResult{}
	upsertedEntities := make(map[string]struct{})
	upsertedLinks := make(map[string]struct{})
	for index, raw := range request.Claims {
		claim, err := normalizeClaim(raw, runtime)
		if err != nil {
			return nil, fmt.Errorf("normalize claim %d: %w", index, err)
		}
		if _, err := s.store.UpsertClaim(ctx, claimRecord(runtime, claim)); err != nil {
			return nil, fmt.Errorf("persist claim %q: %w", claim.GetId(), err)
		}
		result.ClaimsWritten++
		if entity := projectedEntity(runtime, claim.GetSubjectRef(), claim.GetSubjectUrn()); entity != nil {
			wrote, err := s.upsertEntity(ctx, entity, upsertedEntities)
			if err != nil {
				return nil, err
			}
			if wrote {
				result.EntitiesUpserted++
			}
		}
		if entity := projectedEntity(runtime, claim.GetObjectRef(), claim.GetObjectUrn()); entity != nil {
			wrote, err := s.upsertEntity(ctx, entity, upsertedEntities)
			if err != nil {
				return nil, err
			}
			if wrote {
				result.EntitiesUpserted++
			}
		}
		if projected := projectedRelation(runtime, claim); projected != nil {
			wrote, err := s.upsertLink(ctx, projected, upsertedLinks)
			if err != nil {
				return nil, err
			}
			if wrote {
				result.RelationLinksProjected++
			}
		}
	}
	return result, nil
}

// ListClaims loads persisted claims for one runtime.
func (s *Service) ListClaims(ctx context.Context, request ListRequest) (*ListResult, error) {
	if s == nil || s.runtimeStore == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("source runtime id is required")
	}
	if _, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID); err != nil {
		return nil, err
	}
	records, err := s.store.ListClaims(ctx, ports.ListClaimsRequest{
		RuntimeID:   runtimeID,
		ClaimID:     strings.TrimSpace(request.ClaimID),
		SubjectURN:  strings.TrimSpace(request.SubjectURN),
		Predicate:   strings.TrimSpace(request.Predicate),
		ObjectURN:   strings.TrimSpace(request.ObjectURN),
		ObjectValue: strings.TrimSpace(request.ObjectValue),
		ClaimType:   strings.TrimSpace(request.ClaimType),
		Status:      strings.TrimSpace(request.Status),
		Limit:       request.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list claims for runtime %q: %w", runtimeID, err)
	}
	response := &ListResult{Claims: make([]*cerebrov1.Claim, 0, len(records))}
	for _, record := range records {
		if record == nil {
			continue
		}
		response.Claims = append(response.Claims, protoClaim(record))
	}
	return response, nil
}

func (s *Service) upsertEntity(ctx context.Context, entity *ports.ProjectedEntity, seen map[string]struct{}) (bool, error) {
	if entity == nil {
		return false, nil
	}
	if _, ok := seen[entity.URN]; ok {
		return false, nil
	}
	if s.state == nil && s.graph == nil {
		return false, nil
	}
	if s.state != nil {
		if err := s.state.UpsertProjectedEntity(ctx, entity); err != nil {
			return false, fmt.Errorf("upsert projected entity %q: %w", entity.URN, err)
		}
	}
	if s.graph != nil {
		if err := s.graph.UpsertProjectedEntity(ctx, entity); err != nil {
			return false, fmt.Errorf("upsert graph entity %q: %w", entity.URN, err)
		}
	}
	seen[entity.URN] = struct{}{}
	return true, nil
}

func (s *Service) upsertLink(ctx context.Context, link *ports.ProjectedLink, seen map[string]struct{}) (bool, error) {
	if link == nil {
		return false, nil
	}
	key := link.FromURN + "|" + link.Relation + "|" + link.ToURN
	if _, ok := seen[key]; ok {
		return false, nil
	}
	if s.state == nil && s.graph == nil {
		return false, nil
	}
	if s.state != nil {
		if err := s.state.UpsertProjectedLink(ctx, link); err != nil {
			return false, fmt.Errorf("upsert projected link %q: %w", key, err)
		}
	}
	if s.graph != nil {
		if err := s.graph.UpsertProjectedLink(ctx, link); err != nil {
			return false, fmt.Errorf("upsert graph link %q: %w", key, err)
		}
	}
	seen[key] = struct{}{}
	return true, nil
}

func normalizeClaim(claim *cerebrov1.Claim, runtime *cerebrov1.SourceRuntime) (*cerebrov1.Claim, error) {
	if claim == nil {
		return nil, errors.New("claim is required")
	}
	if runtime == nil {
		return nil, errors.New("source runtime is required")
	}
	normalized := proto.Clone(claim).(*cerebrov1.Claim)
	normalized.SubjectUrn = strings.TrimSpace(normalized.GetSubjectUrn())
	normalized.Predicate = strings.TrimSpace(normalized.GetPredicate())
	normalized.ObjectUrn = strings.TrimSpace(normalized.GetObjectUrn())
	normalized.ObjectValue = strings.TrimSpace(normalized.GetObjectValue())
	normalized.ClaimType = strings.TrimSpace(normalized.GetClaimType())
	normalized.Status = strings.TrimSpace(normalized.GetStatus())
	normalized.SourceEventId = strings.TrimSpace(normalized.GetSourceEventId())
	normalized.SubjectRef = normalizeEntityRef(normalized.GetSubjectRef(), normalized.GetSubjectUrn())
	normalized.ObjectRef = normalizeEntityRef(normalized.GetObjectRef(), normalized.GetObjectUrn())
	if normalized.GetSubjectUrn() == "" && normalized.GetSubjectRef() != nil {
		normalized.SubjectUrn = strings.TrimSpace(normalized.GetSubjectRef().GetUrn())
	}
	if normalized.GetObjectUrn() == "" && normalized.GetObjectRef() != nil {
		normalized.ObjectUrn = strings.TrimSpace(normalized.GetObjectRef().GetUrn())
	}
	if normalized.GetSubjectUrn() == "" {
		return nil, errors.New("claim subject urn is required")
	}
	if normalized.GetPredicate() == "" {
		return nil, errors.New("claim predicate is required")
	}
	if normalized.GetClaimType() == "" {
		normalized.ClaimType = inferClaimType(normalized)
	}
	if normalized.GetStatus() == "" {
		normalized.Status = claimStatusAsserted
	}
	switch normalized.GetClaimType() {
	case claimTypeExistence:
	case claimTypeAttribute, claimTypeClassification:
		if normalized.GetObjectValue() == "" {
			return nil, fmt.Errorf("claim object value is required when claim_type=%q", normalized.GetClaimType())
		}
	case claimTypeRelation:
		if normalized.GetObjectUrn() == "" {
			return nil, fmt.Errorf("claim object urn is required when claim_type=%q", normalized.GetClaimType())
		}
	default:
		return nil, fmt.Errorf("unsupported claim type %q", normalized.GetClaimType())
	}
	if normalized.GetId() == "" {
		normalized.Id = hashClaimID(strings.TrimSpace(runtime.GetId()), normalized.GetClaimType(), normalized.GetSubjectUrn(), normalized.GetPredicate(), claimIdentityObject(normalized))
	}
	normalized.Attributes = trimAttributes(normalized.GetAttributes())
	return normalized, nil
}

func normalizeEntityRef(ref *cerebrov1.EntityRef, fallbackURN string) *cerebrov1.EntityRef {
	if ref == nil {
		return nil
	}
	normalized := proto.Clone(ref).(*cerebrov1.EntityRef)
	normalized.Urn = strings.TrimSpace(normalized.GetUrn())
	normalized.EntityType = strings.TrimSpace(normalized.GetEntityType())
	normalized.Label = strings.TrimSpace(normalized.GetLabel())
	if normalized.GetUrn() == "" {
		normalized.Urn = strings.TrimSpace(fallbackURN)
	}
	if normalized.GetUrn() == "" && normalized.GetEntityType() == "" && normalized.GetLabel() == "" {
		return nil
	}
	return normalized
}

func inferClaimType(claim *cerebrov1.Claim) string {
	switch {
	case strings.TrimSpace(claim.GetObjectUrn()) != "" || claim.GetObjectRef() != nil:
		return claimTypeRelation
	case strings.TrimSpace(claim.GetObjectValue()) != "":
		return claimTypeAttribute
	default:
		return claimTypeExistence
	}
}

func claimIdentityObject(claim *cerebrov1.Claim) string {
	switch claim.GetClaimType() {
	case claimTypeRelation:
		return claim.GetObjectUrn()
	case claimTypeAttribute, claimTypeClassification:
		return claim.GetObjectValue()
	default:
		return ""
	}
}

func hashClaimID(runtimeID string, claimType string, subjectURN string, predicate string, objectIdentity string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(runtimeID),
		strings.TrimSpace(claimType),
		strings.TrimSpace(subjectURN),
		strings.TrimSpace(predicate),
		strings.TrimSpace(objectIdentity),
	}, "\x00")))
	return "claim_" + hex.EncodeToString(sum[:])
}

func trimAttributes(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	trimmed := make(map[string]string, len(attributes))
	for key, value := range attributes {
		normalizedKey := strings.TrimSpace(key)
		normalizedValue := strings.TrimSpace(value)
		if normalizedKey == "" || normalizedValue == "" {
			continue
		}
		trimmed[normalizedKey] = normalizedValue
	}
	if len(trimmed) == 0 {
		return nil
	}
	return trimmed
}

func projectedEntity(runtime *cerebrov1.SourceRuntime, ref *cerebrov1.EntityRef, fallbackURN string) *ports.ProjectedEntity {
	normalized := normalizeEntityRef(ref, fallbackURN)
	if runtime == nil || normalized == nil {
		return nil
	}
	if strings.TrimSpace(normalized.GetUrn()) == "" || strings.TrimSpace(normalized.GetEntityType()) == "" {
		return nil
	}
	label := strings.TrimSpace(normalized.GetLabel())
	if label == "" {
		label = strings.TrimSpace(normalized.GetUrn())
	}
	return &ports.ProjectedEntity{
		URN:        strings.TrimSpace(normalized.GetUrn()),
		TenantID:   strings.TrimSpace(runtime.GetTenantId()),
		SourceID:   strings.TrimSpace(runtime.GetSourceId()),
		EntityType: strings.TrimSpace(normalized.GetEntityType()),
		Label:      label,
	}
}

func projectedRelation(runtime *cerebrov1.SourceRuntime, claim *cerebrov1.Claim) *ports.ProjectedLink {
	if runtime == nil || claim == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(claim.GetClaimType()), claimTypeRelation) {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(claim.GetStatus()), claimStatusAsserted) {
		return nil
	}
	fromURN := strings.TrimSpace(claim.GetSubjectUrn())
	relation := strings.TrimSpace(claim.GetPredicate())
	toURN := strings.TrimSpace(claim.GetObjectUrn())
	if fromURN == "" || relation == "" || toURN == "" {
		return nil
	}
	attributes := trimAttributes(claim.GetAttributes())
	if len(attributes) == 0 {
		attributes = make(map[string]string, 4)
	}
	attributes["claim_id"] = strings.TrimSpace(claim.GetId())
	attributes["claim_type"] = strings.TrimSpace(claim.GetClaimType())
	attributes["status"] = strings.TrimSpace(claim.GetStatus())
	if sourceEventID := strings.TrimSpace(claim.GetSourceEventId()); sourceEventID != "" {
		attributes["source_event_id"] = sourceEventID
	}
	return &ports.ProjectedLink{
		TenantID:   strings.TrimSpace(runtime.GetTenantId()),
		SourceID:   strings.TrimSpace(runtime.GetSourceId()),
		FromURN:    fromURN,
		Relation:   relation,
		ToURN:      toURN,
		Attributes: attributes,
	}
}

func claimRecord(runtime *cerebrov1.SourceRuntime, claim *cerebrov1.Claim) *ports.ClaimRecord {
	if runtime == nil || claim == nil {
		return nil
	}
	return &ports.ClaimRecord{
		ID:            strings.TrimSpace(claim.GetId()),
		RuntimeID:     strings.TrimSpace(runtime.GetId()),
		TenantID:      strings.TrimSpace(runtime.GetTenantId()),
		SubjectURN:    strings.TrimSpace(claim.GetSubjectUrn()),
		SubjectRef:    cloneEntityRef(claim.GetSubjectRef()),
		Predicate:     strings.TrimSpace(claim.GetPredicate()),
		ObjectURN:     strings.TrimSpace(claim.GetObjectUrn()),
		ObjectRef:     cloneEntityRef(claim.GetObjectRef()),
		ObjectValue:   strings.TrimSpace(claim.GetObjectValue()),
		ClaimType:     strings.TrimSpace(claim.GetClaimType()),
		Status:        strings.TrimSpace(claim.GetStatus()),
		SourceEventID: strings.TrimSpace(claim.GetSourceEventId()),
		ObservedAt:    claimTime(claim.GetObservedAt()),
		ValidFrom:     claimTime(claim.GetValidFrom()),
		ValidTo:       claimTime(claim.GetValidTo()),
		Attributes:    trimAttributes(claim.GetAttributes()),
	}
}

func protoClaim(record *ports.ClaimRecord) *cerebrov1.Claim {
	if record == nil {
		return nil
	}
	claim := &cerebrov1.Claim{
		Id:            strings.TrimSpace(record.ID),
		SubjectUrn:    strings.TrimSpace(record.SubjectURN),
		SubjectRef:    cloneEntityRef(record.SubjectRef),
		Predicate:     strings.TrimSpace(record.Predicate),
		ObjectUrn:     strings.TrimSpace(record.ObjectURN),
		ObjectRef:     cloneEntityRef(record.ObjectRef),
		ObjectValue:   strings.TrimSpace(record.ObjectValue),
		ClaimType:     strings.TrimSpace(record.ClaimType),
		Status:        strings.TrimSpace(record.Status),
		SourceEventId: strings.TrimSpace(record.SourceEventID),
		Attributes:    trimAttributes(record.Attributes),
	}
	if !record.ObservedAt.IsZero() {
		claim.ObservedAt = timestamppb.New(record.ObservedAt.UTC())
	}
	if !record.ValidFrom.IsZero() {
		claim.ValidFrom = timestamppb.New(record.ValidFrom.UTC())
	}
	if !record.ValidTo.IsZero() {
		claim.ValidTo = timestamppb.New(record.ValidTo.UTC())
	}
	return claim
}

func cloneEntityRef(ref *cerebrov1.EntityRef) *cerebrov1.EntityRef {
	if ref == nil {
		return nil
	}
	return proto.Clone(ref).(*cerebrov1.EntityRef)
}

func claimTime(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.AsTime().UTC()
}
