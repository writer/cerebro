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
	claimStatusRetracted    = "retracted"
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
	RuntimeID       string
	Claims          []*cerebrov1.Claim
	ReplaceExisting bool
}

// WriteResult reports one claim batch write.
type WriteResult struct {
	ClaimsWritten          uint32
	EntitiesUpserted       uint32
	RelationLinksProjected uint32
	ClaimsRetracted        uint32
}

// ListRequest scopes one runtime-scoped claim query.
type ListRequest struct {
	RuntimeID     string
	ClaimID       string
	SubjectURN    string
	Predicate     string
	ObjectURN     string
	ObjectValue   string
	ClaimType     string
	Status        string
	SourceEventID string
	Limit         uint32
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
	normalizedClaims := make([]*cerebrov1.Claim, 0, len(request.Claims))
	for index, raw := range request.Claims {
		claim, err := normalizeClaim(raw, runtime)
		if err != nil {
			return nil, fmt.Errorf("normalize claim %d: %w", index, err)
		}
		normalizedClaims = append(normalizedClaims, claim)
	}
	for _, claim := range normalizedClaims {
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
			if err := s.retractStalePriorLink(ctx, runtime, claim, projected); err != nil {
				return nil, err
			}
			wrote, err := s.upsertLink(ctx, projected, upsertedLinks)
			if err != nil {
				return nil, err
			}
			if wrote {
				result.RelationLinksProjected++
			}
		} else if err := s.retractStalePriorLink(ctx, runtime, claim, nil); err != nil {
			// Claim previously projected a relation but the new claim no longer does (e.g. predicate
			// changed from "belongs_to" to "labeled" with the same claim id). Make sure the old edge
			// is removed.
			return nil, err
		}
		if _, err := s.store.UpsertClaim(ctx, claimRecord(runtime, claim)); err != nil {
			return nil, fmt.Errorf("persist claim %q: %w", claim.GetId(), err)
		}
		result.ClaimsWritten++
	}
	if request.ReplaceExisting {
		retracted, err := s.retractMissingClaims(ctx, runtime, normalizedClaims)
		if err != nil {
			return nil, err
		}
		result.ClaimsRetracted = retracted
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
		RuntimeID:     runtimeID,
		ClaimID:       strings.TrimSpace(request.ClaimID),
		SubjectURN:    strings.TrimSpace(request.SubjectURN),
		Predicate:     strings.TrimSpace(request.Predicate),
		ObjectURN:     strings.TrimSpace(request.ObjectURN),
		ObjectValue:   strings.TrimSpace(request.ObjectValue),
		ClaimType:     strings.TrimSpace(request.ClaimType),
		Status:        strings.TrimSpace(request.Status),
		SourceEventID: strings.TrimSpace(request.SourceEventID),
		Limit:         request.Limit,
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

func (s *Service) retractMissingClaims(ctx context.Context, runtime *cerebrov1.SourceRuntime, claims []*cerebrov1.Claim) (uint32, error) {
	runtimeID := strings.TrimSpace(runtime.GetId())
	incomingIDs := make(map[string]struct{}, len(claims))
	for _, claim := range claims {
		if claim == nil {
			continue
		}
		if claimID := strings.TrimSpace(claim.GetId()); claimID != "" {
			incomingIDs[claimID] = struct{}{}
		}
	}
	existing, err := s.store.ListClaims(ctx, ports.ListClaimsRequest{
		RuntimeID: runtimeID,
		Status:    claimStatusAsserted,
	})
	if err != nil {
		return 0, fmt.Errorf("list existing claims for runtime %q: %w", runtimeID, err)
	}
	retractAt := snapshotObservedAt(claims)
	snapshotEventID := snapshotSourceEventID(claims)
	var retracted uint32
	for _, existingClaim := range existing {
		if existingClaim == nil {
			continue
		}
		if _, ok := incomingIDs[strings.TrimSpace(existingClaim.ID)]; ok {
			continue
		}
		if err := s.deleteLink(ctx, projectedRelation(runtime, protoClaim(existingClaim))); err != nil {
			return retracted, err
		}
		if _, err := s.store.UpsertClaim(ctx, retractedClaim(existingClaim, retractAt, snapshotEventID)); err != nil {
			return retracted, fmt.Errorf("retract claim %q: %w", existingClaim.ID, err)
		}
		retracted++
	}
	return retracted, nil
}

func (s *Service) deleteLink(ctx context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	if deleter, ok := s.state.(ports.ProjectionLinkDeleter); ok {
		if err := deleter.DeleteProjectedLink(ctx, link); err != nil {
			return fmt.Errorf("delete projected link %q: %w", projectedLinkKey(link), err)
		}
	}
	if deleter, ok := s.graph.(ports.ProjectionLinkDeleter); ok {
		if err := deleter.DeleteProjectedLink(ctx, link); err != nil {
			return fmt.Errorf("delete graph link %q: %w", projectedLinkKey(link), err)
		}
	}
	return nil
}

// retractStalePriorLink deletes the projected link emitted by a previous version of the same
// claim_id when the new claim's projection differs (for example because the relation's object_urn
// changed). The new (possibly nil) projection is supplied so we only retract links that are
// actually stale -- if the new projection matches the previous one, upsertLink is a no-op.
func (s *Service) retractStalePriorLink(ctx context.Context, runtime *cerebrov1.SourceRuntime, claim *cerebrov1.Claim, next *ports.ProjectedLink) error {
	if claim == nil {
		return nil
	}
	claimID := strings.TrimSpace(claim.GetId())
	if claimID == "" {
		return nil
	}
	existing, err := s.store.ListClaims(ctx, ports.ListClaimsRequest{
		RuntimeID: strings.TrimSpace(runtime.GetId()),
		ClaimID:   claimID,
		Status:    claimStatusAsserted,
	})
	if err != nil {
		return fmt.Errorf("load existing claim %q: %w", claimID, err)
	}
	for _, prior := range existing {
		if prior == nil {
			continue
		}
		stale := projectedRelation(runtime, protoClaim(prior))
		if stale == nil {
			continue
		}
		if next != nil && projectedLinkKey(stale) == projectedLinkKey(next) {
			continue
		}
		if err := s.deleteLink(ctx, stale); err != nil {
			return err
		}
	}
	return nil
}

func snapshotObservedAt(claims []*cerebrov1.Claim) time.Time {
	latest := time.Time{}
	for _, claim := range claims {
		if claim == nil || claim.GetObservedAt() == nil {
			continue
		}
		observedAt := claim.GetObservedAt().AsTime().UTC()
		if observedAt.IsZero() {
			continue
		}
		if latest.IsZero() || observedAt.After(latest) {
			latest = observedAt
		}
	}
	if latest.IsZero() {
		return time.Now().UTC()
	}
	return latest
}

func snapshotSourceEventID(claims []*cerebrov1.Claim) string {
	for _, claim := range claims {
		if claim == nil {
			continue
		}
		if sourceEventID := strings.TrimSpace(claim.GetSourceEventId()); sourceEventID != "" {
			return sourceEventID
		}
	}
	return ""
}

func retractedClaim(claim *ports.ClaimRecord, retractAt time.Time, sourceEventID string) *ports.ClaimRecord {
	if claim == nil {
		return nil
	}
	attributes := make(map[string]string, len(claim.Attributes))
	for key, value := range claim.Attributes {
		attributes[key] = value
	}
	retracted := &ports.ClaimRecord{
		ID:            strings.TrimSpace(claim.ID),
		RuntimeID:     strings.TrimSpace(claim.RuntimeID),
		TenantID:      strings.TrimSpace(claim.TenantID),
		SubjectURN:    strings.TrimSpace(claim.SubjectURN),
		SubjectRef:    cloneEntityRef(claim.SubjectRef),
		Predicate:     strings.TrimSpace(claim.Predicate),
		ObjectURN:     strings.TrimSpace(claim.ObjectURN),
		ObjectRef:     cloneEntityRef(claim.ObjectRef),
		ObjectValue:   strings.TrimSpace(claim.ObjectValue),
		ClaimType:     strings.TrimSpace(claim.ClaimType),
		Status:        claimStatusRetracted,
		SourceEventID: strings.TrimSpace(claim.SourceEventID),
		ObservedAt:    retractAt.UTC(),
		ValidFrom:     claim.ValidFrom.UTC(),
		ValidTo:       retractAt.UTC(),
		Attributes:    attributes,
	}
	if sourceEventID != "" {
		retracted.SourceEventID = sourceEventID
	}
	return retracted
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
	key := projectedLinkKey(link)
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

func projectedLinkKey(link *ports.ProjectedLink) string {
	if link == nil {
		return ""
	}
	return link.FromURN + "|" + link.Relation + "|" + link.ToURN
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
		normalized.Id = hashClaimID(strings.TrimSpace(runtime.GetId()), normalized.GetClaimType(), normalized.GetSubjectUrn(), normalized.GetPredicate())
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

func hashClaimID(runtimeID string, claimType string, subjectURN string, predicate string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(runtimeID),
		strings.TrimSpace(claimType),
		strings.TrimSpace(subjectURN),
		strings.TrimSpace(predicate),
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

func claimTime(value interface{ AsTime() time.Time }) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.AsTime().UTC()
}
