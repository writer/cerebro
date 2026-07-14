package sourceprojection

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/fabriccontract"
	"github.com/writer/cerebro/internal/observability"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcehealth"
	"github.com/writer/cerebro/internal/telemetry"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

var emailIdentifierPattern = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)

const (
	relationActedOn            = fabriccontract.RelationActedOn
	relationAffectedBy         = fabriccontract.RelationAffectedBy
	relationAffects            = fabriccontract.RelationAffects
	relationAuthored           = fabriccontract.RelationAuthored
	relationBelongsTo          = fabriccontract.RelationBelongsTo
	relationCanPerform         = fabriccontract.RelationCanPerform
	relationHasIdentifier      = fabriccontract.RelationHasIdentifier
	relationAssignedTo         = fabriccontract.RelationAssignedTo
	relationAssociatedWith     = fabriccontract.RelationAssociatedWith
	relationAttachedTo         = fabriccontract.RelationAttachedTo
	relationCanAssume          = fabriccontract.RelationCanAssume
	relationCanAdmin           = fabriccontract.RelationCanAdmin
	relationCanImpersonate     = fabriccontract.RelationCanImpersonate
	relationCanReach           = fabriccontract.RelationCanReach
	relationContains           = fabriccontract.RelationContains
	relationConfersCapability  = fabriccontract.RelationConfersCapability
	relationDependsOn          = fabriccontract.RelationDependsOn
	relationGrantsEntitlement  = fabriccontract.RelationGrantsEntitlement
	relationHasClassification  = fabriccontract.RelationHasClassification
	relationHasContext         = fabriccontract.RelationHasContext
	relationHasDNSRecord       = fabriccontract.RelationHasDNSRecord
	relationHasEvidence        = fabriccontract.RelationHasEvidence
	relationMemberOf           = fabriccontract.RelationMemberOf
	relationObservedOn         = fabriccontract.RelationObservedOn
	relationOwnedBy            = fabriccontract.RelationOwnedBy
	relationRepresents         = fabriccontract.RelationRepresents
	relationRepresentsIdentity = fabriccontract.RelationRepresentsIdentity
	relationResolvesTo         = fabriccontract.RelationResolvesTo
	relationRunsAs             = fabriccontract.RelationRunsAs
	relationSameActor          = fabriccontract.RelationSameActor
	relationSupports           = fabriccontract.RelationSupports
	relationTaggedAs           = fabriccontract.RelationTaggedAs
	relationTargeted           = fabriccontract.RelationTargeted
	relationCNAMETo            = fabriccontract.RelationCNAMETo
	defaultCleanupLimit        = 1000
)

// Service materializes synced source events into current-state and graph stores.
type Service struct {
	state    ports.ProjectionStateStore
	graph    ports.ProjectionGraphStore
	registry *Registry
}

// New constructs a source projector.
func New(state ports.ProjectionStateStore, graph ports.ProjectionGraphStore) *Service {
	return NewWithRegistry(state, graph, BuiltinRegistry())
}

// NewWithRegistry constructs a source projector with an explicit event projector registry.
func NewWithRegistry(state ports.ProjectionStateStore, graph ports.ProjectionGraphStore, registry *Registry) *Service {
	if registry == nil {
		registry = BuiltinRegistry()
	}
	return &Service{state: state, graph: graph, registry: registry}
}

// RegisterConnectorDefinition makes a tenant-authored connector definition projectable.
func (s *Service) RegisterConnectorDefinition(definition connectordefinitions.Definition) {
	if s == nil || s.registry == nil {
		return
	}
	s.registry.RegisterConnectorDefinitions(definition)
}

// Project applies one source event to the configured state and graph stores.
func (s *Service) Project(ctx context.Context, event *cerebrov1.EventEnvelope) (result ports.ProjectionResult, err error) {
	ctx = telemetry.EnsureTraceContext(ctx)
	started := time.Now()
	defer func() {
		sourceID := ""
		eventKind := ""
		if event != nil {
			sourceID = event.GetSourceId()
			eventKind = event.GetKind()
		}
		status := "completed"
		if err != nil {
			status = "failed"
		}
		attrs := observability.SourceProjectionDiagnosticAttributes(sourceProjectionDiagnosticContext(event)).
			With(telemetry.Attrs(
				telemetry.Field{Key: "status", Value: status},
				telemetry.Field{Key: "source_projection.status", Value: status},
				telemetry.Field{Key: "source_projection.entities_projected", Value: result.EntitiesProjected},
				telemetry.Field{Key: "source_projection.links_projected", Value: result.LinksProjected},
				telemetry.Field{Key: "source_projection.entities_deleted", Value: result.EntitiesDeleted},
				telemetry.Field{Key: "source_projection.links_deleted", Value: result.LinksDeleted},
			))
		if err != nil {
			attrs = attrs.WithField(telemetry.Field{Key: "error_kind", Value: sourceProjectionTelemetryErrorKind(err)})
		}
		telemetry.Event(ctx, "source_projection.project", attrs)
		telemetry.AnnotateMain(ctx, attrs)
		telemetry.AnnotateMainPhase(ctx, "source_projection.project", status, attrs)
		observability.RecordSourceProjection(ctx, observability.SourceProjectionMetrics{
			SourceID:          sourceID,
			EventKind:         eventKind,
			Status:            status,
			Duration:          time.Since(started),
			EntitiesProjected: result.EntitiesProjected,
			LinksProjected:    result.LinksProjected,
			EntitiesDeleted:   result.EntitiesDeleted,
			LinksDeleted:      result.LinksDeleted,
		})
	}()
	if event == nil {
		return ports.ProjectionResult{}, fmt.Errorf("event is required")
	}
	if s == nil || (s.state == nil && s.graph == nil) {
		return ports.ProjectionResult{}, nil
	}
	entities, links, err := s.ProjectRecordsContext(ctx, event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	cleanupURNs, err := s.ProjectCleanupRecords(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	entitiesDeleted, err := s.deleteProjectedEntities(ctx, cleanupURNs)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	cleanupRequests, err := s.ProjectCleanupRequests(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	cleanupDeleted, err := s.cleanupProjectedEntities(ctx, cleanupRequests)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	entitiesDeleted += cleanupDeleted.EntitiesDeleted
	retractedLinks, err := s.ProjectRetractions(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	retractedLinksDeleted, err := s.deleteProjectedLinks(ctx, retractedLinks)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	if len(retractedLinks) != 0 {
		attrs := telemetry.Attrs(
			telemetry.Field{Key: "tenant_id", Value: event.GetTenantId()},
			telemetry.Field{Key: "source_id", Value: event.GetSourceId()},
			telemetry.Field{Key: "runtime_id", Value: strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID])},
			telemetry.Field{Key: "event_kind", Value: event.GetKind()},
			telemetry.Field{Key: "reason", Value: projectionRetractionReason(retractedLinks)},
			telemetry.Field{Key: "links_matched", Value: len(retractedLinks)},
			telemetry.Field{Key: "links_deleted", Value: retractedLinksDeleted},
		)
		telemetry.Event(ctx, "source_projection.retractions", attrs)
		telemetry.IncrementMain(ctx, "source_projection.retraction.count", 1)
		telemetry.AnnotateMain(ctx, attrs.With(telemetry.Attrs(
			telemetry.Field{Key: "source_projection.retraction.present", Value: true},
		)))
	}
	if conflictCategory, err := s.detectRuntimeEvidenceConflict(ctx, event, entities); err != nil {
		emitRuntimeEvidenceTelemetry(ctx, event, entities, links, "conflict", conflictCategory)
		return ports.ProjectionResult{}, err
	}
	for _, entity := range entities {
		if s.state != nil {
			if err := s.state.UpsertProjectedEntity(ctx, entity); err != nil {
				return ports.ProjectionResult{}, err
			}
		}
		if s.graph != nil {
			if err := s.graph.UpsertProjectedEntity(ctx, entity); err != nil {
				return ports.ProjectionResult{}, err
			}
		}
	}
	for _, link := range links {
		if s.state != nil {
			if err := s.state.UpsertProjectedLink(ctx, link); err != nil {
				return ports.ProjectionResult{}, err
			}
		}
		if s.graph != nil {
			if err := s.graph.UpsertProjectedLink(ctx, link); err != nil {
				return ports.ProjectionResult{}, err
			}
		}
	}
	emitRuntimeEvidenceTelemetry(ctx, event, entities, links, "projected", "")
	return ports.ProjectionResult{
		EntitiesProjected: boundedUint32(len(entities)),
		LinksProjected:    boundedUint32(len(links)),
		EntitiesDeleted:   entitiesDeleted,
		LinksDeleted:      cleanupDeleted.LinksDeleted + retractedLinksDeleted,
	}, nil
}

func sourceProjectionDiagnosticContext(event *cerebrov1.EventEnvelope) observability.SourceProjectionDiagnosticContext {
	if event == nil {
		return observability.SourceProjectionDiagnosticContext{}
	}
	return observability.SourceProjectionDiagnosticContext{
		RuntimeID: strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID]),
		SourceID:  event.GetSourceId(),
		TenantID:  event.GetTenantId(),
		EventKind: event.GetKind(),
	}
}

func sourceProjectionTelemetryErrorKind(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "event is required"),
		strings.Contains(message, "tenant_id is required"):
		return "invalid_event"
	default:
		return "projection_failed"
	}
}

func projectionRetractionReason(links []*ports.ProjectedLink) string {
	reason := ""
	for _, link := range links {
		if link == nil {
			continue
		}
		next := boundedProjectionRetractionReason(link.Attributes["retraction"])
		if next == "unknown" {
			continue
		}
		if reason == "" {
			reason = next
			continue
		}
		if reason != next {
			return "mixed"
		}
	}
	if reason == "" {
		return "unknown"
	}
	return reason
}

func boundedProjectionRetractionReason(value string) string {
	switch strings.TrimSpace(value) {
	case "endpoint_owner_id",
		"cloudflare_dns_record_zone_reassigned",
		"trivy_vulnerability_resolved",
		"tailscale_device_deauthorized",
		"tailscale_device_blocks_incoming",
		"tailscale_grant_disabled":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func boundedUint32(value int) uint32 {
	if value <= 0 {
		return 0
	}
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value)
}

func (s *Service) detectRuntimeEvidenceConflict(ctx context.Context, event *cerebrov1.EventEnvelope, entities []*ports.ProjectedEntity) (string, error) {
	if s == nil || s.state == nil || !runtimeEvidenceIsEvidenceCAS(event) {
		return "", nil
	}
	reader, ok := s.state.(ports.ProjectionEntityReader)
	sourceEventReader, hasSourceEventReader := s.state.(ports.ProjectionRuntimeEvidenceReader)
	if !ok && !hasSourceEventReader {
		return "", nil
	}
	for _, entity := range entities {
		if entity == nil || entity.EntityType != "runtime.evidence" {
			continue
		}
		existing, err := projectedRuntimeEvidenceBySourceEvent(ctx, sourceEventReader, entity)
		if err != nil {
			return "", err
		}
		if existing == nil && ok {
			existing, err = reader.GetProjectedEntity(ctx, entity.URN)
			if err != nil {
				return "", fmt.Errorf("read projected runtime evidence %q: %w", entity.URN, err)
			}
		}
		if existing == nil || existing.EntityType != "runtime.evidence" {
			continue
		}
		if !sameRuntimeEvidenceSourceEvent(existing.Attributes, entity.Attributes) {
			continue
		}
		if category := runtimeEvidenceConflictCategory(existing.Attributes, entity.Attributes); category != "" {
			return category, fmt.Errorf("evidence_cas conflict for runtime evidence: %s", category)
		}
	}
	return "", nil
}

func projectedRuntimeEvidenceBySourceEvent(ctx context.Context, reader ports.ProjectionRuntimeEvidenceReader, entity *ports.ProjectedEntity) (*ports.ProjectedEntity, error) {
	if reader == nil || entity == nil {
		return nil, nil
	}
	tenantID := strings.TrimSpace(entity.Attributes["tenant_id"])
	if tenantID == "" {
		tenantID = strings.TrimSpace(entity.TenantID)
	}
	sourceRuntimeID := strings.TrimSpace(entity.Attributes[ports.EventAttributeSourceRuntimeID])
	sourceEventID := strings.TrimSpace(entity.Attributes["source_event_id"])
	if tenantID == "" || sourceRuntimeID == "" || sourceEventID == "" {
		return nil, nil
	}
	existing, err := reader.GetProjectedRuntimeEvidenceBySourceEvent(ctx, tenantID, sourceRuntimeID, sourceEventID)
	if err != nil {
		return nil, fmt.Errorf("read projected runtime evidence by source event: %w", err)
	}
	return existing, nil
}

func sameRuntimeEvidenceSourceEvent(existing map[string]string, incoming map[string]string) bool {
	if len(existing) == 0 || len(incoming) == 0 {
		return false
	}
	for _, key := range []string{"tenant_id", ports.EventAttributeSourceRuntimeID, "source_event_id"} {
		left := strings.TrimSpace(existing[key])
		right := strings.TrimSpace(incoming[key])
		if left == "" || right == "" || left != right {
			return false
		}
	}
	return true
}

func runtimeEvidenceConflictCategory(existing map[string]string, incoming map[string]string) string {
	for _, key := range []string{
		"evidence_id",
		"evidence_cas_uri",
		"evidence_cas_digest",
		"evidence_cas_merkle_root",
		"evidence_cas_commit_id",
		"evidence_cas_ref_type",
	} {
		left := strings.TrimSpace(existing[key])
		right := strings.TrimSpace(incoming[key])
		if left != "" && right != "" && left != right {
			return key
		}
	}
	return ""
}

func emitRuntimeEvidenceTelemetry(ctx context.Context, event *cerebrov1.EventEnvelope, entities []*ports.ProjectedEntity, links []*ports.ProjectedLink, outcome string, conflictCategory string) {
	if !runtimeEvidenceIsEvidenceCAS(event) {
		return
	}
	evidenceCount := 0
	orphanCount := 0
	missingCaseCount := 0
	resourceLinkStatus := "not_applicable"
	caseLinkStatus := "not_supplied"
	for _, entity := range entities {
		if entity == nil || entity.EntityType != "runtime.evidence" {
			continue
		}
		evidenceCount++
		resourceLinkStatus = boundedLinkStatus(entity.Attributes["resource_link_status"])
		caseLinkStatus = boundedLinkStatus(entity.Attributes["case_link_status"])
		if resourceLinkStatus == "missing" {
			orphanCount++
		}
		if caseLinkStatus == "missing" {
			missingCaseCount++
		}
	}
	if evidenceCount == 0 && outcome != "conflict" {
		return
	}
	runtimeID := strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID])
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "tenant_id", Value: event.GetTenantId()},
		telemetry.Field{Key: "source_id", Value: boundedEvidenceSourceID(event.GetSourceId())},
		telemetry.Field{Key: "runtime_id", Value: runtimeID},
		telemetry.Field{Key: "event_kind", Value: boundedEvidenceEventKind(event.GetKind())},
		telemetry.Field{Key: "outcome", Value: boundedEvidenceOutcome(outcome)},
		telemetry.Field{Key: "conflict_category", Value: boundedConflictCategory(conflictCategory)},
		telemetry.Field{Key: "resource_link_status", Value: resourceLinkStatus},
		telemetry.Field{Key: "case_link_status", Value: caseLinkStatus},
		telemetry.Field{Key: "orphan_count", Value: orphanCount},
		telemetry.Field{Key: "missing_case_count", Value: missingCaseCount},
		telemetry.Field{Key: "entities_projected", Value: len(entities)},
		telemetry.Field{Key: "links_projected", Value: len(links)},
	)
	telemetry.Event(ctx, "source_projection.runtime_evidence", attrs)
	telemetry.IncrementMain(ctx, "source_projection.runtime_evidence.count", 1)
	if boundedEvidenceOutcome(outcome) == "conflict" {
		telemetry.IncrementMain(ctx, "source_projection.runtime_evidence.conflict.count", 1)
	}
	telemetry.AnnotateMain(ctx, attrs.With(telemetry.Attrs(
		telemetry.Field{Key: "source_projection.runtime_evidence.present", Value: true},
	)))
	linkStatus := sourcehealth.LinkStatusRollup(resourceLinkStatus, caseLinkStatus)
	linkAttrs := telemetry.Attrs(
		telemetry.Field{Key: "tenant_id", Value: event.GetTenantId()},
		telemetry.Field{Key: "source_id", Value: boundedEvidenceSourceID(event.GetSourceId())},
		telemetry.Field{Key: "runtime_id", Value: runtimeID},
		telemetry.Field{Key: "event_kind", Value: boundedEvidenceEventKind(event.GetKind())},
		telemetry.Field{Key: "link_status", Value: linkStatus},
		telemetry.Field{Key: "resource_link_status", Value: resourceLinkStatus},
		telemetry.Field{Key: "case_link_status", Value: caseLinkStatus},
		telemetry.Field{Key: "orphan_count", Value: orphanCount},
		telemetry.Field{Key: "missing_case_count", Value: missingCaseCount},
	)
	telemetry.Event(ctx, "runtime.evidence.link_status", linkAttrs)
	telemetry.IncrementMain(ctx, "runtime.evidence.link_status.count", 1)
	if linkStatus != "linked" {
		telemetry.IncrementMain(ctx, "runtime.evidence.link_status.failure.count", 1)
	}
	telemetry.AnnotateMain(ctx, linkAttrs.With(telemetry.Attrs(
		telemetry.Field{Key: "runtime.evidence.link_status.present", Value: true},
	)))
}

func boundedEvidenceSourceID(value string) string {
	if strings.TrimSpace(value) == "evidence_cas" {
		return "evidence_cas"
	}
	return "other"
}

func boundedEvidenceEventKind(value string) string {
	switch strings.TrimSpace(value) {
	case "evidence_cas.object", "runtime.evidence":
		return strings.TrimSpace(value)
	default:
		return "other"
	}
}

func boundedEvidenceOutcome(value string) string {
	switch strings.TrimSpace(value) {
	case "projected", "conflict":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func boundedLinkStatus(value string) string {
	switch strings.TrimSpace(value) {
	case "linked", "missing", "not_supplied":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func boundedConflictCategory(value string) string {
	switch strings.TrimSpace(value) {
	case "", "evidence_id", "evidence_cas_uri", "evidence_cas_digest", "evidence_cas_merkle_root", "evidence_cas_commit_id", "evidence_cas_ref_type":
		return strings.TrimSpace(value)
	default:
		return "identity"
	}
}

// ProjectRecords converts one event into normalized projection records without
// writing them. Graph ingest uses this to coalesce repeated records before
// touching Neo4j.
func (s *Service) ProjectRecords(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return s.projectRecords(event, func(registry *Registry, event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return registry.Project(event)
	})
}

// ProjectRecordsContext converts one event into normalized projection records while preserving caller cancellation.
func (s *Service) ProjectRecordsContext(ctx context.Context, event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return s.projectRecords(event, func(registry *Registry, event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return registry.ProjectContext(ctx, event)
	})
}

func (s *Service) projectRecords(event *cerebrov1.EventEnvelope, project func(*Registry, *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	if event == nil {
		return nil, nil, fmt.Errorf("event is required")
	}
	if s == nil || s.registry == nil {
		return nil, nil, nil
	}
	entities, links, err := project(s.registry, event)
	if err != nil {
		return nil, nil, err
	}
	normalizeProjectedEntityTypes(entities)
	stampProjectionRuntime(event, entities, links)
	if err := validateProjectedFabricContract(links); err != nil {
		return nil, nil, err
	}
	return entities, links, nil
}

func validateProjectedFabricContract(links []*ports.ProjectedLink) error {
	for _, link := range links {
		if link == nil {
			continue
		}
		relation := strings.TrimSpace(link.Relation)
		if relation == "" {
			return fmt.Errorf("projected link relation is required")
		}
		if !fabriccontract.IsRelation(relation) {
			return fmt.Errorf("projected link relation %q is outside the fabric contract", relation)
		}
	}
	return nil
}

// ProjectCleanupRecords returns stale projection entity URNs that should be
// removed while applying this event.
func (s *Service) ProjectCleanupRecords(event *cerebrov1.EventEnvelope) ([]string, error) {
	if event == nil {
		return nil, fmt.Errorf("event is required")
	}
	if event.GetKind() != "okta.audit" {
		return nil, nil
	}
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, err
	}
	attributes := event.GetAttributes()
	resourceType := strings.TrimSpace(attributes["resource_type"])
	if !oktaEphemeralOAuthRuntimeResource(resourceType, attributes) {
		return nil, nil
	}
	resourceURN := oktaResourceURN(tenantID, resourceType, strings.TrimSpace(attributes["resource_id"]))
	if resourceURN == "" {
		return nil, nil
	}
	return []string{resourceURN}, nil
}

// ProjectCleanupRequests returns scoped cleanup passes that should run while applying this event.
func (s *Service) ProjectCleanupRequests(event *cerebrov1.EventEnvelope) ([]ports.ProjectionCleanupRequest, error) {
	if event == nil {
		return nil, fmt.Errorf("event is required")
	}
	if event.GetKind() != "okta.audit" {
		return nil, nil
	}
	attributes := event.GetAttributes()
	runtimeID := strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])
	if runtimeID == "" {
		return nil, nil
	}
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, err
	}
	return []ports.ProjectionCleanupRequest{{
		TenantID:    tenantID,
		SourceID:    strings.TrimSpace(event.GetSourceId()),
		RuntimeID:   runtimeID,
		EntityTypes: []string{"okta.resource"},
		URNPrefixes: oktaEphemeralOAuthRuntimeResourceURNPrefixes(tenantID),
		Limit:       1000,
	}}, nil
}

// ProjectRetractions returns stale projection links that should be removed for one event.
func (s *Service) ProjectRetractions(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLink, error) {
	if event == nil {
		return nil, fmt.Errorf("event is required")
	}
	links, err := endpointOwnerIDRetractions(event)
	if err != nil {
		return nil, err
	}
	dnsRecordRetractions, err := cloudflareDNSRecordRetractions(event)
	if err != nil {
		return nil, err
	}
	links = append(links, dnsRecordRetractions...)
	trivyRetractions, err := trivyVulnerabilityRetractions(event)
	if err != nil {
		return nil, err
	}
	links = append(links, trivyRetractions...)
	tailscaleRetractions, err := tailscaleAccessRetractions(event)
	if err != nil {
		return nil, err
	}
	links = append(links, tailscaleRetractions...)
	stampProjectionRuntime(event, nil, links)
	return links, nil
}

func (s *Service) deleteProjectedLinks(ctx context.Context, links []*ports.ProjectedLink) (uint32, error) {
	if len(links) == 0 {
		return 0, nil
	}
	var deleted uint32
	stateDeleter, stateCanDelete := s.state.(ports.ProjectionLinkDeleter)
	graphDeleter, graphCanDelete := s.graph.(ports.ProjectionLinkDeleter)
	for _, link := range links {
		if link == nil {
			continue
		}
		deletedLink := false
		if stateCanDelete {
			if err := stateDeleter.DeleteProjectedLink(ctx, link); err != nil {
				return deleted, err
			}
			deletedLink = true
		}
		if graphCanDelete {
			if err := graphDeleter.DeleteProjectedLink(ctx, link); err != nil {
				return deleted, err
			}
			deletedLink = true
		}
		if deletedLink {
			deleted++
		}
	}
	return deleted, nil
}

func (s *Service) deleteProjectedEntities(ctx context.Context, urns []string) (uint32, error) {
	if len(urns) == 0 {
		return 0, nil
	}
	deleted := uint32(0)
	seen := map[string]struct{}{}
	for _, urn := range urns {
		normalizedURN := strings.TrimSpace(urn)
		if normalizedURN == "" {
			continue
		}
		if _, ok := seen[normalizedURN]; ok {
			continue
		}
		seen[normalizedURN] = struct{}{}
		stateDeleted, err := deleteProjectedEntity(ctx, s.state, normalizedURN)
		if err != nil {
			return deleted, err
		}
		graphDeleted, err := deleteProjectedEntity(ctx, s.graph, normalizedURN)
		if err != nil {
			return deleted, err
		}
		if stateDeleted || graphDeleted {
			deleted++
		}
	}
	return deleted, nil
}

func (s *Service) cleanupProjectedEntities(ctx context.Context, requests []ports.ProjectionCleanupRequest) (ports.ProjectionCleanupResult, error) {
	if len(requests) == 0 {
		return ports.ProjectionCleanupResult{}, nil
	}
	result := ports.ProjectionCleanupResult{}
	for _, store := range []any{s.state, s.graph} {
		cleaner, ok := store.(ports.ProjectionCleaner)
		if !ok {
			continue
		}
		cleanup, err := cleanupProjectedEntitiesInStore(ctx, cleaner, requests)
		if err != nil {
			return result, err
		}
		result.EntitiesDeleted += cleanup.EntitiesDeleted
		result.LinksDeleted += cleanup.LinksDeleted
	}
	return result, nil
}

func cleanupProjectedEntitiesInStore(ctx context.Context, cleaner ports.ProjectionCleaner, requests []ports.ProjectionCleanupRequest) (ports.ProjectionCleanupResult, error) {
	result := ports.ProjectionCleanupResult{}
	for _, request := range requests {
		limit := cleanupBatchLimit(request)
		for {
			cleanup, err := cleaner.CleanupProjectedEntities(ctx, request)
			if err != nil {
				return result, err
			}
			result.EntitiesDeleted += cleanup.EntitiesDeleted
			result.LinksDeleted += cleanup.LinksDeleted
			if cleanup.EntitiesDeleted < limit {
				break
			}
		}
	}
	return result, nil
}

func cleanupBatchLimit(request ports.ProjectionCleanupRequest) uint32 {
	if request.Limit == 0 {
		return defaultCleanupLimit
	}
	return request.Limit
}

func deleteProjectedEntity(ctx context.Context, store any, urn string) (bool, error) {
	deleter, ok := store.(ports.ProjectionEntityDeleter)
	if !ok {
		return false, nil
	}
	if err := deleter.DeleteProjectedEntity(ctx, urn); err != nil {
		return true, fmt.Errorf("delete projected entity %q: %w", urn, err)
	}
	return true, nil
}

func stampProjectionRuntime(event *cerebrov1.EventEnvelope, entities []*ports.ProjectedEntity, links []*ports.ProjectedLink) {
	if event == nil {
		return
	}
	runtimeID := strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID])
	if runtimeID == "" {
		return
	}
	for _, entity := range entities {
		if entity == nil {
			continue
		}
		if strings.TrimSpace(entity.RuntimeID) == "" {
			entity.RuntimeID = runtimeID
		}
		if entity.Attributes == nil {
			entity.Attributes = map[string]string{}
		}
		if strings.TrimSpace(entity.Attributes[ports.EventAttributeSourceRuntimeID]) == "" {
			entity.Attributes[ports.EventAttributeSourceRuntimeID] = runtimeID
		}
	}
	for _, link := range links {
		if link == nil {
			continue
		}
		if strings.TrimSpace(link.RuntimeID) == "" {
			link.RuntimeID = runtimeID
		}
		if link.Attributes == nil {
			link.Attributes = map[string]string{}
		}
		if strings.TrimSpace(link.Attributes[ports.EventAttributeSourceRuntimeID]) == "" {
			link.Attributes[ports.EventAttributeSourceRuntimeID] = runtimeID
		}
	}
}

func entitiesAndLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink) ([]*ports.ProjectedEntity, []*ports.ProjectedLink) {
	projectedEntities := make([]*ports.ProjectedEntity, 0, len(entities))
	for _, entity := range entities {
		projectedEntities = append(projectedEntities, entity)
	}
	projectedLinks := make([]*ports.ProjectedLink, 0, len(links))
	for _, link := range links {
		projectedLinks = append(projectedLinks, link)
	}
	return projectedEntities, projectedLinks
}

func tenantID(event *cerebrov1.EventEnvelope) (string, error) {
	tenantID := strings.TrimSpace(event.GetTenantId())
	if tenantID == "" {
		return "", fmt.Errorf("event %q tenant_id is required for projection", event.GetId())
	}
	return tenantID, nil
}

func addEntity(entities map[string]*ports.ProjectedEntity, entity *ports.ProjectedEntity) {
	if entity == nil || strings.TrimSpace(entity.URN) == "" {
		return
	}
	if existing := entities[entity.URN]; existing != nil {
		if strings.TrimSpace(entity.TenantID) != "" {
			existing.TenantID = entity.TenantID
		}
		if strings.TrimSpace(entity.SourceID) != "" {
			existing.SourceID = entity.SourceID
		}
		if strings.TrimSpace(entity.EntityType) != "" {
			existing.EntityType = entity.EntityType
		}
		if strings.TrimSpace(entity.Label) != "" {
			existing.Label = entity.Label
		}
		if len(entity.Attributes) != 0 {
			if existing.Attributes == nil {
				existing.Attributes = map[string]string{}
			}
			for key, value := range entity.Attributes {
				existing.Attributes[key] = value
			}
		}
		return
	}
	entities[entity.URN] = entity
}

func addLink(links map[string]*ports.ProjectedLink, link *ports.ProjectedLink) {
	if link == nil || strings.TrimSpace(link.FromURN) == "" || strings.TrimSpace(link.ToURN) == "" || strings.TrimSpace(link.Relation) == "" {
		return
	}
	key := link.FromURN + "|" + link.Relation + "|" + link.ToURN
	links[key] = link
}

func addProjectedAttribute(attributes map[string]string, key string, value string) {
	if attributes == nil {
		return
	}
	if strings.TrimSpace(value) == "" {
		return
	}
	attributes[key] = strings.TrimSpace(value)
}

func addIdentifierLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, eventID string, fromURN string, value string, occurredAt *timestamppb.Timestamp) {
	identifierURN, identifierType, label := identifierURN(tenantID, value)
	if identifierURN == "" {
		return
	}
	evidenceAttributes := identifierEvidenceAttributes(value, identifierType, label, eventID, occurredAt)
	canonicalIdentityURN, canonicalIdentityType := canonicalIdentityURN(tenantID, value)
	if canonicalIdentityURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        canonicalIdentityURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: canonicalIdentityType,
			Label:      label,
			Attributes: map[string]string{"value": label},
		})
		addLink(links, projectedLink(tenantID, sourceID, fromURN, canonicalIdentityURN, relationRepresentsIdentity, evidenceAttributes))
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        identifierURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: identifierType,
		Label:      label,
		Attributes: map[string]string{"value": label},
	})
	addLink(links, projectedLink(tenantID, sourceID, fromURN, identifierURN, relationHasIdentifier, evidenceAttributes))
	if canonicalIdentityURN != "" {
		addLink(links, projectedLink(tenantID, sourceID, canonicalIdentityURN, identifierURN, relationHasIdentifier, evidenceAttributes))
		// Reverse pointer from identifier.* to identity.*. The canonical identity is the
		// stable anchor; the identifier nodes are evidence pointing back to it, so they
		// need a represents_identity edge to keep cross-source identity traversal
		// symmetric (otherwise queries that start at identifier.email cannot reach the
		// identity without going through the original actor).
		addLink(links, projectedLink(tenantID, sourceID, identifierURN, canonicalIdentityURN, relationRepresentsIdentity, evidenceAttributes))
	}
}

func addSameActorEmailLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, eventID string, fromURN string, email string, occurredAt *timestamppb.Timestamp) {
	normalizedEmail := normalizeIdentifier(extractEmailIdentifier(email))
	if normalizedEmail == "" || strings.TrimSpace(fromURN) == "" {
		return
	}
	identityURN := projectionURN(tenantID, "identity", "email", normalizedEmail)
	if identityURN == "" {
		return
	}
	attributes := identifierEvidenceAttributes(email, "identifier.email", normalizedEmail, eventID, occurredAt)
	attributes["match_type"] = "shared_identity_email"
	attributes["relationship"] = relationSameActor
	addEntity(entities, &ports.ProjectedEntity{
		URN:        identityURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "identity.email",
		Label:      normalizedEmail,
		Attributes: map[string]string{"value": normalizedEmail},
	})
	addLink(links, projectedLink(tenantID, sourceID, fromURN, identityURN, relationSameActor, attributes))
	addLink(links, projectedLink(tenantID, sourceID, identityURN, fromURN, relationSameActor, attributes))
}

func identifierEvidenceAttributes(rawValue string, identifierType string, normalizedValue string, eventID string, occurredAt *timestamppb.Timestamp) map[string]string {
	matchType := "login"
	confidence := "0.60"
	identityQuality := "weak_login"
	identityScope := "source_local"
	crossSourceIdentity := "false"
	value := strings.TrimSpace(rawValue)
	if identifierType == "identifier.email" {
		identityScope = "global"
		crossSourceIdentity = "true"
		if strings.EqualFold(normalizeIdentifier(value), normalizedValue) {
			matchType = "exact_email"
			confidence = "0.95"
			identityQuality = "stable_email"
		} else {
			matchType = "extracted_email"
			confidence = "0.85"
			identityQuality = "extracted_email"
		}
	}
	attributes := map[string]string{
		"confidence":            confidence,
		"cross_source_identity": crossSourceIdentity,
		"evidence_type":         "shared_identifier",
		"identifier_type":       strings.TrimPrefix(identifierType, "identifier."),
		"identifier_value":      normalizedValue,
		"identity_quality":      identityQuality,
		"identity_scope":        identityScope,
		"match_type":            matchType,
	}
	if normalizedEventID := strings.TrimSpace(eventID); normalizedEventID != "" {
		attributes["source_event_id"] = normalizedEventID
	}
	// `at` carries the most recent OccurredAt that re-asserted this identifier
	// link. Source projection is upsert-only and never retracts old edges, so an
	// Okta email/login or GitHub external_identity_nameid that has been renamed
	// would otherwise leave the stale represents_identity edge intact forever
	// and let identity-aware graph rules keep matching through it. The
	// chronological-max merge for `at` (see neo4j store mergeAttributeValue)
	// means rules can scope joins to recently re-observed links and the stale
	// edge naturally ages out of the window once it stops being refreshed.
	if occurredAt != nil && occurredAt.IsValid() {
		attributes["at"] = occurredAt.AsTime().UTC().Format(time.RFC3339)
	}
	return attributes
}

func projectedLink(tenantID string, sourceID string, fromURN string, toURN string, relation string, attributes map[string]string) *ports.ProjectedLink {
	return &ports.ProjectedLink{
		TenantID:   tenantID,
		SourceID:   sourceID,
		FromURN:    fromURN,
		ToURN:      toURN,
		Relation:   relation,
		Attributes: attributes,
	}
}

func projectionURN(tenantID string, kind string, parts ...string) string {
	value, err := cerebrourn.Mint(tenantID, kind, parts...)
	if err != nil {
		return ""
	}
	return value
}

func identifierURN(tenantID string, raw string) (string, string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", ""
	}
	if email := extractEmailIdentifier(value); email != "" {
		normalized := normalizeIdentifier(email)
		return projectionURN(tenantID, "identifier", "email", normalized), "identifier.email", normalized
	}
	normalized := normalizeIdentifier(value)
	return projectionURN(tenantID, "identifier", "login", normalized), "identifier.login", normalized
}

func canonicalIdentityURN(tenantID string, raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", ""
	}
	if email := extractEmailIdentifier(value); email != "" {
		normalized := normalizeIdentifier(email)
		return projectionURN(tenantID, "identity", "email", normalized), "identity.email"
	}
	normalized := normalizeIdentifier(value)
	return projectionURN(tenantID, "identity", "login", normalized), "identity.login"
}

func extractEmailIdentifier(value string) string {
	return strings.TrimSpace(emailIdentifierPattern.FindString(strings.TrimSpace(value)))
}

func sameIdentifier(left string, right string) bool {
	if strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
		return false
	}
	return normalizeIdentifier(left) == normalizeIdentifier(right)
}

func normalizeIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeProjectedEntityTypes(entities []*ports.ProjectedEntity) {
	for _, entity := range entities {
		if entity == nil {
			continue
		}
		entity.EntityType = canonicalProjectedEntityType(entity.EntityType)
	}
}

func canonicalProjectedEntityType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return normalized
	}
	normalized = strings.ReplaceAll(normalized, " ", "_")
	normalized = strings.ReplaceAll(normalized, "..", ".")
	if strings.HasPrefix(normalized, "aws.aws.") {
		normalized = strings.TrimPrefix(normalized, "aws.")
	}
	switch normalized {
	case "okta.publicclientappentity":
		return "okta.publicclientapp"
	case "okta.ip_address":
		return "okta.ip"
	}
	return normalized
}

func payloadMap(event *cerebrov1.EventEnvelope) map[string]any {
	if len(event.GetPayload()) == 0 {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		return nil
	}
	return payload
}

func stringValue(values map[string]any, key string) string {
	if len(values) == 0 {
		return ""
	}
	value, ok := values[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
