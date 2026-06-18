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
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
)

var emailIdentifierPattern = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)

const (
	relationActedOn            = "acted_on"
	relationAffectedBy         = "affected_by"
	relationAffects            = "affects"
	relationAuthored           = "authored"
	relationBelongsTo          = "belongs_to"
	relationCanPerform         = "can_perform"
	relationHasIdentifier      = "has_identifier"
	relationAssignedTo         = "assigned_to"
	relationAssociatedWith     = "associated_with"
	relationAttachedTo         = "attached_to"
	relationCanAssume          = "can_assume"
	relationCanAdmin           = "can_admin"
	relationCanImpersonate     = "can_impersonate"
	relationCanReach           = "can_reach"
	relationContains           = "contains"
	relationConfersCapability  = "confers_capability"
	relationGrantsEntitlement  = "grants_entitlement"
	relationHasClassification  = "has_classification"
	relationHasDNSRecord       = "has_dns_record"
	relationHasEvidence        = "has_evidence"
	relationMemberOf           = "member_of"
	relationObservedOn         = "observed_on"
	relationOwnedBy            = "owned_by"
	relationRepresents         = "represents"
	relationRepresentsIdentity = "represents_identity"
	relationResolvesTo         = "resolves_to"
	relationRunsAs             = "runs_as"
	relationSameActor          = "same_actor"
	relationSupports           = "supports"
	relationTaggedAs           = "tagged_as"
	relationTargeted           = "targeted"
	relationCNAMETo            = "cname_to"
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

// Project applies one source event to the configured state and graph stores.
func (s *Service) Project(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	if event == nil {
		return ports.ProjectionResult{}, fmt.Errorf("event is required")
	}
	if s == nil || (s.state == nil && s.graph == nil) {
		return ports.ProjectionResult{}, nil
	}
	entities, links, err := s.ProjectRecords(event)
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
			telemetry.Field{Key: "reason", Value: "endpoint_owner_id"},
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
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "source_id", Value: boundedEvidenceSourceID(event.GetSourceId())},
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
	if event == nil {
		return nil, nil, fmt.Errorf("event is required")
	}
	if s == nil || s.registry == nil {
		return nil, nil, nil
	}
	entities, links, err := s.registry.Project(event)
	if err != nil {
		return nil, nil, err
	}
	normalizeProjectedEntityTypes(entities)
	stampProjectionRuntime(event, entities, links)
	return entities, links, nil
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

func githubPullRequestProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	payload := payloadMap(event)
	owner := strings.TrimSpace(attributes["owner"])
	repository := strings.TrimSpace(attributes["repository"])
	pullNumber := strings.TrimSpace(attributes["pull_number"])
	author := strings.TrimSpace(attributes["author"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := ""
	if owner != "" {
		orgURN = projectionURN(tenantID, "github_org", owner)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.org",
			Label:      owner,
			Attributes: map[string]string{"org": owner},
		})
	}

	repoURN := projectionURN(tenantID, "github_code_repository", repository)
	if repository != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        repoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.code.repository",
			Label:      repository,
			Attributes: map[string]string{"repository": repository},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	prURN := ""
	if repository != "" && pullNumber != "" {
		prURN = projectionURN(tenantID, "github_pull_request", repository+"#"+pullNumber)
		label := firstNonEmpty(stringValue(payload, "title"), repository+"#"+pullNumber)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        prURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.pull_request",
			Label:      label,
			Attributes: map[string]string{
				"html_url":    strings.TrimSpace(attributes["html_url"]),
				"pull_number": pullNumber,
				"repository":  repository,
				"state":       strings.TrimSpace(attributes["state"]),
			},
		})
		if repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), prURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	authorURN := githubUserURN(tenantID, author)
	if authorURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        authorURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.user",
			Label:      author,
			Attributes: map[string]string{"login": author},
		})
		if prURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), authorURN, prURN, relationAuthored, map[string]string{"event_id": event.GetId()}))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), authorURN, author, event.GetOccurredAt())
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func githubCodeRepositoryProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	repository := strings.TrimSpace(firstNonEmpty(attributes["repository"], attributes["full_name"], attributes["resource_name"]))
	owner := strings.TrimSpace(firstNonEmpty(attributes["owner_login"], attributes["owner"]))
	repoID := strings.TrimSpace(firstNonEmpty(attributes["repo_id"], attributes["resource_id"], repository))
	if repoID == "" {
		return nil, nil, nil
	}

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "github_org", owner)
	if owner != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.org",
			Label:      owner,
			Attributes: map[string]string{"org": owner, "owner_login": owner},
		})
	}

	codeRepoURN := projectionURN(tenantID, "github_code_repository", repoID)
	if codeRepoURN != "" {
		codeRepoAttrs := map[string]string{
			"archived":       strings.TrimSpace(attributes["archived"]),
			"default_branch": strings.TrimSpace(attributes["default_branch"]),
			"fork":           strings.TrimSpace(attributes["fork"]),
			"html_url":       strings.TrimSpace(attributes["html_url"]),
			"name":           strings.TrimSpace(attributes["name"]),
			"owner_login":    owner,
			"private":        strings.TrimSpace(attributes["private"]),
			"repo_id":        strings.TrimSpace(attributes["repo_id"]),
			"repository":     repository,
			"resource_id":    repoID,
			"resource_type":  "code_repository",
			"visibility":     strings.TrimSpace(attributes["visibility"]),
		}
		for _, key := range []string{"secret_scanning", "secret_scanning_push_protection", "dependabot_security_updates"} {
			if v := strings.TrimSpace(attributes[key]); v != "" {
				codeRepoAttrs[key] = v
			}
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        codeRepoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.code.repository",
			Label:      firstNonEmpty(repository, repoID),
			Attributes: codeRepoAttrs,
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), codeRepoURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "owner_login": owner}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func githubAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	org := strings.TrimSpace(attributes["org"])
	repo := strings.TrimSpace(attributes["repo"])
	resourceID := strings.TrimSpace(attributes["resource_id"])
	resourceType := strings.TrimSpace(attributes["resource_type"])
	actor := strings.TrimSpace(attributes["actor"])
	actorID := strings.TrimSpace(attributes["actor_id"])
	actorIsBot := strings.TrimSpace(attributes["actor_is_bot"])
	actorIsAgent := strings.TrimSpace(attributes["actor_is_agent"])
	actorType := strings.TrimSpace(attributes["actor_type"])
	actorEmail := strings.TrimSpace(attributes["actor_email"])
	actorExternalNameID := strings.TrimSpace(attributes["external_identity_nameid"])
	actorExternalUsername := strings.TrimSpace(attributes["external_identity_username"])
	orgID := strings.TrimSpace(attributes["org_id"])
	programmaticAccessType := strings.TrimSpace(attributes["programmatic_access_type"])
	targetUser := strings.TrimSpace(attributes["user"])
	tokenID := strings.TrimSpace(attributes["token_id"])

	// actorIsOrgSelf is true when GitHub stamps the audit event with the org
	// as its own actor — a pattern that shows up on system-level events such
	// as `integration_installation.version_updated` where no specific user
	// triggered the action. We detect it by comparing the audit log's
	// actor_id against org_id (both numeric and stamped by GitHub itself).
	// When this is true we route the acted_on edge from the github.org node
	// rather than minting a phantom `github.user:<org>` node, mirroring
	// cartography's separation of GitHubOrganization and GitHubUser.
	actorTypeIsOrg := strings.EqualFold(actorType, "Organization")
	actorIsOrgSelf := actorID != "" && orgID != "" && actorID == orgID
	actorIsUnresolvedPublicKey := strings.EqualFold(actorType, "Unresolved") && isGitHubPublicKeyCredential(programmaticAccessType)
	actorIsAutomation := githubAuditActorIsAutomation(actor, actorType, actorIsBot, actorIsAgent)

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "github_org", org)
	if org != "" {
		orgAttrs := map[string]string{"org": org}
		// Stamp the numeric org_id onto the github.org node so it stays
		// available when consumers need to reason about the org as a
		// first-class actor (e.g. distinguishing org-self events from
		// user actions in downstream rules).
		if orgID != "" {
			orgAttrs["org_id"] = orgID
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.org",
			Label:      org,
			Attributes: orgAttrs,
		})
	}
	actorOrgURN := orgURN
	if actorTypeIsOrg {
		actorOrgURN = projectionURN(tenantID, "github_org", firstNonEmpty(actor, org))
		if actorOrgURN != "" && actor != "" && !strings.EqualFold(actor, org) {
			actorOrgAttrs := map[string]string{"org": actor}
			addProjectedAttribute(actorOrgAttrs, "org_id", actorID)
			addEntity(entities, &ports.ProjectedEntity{
				URN:        actorOrgURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "github.org",
				Label:      actor,
				Attributes: actorOrgAttrs,
			})
		}
	}

	repoURN := projectionURN(tenantID, "github_code_repository", firstNonEmpty(repo, resourceID))
	repoScopePresent := repo != "" || (resourceID != "" && strings.Contains(resourceID, "/"))
	if repoScopePresent {
		label := firstNonEmpty(repo, resourceID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        repoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.code.repository",
			Label:      label,
			Attributes: map[string]string{"repository": label},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	resourceURN := githubResourceURN(tenantID, resourceType, resourceID, repoURN)
	programmaticCredential := githubAuditProgrammaticCredentialResource(resourceType)
	programmaticCredentialURN := ""
	if programmaticCredential {
		programmaticCredentialURN = githubCredentialURN(tenantID, githubProgrammaticCredentialID(attributes))
	}
	if resourceURN != "" {
		label := firstNonEmpty(resourceID, resourceType)
		entityType := "github.resource"
		if repoURN != "" && resourceURN == repoURN {
			entityType = "github.code.repository"
			label = firstNonEmpty(repo, resourceID)
		}
		resourceAttrs := map[string]string{
			"resource_id":   resourceID,
			"resource_type": resourceType,
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: entityType,
			Label:      label,
			Attributes: resourceAttrs,
		})
		if orgURN != "" && repoURN == "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if repoURN != "" && resourceURN != repoURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
	if programmaticCredentialURN != "" {
		credentialAttrs := map[string]string{
			"credential_type":          resourceType,
			"programmatic_access_type": programmaticAccessType,
			"resource_id":              resourceID,
			"resource_type":            resourceType,
			"status":                   githubProgrammaticCredentialStatus(attributes),
		}
		addProjectedAttribute(credentialAttrs, "actor", actor)
		addProjectedAttribute(credentialAttrs, "github_app_id", strings.TrimSpace(attributes["github_app_id"]))
		addProjectedAttribute(credentialAttrs, "org", org)
		addProjectedAttribute(credentialAttrs, "org_id", orgID)
		addProjectedAttribute(credentialAttrs, "repository", repo)
		addProjectedAttribute(credentialAttrs, "scope", strings.TrimSpace(attributes["scope"]))
		addProjectedAttribute(credentialAttrs, "token_id", tokenID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        programmaticCredentialURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.credential",
			Label:      firstNonEmpty(attributes["name"], attributes["github_app_id"], tokenID, resourceID, resourceType),
			Attributes: credentialAttrs,
		})
		if resourceURN != "" && resourceURN != programmaticCredentialURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), programmaticCredentialURN, resourceURN, relationActedOn, map[string]string{
				"action":                   strings.TrimSpace(attributes["action"]),
				"event_id":                 event.GetId(),
				"programmatic_access_type": programmaticAccessType,
			}))
		}
		if repoScopePresent && repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), programmaticCredentialURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		} else if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), programmaticCredentialURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
	if runnerURN, runnerAttrs := githubSelfHostedRunnerProjection(tenantID, attributes); runnerURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        runnerURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.runner",
			Label:      firstNonEmpty(runnerAttrs["runner_name"], runnerAttrs["runner_id"]),
			Attributes: runnerAttrs,
		})
		if repoScopePresent && repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), runnerURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		} else if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), runnerURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	// `at` carries the audit event's OccurredAt timestamp so graph rules can tell
	// recent GitHub activity from stale historical edges. mergeGraphAttributes is
	// latest-wins, so under the normal in-order ingestion path this field always
	// reflects the most recent action that touched the edge. The
	// deprovisioned-Okta-active-in-GitHub rule uses this to avoid reporting users as
	// "still active" purely from pre-offboarding history.
	actedAttrs := map[string]string{
		"action":   strings.TrimSpace(attributes["action"]),
		"event_id": event.GetId(),
	}
	addProjectedAttribute(actedAttrs, "actor_type", actorType)
	addProjectedAttribute(actedAttrs, "programmatic_access_type", programmaticAccessType)
	addProjectedAttribute(actedAttrs, "source_runtime_id", strings.TrimSpace(attributes["source_runtime_id"]))
	addProjectedAttribute(actedAttrs, "transport_protocol_name", strings.TrimSpace(attributes["transport_protocol_name"]))
	if occurredAt := event.GetOccurredAt(); occurredAt != nil && occurredAt.IsValid() {
		actedAttrs["at"] = occurredAt.AsTime().UTC().Format(time.RFC3339)
	}

	// When the audit event's actor is the org itself (system-level events),
	// route the acted_on edge from the github.org node rather than minting a
	// `github.user:<org>` shadow node. This matches GitHub's data model
	// (orgs are not users) and prevents identity rules from chasing the org
	// as if it were a person that should have an Okta link.
	if (actorIsOrgSelf || actorTypeIsOrg) && actorOrgURN != "" {
		if resourceURN != "" && resourceURN != actorOrgURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorOrgURN, resourceURN, relationActedOn, actedAttrs))
		}
	} else if actorIsUnresolvedPublicKey {
		credentialURN := githubCredentialURN(tenantID, githubPublicKeyCredentialID(tokenID, actor, repo, resourceID, org))
		if credentialURN != "" {
			credentialAttrs := map[string]string{
				"actor":                    actor,
				"credential_type":          "public_key",
				"programmatic_access_type": programmaticAccessType,
			}
			addProjectedAttribute(credentialAttrs, "org", org)
			addProjectedAttribute(credentialAttrs, "org_id", orgID)
			addProjectedAttribute(credentialAttrs, "repository", firstNonEmpty(repo, resourceID))
			addProjectedAttribute(credentialAttrs, "token_id", tokenID)
			addProjectedAttribute(credentialAttrs, "transport_protocol_name", strings.TrimSpace(attributes["transport_protocol_name"]))
			addEntity(entities, &ports.ProjectedEntity{
				URN:        credentialURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "github.credential",
				Label:      actor,
				Attributes: credentialAttrs,
			})
			if resourceURN != "" {
				addLink(links, projectedLink(tenantID, event.GetSourceId(), credentialURN, resourceURN, relationActedOn, actedAttrs))
			}
		}
	} else if actorIsAutomation {
		credentialID := githubAutomationCredentialID(attributes)
		if credentialID != "" {
			credentialURN := githubCredentialURN(tenantID, credentialID)
			credentialAttrs := map[string]string{
				"actor":                    actor,
				"actor_is_agent":           actorIsAgent,
				"actor_is_bot":             actorIsBot,
				"actor_type":               actorType,
				"credential_type":          "automation_actor",
				"programmatic_access_type": programmaticAccessType,
			}
			addProjectedAttribute(credentialAttrs, "github_app_id", strings.TrimSpace(attributes["github_app_id"]))
			addProjectedAttribute(credentialAttrs, "org", org)
			addProjectedAttribute(credentialAttrs, "org_id", orgID)
			addProjectedAttribute(credentialAttrs, "repository", repo)
			addProjectedAttribute(credentialAttrs, "token_id", tokenID)
			addEntity(entities, &ports.ProjectedEntity{
				URN:        credentialURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "github.credential",
				Label:      firstNonEmpty(strings.TrimSpace(attributes["github_app_name"]), strings.TrimSpace(attributes["github_app_id"]), actor, tokenID),
				Attributes: credentialAttrs,
			})
			if resourceURN != "" && resourceURN != credentialURN {
				automationActedAttrs := cloneStringMap(actedAttrs)
				automationActedAttrs["match_type"] = "automation_actor"
				addLink(links, projectedLink(tenantID, event.GetSourceId(), credentialURN, resourceURN, relationActedOn, automationActedAttrs))
			}
			if repoScopePresent && repoURN != "" {
				addLink(links, projectedLink(tenantID, event.GetSourceId(), credentialURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
			} else if orgURN != "" {
				addLink(links, projectedLink(tenantID, event.GetSourceId(), credentialURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
			}
		}
	} else {
		actorURN := githubUserURN(tenantID, actor)
		if actorURN != "" {
			actorAttrs := map[string]string{
				"external_identity_nameid":   actorExternalNameID,
				"external_identity_username": actorExternalUsername,
				"login":                      actor,
			}
			// Stamp the GitHub-native actor classification signals onto
			// the github.user node so downstream rules can distinguish
			// real users from bots and integration agents structurally,
			// without resorting to login-string heuristics. These fields
			// are stamped by GitHub itself on every audit event; values
			// are kept verbatim ("true" / "false") and merged latest-wins.
			if actorID != "" {
				actorAttrs["actor_id"] = actorID
			}
			if actorType != "" {
				actorAttrs["actor_type"] = actorType
			}
			if actorIsBot != "" {
				actorAttrs["actor_is_bot"] = actorIsBot
			}
			if actorIsAgent != "" {
				actorAttrs["actor_is_agent"] = actorIsAgent
			}
			if orgID != "" {
				actorAttrs["org_id"] = orgID
			}
			addEntity(entities, &ports.ProjectedEntity{
				URN:        actorURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "github.user",
				Label:      actor,
				Attributes: actorAttrs,
			})
			if resourceURN != "" {
				addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, resourceURN, relationActedOn, actedAttrs))
			}
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actor, event.GetOccurredAt())
			if !sameIdentifier(actor, actorExternalNameID) {
				addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actorExternalNameID, event.GetOccurredAt())
			}
			if !sameIdentifier(actor, actorExternalUsername) && !sameIdentifier(actorExternalNameID, actorExternalUsername) {
				addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actorExternalUsername, event.GetOccurredAt())
			}
			if !sameIdentifier(actor, actorEmail) && !sameIdentifier(actorExternalNameID, actorEmail) && !sameIdentifier(actorExternalUsername, actorEmail) {
				addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actorEmail, event.GetOccurredAt())
			}
		}
	}

	// The previous-version actor URN computed against the github.user
	// URN scheme is used here only to suppress redundant targeted edges
	// when actor==targetUser. The org-self path above doesn't create a
	// github.user actor, so this is purely for the user-actor case.
	previousActorURN := githubUserURN(tenantID, actor)
	targetURN := githubUserURN(tenantID, targetUser)
	if targetURN != "" && targetURN != previousActorURN && githubSyntheticTargetActorType(targetUser) == "" {
		targetAttrs := map[string]string{"login": targetUser}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        targetURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.user",
			Label:      targetUser,
			Attributes: targetAttrs,
		})
		if resourceURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, resourceURN, relationTargeted, map[string]string{"event_id": event.GetId()}))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), targetURN, targetUser, event.GetOccurredAt())
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func isGitHubPublicKeyCredential(programmaticAccessType string) bool {
	normalized := strings.ToLower(strings.TrimSpace(programmaticAccessType))
	return strings.Contains(normalized, "public key")
}

func githubAuditActorIsAutomation(actor string, actorType string, actorIsBot string, actorIsAgent string) bool {
	if strings.EqualFold(strings.TrimSpace(actorIsBot), "true") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(actorIsAgent), "true") {
		return true
	}
	if githubActorTypeClassifiesAutomation(actorType) {
		return true
	}
	return githubSyntheticTargetActorType(actor) != ""
}

func githubActorTypeClassifiesAutomation(actorType string) bool {
	switch strings.ToLower(strings.TrimSpace(actorType)) {
	case "bot", "organization", "unresolved":
		return true
	}
	return false
}

// githubSyntheticTargetActorType returns the automation classification for a
// structurally synthetic login (i.e. not a real user that could be linked to
// Okta).
//
// Two synthetic shapes are recognised today:
//
//   - GitHub reserves the trailing `[bot]` suffix for App-issued
//     identities (dependabot[bot], github-actions[bot], renovate[bot],
//     coderabbitai[bot], factory-droid[bot], ...). The suffix is part of
//     GitHub's public contract; vendor changes don't alter it.
//
//   - The literal `deploy_key` login is GitHub's synthetic placeholder
//     for SSH-key activity (no real /users/{login} resolution). The
//     actor-side projector path routes these to `github.credential`
//     via `actorIsUnresolvedPublicKey`.
//
// Returns "" when the login is a plain human-shaped GitHub username.
func githubSyntheticTargetActorType(login string) string {
	trimmed := strings.TrimSpace(login)
	if trimmed == "" {
		return ""
	}
	lower := strings.ToLower(trimmed)
	if strings.HasSuffix(lower, "[bot]") {
		return "Bot"
	}
	switch lower {
	case "deploy_key", "deploy-key":
		return "Unresolved"
	}
	return ""
}

func githubPublicKeyCredentialID(tokenID string, actor string, repo string, resourceID string, org string) string {
	if strings.TrimSpace(tokenID) != "" {
		return strings.TrimSpace(tokenID)
	}
	scope := firstNonEmpty(repo, resourceID, org)
	if strings.TrimSpace(actor) != "" && scope != "" {
		return strings.TrimSpace(actor) + "@" + scope
	}
	return firstNonEmpty(actor, scope)
}

func githubCredentialURN(tenantID string, credentialID string) string {
	return projectionURN(tenantID, "github_credential", credentialID)
}

func githubAuditProgrammaticCredentialResource(resourceType string) bool {
	switch strings.ToLower(strings.TrimSpace(resourceType)) {
	case "personal_access_token",
		"org_credential_authorization",
		"integration_installation",
		"integration_installation_request",
		"oauth_application",
		"integration":
		return true
	default:
		return false
	}
}

func githubProgrammaticCredentialID(attributes map[string]string) string {
	resourceType := strings.TrimSpace(attributes["resource_type"])
	prefix := firstNonEmpty(resourceType, "programmatic_credential")
	switch strings.ToLower(resourceType) {
	case "personal_access_token", "org_credential_authorization":
		if tokenID := strings.TrimSpace(attributes["token_id"]); tokenID != "" {
			return prefix + ":" + tokenID
		}
	case "integration_installation", "integration_installation_request", "integration":
		if appID := strings.TrimSpace(attributes["github_app_id"]); appID != "" {
			return prefix + ":" + appID
		}
	}
	scope := firstNonEmpty(attributes["repo"], attributes["org"], attributes["scope"])
	return strings.Join(nonEmptyStrings(prefix, attributes["resource_id"], scope, attributes["actor"]), ":")
}

func githubAutomationCredentialID(attributes map[string]string) string {
	if appID := strings.TrimSpace(attributes["github_app_id"]); appID != "" {
		return "automation_app:" + appID
	}
	if tokenID := strings.TrimSpace(attributes["token_id"]); tokenID != "" {
		return "automation_token:" + tokenID
	}
	actor := strings.TrimSpace(attributes["actor"])
	scope := strings.TrimSpace(firstNonEmpty(attributes["repo"], attributes["resource_id"], attributes["org"], attributes["scope"]))
	if actor == "" && scope == "" {
		return ""
	}
	return strings.Join(nonEmptyStrings("automation_actor", actor, scope), ":")
}

func githubProgrammaticCredentialStatus(attributes map[string]string) string {
	normalized := strings.ToLower(strings.TrimSpace(attributes["action"]))
	operationType := strings.ToLower(strings.TrimSpace(attributes["operation_type"]))
	if containsAny(operationType, "remove", "removed", "revoke", "revoked", "expire", "expired", "delete", "deleted") {
		return "inactive"
	}
	if containsAny(normalized, "revoke", "revoked", "deauthorize", "delete", "remove", "destroy", "suspend") {
		return "inactive"
	}
	if containsAny(normalized, "create", "grant", "authorize", "install", "request", "access_granted", "approve") {
		return "active"
	}
	return "unknown"
}

func githubSelfHostedRunnerProjection(tenantID string, attributes map[string]string) (string, map[string]string) {
	if !githubAuditProjectsSelfHostedRunner(attributes) {
		return "", nil
	}
	runnerID := strings.TrimSpace(attributes["runner_id"])
	if runnerID == "" {
		return "", nil
	}
	scope := strings.TrimSpace(firstNonEmpty(attributes["runner_scope"], attributes["scope"], attributes["repo"], attributes["org"]))
	if scope == "" {
		return "", nil
	}
	scopeType, scopeID := githubRunnerScope(scope)
	if scopeID == "" {
		return "", nil
	}
	attrs := map[string]string{
		"action":            strings.TrimSpace(attributes["action"]),
		"runner_id":         runnerID,
		"runner_name":       strings.TrimSpace(attributes["runner_name"]),
		"runner_scope":      scopeID,
		"runner_scope_type": scopeType,
		"runner_status":     githubSelfHostedRunnerStatus(attributes),
	}
	addProjectedAttribute(attrs, "host_trusted", firstNonEmpty(attributes["runner_host_trusted"], attributes["host_trusted"], attributes["trusted_host"]))
	addProjectedAttribute(attrs, "runner_ephemeral", firstNonEmpty(attributes["runner_ephemeral"], attributes["ephemeral"], attributes["is_ephemeral"]))
	addProjectedAttribute(attrs, "runner_group_name", attributes["runner_group_name"])
	addProjectedAttribute(attrs, "runner_registered", firstNonEmpty(attributes["runner_registered"], attributes["registered"], attributes["is_registered"]))
	addProjectedAttribute(attrs, "runner_state", attributes["runner_state"])
	addProjectedAttribute(attrs, "runner_untrusted", firstNonEmpty(attributes["runner_untrusted"], attributes["host_untrusted"], attributes["untrusted_host"]))
	return projectionURN(tenantID, "github_runner", scopeID, runnerID), attrs
}

func githubAuditProjectsSelfHostedRunner(attributes map[string]string) bool {
	action := strings.TrimSpace(attributes["action"])
	return githubSelfHostedRunnerAuditAction(action)
}

func githubSelfHostedRunnerAuditAction(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		return false
	}
	// GitHub audit rows such as workflows.prepared_workflow_job include per-job
	// GitHub-hosted runner IDs. Those are ephemeral execution details, not
	// customer-managed self-hosted runner assets.
	if strings.HasPrefix(action, "workflows.") {
		return false
	}
	return strings.Contains(action, "self_hosted_runner")
}

func githubRunnerScope(scope string) (string, string) {
	normalized := strings.TrimSpace(scope)
	if normalized == "" {
		return "", ""
	}
	lower := strings.ToLower(normalized)
	switch {
	case strings.HasPrefix(lower, "repo:"), strings.Contains(normalized, "/"):
		return "repo", normalizeGitHubRunnerScopeID(normalized, "repo")
	case strings.HasPrefix(lower, "enterprise:"):
		return "enterprise", normalizeGitHubRunnerScopeID(normalized, "enterprise")
	case strings.HasPrefix(lower, "org:"):
		return "org", normalizeGitHubRunnerScopeID(normalized, "org")
	default:
		return "org", "org:" + normalized
	}
}

func normalizeGitHubRunnerScopeID(scope string, kind string) string {
	normalized := strings.TrimSpace(scope)
	prefix := kind + ":"
	if strings.HasPrefix(strings.ToLower(normalized), prefix) {
		return normalized
	}
	return prefix + normalized
}

func githubSelfHostedRunnerStatus(attributes map[string]string) string {
	action := strings.ToLower(strings.TrimSpace(attributes["action"]))
	state := strings.ToLower(strings.TrimSpace(firstNonEmpty(attributes["runner_state"], attributes["state"], attributes["status"])))
	registered := strings.ToLower(strings.TrimSpace(firstNonEmpty(attributes["runner_registered"], attributes["registered"], attributes["is_registered"])))
	if registered == "false" || registered == "0" || registered == "no" {
		return "inactive"
	}
	if containsAny(state, "removed", "deleted", "deregistered", "unregistered") ||
		containsAny(action, "remove_self_hosted_runner", "deregister_self_hosted_runner", "runner_removed") {
		return "inactive"
	}
	return "active"
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func nonEmptyStrings(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func githubDependabotAlertProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	repository := strings.TrimSpace(attributes["repository"])
	owner := strings.TrimSpace(attributes["owner"])
	alertNumber := strings.TrimSpace(attributes["alert_number"])
	packageName := strings.TrimSpace(attributes["package"])
	ecosystem := strings.TrimSpace(attributes["ecosystem"])
	manifestPath := strings.TrimSpace(attributes["manifest_path"])
	advisoryID := firstNonEmpty(attributes["advisory_ghsa_id"], attributes["advisory_cve_id"])
	vulnerabilityID := firstNonEmpty(canonicalVulnerabilityIdentifier(attributes), advisoryID)

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "github_org", owner)
	if owner != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.org",
			Label:      owner,
			Attributes: map[string]string{"org": owner},
		})
	}

	repoURN := projectionURN(tenantID, "github_code_repository", repository)
	if repository != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        repoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.code.repository",
			Label:      repository,
			Attributes: map[string]string{"repository": repository},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	alertURN := projectionURN(tenantID, "github_dependabot_alert", repository, alertNumber)
	if repository != "" && alertNumber != "" {
		label := firstNonEmpty(attributes["advisory_ghsa_id"], attributes["advisory_cve_id"], repository+"#"+alertNumber)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        alertURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.dependabot_alert",
			Label:      label,
			Attributes: map[string]string{
				"alert_number":       alertNumber,
				"ecosystem":          ecosystem,
				"html_url":           strings.TrimSpace(attributes["html_url"]),
				"package":            packageName,
				"repository":         repository,
				"severity":           strings.TrimSpace(attributes["severity"]),
				"state":              strings.TrimSpace(attributes["state"]),
				"vulnerability_id":   vulnerabilityID,
				"vulnerability_type": "dependabot",
			},
		})
		if repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	advisoryURN := projectionURN(tenantID, "github_advisory", advisoryID)
	if advisoryID != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        advisoryURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.security_advisory",
			Label:      advisoryID,
			Attributes: map[string]string{
				"cve_id":   strings.TrimSpace(attributes["advisory_cve_id"]),
				"ghsa_id":  strings.TrimSpace(attributes["advisory_ghsa_id"]),
				"severity": strings.TrimSpace(attributes["advisory_severity"]),
			},
		})
		if alertURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, advisoryURN, relationAffectedBy, map[string]string{"event_id": event.GetId()}))
		}
	}

	packageURN := projectionURN(tenantID, "package", ecosystem, packageName)
	if packageName != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        packageURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "package",
			Label:      firstNonEmpty(ecosystem+"/"+packageName, packageName),
			Attributes: map[string]string{
				"ecosystem": ecosystem,
				"name":      packageName,
			},
		})
		if alertURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, packageURN, relationAffects, map[string]string{"event_id": event.GetId()}))
		}
	}

	vulnerabilityURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), attributes)
	canonicalPackageURN := addCanonicalPackageEntity(entities, tenantID, event.GetSourceId(), attributes, ecosystem)
	if vulnerabilityURN != "" {
		evidenceAttributes := vulnerabilityEvidenceAttributes(event, attributes)
		if alertURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, vulnerabilityURN, relationAffectedBy, evidenceAttributes))
		}
		if packageURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, vulnerabilityURN, relationAffectedBy, evidenceAttributes))
		}
		if canonicalPackageURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), canonicalPackageURN, vulnerabilityURN, relationAffectedBy, evidenceAttributes))
		}
	}
	if packageURN != "" && canonicalPackageURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, canonicalPackageURN, relationRepresents, packageIdentityAttributes(event, attributes, ecosystem)))
	}
	addGitHubDependabotDependencyContext(entities, links, tenantID, event, repoURN, alertURN, packageURN, canonicalPackageURN, repository, manifestPath, ecosystem, packageName)
	addGitHubAlertActorLinks(entities, links, tenantID, event, alertURN, attributes["dismissed_by"], attributes["dismissed_by_id"], "dismissed_by")

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addGitHubDependabotDependencyContext(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, repoURN string, alertURN string, packageURN string, canonicalPackageURN string, repository string, manifestPath string, ecosystem string, packageName string) {
	repository = strings.TrimSpace(repository)
	manifestPath = strings.TrimSpace(manifestPath)
	packageName = strings.TrimSpace(packageName)
	if repository == "" || manifestPath == "" || packageName == "" {
		return
	}
	manifestURN := projectionURN(tenantID, "github_dependency_manifest", repository, manifestPath)
	dependencyURN := projectionURN(tenantID, "github_dependency", repository, manifestPath, ecosystem, packageName)
	if manifestURN == "" || dependencyURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        manifestURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "github.dependency_manifest",
		Label:      manifestPath,
		Attributes: map[string]string{
			"ecosystem":     strings.TrimSpace(ecosystem),
			"manifest_path": manifestPath,
			"repository":    repository,
		},
	})
	addEntity(entities, &ports.ProjectedEntity{
		URN:        dependencyURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "github.dependency",
		Label:      packageName,
		Attributes: map[string]string{
			"ecosystem":     strings.TrimSpace(ecosystem),
			"manifest_path": manifestPath,
			"package":       packageName,
			"repository":    repository,
		},
	})
	if repoURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), manifestURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, dependencyURN, relationContains, map[string]string{
			"ecosystem":     strings.TrimSpace(ecosystem),
			"event_id":      event.GetId(),
			"manifest_path": manifestPath,
			"package":       packageName,
		}))
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), dependencyURN, manifestURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), manifestURN, dependencyURN, relationContains, map[string]string{"event_id": event.GetId()}))
	if packageURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), dependencyURN, packageURN, relationRepresents, map[string]string{
			"ecosystem":     strings.TrimSpace(ecosystem),
			"event_id":      event.GetId(),
			"manifest_path": manifestPath,
			"package":       packageName,
		}))
		if repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, packageURN, relationContains, map[string]string{
				"ecosystem":     strings.TrimSpace(ecosystem),
				"event_id":      event.GetId(),
				"manifest_path": manifestPath,
				"package":       packageName,
			}))
		}
	}
	if canonicalPackageURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), dependencyURN, canonicalPackageURN, relationRepresents, packageIdentityAttributes(event, event.GetAttributes(), ecosystem)))
		if repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, canonicalPackageURN, relationContains, map[string]string{
				"ecosystem":     strings.TrimSpace(ecosystem),
				"event_id":      event.GetId(),
				"manifest_path": manifestPath,
				"package":       packageName,
			}))
		}
		if alertURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, canonicalPackageURN, relationAffects, map[string]string{
				"ecosystem":     strings.TrimSpace(ecosystem),
				"event_id":      event.GetId(),
				"manifest_path": manifestPath,
				"package":       packageName,
			}))
		}
	}
	if alertURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, dependencyURN, relationAffects, map[string]string{"event_id": event.GetId()}))
	}
}

func githubSecretScanningAlertProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	owner := strings.TrimSpace(attributes["owner"])
	repository := strings.TrimSpace(attributes["repository"])
	alertNumber := strings.TrimSpace(attributes["alert_number"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "github_org", owner)
	if owner != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.org",
			Label:      owner,
			Attributes: map[string]string{"org": owner},
		})
	}

	repoURN := projectionURN(tenantID, "github_code_repository", repository)
	if repository != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        repoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.code.repository",
			Label:      repository,
			Attributes: map[string]string{"repository": repository},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	alertLabel := repository + "#" + alertNumber
	if repository == "" {
		alertLabel = owner + "#" + alertNumber
	}
	alertURN := projectionURN(tenantID, "github_secret_scanning_alert", owner, alertNumber)
	if alertNumber != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        alertURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.secret_scanning_alert",
			Label:      alertLabel,
			Attributes: map[string]string{
				"alert_number":             alertNumber,
				"html_url":                 strings.TrimSpace(attributes["html_url"]),
				"push_protection_bypassed": strings.TrimSpace(attributes["push_protection_bypassed"]),
				"repository":               repository,
				"resolution":               strings.TrimSpace(attributes["resolution"]),
				"secret_type":              strings.TrimSpace(attributes["secret_type"]),
				"secret_type_display_name": strings.TrimSpace(attributes["secret_type_display_name"]),
				"state":                    strings.TrimSpace(attributes["state"]),
			},
		})
		if repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
	addGitHubAlertActorLinks(entities, links, tenantID, event, alertURN, attributes["resolved_by"], attributes["resolved_by_id"], "resolved_by")
	addGitHubAlertActorLinks(entities, links, tenantID, event, alertURN, attributes["push_protection_bypassed_by"], attributes["push_protection_bypassed_by_id"], "push_protection_bypassed_by")

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addGitHubAlertActorLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, alertURN string, login string, userID string, actorRole string) {
	login = strings.TrimSpace(login)
	alertURN = strings.TrimSpace(alertURN)
	if login == "" || alertURN == "" {
		return
	}
	userID = strings.TrimSpace(userID)
	actorRole = strings.TrimSpace(actorRole)
	actorURN := projectionURN(tenantID, "github_user", login)
	actorAttrs := map[string]string{"login": login}
	if userID != "" {
		actorAttrs["user_id"] = userID
	}
	if actorRole != "" {
		actorAttrs["actor_role"] = actorRole
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        actorURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "github.user",
		Label:      login,
		Attributes: actorAttrs,
	})
	linkAttrs := map[string]string{"event_id": event.GetId()}
	if actorRole != "" {
		linkAttrs["actor_role"] = actorRole
	}
	linkKey := actorURN + "|" + relationActedOn + "|" + alertURN
	if existing := links[linkKey]; existing != nil {
		mergeCSVLinkAttribute(existing.Attributes, "event_id", event.GetId())
		mergeCSVLinkAttribute(existing.Attributes, "actor_role", actorRole)
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, login, event.GetOccurredAt())
		return
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, alertURN, relationActedOn, linkAttrs))
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, login, event.GetOccurredAt())
}

func mergeCSVLinkAttribute(attributes map[string]string, key string, value string) {
	value = strings.TrimSpace(value)
	if attributes == nil || key == "" || value == "" {
		return
	}
	for _, existing := range strings.Split(attributes[key], ",") {
		if strings.TrimSpace(existing) == value {
			return
		}
	}
	if strings.TrimSpace(attributes[key]) == "" {
		attributes[key] = value
		return
	}
	attributes[key] += "," + value
}

func githubOrgMemberProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	owner := strings.TrimSpace(attributes["owner"])
	login := strings.TrimSpace(attributes["login"])
	role := strings.TrimSpace(attributes["role"])
	userID := strings.TrimSpace(attributes["user_id"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "github_org", owner)
	if owner != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "github.org", Label: owner,
			Attributes: map[string]string{"org": owner},
		})
	}

	memberURN := projectionURN(tenantID, "github_user", login)
	if login != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: memberURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "github.user", Label: login,
			Attributes: map[string]string{"login": login, "user_id": userID, "role": role},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), memberURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "role": role}))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), memberURN, login, event.GetOccurredAt())
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func githubOrgInstallationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	owner := strings.TrimSpace(attributes["owner"])
	installID := strings.TrimSpace(attributes["installation_id"])
	appSlug := strings.TrimSpace(attributes["app_slug"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "github_org", owner)
	if owner != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "github.org", Label: owner,
			Attributes: map[string]string{"org": owner},
		})
	}

	installURN := projectionURN(tenantID, "github_installation", installID)
	if installID != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: installURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "github.org_installation", Label: firstNonEmpty(appSlug, installID),
			Attributes: map[string]string{
				"app_slug":             appSlug,
				"installation_id":      installID,
				"repository_selection": strings.TrimSpace(attributes["repository_selection"]),
				"target_type":          strings.TrimSpace(attributes["target_type"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), installURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaAuthenticatorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	authID := strings.TrimSpace(attributes["authenticator_id"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.org", Label: domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	authURN := projectionURN(tenantID, "okta_authenticator", authID)
	if authID != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: authURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.authenticator", Label: firstNonEmpty(attributes["name"], authID),
			Attributes: map[string]string{
				"authenticator_id": authID,
				"key":              strings.TrimSpace(attributes["key"]),
				"name":             strings.TrimSpace(attributes["name"]),
				"status":           strings.TrimSpace(attributes["status"]),
				"type":             strings.TrimSpace(attributes["type"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), authURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaThreatInsightProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.org", Label: domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	tiURN := projectionURN(tenantID, "okta_threat_insight", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: tiURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.threat_insight", Label: "ThreatInsight",
			Attributes: map[string]string{
				"action":             strings.TrimSpace(attributes["action"]),
				"exclude_zone_count": strings.TrimSpace(attributes["exclude_zone_count"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), tiURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaIdentityProviderProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	idpID := strings.TrimSpace(firstNonEmpty(attributes["idp_id"], attributes["identity_provider_id"]))

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.org", Label: domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	idpURN := projectionURN(tenantID, "okta_identity_provider", idpID)
	if idpID != "" {
		idpAttrs := map[string]string{
			"idp_id":               idpID,
			"identity_provider_id": idpID,
			"name":                 strings.TrimSpace(firstNonEmpty(attributes["name"], attributes["idp_name"])),
			"status":               strings.TrimSpace(attributes["status"]),
			"type":                 strings.TrimSpace(firstNonEmpty(attributes["type"], attributes["idp_type"])),
		}
		for _, key := range []string{"acs_type", "audience", "client_id", "issuer", "kid", "protocol_type", "sso_binding", "sso_url_host"} {
			addProjectedAttribute(idpAttrs, key, attributes[key])
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        idpURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.identity_provider",
			Label:      firstNonEmpty(idpAttrs["name"], idpID),
			Attributes: idpAttrs,
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), idpURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaNetworkZoneProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	zoneID := strings.TrimSpace(firstNonEmpty(attributes["zone_id"], attributes["network_zone_id"]))

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.org", Label: domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	zoneURN := projectionURN(tenantID, "okta_network_zone", zoneID)
	if zoneID != "" {
		zoneAttrs := map[string]string{
			"name":            strings.TrimSpace(attributes["name"]),
			"network_zone_id": zoneID,
			"status":          strings.TrimSpace(attributes["status"]),
			"type":            strings.TrimSpace(firstNonEmpty(attributes["type"], attributes["zone_type"])),
			"usage":           strings.TrimSpace(attributes["usage"]),
			"zone_id":         zoneID,
		}
		for _, key := range []string{"asn_count", "asns", "gateway_count", "gateway_values", "location_count", "proxy_count", "proxy_values", "system"} {
			addProjectedAttribute(zoneAttrs, key, attributes[key])
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        zoneURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.network_zone",
			Label:      firstNonEmpty(zoneAttrs["name"], zoneID),
			Attributes: zoneAttrs,
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), zoneURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaTrustedOriginProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	originID := strings.TrimSpace(attributes["trusted_origin_id"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.org", Label: domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	originURN := projectionURN(tenantID, "okta_trusted_origin", originID)
	if originID != "" {
		originAttrs := map[string]string{
			"name":              strings.TrimSpace(attributes["name"]),
			"origin":            strings.TrimSpace(attributes["origin"]),
			"origin_host":       strings.TrimSpace(attributes["origin_host"]),
			"status":            strings.TrimSpace(attributes["status"]),
			"trusted_origin_id": originID,
		}
		for _, key := range []string{"cors", "redirect", "scope_count", "scope_types", "wildcard_origin"} {
			addProjectedAttribute(originAttrs, key, attributes[key])
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        originURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.trusted_origin",
			Label:      firstNonEmpty(originAttrs["name"], originAttrs["origin"], originID),
			Attributes: originAttrs,
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), originURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	userID := strings.TrimSpace(attributes["user_id"])
	email := strings.TrimSpace(attributes["email"])
	login := strings.TrimSpace(attributes["login"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.org",
			Label:      domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	userURN := oktaUserURN(tenantID, userID)
	if userURN != "" {
		userAttrs := map[string]string{
			"email":  email,
			"login":  login,
			"status": strings.TrimSpace(attributes["status"]),
		}
		for _, key := range []string{
			"department",
			"employee_number",
			"job_title",
			"manager",
			"manager_id",
			"mfa_enrolled",
			"mfa_factor_count",
			"mfa_factor_types",
			"mfa_phishing_resistant",
			"organization",
			"user_type",
		} {
			if v := strings.TrimSpace(attributes[key]); v != "" {
				userAttrs[key] = v
			}
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        userURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.user",
			Label:      firstNonEmpty(email, login, userID),
			Attributes: userAttrs,
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		// observedAt is the time this projection ran, not the event's
		// OccurredAt. okta.user events derive OccurredAt from profile-history
		// fields (LastUpdated/Created/Activated/StatusChanged/LastLogin/
		// PasswordChanged) in sources/okta/source.go's userOccurredAt, so any
		// user whose profile has been static for longer than the graph-rule
		// recency window would have its represents_identity edges restamped
		// with an already-stale `at` on every fresh sync. Identity-aware rules
		// (e.g. the deprovisioned-Okta-active-in-GitHub graph rule) treat
		// stale-`at` rows as evidence the identifier link is no longer
		// asserted and drop them, which silently swallows offboarding gaps for
		// long-static accounts. Stamping with the projection's own clock
		// instead means any current inventory link is always recent, while
		// edges that stop being re-asserted (e.g. a renamed email) still age
		// out naturally because subsequent syncs no longer refresh them.
		observedAt := timestamppb.New(time.Now().UTC())
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, email, observedAt)
		if !sameIdentifier(email, login) {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, login, observedAt)
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	actorID := strings.TrimSpace(attributes["actor_id"])
	actorType := strings.TrimSpace(attributes["actor_type"])
	actorAlternateID := strings.TrimSpace(attributes["actor_alternate_id"])
	actorDisplayName := strings.TrimSpace(attributes["actor_display_name"])
	resourceID := strings.TrimSpace(attributes["resource_id"])
	resourceType := strings.TrimSpace(attributes["resource_type"])
	targetType := strings.TrimSpace(attributes["target_type"])
	targetAlternateID := strings.TrimSpace(attributes["target_alternate_id"])
	targetAppID := firstNonEmpty(attributes["target_app_id"], attributes["app_id"])
	targetAppLabel := firstNonEmpty(attributes["target_app_label"], attributes["target_display_name"], targetAppID)
	oauthClientID := firstNonEmpty(attributes["oauth_client_id"], attributes["client_id"])
	oauthClientLabel := firstNonEmpty(attributes["oauth_client_label"], attributes["actor_display_name"], oauthClientID)

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.org",
			Label:      domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	suppressResource := oktaEphemeralOAuthRuntimeResource(resourceType, attributes)
	resourceURN := ""
	if !suppressResource {
		resourceURN = oktaResourceURN(tenantID, resourceType, resourceID)
	}
	if resourceURN != "" {
		entityType := "okta.resource"
		if strings.EqualFold(resourceType, "user") {
			entityType = "okta.user"
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: entityType,
			Label:      firstNonEmpty(resourceID, resourceType),
			Attributes: map[string]string{
				"resource_id":   resourceID,
				"resource_type": resourceType,
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if oktaAuditTargetUser(resourceType, targetType) {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), resourceURN, targetAlternateID, event.GetOccurredAt())
		}
	}

	targetAppURN := oktaApplicationURN(tenantID, targetAppID)
	if targetAppURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        targetAppURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.application",
			Label:      targetAppLabel,
			Attributes: map[string]string{
				"app_id":    targetAppID,
				"app_label": targetAppLabel,
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetAppURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	oauthClientURN := oktaApplicationURN(tenantID, oauthClientID)
	if oauthClientURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        oauthClientURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.application",
			Label:      oauthClientLabel,
			Attributes: map[string]string{
				"app_id":               oauthClientID,
				"client_id":            oauthClientID,
				"oauth_client_type":    strings.TrimSpace(attributes["oauth_client_type"]),
				"oauth_event_category": strings.TrimSpace(attributes["oauth_event_category"]),
				"grant_type":           strings.TrimSpace(attributes["grant_type"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), oauthClientURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if resourceURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), oauthClientURN, resourceURN, relationActedOn, oktaOAuthRelationAttributes(event, attributes)))
		}
	}

	actorURN := oktaActorURN(tenantID, actorType, actorID)
	if actorURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        actorURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: oktaActorEntityType(actorType),
			Label:      firstNonEmpty(actorAlternateID, actorDisplayName, actorID),
			Attributes: map[string]string{
				"actor_id":           actorID,
				"actor_type":         actorType,
				"actor_alternate_id": actorAlternateID,
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if resourceURN != "" && resourceURN != actorURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, resourceURN, relationActedOn, oktaAuditRelationAttributes(event, attributes, nil)))
		}
		if targetAppURN != "" && targetAppURN != actorURN && targetAppURN != resourceURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, targetAppURN, relationActedOn, oktaAuditRelationAttributes(event, attributes, map[string]string{
				"target_app_id":    targetAppID,
				"target_app_label": targetAppLabel,
			})))
		}
		if suppressResource && oauthClientURN != "" && oauthClientURN != actorURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, oauthClientURN, relationActedOn, oktaOAuthRelationAttributes(event, attributes)))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actorAlternateID, event.GetOccurredAt())
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaAuditRelationAttributes(event *cerebrov1.EventEnvelope, attributes map[string]string, extra map[string]string) map[string]string {
	relationAttrs := map[string]string{
		"event_id":   event.GetId(),
		"event_type": strings.TrimSpace(attributes["event_type"]),
	}
	addProjectedAttribute(relationAttrs, "outcome_result", strings.TrimSpace(attributes["outcome_result"]))
	addProjectedAttribute(relationAttrs, "outcome_reason", strings.TrimSpace(attributes["outcome_reason"]))
	addProjectedAttribute(relationAttrs, "transaction_id", strings.TrimSpace(attributes["transaction_id"]))
	addProjectedAttribute(relationAttrs, "client_ip", strings.TrimSpace(attributes["client_ip"]))
	addProjectedAttribute(relationAttrs, "source_runtime_id", strings.TrimSpace(attributes["source_runtime_id"]))
	if occurredAt := event.GetOccurredAt(); occurredAt != nil && occurredAt.IsValid() {
		relationAttrs["at"] = occurredAt.AsTime().UTC().Format(time.RFC3339)
	}
	for key, value := range extra {
		addProjectedAttribute(relationAttrs, key, strings.TrimSpace(value))
	}
	return relationAttrs
}

func oktaOAuthRelationAttributes(event *cerebrov1.EventEnvelope, attributes map[string]string) map[string]string {
	return oktaAuditRelationAttributes(event, attributes, map[string]string{
		"oauth_event_category": attributes["oauth_event_category"],
		"grant_type":           attributes["grant_type"],
	})
}

func oktaEphemeralOAuthRuntimeResource(resourceType string, attributes map[string]string) bool {
	if !oktaRuntimeGrant(attributes) {
		return false
	}
	switch compactOktaResourceType(resourceType) {
	case "accesstoken", "refreshtoken", "authorizationcode", "idtoken", "code":
		return true
	default:
		return false
	}
}

func oktaEphemeralOAuthRuntimeResourceURNPrefixes(tenantID string) []string {
	resourceTypes := []string{
		"access_token",
		"accesstoken",
		"access-token",
		"access token",
		"refresh_token",
		"refreshtoken",
		"refresh-token",
		"refresh token",
		"authorization_code",
		"authorizationcode",
		"authorization-code",
		"authorization code",
		"id_token",
		"idtoken",
		"id-token",
		"id token",
		"code",
	}
	prefixes := make([]string, 0, len(resourceTypes))
	for _, resourceType := range resourceTypes {
		prefix := projectionURN(tenantID, "okta_resource", resourceType)
		if prefix != "" {
			prefixes = append(prefixes, prefix+":")
		}
	}
	return prefixes
}

func oktaRuntimeGrant(attributes map[string]string) bool {
	if strings.EqualFold(strings.TrimSpace(attributes["oauth_event_category"]), "runtime_grant") {
		return true
	}
	eventType := strings.ToLower(strings.TrimSpace(attributes["event_type"]))
	switch eventType {
	case "app.oauth2.authorize.code", "app.oauth2.as.authorize.code":
		return true
	default:
		return strings.HasPrefix(eventType, "app.oauth2.token.grant.") ||
			strings.HasPrefix(eventType, "app.oauth2.as.token.grant.")
	}
}

func compactOktaResourceType(resourceType string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r >= '0' && r <= '9':
			return r
		default:
			return -1
		}
	}, strings.TrimSpace(resourceType))
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

func githubUserURN(tenantID string, login string) string {
	value := strings.TrimSpace(login)
	if value == "" {
		return ""
	}
	return projectionURN(tenantID, "github_user", value)
}

func oktaUserURN(tenantID string, userID string) string {
	value := strings.TrimSpace(userID)
	if value == "" {
		return ""
	}
	return projectionURN(tenantID, "okta_user", value)
}

func oktaApplicationURN(tenantID string, appID string) string {
	value := strings.TrimSpace(appID)
	if value == "" {
		return ""
	}
	return projectionURN(tenantID, "okta_application", value)
}

func oktaActorURN(tenantID string, actorType string, actorID string) string {
	switch {
	case strings.EqualFold(actorType, "user"):
		return oktaUserURN(tenantID, actorID)
	case strings.TrimSpace(actorID) == "":
		return ""
	default:
		return projectionURN(tenantID, "okta_actor", normalizeIdentifier(actorType), strings.TrimSpace(actorID))
	}
}

func oktaActorEntityType(actorType string) string {
	if strings.EqualFold(actorType, "user") {
		return "okta.user"
	}
	if strings.TrimSpace(actorType) == "" {
		return "okta.actor"
	}
	return "okta." + normalizeIdentifier(actorType)
}

func githubResourceURN(tenantID string, resourceType string, resourceID string, repoURN string) string {
	if repoURN != "" && (strings.Contains(strings.ToLower(resourceType), "repository") || strings.Contains(resourceID, "/")) {
		return repoURN
	}
	if strings.TrimSpace(resourceID) == "" && strings.TrimSpace(resourceType) == "" {
		return ""
	}
	return projectionURN(tenantID, "github_resource", normalizeIdentifier(resourceType), strings.TrimSpace(resourceID))
}

func oktaResourceURN(tenantID string, resourceType string, resourceID string) string {
	if strings.TrimSpace(resourceID) == "" {
		return ""
	}
	if strings.EqualFold(resourceType, "user") {
		return oktaUserURN(tenantID, resourceID)
	}
	return projectionURN(tenantID, "okta_resource", normalizeIdentifier(resourceType), strings.TrimSpace(resourceID))
}

func oktaAuditTargetUser(resourceType string, targetType string) bool {
	return strings.EqualFold(resourceType, "user") || strings.EqualFold(targetType, "user")
}

func projectionURN(tenantID string, kind string, parts ...string) string {
	tenant := strings.TrimSpace(tenantID)
	entityKind := strings.TrimSpace(kind)
	if tenant == "" || entityKind == "" {
		return ""
	}
	values := make([]string, 0, len(parts)+3)
	values = append(values, "urn", "cerebro", tenant, entityKind)
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	return strings.Join(values, ":")
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
