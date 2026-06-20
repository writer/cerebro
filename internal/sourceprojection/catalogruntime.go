package sourceprojection

import (
	"log"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
)

func registerCatalogRuntimeProjectors(projectors map[string]ProjectFunc) {
	catalog, err := connectorcatalog.Builtin()
	if err != nil {
		log.Printf("sourceprojection: load connector catalog runtime projectors: %v", err)
		return
	}
	registerCatalogRuntimeProjectorsForEntries(projectors, catalog.Entries)
}

func registerCatalogRuntimeProjectorsForEntries(projectors map[string]ProjectFunc, entries []connectorcatalog.Entry) {
	if projectors == nil {
		return
	}
	for _, entry := range entries {
		if entry.Status != connectorcatalog.StatusGenerateable {
			continue
		}
		sourceID := strings.TrimSpace(entry.Definition.SourceID)
		if sourceID == "" {
			continue
		}
		for _, resource := range entry.Definition.ResourceFamilies {
			kind := catalogRuntimeEventKind(sourceID, resource)
			if kind == "" {
				continue
			}
			if _, exists := projectors[kind]; exists {
				continue
			}
			projectors[kind] = catalogRuntimeProjectorFor(sourceID, resource)
		}
	}
}

func catalogRuntimeEventKind(sourceID string, resource connectordefinitions.ResourceFamily) string {
	if kind := strings.TrimSpace(resource.Event.Kind); kind != "" {
		return kind
	}
	if kind := strings.TrimSpace(resource.EventKind); kind != "" {
		return kind
	}
	if family := strings.TrimSpace(resource.ID); family != "" && strings.TrimSpace(sourceID) != "" {
		return strings.TrimSpace(sourceID) + "." + family
	}
	return ""
}

func catalogRuntimeProjectorFor(sourceID string, resource connectordefinitions.ResourceFamily) ProjectFunc {
	template := ""
	if resource.Projection != nil {
		template = strings.TrimSpace(resource.Projection.Template)
	}
	var base ProjectFunc
	switch template {
	case "identity_user":
		base = func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return identityUserProjections(event, identityProjectionProfile{Provider: sourceID})
		}
	case "identity_group":
		base = func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return identityGroupProjections(event, identityProjectionProfile{Provider: sourceID})
		}
	case "group_membership":
		base = func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return identityGroupMembershipProjections(event, identityProjectionProfile{Provider: sourceID})
		}
	case "audit_event":
		base = func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return identityAuditProjections(event, identityProjectionProfile{Provider: sourceID})
		}
	case "evidence_cas_reference":
		base = runtimeEvidenceProjections
	case "finding", "vulnerability":
		base = catalogRuntimeFindingProjections
	default:
		base = catalogRuntimeAssetProjections
	}
	return augmentCatalogRuntimeProjector(sourceID, resource, base)
}

func catalogRuntimeAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	resourceType := firstNonEmpty(attributes["resource_type"], attributes["family"], catalogRuntimeKindFamily(event), "asset")
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["external_id"], attributes["id"], attributes["name"])
	resourceURN := strings.TrimSpace(attributes["resource_urn"])
	if resourceURN == "" && resourceID != "" {
		resourceURN = projectionURN(tenantID, "runtime_"+normalizeCloudType(resourceType), resourceID)
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "runtime." + strings.ReplaceAll(normalizeCloudType(resourceType), "_", "."),
			Label:      firstNonEmpty(attributes["resource_name"], attributes["name"], resourceID),
			Attributes: map[string]string{
				"resource_id":       resourceID,
				"resource_type":     resourceType,
				"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
			},
		})
	}
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        evidenceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "runtime.evidence",
			Label:      firstNonEmpty(attributes["evidence_type"], evidenceID),
			Attributes: map[string]string{
				"evidence_id":         evidenceID,
				"evidence_cas_uri":    strings.TrimSpace(attributes["evidence_cas_uri"]),
				"evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"]),
			},
		})
		if resourceURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
			addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, resourceURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
		}
	}
	return identityProjectionResult(entities, links)
}

func catalogRuntimeFindingProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	findingID := firstNonEmpty(attributes["finding_id"], attributes["id"])
	findingURN := ""
	if findingID != "" {
		findingURN = projectionURN(tenantID, "finding", findingID)
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if findingURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        findingURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "finding",
			Label:      firstNonEmpty(attributes["title"], attributes["name"], attributes["summary"], findingID),
			Attributes: map[string]string{
				"finding_id":        findingID,
				"severity":          strings.TrimSpace(attributes["severity"]),
				"status":            strings.TrimSpace(attributes["status"]),
				"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
			},
		})
	}
	if resourceURN := strings.TrimSpace(attributes["resource_urn"]); findingURN != "" && resourceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), findingURN, resourceURN, relationAffects, map[string]string{"event_id": event.GetId()}))
	}
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); findingURN != "" && evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime.evidence", Label: evidenceID, Attributes: map[string]string{"evidence_id": evidenceID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, findingURN, relationSupports, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}

func catalogRuntimeKindFamily(event *cerebrov1.EventEnvelope) string {
	kind := strings.TrimSpace(event.GetKind())
	sourcePrefix := strings.TrimSpace(event.GetSourceId()) + "."
	if strings.HasPrefix(kind, sourcePrefix) {
		return strings.TrimPrefix(kind, sourcePrefix)
	}
	if _, family, ok := strings.Cut(kind, "."); ok {
		return family
	}
	return ""
}
