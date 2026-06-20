package sourceprojection

import (
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
)

func augmentCatalogRuntimeProjector(sourceID string, resource connectordefinitions.ResourceFamily, base ProjectFunc) ProjectFunc {
	if base == nil {
		return nil
	}
	projection := resource.Projection
	if projection == nil || (projection.Entity == nil && len(projection.Relationships) == 0) {
		return base
	}
	return func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return projectCatalogRuntimeWithRelationships(sourceID, resource, base, event)
	}
}

func projectCatalogRuntimeWithRelationships(sourceID string, resource connectordefinitions.ResourceFamily, base ProjectFunc, event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := base(event)
	if err != nil || event == nil || resource.Projection == nil {
		return entities, links, err
	}
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	entityMap := projectedEntityMap(entities)
	linkMap := projectedLinkMap(links)
	attributes := event.GetAttributes()
	primaryURN := catalogProjectionPrimaryURN(entities)
	if resource.Projection.Entity != nil {
		if entity := catalogProjectionEntityFromSpec(tenantID, sourceID, attributes, *resource.Projection.Entity); entity != nil {
			previousPrimaryURN := primaryURN
			primaryURN = entity.URN
			mergePrimaryProjectionEntity(entityMap[previousPrimaryURN], entity)
			addEntity(entityMap, entity)
			if previousPrimaryURN != "" && previousPrimaryURN != primaryURN && shouldReplaceCatalogProjectionPrimary(entityMap[previousPrimaryURN]) {
				rewireCatalogProjectionLinks(linkMap, previousPrimaryURN, primaryURN)
				delete(entityMap, previousPrimaryURN)
			}
		}
	}
	for _, relationship := range resource.Projection.Relationships {
		if !catalogProjectionRelationshipRequired(attributes, relationship) {
			continue
		}
		fromURN := primaryURN
		if relationship.From != nil {
			fromEntity := catalogProjectionEntityFromSpec(tenantID, sourceID, attributes, *relationship.From)
			if fromEntity == nil {
				continue
			}
			addEntity(entityMap, fromEntity)
			fromURN = fromEntity.URN
		}
		if strings.TrimSpace(fromURN) == "" {
			continue
		}
		toEntity := catalogProjectionEntityFromSpec(tenantID, sourceID, attributes, relationship.To)
		if toEntity == nil {
			continue
		}
		addEntity(entityMap, toEntity)
		addLink(linkMap, projectedLink(tenantID, sourceID, fromURN, toEntity.URN, relationship.Relation, catalogProjectionLinkAttributes(event, attributes, relationship)))
	}
	return identityProjectionResult(entityMap, linkMap)
}

func projectedEntityMap(entities []*ports.ProjectedEntity) map[string]*ports.ProjectedEntity {
	out := map[string]*ports.ProjectedEntity{}
	for _, entity := range entities {
		addEntity(out, entity)
	}
	return out
}

func projectedLinkMap(links []*ports.ProjectedLink) map[string]*ports.ProjectedLink {
	out := map[string]*ports.ProjectedLink{}
	for _, link := range links {
		addLink(out, link)
	}
	return out
}

func catalogProjectionPrimaryURN(entities []*ports.ProjectedEntity) string {
	candidates := make([]*ports.ProjectedEntity, 0, len(entities))
	for _, entity := range entities {
		if entity == nil || strings.TrimSpace(entity.URN) == "" || isProjectionEvidenceEntity(entity) {
			continue
		}
		candidates = append(candidates, entity)
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.SliceStable(candidates, func(i int, j int) bool {
		leftRuntime := strings.HasPrefix(strings.TrimSpace(candidates[i].EntityType), "runtime.")
		rightRuntime := strings.HasPrefix(strings.TrimSpace(candidates[j].EntityType), "runtime.")
		if leftRuntime != rightRuntime {
			return !leftRuntime
		}
		return candidates[i].URN < candidates[j].URN
	})
	return candidates[0].URN
}

// isProjectionEvidenceEntity reports whether an entity is an evidence node. The
// generated bases disagree on spelling: asset/finding bases label evidence
// "runtime.evidence" while the secret bases label it "runtime_evidence". Both
// must be excluded from primary-anchor selection, otherwise a relationship edge
// can anchor on (and then rewire/delete) the evidence node.
func isProjectionEvidenceEntity(entity *ports.ProjectedEntity) bool {
	entityType := strings.TrimSpace(entity.EntityType)
	return entityType == "runtime.evidence" || entityType == "runtime_evidence"
}

func shouldReplaceCatalogProjectionPrimary(entity *ports.ProjectedEntity) bool {
	if entity == nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(entity.EntityType), "runtime.")
}

func mergePrimaryProjectionEntity(previous *ports.ProjectedEntity, next *ports.ProjectedEntity) {
	if previous == nil || next == nil {
		return
	}
	if next.Attributes == nil {
		next.Attributes = map[string]string{}
	}
	for key, value := range previous.Attributes {
		if strings.TrimSpace(next.Attributes[key]) == "" && strings.TrimSpace(value) != "" {
			next.Attributes[key] = value
		}
	}
}

func rewireCatalogProjectionLinks(links map[string]*ports.ProjectedLink, previousURN string, nextURN string) {
	if strings.TrimSpace(previousURN) == "" || strings.TrimSpace(nextURN) == "" || previousURN == nextURN {
		return
	}
	for key, link := range links {
		if link == nil {
			continue
		}
		changed := false
		if link.FromURN == previousURN {
			link.FromURN = nextURN
			changed = true
		}
		if link.ToURN == previousURN {
			link.ToURN = nextURN
			changed = true
		}
		if changed {
			delete(links, key)
			addLink(links, link)
		}
	}
}

func catalogProjectionEntityFromSpec(tenantID string, sourceID string, attributes map[string]string, spec connectordefinitions.ProjectionEntitySpec) *ports.ProjectedEntity {
	idParts := make([]string, 0, len(spec.IDAttributes))
	entityAttrs := map[string]string{}
	for _, attr := range spec.IDAttributes {
		value := strings.TrimSpace(attributes[attr])
		if value == "" {
			return nil
		}
		idParts = append(idParts, value)
		entityAttrs[attr] = value
	}
	urn := projectionURN(tenantID, spec.URNKind, idParts...)
	if urn == "" {
		return nil
	}
	label := strings.TrimSpace(attributes[spec.LabelAttribute])
	if label == "" {
		label = strings.Join(idParts, "/")
	}
	if spec.LabelAttribute != "" {
		addProjectedAttribute(entityAttrs, spec.LabelAttribute, attributes[spec.LabelAttribute])
	}
	addProjectedAttribute(entityAttrs, ports.EventAttributeSourceRuntimeID, attributes[ports.EventAttributeSourceRuntimeID])
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: spec.EntityType,
		Label:      label,
		Attributes: entityAttrs,
	}
}

func catalogProjectionRelationshipRequired(attributes map[string]string, relationship connectordefinitions.ProjectionRelationshipSpec) bool {
	required := relationship.RequiredAttributes
	if len(required) == 0 {
		required = append(required, relationship.To.IDAttributes...)
		if relationship.From != nil {
			required = append(required, relationship.From.IDAttributes...)
		}
	}
	for _, attr := range required {
		if strings.TrimSpace(attributes[attr]) == "" {
			return false
		}
	}
	return true
}

func catalogProjectionLinkAttributes(event *cerebrov1.EventEnvelope, attributes map[string]string, relationship connectordefinitions.ProjectionRelationshipSpec) map[string]string {
	out := map[string]string{"event_id": event.GetId()}
	addProjectedAttribute(out, "match_type", relationship.MatchType)
	for _, attr := range relationship.LinkAttributes {
		addProjectedAttribute(out, attr, attributes[attr])
	}
	return out
}
