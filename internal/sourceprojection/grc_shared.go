package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type grcProjectionContext struct {
	event    *cerebrov1.EventEnvelope
	tenantID string
	sourceID string
	provider string
	attrs    map[string]string
	entities map[string]*ports.ProjectedEntity
	links    map[string]*ports.ProjectedLink
}

func newGRCProjectionContext(event *cerebrov1.EventEnvelope) (*grcProjectionContext, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, err
	}
	attrs := event.GetAttributes()
	return &grcProjectionContext{
		event:    event,
		tenantID: tenantID,
		sourceID: event.GetSourceId(),
		provider: grcProvider(attrs),
		attrs:    attrs,
		entities: map[string]*ports.ProjectedEntity{},
		links:    map[string]*ports.ProjectedLink{},
	}, nil
}

func (ctx *grcProjectionContext) resourceURN(kind string, id string) string {
	return projectionURN(ctx.tenantID, kind, ctx.provider, id)
}

func (ctx *grcProjectionContext) globalURN(kind string, parts ...string) string {
	return projectionURN(ctx.tenantID, kind, parts...)
}

func (ctx *grcProjectionContext) addResourceEntity(urn string, entityType string, label string, extra map[string]string) {
	ctx.addEntity(urn, entityType, label, grcAttributes(ctx.attrs, extra))
}

func (ctx *grcProjectionContext) addReferenceEntity(urn string, entityType string, label string, attrs map[string]string) {
	ctx.addEntity(urn, entityType, label, grcAttributes(nil, attrs))
}

func (ctx *grcProjectionContext) addEntity(urn string, entityType string, label string, attrs map[string]string) {
	addEntity(ctx.entities, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   ctx.tenantID,
		SourceID:   ctx.sourceID,
		EntityType: entityType,
		Label:      label,
		Attributes: attrs,
	})
}

func (ctx *grcProjectionContext) addEventLink(fromURN string, toURN string, relation string, attrs map[string]string) {
	addLink(ctx.links, projectedLink(ctx.tenantID, ctx.sourceID, fromURN, toURN, relation, ctx.eventLinkAttributes(attrs)))
}

func (ctx *grcProjectionContext) eventLinkAttributes(attrs map[string]string) map[string]string {
	merged := map[string]string{"event_id": ctx.event.GetId()}
	for key, value := range attrs {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			merged[key] = trimmed
		}
	}
	return merged
}

func (ctx *grcProjectionContext) done() ([]*ports.ProjectedEntity, []*ports.ProjectedLink) {
	return entitiesAndLinks(ctx.entities, ctx.links)
}

func grcAttributeList(value string) []string {
	values := []string{}
	seen := map[string]struct{}{}
	for _, part := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		values = append(values, trimmed)
		seen[trimmed] = struct{}{}
	}
	return values
}

func grcAttributeSequence(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	})
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func grcJoinedAttributeValues(attrs map[string]string, keys ...string) string {
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, ",")
}

func stringAt(values []string, index int) string {
	if index < 0 || index >= len(values) {
		return ""
	}
	return values[index]
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func maxInt(values ...int) int {
	max := 0
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

func grcProjectionAttrsWith(attrs map[string]string, pairs ...string) map[string]string {
	copy := make(map[string]string, len(attrs)+len(pairs)/2)
	for key, value := range attrs {
		copy[key] = value
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		copy[pairs[i]] = pairs[i+1]
	}
	return copy
}

func grcAttributes(attrs map[string]string, extra map[string]string) map[string]string {
	merged := make(map[string]string, len(attrs)+len(extra))
	for key, value := range attrs {
		if strings.TrimSpace(value) != "" {
			merged[key] = strings.TrimSpace(value)
		}
	}
	for key, value := range extra {
		if strings.TrimSpace(value) != "" {
			merged[key] = strings.TrimSpace(value)
		}
	}
	return merged
}

func grcProvider(attrs map[string]string) string {
	return firstNonEmpty(attrs["provider"], attrs["source_provider"], "grc")
}

func addGRCAssetTagLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, namespace string, rawValues string) {
	if fromURN == "" {
		return
	}
	for _, value := range grcAttributeSequence(rawValues) {
		tagID := grcAssetTagID(value)
		if tagID == "" {
			continue
		}
		tagURN := projectionURN(tenantID, "asset_tag", namespace, tagID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        tagURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "asset.tag",
			Label:      value,
			Attributes: map[string]string{
				"tag":           tagID,
				"tag_namespace": namespace,
				"tag_value":     value,
			},
		})
		addLink(links, projectedLink(tenantID, sourceID, fromURN, tagURN, relationTaggedAs, map[string]string{
			"event_id":      event.GetId(),
			"tag_namespace": namespace,
			"tag_value":     value,
		}))
	}
}

func grcAssetTagID(value string) string {
	normalized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, strings.TrimSpace(value))
	normalized = strings.Trim(normalized, "_")
	for strings.Contains(normalized, "__") {
		normalized = strings.ReplaceAll(normalized, "__", "_")
	}
	return normalized
}

func grcDerivedID(parts ...string) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	if len(values) == 0 {
		return ""
	}
	return grcAssetTagID(strings.Join(values, "_"))
}
