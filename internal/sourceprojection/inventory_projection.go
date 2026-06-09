package sourceprojection

import (
	"fmt"
	"net/url"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func genericInventoryProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	sourceID := strings.TrimSpace(event.GetSourceId())
	family := strings.TrimSpace(attrs["family"])
	if family == "" {
		family = strings.TrimPrefix(strings.TrimSpace(event.GetKind()), sourceID+".")
	}
	entityID := firstProjectionValue(attrs, "external_id", family+"_id", "id", "name", "email", "username", "package", "vulnerability_id")
	if entityID == "" {
		entityID = strings.TrimSpace(event.GetId())
	}
	entityType := sourceID + "." + family
	entityURN := fmt.Sprintf("urn:cerebro:%s:%s:%s", url.PathEscape(tenantID), url.PathEscape(strings.ReplaceAll(entityType, ".", "_")), url.PathEscape(entityID))
	entityAttrs := cloneAttributes(attrs)
	entityAttrs["event_kind"] = event.GetKind()
	entityAttrs["source_event_id"] = event.GetId()
	entity := &ports.ProjectedEntity{
		URN:        entityURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: entityType,
		Label:      inventoryLabel(attrs, entityID),
		Attributes: entityAttrs,
	}
	stampProjectionRuntime(event, []*ports.ProjectedEntity{entity}, nil)
	return []*ports.ProjectedEntity{entity}, nil, nil
}

func inventoryLabel(attrs map[string]string, fallback string) string {
	if label := firstProjectionValue(attrs, "name", "display_name", "email", "username", "hostname", "package", "vulnerability_id", "title"); label != "" {
		return label
	}
	return strings.TrimSpace(fallback)
}

func firstProjectionValue(attrs map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			return value
		}
	}
	return ""
}

func cloneAttributes(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for key, value := range attrs {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			out[key] = value
		}
	}
	return out
}
