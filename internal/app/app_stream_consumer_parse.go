package app

import (
	"fmt"
	"sort"
	"strings"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/setutil"
)

func sourceSystemFromTapType(eventType string) string {
	parts := strings.Split(strings.TrimSpace(eventType), ".")
	if len(parts) >= 3 {
		return strings.ToLower(strings.TrimSpace(parts[2]))
	}
	return ""
}

func parseTapType(eventType string) (system string, entityType string, action string) {
	parts := strings.Split(strings.TrimSpace(eventType), ".")
	if len(parts) < 5 {
		return "", "", ""
	}
	if len(parts) >= 5 && strings.EqualFold(parts[2], "activity") {
		return strings.ToLower(parts[3]), strings.ToLower(parts[4]), strings.ToLower(parts[len(parts)-1])
	}
	system = strings.ToLower(parts[2])
	entityType = strings.ToLower(parts[3])
	action = strings.ToLower(parts[len(parts)-1])
	return system, entityType, action
}

type tapSchemaEntityDefinition struct {
	Kind          string
	Categories    []graph.NodeKindCategory
	Properties    map[string]string
	Required      []string
	Relationships []graph.EdgeKind
	Capabilities  []graph.NodeKindCapability
	Description   string
}

func isTapSchemaEventType(eventType string) bool {
	lower := strings.ToLower(strings.TrimSpace(eventType))
	switch {
	case strings.HasPrefix(lower, "ensemble.tap.schema."),
		strings.HasPrefix(lower, "ensemble.tap.integration.schema."),
		strings.Contains(lower, ".schema.updated"),
		strings.Contains(lower, ".schema.created"),
		strings.Contains(lower, ".schema.connected"):
		return true
	default:
		return false
	}
}

func parseTapSchemaIntegration(eventType string, data map[string]any) string {
	integration := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(data, "integration", "source_system", "system", "provider", "integration_name"))))
	if integration != "" {
		return integration
	}

	parts := strings.Split(strings.TrimSpace(eventType), ".")
	if len(parts) >= 5 {
		if strings.EqualFold(parts[2], "schema") {
			return strings.ToLower(strings.TrimSpace(parts[3]))
		}
		if strings.EqualFold(parts[3], "schema") {
			return strings.ToLower(strings.TrimSpace(parts[2]))
		}
	}
	return ""
}

func parseTapSchemaEntities(data map[string]any) []tapSchemaEntityDefinition {
	raw := firstPresent(data, "entity_types", "entities", "node_kinds")
	items := make([]any, 0)
	switch typed := raw.(type) {
	case []any:
		items = append(items, typed...)
	case []map[string]any:
		for _, item := range typed {
			items = append(items, item)
		}
	}

	out := make([]tapSchemaEntityDefinition, 0, len(items))
	for _, item := range items {
		entity := mapFromAny(item)
		if len(entity) == 0 {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(entity, "kind", "entity_type", "type", "name"))))
		if kind == "" {
			continue
		}
		rawProperties := firstPresent(entity, "properties", "fields", "schema")

		definition := tapSchemaEntityDefinition{
			Kind:          kind,
			Categories:    parseTapSchemaCategories(firstPresent(entity, "categories", "category"), kind),
			Properties:    parseTapSchemaProperties(rawProperties),
			Required:      parseTapSchemaRequiredProperties(firstPresent(entity, "required_properties", "required_fields", "required"), rawProperties),
			Relationships: parseTapSchemaRelationships(firstPresent(entity, "relationships", "edges", "relation_types")),
			Capabilities:  parseTapSchemaCapabilities(firstPresent(entity, "capabilities", "features")),
			Description:   strings.TrimSpace(anyToString(firstPresent(entity, "description", "summary"))),
		}
		out = append(out, definition)
	}
	return out
}

func parseTapSchemaCategories(raw any, kind string) []graph.NodeKindCategory {
	values := make([]graph.NodeKindCategory, 0)
	switch typed := raw.(type) {
	case string:
		for _, part := range strings.Split(typed, ",") {
			category := strings.ToLower(strings.TrimSpace(part))
			if category != "" {
				values = append(values, graph.NodeKindCategory(category))
			}
		}
	case []any:
		for _, item := range typed {
			category := strings.ToLower(strings.TrimSpace(anyToString(item)))
			if category != "" {
				values = append(values, graph.NodeKindCategory(category))
			}
		}
	}
	if len(values) == 0 {
		return inferTapSchemaCategories(kind)
	}

	unique := make(map[graph.NodeKindCategory]struct{}, len(values))
	for _, category := range values {
		switch category {
		case graph.NodeCategoryIdentity, graph.NodeCategoryResource, graph.NodeCategoryBusiness, graph.NodeCategoryKubernetes:
			unique[category] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return inferTapSchemaCategories(kind)
	}

	out := make([]graph.NodeKindCategory, 0, len(unique))
	for category := range unique {
		out = append(out, category)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func inferTapSchemaCategories(kind string) []graph.NodeKindCategory {
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch {
	case strings.Contains(kind, "user"),
		strings.Contains(kind, "person"),
		strings.Contains(kind, "employee"),
		strings.Contains(kind, "contact"),
		strings.Contains(kind, "member"),
		strings.Contains(kind, "identity"):
		return []graph.NodeKindCategory{graph.NodeCategoryIdentity, graph.NodeCategoryBusiness}
	case strings.Contains(kind, "pod"),
		strings.Contains(kind, "cluster"),
		strings.Contains(kind, "namespace"),
		strings.Contains(kind, "k8s"):
		return []graph.NodeKindCategory{graph.NodeCategoryResource, graph.NodeCategoryKubernetes}
	case strings.Contains(kind, "bucket"),
		strings.Contains(kind, "database"),
		strings.Contains(kind, "instance"),
		strings.Contains(kind, "secret"),
		strings.Contains(kind, "function"),
		strings.Contains(kind, "application"),
		strings.Contains(kind, "service"):
		return []graph.NodeKindCategory{graph.NodeCategoryResource}
	default:
		return []graph.NodeKindCategory{graph.NodeCategoryBusiness}
	}
}

func parseTapSchemaProperties(raw any) map[string]string {
	properties := make(map[string]string)
	for key, value := range mapFromAny(raw) {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}

		valueType := strings.TrimSpace(anyToString(value))
		if nested := mapFromAny(value); len(nested) > 0 {
			valueType = strings.TrimSpace(anyToString(firstPresent(nested, "type", "kind", "data_type")))
		}
		if valueType == "" {
			valueType = "any"
		}
		properties[trimmedKey] = strings.ToLower(valueType)
	}
	return properties
}

func parseTapSchemaRequiredProperties(raw any, schemaRaw any) []string {
	required := make(map[string]struct{})

	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		required[value] = struct{}{}
	}

	switch typed := raw.(type) {
	case string:
		for _, part := range strings.Split(typed, ",") {
			add(part)
		}
	case []string:
		for _, item := range typed {
			add(item)
		}
	case []any:
		for _, item := range typed {
			add(anyToString(item))
		}
	}

	for key, value := range mapFromAny(schemaRaw) {
		nested := mapFromAny(value)
		if len(nested) == 0 {
			continue
		}
		if requiredFlag, ok := firstPresent(nested, "required", "is_required").(bool); ok && requiredFlag {
			add(key)
		}
	}

	return setutil.SortedStrings(required)
}

func parseTapSchemaCapabilities(raw any) []graph.NodeKindCapability {
	capabilities := make(map[graph.NodeKindCapability]struct{})

	add := func(value string) {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case string(graph.NodeCapabilityInternetExposable):
			capabilities[graph.NodeCapabilityInternetExposable] = struct{}{}
		case string(graph.NodeCapabilitySensitiveData):
			capabilities[graph.NodeCapabilitySensitiveData] = struct{}{}
		case string(graph.NodeCapabilityPrivilegedIdentity):
			capabilities[graph.NodeCapabilityPrivilegedIdentity] = struct{}{}
		case string(graph.NodeCapabilityCredentialStore):
			capabilities[graph.NodeCapabilityCredentialStore] = struct{}{}
		}
	}

	switch typed := raw.(type) {
	case string:
		for _, part := range strings.Split(typed, ",") {
			add(part)
		}
	case []string:
		for _, item := range typed {
			add(item)
		}
	case []any:
		for _, item := range typed {
			add(anyToString(item))
		}
	}

	if len(capabilities) == 0 {
		return nil
	}
	out := make([]graph.NodeKindCapability, 0, len(capabilities))
	for capability := range capabilities {
		out = append(out, capability)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func parseTapSchemaRelationships(raw any) []graph.EdgeKind {
	values := make([]graph.EdgeKind, 0)
	switch typed := raw.(type) {
	case []any:
		for _, item := range typed {
			switch relationship := item.(type) {
			case string:
				kind := strings.ToLower(strings.TrimSpace(relationship))
				if kind != "" {
					values = append(values, graph.EdgeKind(kind))
				}
			case map[string]any:
				kind := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(relationship, "kind", "type", "edge_kind", "relationship"))))
				if kind != "" {
					values = append(values, graph.EdgeKind(kind))
				}
			}
		}
	case []string:
		for _, item := range typed {
			kind := strings.ToLower(strings.TrimSpace(item))
			if kind != "" {
				values = append(values, graph.EdgeKind(kind))
			}
		}
	}

	if len(values) == 0 {
		return nil
	}
	unique := make(map[graph.EdgeKind]struct{}, len(values))
	for _, value := range values {
		unique[value] = struct{}{}
	}
	out := make([]graph.EdgeKind, 0, len(unique))
	for value := range unique {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func isTapActivityType(eventType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(eventType)), "ensemble.tap.activity.")
}

func isTapInteractionType(eventType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(eventType)), "ensemble.tap.interaction.")
}

type tapInteractionParticipant struct {
	ID   string
	Name string
}

func parseTapActivityActor(raw any) (id string, name string) {
	switch actor := raw.(type) {
	case string:
		return strings.TrimSpace(actor), ""
	case map[string]any:
		id = strings.TrimSpace(anyToString(firstPresent(actor, "email", "id", "user_id", "actor_id")))
		name = strings.TrimSpace(anyToString(firstPresent(actor, "name", "display_name", "full_name")))
		return id, name
	default:
		return "", ""
	}
}

func parseTapActivityTarget(raw any, defaultSystem string) (nodeID string, kind graph.NodeKind, name string) {
	switch target := raw.(type) {
	case string:
		targetID := strings.TrimSpace(target)
		if targetID == "" {
			return "", "", ""
		}
		return fmt.Sprintf("%s:entity:%s", defaultSystem, targetID), graph.NodeKindCompany, targetID
	case map[string]any:
		targetID := strings.TrimSpace(anyToString(firstPresent(target, "id", "entity_id", "target_id")))
		if targetID == "" {
			return "", "", ""
		}
		targetType := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(target, "type", "entity_type", "kind"))))
		if targetType == "" {
			targetType = "entity"
		}
		system := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(target, "system", "source"))))
		if system == "" {
			system = defaultSystem
		}
		name = strings.TrimSpace(anyToString(firstPresent(target, "name", "display_name", "title")))
		return fmt.Sprintf("%s:%s:%s", system, targetType, targetID), mapBusinessEntityKind(targetType), name
	default:
		return "", "", ""
	}
}

func parseTapInteractionType(eventType string) (channel string, interactionType string) {
	parts := strings.Split(strings.TrimSpace(eventType), ".")
	if len(parts) < 4 || !strings.EqualFold(parts[2], "interaction") {
		return "", ""
	}
	channel = strings.ToLower(strings.TrimSpace(parts[3]))
	if len(parts) > 4 {
		interactionType = strings.ToLower(strings.Join(parts[4:], "_"))
	}
	return channel, interactionType
}
