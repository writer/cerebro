package stream

import (
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/setutil"
)

type SchemaEntityDefinition struct {
	Kind          string
	Categories    []graph.NodeKindCategory
	Properties    map[string]string
	Required      []string
	Relationships []graph.EdgeKind
	Capabilities  []graph.NodeKindCapability
	Description   string
}

func IsTapSchemaEventType(eventType string) bool {
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

func ParseTapSchemaIntegration(eventType string, data map[string]any) string {
	integration := strings.ToLower(strings.TrimSpace(AnyToString(FirstPresent(data, "integration", "source_system", "system", "provider", "integration_name"))))
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

func ParseTapSchemaEntities(data map[string]any) []SchemaEntityDefinition {
	raw := FirstPresent(data, "entity_types", "entities", "node_kinds")
	items := make([]any, 0)
	switch typed := raw.(type) {
	case []any:
		items = append(items, typed...)
	case []map[string]any:
		for _, item := range typed {
			items = append(items, item)
		}
	}

	out := make([]SchemaEntityDefinition, 0, len(items))
	for _, item := range items {
		entity := MapFromAny(item)
		if len(entity) == 0 {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(AnyToString(FirstPresent(entity, "kind", "entity_type", "type", "name"))))
		if kind == "" {
			continue
		}
		rawProperties := FirstPresent(entity, "properties", "fields", "schema")

		definition := SchemaEntityDefinition{
			Kind:          kind,
			Categories:    ParseTapSchemaCategories(FirstPresent(entity, "categories", "category"), kind),
			Properties:    ParseTapSchemaProperties(rawProperties),
			Required:      ParseTapSchemaRequiredProperties(FirstPresent(entity, "required_properties", "required_fields", "required"), rawProperties),
			Relationships: ParseTapSchemaRelationships(FirstPresent(entity, "relationships", "edges", "relation_types")),
			Capabilities:  ParseTapSchemaCapabilities(FirstPresent(entity, "capabilities", "features")),
			Description:   strings.TrimSpace(AnyToString(FirstPresent(entity, "description", "summary"))),
		}
		out = append(out, definition)
	}
	return out
}

func ParseTapSchemaCategories(raw any, kind string) []graph.NodeKindCategory {
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
			category := strings.ToLower(strings.TrimSpace(AnyToString(item)))
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

func ParseTapSchemaProperties(raw any) map[string]string {
	properties := make(map[string]string)
	for key, value := range MapFromAny(raw) {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}

		valueType := strings.TrimSpace(AnyToString(value))
		if nested := MapFromAny(value); len(nested) > 0 {
			valueType = strings.TrimSpace(AnyToString(FirstPresent(nested, "type", "kind", "data_type")))
		}
		if valueType == "" {
			valueType = "any"
		}
		properties[trimmedKey] = strings.ToLower(valueType)
	}
	return properties
}

func ParseTapSchemaRequiredProperties(raw any, schemaRaw any) []string {
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
			add(AnyToString(item))
		}
	}

	for key, value := range MapFromAny(schemaRaw) {
		nested := MapFromAny(value)
		if len(nested) == 0 {
			continue
		}
		if requiredFlag, ok := FirstPresent(nested, "required", "is_required").(bool); ok && requiredFlag {
			add(key)
		}
	}

	return setutil.SortedStrings(required)
}

func ParseTapSchemaCapabilities(raw any) []graph.NodeKindCapability {
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
			add(AnyToString(item))
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

func ParseTapSchemaRelationships(raw any) []graph.EdgeKind {
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
				kind := strings.ToLower(strings.TrimSpace(AnyToString(FirstPresent(relationship, "kind", "type", "edge_kind", "relationship"))))
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
