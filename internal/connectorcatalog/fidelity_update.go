package connectorcatalog

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

var urnKindSegment = regexp.MustCompile(`[^a-z0-9_]+`)

// DefinitionFidelityChange describes one deterministic catalog hardening edit.
type DefinitionFidelityChange struct {
	SourceID string `json:"source_id"`
	FamilyID string `json:"family_id,omitempty"`
	Path     string `json:"path"`
	Detail   string `json:"detail"`
}

// HardenDefinitionFidelity fills fields that the Source CDK and catalog runtime
// can already consume but that older catalog entries often left implicit.
func HardenDefinitionFidelity(definition connectordefinitions.Definition) (connectordefinitions.Definition, []DefinitionFidelityChange) {
	definition = cloneDefinitionForFidelity(definition)
	sourceID := strings.TrimSpace(definition.SourceID)
	var changes []DefinitionFidelityChange
	addChange := func(familyID string, path string, detail string) {
		changes = append(changes, DefinitionFidelityChange{
			SourceID: sourceID,
			FamilyID: familyID,
			Path:     path,
			Detail:   detail,
		})
	}

	if wordCount(definition.Description) < 18 && len(definition.ResourceFamilies) > 0 {
		definition.Description = defaultFidelityDescription(definition)
		addChange("", "definition.description", "expanded source description")
	}

	for i := range definition.ResourceFamilies {
		family := &definition.ResourceFamilies[i]
		familyID := strings.TrimSpace(family.ID)
		if familyID == "" {
			continue
		}
		if strings.TrimSpace(family.Event.Kind) == "" && sourceID != "" {
			family.Event.Kind = defaultEventKind(sourceID, familyID)
			addChange(familyID, "resource_families.event.kind", fmt.Sprintf("set event kind to %s", family.Event.Kind))
		}
		if strings.TrimSpace(family.Event.SchemaRef) == "" && sourceID != "" {
			family.Event.SchemaRef = sourceID + "/" + familyID + "/v1"
			addChange(familyID, "resource_families.event.schema_ref", fmt.Sprintf("set schema ref to %s", family.Event.SchemaRef))
		}
		if strings.TrimSpace(family.Event.URNKind) == "" && sourceID != "" {
			family.Event.URNKind = defaultURNKind(sourceID, familyID)
			addChange(familyID, "resource_families.event.urn_kind", fmt.Sprintf("set URN kind to %s", family.Event.URNKind))
		}
		if len(family.Event.RequiredPayloadFields) == 0 && strings.TrimSpace(family.IDField) != "" {
			family.Event.RequiredPayloadFields = []string{strings.TrimSpace(family.IDField)}
			addChange(familyID, "resource_families.event.required_payload_fields", fmt.Sprintf("require payload field %s", family.Event.RequiredPayloadFields[0]))
		}
		if family.Projection == nil || strings.TrimSpace(family.Projection.Template) == "" {
			continue
		}
		if family.Projection.Fields == nil {
			family.Projection.Fields = map[string]string{}
		}
		if len(family.Projection.Fields) >= 2 || family.Projection.Entity != nil || len(family.Projection.Relationships) > 0 {
			continue
		}
		for _, field := range defaultProjectionFieldMappings(*family) {
			if strings.TrimSpace(field.key) == "" || strings.TrimSpace(field.value) == "" {
				continue
			}
			if _, exists := family.Projection.Fields[field.key]; exists {
				continue
			}
			family.Projection.Fields[field.key] = field.value
			addChange(familyID, "resource_families.projection.fields."+field.key, fmt.Sprintf("map %s from %s", field.key, field.value))
		}
	}
	sort.SliceStable(changes, func(i int, j int) bool {
		if changes[i].SourceID != changes[j].SourceID {
			return changes[i].SourceID < changes[j].SourceID
		}
		if changes[i].FamilyID != changes[j].FamilyID {
			return changes[i].FamilyID < changes[j].FamilyID
		}
		return changes[i].Path < changes[j].Path
	})
	return definition, changes
}

func cloneDefinitionForFidelity(definition connectordefinitions.Definition) connectordefinitions.Definition {
	payload, err := json.Marshal(definition)
	if err != nil {
		return definition
	}
	var cloned connectordefinitions.Definition
	if err := json.Unmarshal(payload, &cloned); err != nil {
		return definition
	}
	return cloned
}

type projectionFieldMapping struct {
	key   string
	value string
}

func defaultProjectionFieldMappings(family connectordefinitions.ResourceFamily) []projectionFieldMapping {
	idField := strings.TrimSpace(family.IDField)
	nameField := strings.TrimSpace(family.NameField)
	template := ""
	if family.Projection != nil {
		template = strings.TrimSpace(family.Projection.Template)
	}
	base := []projectionFieldMapping{}
	addIDName := func(idKey string, nameKey string) {
		if idField != "" {
			base = append(base, projectionFieldMapping{key: idKey, value: idField})
		}
		if nameField != "" {
			base = append(base, projectionFieldMapping{key: nameKey, value: nameField})
		}
	}
	switch template {
	case "identity_user":
		addIDName("user_id", "display_name")
		base = append(base,
			projectionFieldMapping{key: "email", value: "email|primary_email|profile.email"},
			projectionFieldMapping{key: "status", value: "status|state|lifecycle_state"},
		)
	case "identity_group":
		addIDName("group_id", "group_name")
		base = append(base,
			projectionFieldMapping{key: "group_email", value: "group_email|email"},
			projectionFieldMapping{key: "description", value: "description|summary"},
		)
	case "group_membership":
		if idField != "" {
			base = append(base, projectionFieldMapping{key: "member_id", value: idField})
		}
		base = append(base,
			projectionFieldMapping{key: "group_id", value: "group_id|group.id|groupId"},
			projectionFieldMapping{key: "member_email", value: "member_email|user_email|email|member.email|user.email"},
			projectionFieldMapping{key: "role", value: "role|membership_role"},
		)
	case "audit_event":
		addIDName("id", "name")
		base = append(base,
			projectionFieldMapping{key: "event_type", value: "event_type|event_name|action|type"},
			projectionFieldMapping{key: "actor_id", value: "actor_id|actor.id|actorId|user_id|user.id"},
			projectionFieldMapping{key: "actor_email", value: "actor_email|actor.email|email|user.email"},
		)
	case "finding", "vulnerability":
		addIDName("finding_id", "title")
		base = append(base,
			projectionFieldMapping{key: "severity", value: "severity|risk|priority"},
			projectionFieldMapping{key: "status", value: "status|state"},
			projectionFieldMapping{key: "description", value: "description|summary"},
		)
	case "secret":
		addIDName("secret_id", "secret_name")
		base = append(base,
			projectionFieldMapping{key: "secret_type", value: "secret_type|type|kind"},
			projectionFieldMapping{key: "secret_status", value: "secret_status|status|state"},
		)
	case "policy", "compliance_control":
		addIDName("policy_id", "policy_name")
		base = append(base,
			projectionFieldMapping{key: "policy_type", value: "policy_type|type|kind|category"},
			projectionFieldMapping{key: "policy_status", value: "policy_status|status|state|enabled"},
		)
	case "deployment":
		addIDName("deployment_id", "deployment_name")
		base = append(base,
			projectionFieldMapping{key: "deployment_environment", value: "environment|env|stage|target"},
			projectionFieldMapping{key: "deployment_status", value: "status|state|ready"},
			projectionFieldMapping{key: "deployment_url", value: "url|deployment_url|endpoint|domain"},
		)
	case "alert":
		addIDName("alert_id", "alert_name")
		base = append(base,
			projectionFieldMapping{key: "alert_severity", value: "severity|priority|level|risk"},
			projectionFieldMapping{key: "alert_status", value: "status|state|resolved|acknowledged"},
			projectionFieldMapping{key: "alert_type", value: "alert_type|type|category|kind"},
		)
	case "evidence_cas_reference":
		addIDName("evidence_id", "evidence_type")
		base = append(base,
			projectionFieldMapping{key: "evidence_cas_uri", value: "uri|evidence_cas_uri|evidence_cas.uri"},
			projectionFieldMapping{key: "evidence_cas_digest", value: "digest|evidence_cas_digest|evidence_cas.digest"},
		)
	default:
		addIDName("resource_id", "resource_name")
		base = append(base,
			projectionFieldMapping{key: "resource_type", value: "resource_type|type|kind"},
			projectionFieldMapping{key: "resource_urn", value: "resource_urn|urn|metadata.resource_urn"},
		)
	}
	return dedupeProjectionMappings(base)
}

func dedupeProjectionMappings(values []projectionFieldMapping) []projectionFieldMapping {
	seen := map[string]struct{}{}
	out := make([]projectionFieldMapping, 0, len(values))
	for _, value := range values {
		key := strings.TrimSpace(value.key)
		mapped := strings.TrimSpace(value.value)
		if key == "" || mapped == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, projectionFieldMapping{key: key, value: mapped})
	}
	return out
}

func defaultFidelityDescription(definition connectordefinitions.Definition) string {
	sourceName := strings.TrimSpace(definition.DisplayName)
	if sourceName == "" {
		sourceName = titleFromIDForFidelity(definition.SourceID)
	}
	familyNames := make([]string, 0, len(definition.ResourceFamilies))
	templateNames := map[string]struct{}{}
	for _, family := range definition.ResourceFamilies {
		label := strings.TrimSpace(family.Label)
		if label == "" {
			label = titleFromIDForFidelity(family.ID)
		}
		if label != "" && len(familyNames) < 6 {
			familyNames = append(familyNames, strings.ToLower(label))
		}
		if family.Projection != nil && strings.TrimSpace(family.Projection.Template) != "" {
			templateNames[projectionTemplateLabel(family.Projection.Template)] = struct{}{}
		}
	}
	graphTypes := make([]string, 0, len(templateNames))
	for graphType := range templateNames {
		graphTypes = append(graphTypes, graphType)
	}
	sort.Strings(graphTypes)
	if len(graphTypes) == 0 {
		graphTypes = []string{"assets"}
	}
	return fmt.Sprintf("Collects %s from %s and projects them into the Cerebro graph as %s for inventory, access review, audit, risk, and operational context.",
		humanList(familyNames),
		sourceName,
		humanList(graphTypes),
	)
}

func projectionTemplateLabel(template string) string {
	switch strings.TrimSpace(template) {
	case "identity_user":
		return "users"
	case "identity_group":
		return "groups"
	case "group_membership":
		return "memberships"
	case "audit_event":
		return "audit events"
	case "finding", "vulnerability":
		return "findings"
	case "secret":
		return "secrets"
	case "policy", "compliance_control":
		return "policies"
	case "deployment":
		return "deployments"
	case "alert":
		return "alerts"
	case "evidence_cas_reference":
		return "evidence references"
	default:
		return "assets"
	}
}

func humanList(values []string) string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			cleaned = append(cleaned, value)
		}
	}
	switch len(cleaned) {
	case 0:
		return "source records"
	case 1:
		return cleaned[0]
	case 2:
		return cleaned[0] + " and " + cleaned[1]
	default:
		return strings.Join(cleaned[:len(cleaned)-1], ", ") + ", and " + cleaned[len(cleaned)-1]
	}
}

func defaultURNKind(sourceID string, familyID string) string {
	value := strings.ToLower(strings.TrimSpace(sourceID) + "_" + strings.TrimSpace(familyID))
	value = strings.ReplaceAll(value, "-", "_")
	value = urnKindSegment.ReplaceAllString(value, "_")
	value = strings.Trim(value, "_")
	if value == "" {
		return "runtime_resource"
	}
	if value[0] < 'a' || value[0] > 'z' {
		value = "runtime_" + value
	}
	return value
}

func defaultEventKind(sourceID string, familyID string) string {
	return defaultEventKindPart(sourceID, "runtime") + "." + defaultEventKindPart(familyID, "resource")
}

func defaultEventKindPart(value string, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = urnKindSegment.ReplaceAllString(value, "_")
	value = strings.Trim(value, "_")
	if value == "" {
		value = fallback
	}
	if value[0] < 'a' || value[0] > 'z' {
		value = fallback + "_" + value
	}
	return value
}

func titleFromIDForFidelity(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	parts := strings.Fields(value)
	for i, part := range parts {
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}
