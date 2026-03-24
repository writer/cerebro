package graphingest

import (
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/platformevents"
)

const (
	defaultMappingConfigAPIVersion = "cerebro.graphingest/v1alpha1"
	defaultMappingConfigKind       = "MappingConfig"
	defaultMappingContractVersion  = "1.0.0"

	defaultContractCatalogAPIVersion = "cerebro.graph.contracts/v1alpha1"
	defaultContractCatalogKind       = "CloudEventMappingContractCatalog"
)

// CloudEventFieldContract describes one envelope field and whether it is required.
type CloudEventFieldContract struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

// MappingContract describes one mapping's expected event contract surface.
type MappingContract struct {
	Name             string              `json:"name"`
	SourcePattern    string              `json:"source_pattern"`
	Domain           string              `json:"domain"`
	WildcardPattern  bool                `json:"wildcard_pattern"`
	APIVersion       string              `json:"apiVersion,omitempty"`
	ContractVersion  string              `json:"contractVersion,omitempty"`
	SchemaURL        string              `json:"schemaURL,omitempty"`
	NodeKinds        []string            `json:"node_kinds,omitempty"`
	EdgeKinds        []string            `json:"edge_kinds,omitempty"`
	RequiredDataKeys []string            `json:"required_data_keys,omitempty"`
	OptionalDataKeys []string            `json:"optional_data_keys,omitempty"`
	ContextKeys      []string            `json:"context_keys,omitempty"`
	ResolveKeys      []string            `json:"resolve_keys,omitempty"`
	DataEnums        map[string][]string `json:"data_enums,omitempty"`
	DataSchema       map[string]any      `json:"data_schema,omitempty"`
}

// ContractCatalog captures envelope + mapping + platform lifecycle contract metadata.
type ContractCatalog struct {
	APIVersion           string                                  `json:"apiVersion"`
	Kind                 string                                  `json:"kind"`
	GeneratedAt          time.Time                               `json:"generated_at,omitempty"`
	EnvelopeFields       []CloudEventFieldContract               `json:"envelope_fields,omitempty"`
	LifecycleEvents      []platformevents.LifecycleEventContract `json:"lifecycle_events,omitempty"`
	Mappings             []MappingContract                       `json:"mappings,omitempty"`
	DistinctRequiredData []string                                `json:"distinct_required_data,omitempty"`
	DistinctOptionalData []string                                `json:"distinct_optional_data,omitempty"`
	DistinctContextKeys  []string                                `json:"distinct_context_keys,omitempty"`
	DistinctResolveKeys  []string                                `json:"distinct_resolve_keys,omitempty"`
}

// ContractCompatibilityIssue captures one compatibility-affecting change.
type ContractCompatibilityIssue struct {
	ContractType            string   `json:"contract_type,omitempty"`
	ContractName            string   `json:"contract_name,omitempty"`
	MappingName             string   `json:"mapping_name"`
	ChangeType              string   `json:"change_type"`
	Detail                  string   `json:"detail"`
	PreviousContractVersion string   `json:"previous_contract_version,omitempty"`
	CurrentContractVersion  string   `json:"current_contract_version,omitempty"`
	AddedRequiredKeys       []string `json:"added_required_keys,omitempty"`
	EnumKey                 string   `json:"enum_key,omitempty"`
	RemovedEnumValues       []string `json:"removed_enum_values,omitempty"`
}

// ContractCompatibilityReport summarizes compatibility drift between baseline/current catalogs.
type ContractCompatibilityReport struct {
	GeneratedAt             time.Time                    `json:"generated_at"`
	BaselineMappings        int                          `json:"baseline_mappings"`
	CurrentMappings         int                          `json:"current_mappings"`
	BaselineLifecycleEvents int                          `json:"baseline_lifecycle_events"`
	CurrentLifecycleEvents  int                          `json:"current_lifecycle_events"`
	AddedMappings           []string                     `json:"added_mappings,omitempty"`
	RemovedMappings         []string                     `json:"removed_mappings,omitempty"`
	AddedLifecycleEvents    []string                     `json:"added_lifecycle_events,omitempty"`
	RemovedLifecycleEvents  []string                     `json:"removed_lifecycle_events,omitempty"`
	BreakingChanges         []ContractCompatibilityIssue `json:"breaking_changes,omitempty"`
	VersioningViolations    []ContractCompatibilityIssue `json:"versioning_violations,omitempty"`
	Compatible              bool                         `json:"compatible"`
}

type templateRef struct {
	Path       string
	ResolveRef bool
	FromData   bool
}

// BuildContractCatalog builds envelope + mapping + lifecycle contract output from one mapping config.
func BuildContractCatalog(config MappingConfig, now time.Time) ContractCatalog {
	if !now.IsZero() {
		now = now.UTC()
	}
	mappings := BuildMappingContracts(config)
	required := make(map[string]struct{})
	optional := make(map[string]struct{})
	context := make(map[string]struct{})
	resolve := make(map[string]struct{})
	for _, mapping := range mappings {
		for _, key := range mapping.RequiredDataKeys {
			required[key] = struct{}{}
		}
		for _, key := range mapping.OptionalDataKeys {
			optional[key] = struct{}{}
		}
		for _, key := range mapping.ContextKeys {
			context[key] = struct{}{}
		}
		for _, key := range mapping.ResolveKeys {
			resolve[key] = struct{}{}
		}
	}
	for key := range required {
		delete(optional, key)
	}
	return ContractCatalog{
		APIVersion:           defaultContractCatalogAPIVersion,
		Kind:                 defaultContractCatalogKind,
		GeneratedAt:          now,
		EnvelopeFields:       cloudEventEnvelopeFields(),
		LifecycleEvents:      platformevents.LifecycleContracts(),
		Mappings:             mappings,
		DistinctRequiredData: sortedSetKeys(required),
		DistinctOptionalData: sortedSetKeys(optional),
		DistinctContextKeys:  sortedSetKeys(context),
		DistinctResolveKeys:  sortedSetKeys(resolve),
	}
}

// BuildMappingContracts derives contract rows from declarative mappings.
func BuildMappingContracts(config MappingConfig) []MappingContract {
	contracts := make([]MappingContract, 0, len(config.Mappings))
	for _, mapping := range config.Mappings {
		row := MappingContract{
			Name:            strings.TrimSpace(mapping.Name),
			SourcePattern:   strings.TrimSpace(mapping.Source),
			Domain:          mappingSourceDomain(mapping.Source),
			WildcardPattern: strings.Contains(mapping.Source, "*"),
			APIVersion:      normalizeMappingConfigAPIVersion(firstNonEmptyString(mapping.APIVersion, config.APIVersion)),
			ContractVersion: normalizeMappingContractVersion(mapping.ContractVersion),
			SchemaURL:       strings.TrimSpace(mapping.SchemaURL),
			DataEnums:       normalizeDataEnums(mapping.DataEnums),
		}

		nodeKinds := make(map[string]struct{})
		edgeKinds := make(map[string]struct{})
		requiredData := make(map[string]struct{})
		optionalData := make(map[string]struct{})
		contextKeys := make(map[string]struct{})
		resolveKeys := make(map[string]struct{})

		for _, node := range mapping.Nodes {
			addAllRefs(collectTemplateRefs(node.When), false, requiredData, optionalData, contextKeys, resolveKeys)
			nodeRequired := strings.TrimSpace(node.When) == ""
			addAllRefs(collectTemplateRefs(node.ID), nodeRequired, requiredData, optionalData, contextKeys, resolveKeys)
			addAllRefs(collectTemplateRefs(node.Kind), nodeRequired, requiredData, optionalData, contextKeys, resolveKeys)
			addAllRefs(collectTemplateRefs(node.Name), false, requiredData, optionalData, contextKeys, resolveKeys)
			addAllRefs(collectTemplateRefs(node.Provider), false, requiredData, optionalData, contextKeys, resolveKeys)
			for _, value := range node.Properties {
				if asString, ok := value.(string); ok {
					addAllRefs(collectTemplateRefs(asString), false, requiredData, optionalData, contextKeys, resolveKeys)
				}
			}
			kind := normalizeKindLiteral(node.Kind)
			if kind != "" {
				nodeKinds[kind] = struct{}{}
			}
		}

		for _, edge := range mapping.Edges {
			addAllRefs(collectTemplateRefs(edge.When), false, requiredData, optionalData, contextKeys, resolveKeys)
			edgeRequired := strings.TrimSpace(edge.When) == ""
			addAllRefs(collectTemplateRefs(edge.ID), false, requiredData, optionalData, contextKeys, resolveKeys)
			addAllRefs(collectTemplateRefs(edge.Source), edgeRequired, requiredData, optionalData, contextKeys, resolveKeys)
			addAllRefs(collectTemplateRefs(edge.Target), edgeRequired, requiredData, optionalData, contextKeys, resolveKeys)
			addAllRefs(collectTemplateRefs(edge.Kind), edgeRequired, requiredData, optionalData, contextKeys, resolveKeys)
			addAllRefs(collectTemplateRefs(edge.Effect), false, requiredData, optionalData, contextKeys, resolveKeys)
			for _, value := range edge.Properties {
				if asString, ok := value.(string); ok {
					addAllRefs(collectTemplateRefs(asString), false, requiredData, optionalData, contextKeys, resolveKeys)
				}
			}
			kind := normalizeKindLiteral(edge.Kind)
			if kind != "" {
				edgeKinds[kind] = struct{}{}
			}
		}

		for key := range requiredData {
			delete(optionalData, key)
		}
		row.NodeKinds = sortedSetKeys(nodeKinds)
		row.EdgeKinds = sortedSetKeys(edgeKinds)
		row.RequiredDataKeys = sortedSetKeys(requiredData)
		row.OptionalDataKeys = sortedSetKeys(optionalData)
		row.ContextKeys = sortedSetKeys(contextKeys)
		row.ResolveKeys = sortedSetKeys(resolveKeys)
		row.DataSchema = buildDataSchema(row.RequiredDataKeys, row.OptionalDataKeys, row.DataEnums)
		contracts = append(contracts, row)
	}

	sort.Slice(contracts, func(i, j int) bool {
		if contracts[i].SourcePattern == contracts[j].SourcePattern {
			return contracts[i].Name < contracts[j].Name
		}
		return contracts[i].SourcePattern < contracts[j].SourcePattern
	})
	return contracts
}

// BuildMappingContractLookup creates a mapping-name index for runtime validation.
func BuildMappingContractLookup(contracts []MappingContract) map[string]MappingContract {
	out := make(map[string]MappingContract, len(contracts))
	for _, contract := range contracts {
		name := strings.TrimSpace(contract.Name)
		if name == "" {
			continue
		}
		out[name] = contract
	}
	return out
}

// ValidateEventAgainstMappingContract validates event envelope and data keys before graph writes.
func ValidateEventAgainstMappingContract(evt events.CloudEvent, mapping EventMapping, contract MappingContract) []graph.SchemaValidationIssue {
	issues := make([]graph.SchemaValidationIssue, 0, 8)
	appendIssue := func(property, message string) {
		issues = append(issues, graph.SchemaValidationIssue{
			Code:     graph.SchemaIssueInvalidEventContract,
			EntityID: strings.TrimSpace(evt.ID),
			Kind:     strings.TrimSpace(evt.Type),
			Property: strings.TrimSpace(property),
			Message:  strings.TrimSpace(message),
		})
	}

	if strings.TrimSpace(evt.ID) == "" {
		appendIssue("id", "event id is required")
	}
	if strings.TrimSpace(evt.Source) == "" {
		appendIssue("source", "event source is required")
	}
	if strings.TrimSpace(evt.Type) == "" {
		appendIssue("type", "event type is required")
	}
	if evt.Time.IsZero() {
		appendIssue("time", "event time is required")
	}
	if !mappingMatchesSource(mapping.Source, evt.Type) {
		appendIssue("type", fmt.Sprintf("event type %q does not match mapping source pattern %q", strings.TrimSpace(evt.Type), strings.TrimSpace(mapping.Source)))
	}

	for _, key := range contract.RequiredDataKeys {
		if hasNonEmptyDataPath(evt.Data, key) {
			continue
		}
		appendIssue("data."+key, fmt.Sprintf("required data key %q is missing or empty", key))
	}

	for key, allowed := range contract.DataEnums {
		allowedSet := make(map[string]struct{}, len(allowed))
		for _, value := range allowed {
			value = strings.TrimSpace(strings.ToLower(value))
			if value == "" {
				continue
			}
			allowedSet[value] = struct{}{}
		}
		if len(allowedSet) == 0 {
			continue
		}
		value, ok := lookupDataPath(evt.Data, key)
		if !ok {
			continue
		}
		normalized := strings.TrimSpace(strings.ToLower(valueToString(value)))
		if normalized == "" {
			continue
		}
		if _, ok := allowedSet[normalized]; ok {
			continue
		}
		appendIssue("data."+key, fmt.Sprintf("value %q is not in allowed enum set %v", normalized, sortedSetKeys(allowedSet)))
	}

	expectedVersion := normalizeMappingContractVersion(mapping.ContractVersion)
	if expectedVersion != "" && strings.TrimSpace(evt.SchemaVersion) != "" && strings.TrimSpace(evt.SchemaVersion) != expectedVersion {
		appendIssue("schema_version", fmt.Sprintf("schema_version %q does not match mapping contractVersion %q", strings.TrimSpace(evt.SchemaVersion), expectedVersion))
	}
	expectedSchemaURL := strings.TrimSpace(mapping.SchemaURL)
	if expectedSchemaURL != "" && strings.TrimSpace(evt.DataSchema) != "" && strings.TrimSpace(evt.DataSchema) != expectedSchemaURL {
		appendIssue("dataschema", fmt.Sprintf("dataschema %q does not match mapping schemaURL %q", strings.TrimSpace(evt.DataSchema), expectedSchemaURL))
	}
	return issues
}

// CompareContractCatalogs compares baseline/current contract catalogs and flags breaking changes.
func CompareContractCatalogs(baseline, current ContractCatalog, now time.Time) ContractCompatibilityReport {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	report := ContractCompatibilityReport{
		GeneratedAt:             now,
		BaselineMappings:        len(baseline.Mappings),
		CurrentMappings:         len(current.Mappings),
		BaselineLifecycleEvents: len(baseline.LifecycleEvents),
		CurrentLifecycleEvents:  len(current.LifecycleEvents),
		Compatible:              true,
	}

	baselineByName := make(map[string]MappingContract, len(baseline.Mappings))
	currentByName := make(map[string]MappingContract, len(current.Mappings))
	for _, mapping := range baseline.Mappings {
		name := strings.TrimSpace(mapping.Name)
		if name == "" {
			continue
		}
		baselineByName[name] = mapping
	}
	for _, mapping := range current.Mappings {
		name := strings.TrimSpace(mapping.Name)
		if name == "" {
			continue
		}
		currentByName[name] = mapping
	}

	for name := range currentByName {
		if _, ok := baselineByName[name]; ok {
			continue
		}
		report.AddedMappings = append(report.AddedMappings, name)
	}
	for name := range baselineByName {
		if _, ok := currentByName[name]; ok {
			continue
		}
		report.RemovedMappings = append(report.RemovedMappings, name)
	}
	sort.Strings(report.AddedMappings)
	sort.Strings(report.RemovedMappings)

	baselineLifecycleByType := make(map[string]platformevents.LifecycleEventContract, len(baseline.LifecycleEvents))
	currentLifecycleByType := make(map[string]platformevents.LifecycleEventContract, len(current.LifecycleEvents))
	for _, contract := range baseline.LifecycleEvents {
		name := strings.TrimSpace(string(contract.EventType))
		if name == "" {
			continue
		}
		baselineLifecycleByType[name] = contract
	}
	for _, contract := range current.LifecycleEvents {
		name := strings.TrimSpace(string(contract.EventType))
		if name == "" {
			continue
		}
		currentLifecycleByType[name] = contract
	}
	for name := range currentLifecycleByType {
		if _, ok := baselineLifecycleByType[name]; ok {
			continue
		}
		report.AddedLifecycleEvents = append(report.AddedLifecycleEvents, name)
	}
	for name := range baselineLifecycleByType {
		if _, ok := currentLifecycleByType[name]; ok {
			continue
		}
		report.RemovedLifecycleEvents = append(report.RemovedLifecycleEvents, name)
	}
	sort.Strings(report.AddedLifecycleEvents)
	sort.Strings(report.RemovedLifecycleEvents)

	for name, previous := range baselineByName {
		next, ok := currentByName[name]
		if !ok {
			continue
		}
		addedRequired := subtractStrings(next.RequiredDataKeys, previous.RequiredDataKeys)
		if len(addedRequired) > 0 {
			issue := ContractCompatibilityIssue{
				ContractType:            "mapping",
				ContractName:            name,
				MappingName:             name,
				ChangeType:              "required_keys_added",
				Detail:                  fmt.Sprintf("new required data keys added: %v", addedRequired),
				PreviousContractVersion: strings.TrimSpace(previous.ContractVersion),
				CurrentContractVersion:  strings.TrimSpace(next.ContractVersion),
				AddedRequiredKeys:       addedRequired,
			}
			report.BreakingChanges = append(report.BreakingChanges, issue)
			if !hasMajorVersionBump(previous.ContractVersion, next.ContractVersion) {
				report.VersioningViolations = append(report.VersioningViolations, issue)
			}
		}

		for key, prevValues := range previous.DataEnums {
			nextValues, ok := next.DataEnums[key]
			if !ok {
				continue
			}
			removed := subtractStrings(prevValues, nextValues)
			if len(removed) == 0 {
				continue
			}
			issue := ContractCompatibilityIssue{
				ContractType:            "mapping",
				ContractName:            name,
				MappingName:             name,
				ChangeType:              "enum_tightened",
				Detail:                  fmt.Sprintf("enum %q removed allowed value(s): %v", key, removed),
				PreviousContractVersion: strings.TrimSpace(previous.ContractVersion),
				CurrentContractVersion:  strings.TrimSpace(next.ContractVersion),
				EnumKey:                 key,
				RemovedEnumValues:       removed,
			}
			report.BreakingChanges = append(report.BreakingChanges, issue)
			if !hasMajorVersionBump(previous.ContractVersion, next.ContractVersion) {
				report.VersioningViolations = append(report.VersioningViolations, issue)
			}
		}
	}

	for name, previous := range baselineLifecycleByType {
		next, ok := currentLifecycleByType[name]
		if !ok {
			continue
		}

		addedRequired := subtractStrings(next.RequiredDataKeys, previous.RequiredDataKeys)
		if len(addedRequired) > 0 {
			issue := ContractCompatibilityIssue{
				ContractType:            "lifecycle_event",
				ContractName:            name,
				MappingName:             name,
				ChangeType:              "lifecycle_required_keys_added",
				Detail:                  fmt.Sprintf("new required lifecycle data keys added: %v", addedRequired),
				PreviousContractVersion: strings.TrimSpace(previous.SchemaURL),
				CurrentContractVersion:  strings.TrimSpace(next.SchemaURL),
				AddedRequiredKeys:       addedRequired,
			}
			report.BreakingChanges = append(report.BreakingChanges, issue)
			if !hasLifecycleVersionBump(previous.SchemaURL, next.SchemaURL) {
				report.VersioningViolations = append(report.VersioningViolations, issue)
			}
		}

		for _, key := range subtractStrings(lifecycleSchemaPropertyKeys(previous.DataSchema), lifecycleSchemaPropertyKeys(next.DataSchema)) {
			issue := ContractCompatibilityIssue{
				ContractType:            "lifecycle_event",
				ContractName:            name,
				MappingName:             name,
				ChangeType:              "lifecycle_property_removed",
				Detail:                  fmt.Sprintf("lifecycle property %q removed from event payload", key),
				PreviousContractVersion: strings.TrimSpace(previous.SchemaURL),
				CurrentContractVersion:  strings.TrimSpace(next.SchemaURL),
			}
			report.BreakingChanges = append(report.BreakingChanges, issue)
			if !hasLifecycleVersionBump(previous.SchemaURL, next.SchemaURL) {
				report.VersioningViolations = append(report.VersioningViolations, issue)
			}
		}

		for _, key := range intersectStrings(lifecycleSchemaPropertyKeys(previous.DataSchema), lifecycleSchemaPropertyKeys(next.DataSchema)) {
			if lifecycleSchemaPropertySignature(previous.DataSchema, key) == lifecycleSchemaPropertySignature(next.DataSchema, key) {
				continue
			}
			issue := ContractCompatibilityIssue{
				ContractType:            "lifecycle_event",
				ContractName:            name,
				MappingName:             name,
				ChangeType:              "lifecycle_property_changed",
				Detail:                  fmt.Sprintf("lifecycle property %q schema changed", key),
				PreviousContractVersion: strings.TrimSpace(previous.SchemaURL),
				CurrentContractVersion:  strings.TrimSpace(next.SchemaURL),
			}
			report.BreakingChanges = append(report.BreakingChanges, issue)
			if !hasLifecycleVersionBump(previous.SchemaURL, next.SchemaURL) {
				report.VersioningViolations = append(report.VersioningViolations, issue)
			}
		}
	}

	if len(report.VersioningViolations) > 0 {
		report.Compatible = false
	}
	return report
}

func hasLifecycleVersionBump(previousSchemaURL, currentSchemaURL string) bool {
	return lifecycleSchemaVersion(currentSchemaURL) > lifecycleSchemaVersion(previousSchemaURL)
}

func lifecycleSchemaVersion(schemaURL string) int {
	schemaURL = strings.TrimSpace(schemaURL)
	if schemaURL == "" {
		return 0
	}
	parts := strings.Split(strings.TrimRight(schemaURL, "/"), "/")
	if len(parts) == 0 {
		return 0
	}
	last := strings.TrimSpace(parts[len(parts)-1])
	if len(last) < 2 || (last[0] != 'v' && last[0] != 'V') {
		return 0
	}
	version, err := strconv.Atoi(last[1:])
	if err != nil || version < 0 {
		return 0
	}
	return version
}

func lifecycleSchemaPropertyKeys(schema map[string]any) []string {
	properties, _ := schema["properties"].(map[string]any)
	keys := make([]string, 0, len(properties))
	for key := range properties {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func lifecycleSchemaPropertySignature(schema map[string]any, key string) string {
	properties, _ := schema["properties"].(map[string]any)
	value, ok := properties[key]
	if !ok {
		return ""
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(encoded)
}

func intersectStrings(left, right []string) []string {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(left))
	for _, value := range left {
		seen[value] = struct{}{}
	}
	out := make([]string, 0, len(right))
	for _, value := range right {
		if _, ok := seen[value]; !ok {
			continue
		}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func cloudEventEnvelopeFields() []CloudEventFieldContract {
	typeOfEvent := reflect.TypeOf(events.CloudEvent{})
	fields := make([]CloudEventFieldContract, 0, typeOfEvent.NumField())
	for i := 0; i < typeOfEvent.NumField(); i++ {
		field := typeOfEvent.Field(i)
		jsonTag := strings.TrimSpace(field.Tag.Get("json"))
		if jsonTag == "" || jsonTag == "-" {
			continue
		}
		parts := strings.Split(jsonTag, ",")
		name := strings.TrimSpace(parts[0])
		if name == "" || name == "-" {
			continue
		}
		required := true
		for _, option := range parts[1:] {
			if strings.TrimSpace(option) == "omitempty" {
				required = false
				break
			}
		}
		fields = append(fields, CloudEventFieldContract{
			Name:     name,
			Type:     field.Type.String(),
			Required: required,
		})
	}
	sort.Slice(fields, func(i, j int) bool {
		if fields[i].Required == fields[j].Required {
			return fields[i].Name < fields[j].Name
		}
		return fields[i].Required
	})
	return fields
}

func collectTemplateRefs(input string) []templateRef {
	if !strings.Contains(input, "{{") {
		return nil
	}
	matches := templatePattern.FindAllStringSubmatch(input, -1)
	if len(matches) == 0 {
		return nil
	}
	refs := make([]templateRef, 0, len(matches))
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		expr := strings.TrimSpace(match[1])
		if expr == "" {
			continue
		}
		path, resolved, fromData := normalizeTemplateExpression(expr)
		if path == "" {
			continue
		}
		refs = append(refs, templateRef{Path: path, ResolveRef: resolved, FromData: fromData})
	}
	return refs
}

func normalizeTemplateExpression(expr string) (string, bool, bool) {
	expr = strings.TrimSpace(expr)
	resolved := false
	if strings.HasPrefix(expr, "resolve(") && strings.HasSuffix(expr, ")") {
		resolved = true
		expr = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expr, "resolve("), ")"))
	}
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", resolved, false
	}

	rootKeys := map[string]struct{}{
		"id":        {},
		"existing":  {},
		"source":    {},
		"type":      {},
		"subject":   {},
		"time":      {},
		"tenant_id": {},
	}
	if _, ok := rootKeys[expr]; ok {
		return expr, resolved, false
	}
	if strings.HasPrefix(expr, "data.") {
		pathExpr := strings.Trim(strings.TrimPrefix(expr, "data."), ".")
		if pathExpr == "" {
			return "", resolved, false
		}
		return pathExpr, resolved, true
	}
	if strings.HasPrefix(expr, "data") {
		pathExpr := strings.Trim(strings.TrimPrefix(expr, "data"), ".")
		if pathExpr == "" {
			return "", resolved, false
		}
		return pathExpr, resolved, true
	}
	if strings.Contains(expr, ".") {
		parts := strings.Split(expr, ".")
		if len(parts) > 0 {
			if _, ok := rootKeys[strings.TrimSpace(parts[0])]; ok {
				return strings.TrimSpace(expr), resolved, false
			}
		}
	}
	return strings.Trim(expr, "."), resolved, true
}

func addAllRefs(refs []templateRef, required bool, requiredData, optionalData, contextKeys, resolveKeys map[string]struct{}) {
	for _, ref := range refs {
		pathExpr := strings.TrimSpace(ref.Path)
		if pathExpr == "" {
			continue
		}
		if !ref.FromData && strings.Contains(pathExpr, ".") {
			parts := strings.SplitN(pathExpr, ".", 2)
			root := strings.TrimSpace(parts[0])
			if isEnvelopeContextKey(root) {
				contextKeys[pathExpr] = struct{}{}
				continue
			}
		}
		if !ref.FromData && isEnvelopeContextKey(pathExpr) {
			contextKeys[pathExpr] = struct{}{}
			continue
		}
		if required {
			requiredData[pathExpr] = struct{}{}
		} else {
			optionalData[pathExpr] = struct{}{}
		}
		if ref.ResolveRef {
			resolveKeys[pathExpr] = struct{}{}
		}
	}
}

func isEnvelopeContextKey(key string) bool {
	switch strings.TrimSpace(key) {
	case "existing", "id", "source", "type", "subject", "time", "tenant_id":
		return true
	default:
		return false
	}
}

func mappingSourceDomain(source string) string {
	parts := strings.Split(strings.TrimSpace(source), ".")
	if len(parts) < 3 {
		return "unknown"
	}
	if parts[0] != "ensemble" || parts[1] != "tap" {
		return "unknown"
	}
	domain := strings.TrimSpace(parts[2])
	if domain == "" {
		return "unknown"
	}
	return domain
}

func normalizeKindLiteral(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" || strings.Contains(value, "{{") {
		return ""
	}
	return value
}

type dataContractNode struct {
	children map[string]*dataContractNode
	required map[string]struct{}
	enum     map[string]struct{}
}

func newDataContractNode() *dataContractNode {
	return &dataContractNode{
		children: make(map[string]*dataContractNode),
		required: make(map[string]struct{}),
		enum:     make(map[string]struct{}),
	}
}

func (n *dataContractNode) addPath(pathExpr string, required bool, enumValues []string) {
	segments := splitPath(pathExpr)
	if len(segments) == 0 {
		return
	}
	current := n
	for idx, segment := range segments {
		next := current.children[segment]
		if next == nil {
			next = newDataContractNode()
			current.children[segment] = next
		}
		if required {
			current.required[segment] = struct{}{}
		}
		current = next
		if idx == len(segments)-1 {
			for _, value := range enumValues {
				value = strings.TrimSpace(value)
				if value == "" {
					continue
				}
				current.enum[value] = struct{}{}
			}
		}
	}
}

func (n *dataContractNode) toSchema() map[string]any {
	schema := make(map[string]any)
	if len(n.children) == 0 {
		if len(n.enum) > 0 {
			schema["enum"] = sortedSetKeys(n.enum)
		}
		return schema
	}
	schema["type"] = "object"
	schema["additionalProperties"] = true
	properties := make(map[string]any, len(n.children))
	for key, child := range n.children {
		properties[key] = child.toSchema()
	}
	schema["properties"] = properties
	if len(n.required) > 0 {
		schema["required"] = sortedSetKeys(n.required)
	}
	return schema
}

func buildDataSchema(requiredKeys, optionalKeys []string, enums map[string][]string) map[string]any {
	root := newDataContractNode()
	for _, key := range requiredKeys {
		root.addPath(key, true, nil)
	}
	for _, key := range optionalKeys {
		root.addPath(key, false, nil)
	}
	for key, values := range enums {
		root.addPath(key, containsExactString(requiredKeys, key), values)
	}

	schema := root.toSchema()
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	return schema
}

func splitPath(pathExpr string) []string {
	parts := strings.Split(strings.TrimSpace(pathExpr), ".")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func sortedSetKeys[T ~string](values map[T]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for key := range values {
		trimmed := strings.TrimSpace(string(key))
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func normalizeDataEnums(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string][]string, len(values))
	for key, entries := range values {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		set := make(map[string]struct{}, len(entries))
		for _, entry := range entries {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			set[entry] = struct{}{}
		}
		normalized := sortedSetKeys(set)
		if len(normalized) == 0 {
			continue
		}
		out[key] = normalized
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeMappingConfigAPIVersion(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultMappingConfigAPIVersion
	}
	return value
}

func normalizeMappingConfigKind(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultMappingConfigKind
	}
	return value
}

func normalizeMappingContractVersion(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultMappingContractVersion
	}
	return value
}

func hasNonEmptyDataPath(data map[string]any, pathExpr string) bool {
	value, ok := lookupDataPath(data, pathExpr)
	if !ok {
		return false
	}
	if value == nil {
		return false
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) != ""
	default:
		return true
	}
}

func lookupDataPath(data map[string]any, pathExpr string) (any, bool) {
	if len(data) == 0 {
		return nil, false
	}
	segments := splitPath(pathExpr)
	if len(segments) == 0 {
		return nil, false
	}
	value := lookupPath(data, segments)
	if value == nil {
		return nil, false
	}
	return value, true
}

func subtractStrings(values, subtract []string) []string {
	set := make(map[string]struct{}, len(subtract))
	for _, value := range subtract {
		normalized := strings.TrimSpace(strings.ToLower(value))
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	out := make([]string, 0)
	for _, value := range values {
		normalized := strings.TrimSpace(strings.ToLower(value))
		if normalized == "" {
			continue
		}
		if _, ok := set[normalized]; ok {
			continue
		}
		out = append(out, strings.TrimSpace(value))
	}
	sort.Strings(out)
	return out
}

func hasMajorVersionBump(previous, current string) bool {
	prev := parseMajorVersion(previous)
	next := parseMajorVersion(current)
	if prev == 0 || next == 0 {
		return false
	}
	return next > prev
}

func parseMajorVersion(raw string) int {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(raw), "v"))
	if raw == "" {
		return 0
	}
	parts := strings.Split(raw, ".")
	if len(parts) == 0 {
		return 0
	}
	major, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || major < 0 {
		return 0
	}
	return major
}

func containsExactString(values []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func cloneMappingConfig(config MappingConfig) MappingConfig {
	out := MappingConfig{
		APIVersion: strings.TrimSpace(config.APIVersion),
		Kind:       strings.TrimSpace(config.Kind),
		Mappings:   make([]EventMapping, 0, len(config.Mappings)),
	}
	for _, mapping := range config.Mappings {
		cloned := EventMapping{
			Name:            strings.TrimSpace(mapping.Name),
			Source:          strings.TrimSpace(mapping.Source),
			APIVersion:      strings.TrimSpace(mapping.APIVersion),
			ContractVersion: strings.TrimSpace(mapping.ContractVersion),
			SchemaURL:       strings.TrimSpace(mapping.SchemaURL),
			DataEnums:       normalizeDataEnums(mapping.DataEnums),
			Nodes:           make([]NodeMapping, 0, len(mapping.Nodes)),
			Edges:           make([]EdgeMapping, 0, len(mapping.Edges)),
		}
		for _, node := range mapping.Nodes {
			clonedNode := NodeMapping{
				ID:         node.ID,
				When:       node.When,
				Kind:       node.Kind,
				Name:       node.Name,
				Provider:   node.Provider,
				Risk:       node.Risk,
				Properties: cloneAnyMap(node.Properties),
			}
			cloned.Nodes = append(cloned.Nodes, clonedNode)
		}
		for _, edge := range mapping.Edges {
			clonedEdge := EdgeMapping{
				ID:         edge.ID,
				When:       edge.When,
				Source:     edge.Source,
				Target:     edge.Target,
				Kind:       edge.Kind,
				Effect:     edge.Effect,
				Properties: cloneAnyMap(edge.Properties),
			}
			cloned.Edges = append(cloned.Edges, clonedEdge)
		}
		out.Mappings = append(out.Mappings, cloned)
	}
	return out
}

func normalizeMappingConfig(config *MappingConfig) {
	if config == nil {
		return
	}
	config.APIVersion = normalizeMappingConfigAPIVersion(config.APIVersion)
	config.Kind = normalizeMappingConfigKind(config.Kind)

	seenNames := make(map[string]struct{}, len(config.Mappings))
	for idx := range config.Mappings {
		mapping := &config.Mappings[idx]
		mapping.Name = strings.TrimSpace(mapping.Name)
		mapping.Source = strings.TrimSpace(mapping.Source)
		mapping.APIVersion = normalizeMappingConfigAPIVersion(firstNonEmptyString(mapping.APIVersion, config.APIVersion))
		mapping.ContractVersion = normalizeMappingContractVersion(mapping.ContractVersion)
		mapping.SchemaURL = strings.TrimSpace(mapping.SchemaURL)
		mapping.DataEnums = normalizeDataEnums(mapping.DataEnums)
		if mapping.Name == "" {
			mapping.Name = fmt.Sprintf("mapping_%d", idx+1)
		}
		original := mapping.Name
		suffix := 2
		for {
			if _, exists := seenNames[mapping.Name]; !exists {
				break
			}
			mapping.Name = fmt.Sprintf("%s_%d", original, suffix)
			suffix++
		}
		seenNames[mapping.Name] = struct{}{}
	}
}

func validateMappingConfig(config MappingConfig) error {
	if len(config.Mappings) == 0 {
		return fmt.Errorf("mapping config requires at least one mapping")
	}
	seen := make(map[string]struct{}, len(config.Mappings))
	for _, mapping := range config.Mappings {
		name := strings.TrimSpace(mapping.Name)
		if name == "" {
			return fmt.Errorf("mapping requires non-empty name")
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("mapping name %q must be unique", name)
		}
		seen[name] = struct{}{}
		if strings.TrimSpace(mapping.Source) == "" {
			return fmt.Errorf("mapping %q requires source", name)
		}
		if _, err := path.Match(strings.TrimSpace(mapping.Source), strings.TrimSpace(mapping.Source)); err != nil {
			return fmt.Errorf("mapping %q has invalid source pattern %q: %w", name, mapping.Source, err)
		}
	}
	return nil
}
