package resourcescope

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	// ConfigKey stores the non-secret runtime resource-scope policy.
	ConfigKey = "cerebro_resource_scope_policy"

	ModeExclude = "exclude"
)

const (
	maxScopeValues       = 500
	maxScopeValueLength  = 1024
	maxScopeReasonLength = 512
)

// Policy describes source-runtime resources that should be skipped when possible.
type Policy struct {
	Mode                 string             `json:"mode,omitempty"`
	ExcludedFamilies     []string           `json:"excluded_families,omitempty"`
	ExcludedAssetClasses []string           `json:"excluded_asset_classes,omitempty"`
	ExcludedKinds        []string           `json:"excluded_kinds,omitempty"`
	ExcludedResourceURNs []string           `json:"excluded_resource_urns,omitempty"`
	ExcludedResources    []ResourceSelector `json:"excluded_resources,omitempty"`
}

// ResourceSelector identifies one concrete resource by URN or provider type/id.
type ResourceSelector struct {
	URN    string `json:"urn,omitempty"`
	Type   string `json:"type,omitempty"`
	ID     string `json:"id,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// FromConfig parses the policy stored on a source runtime config map.
func FromConfig(values map[string]string) (Policy, error) {
	raw := strings.TrimSpace(values[ConfigKey])
	if raw == "" {
		return Policy{}, nil
	}
	var policy Policy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		return Policy{}, fmt.Errorf("parse resource scope policy: %w", err)
	}
	return Normalize(policy)
}

// ConfigValue returns the canonical JSON value for storing this policy in runtime config.
func ConfigValue(policy Policy) (string, error) {
	normalized, err := Normalize(policy)
	if err != nil {
		return "", err
	}
	if normalized.Empty() {
		return "", nil
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal resource scope policy: %w", err)
	}
	return string(payload), nil
}

// Normalize trims, deduplicates, and validates policy values.
func Normalize(policy Policy) (Policy, error) {
	mode := strings.ToLower(strings.TrimSpace(policy.Mode))
	if mode == "" {
		mode = ModeExclude
	}
	if mode != ModeExclude {
		return Policy{}, fmt.Errorf("resource scope mode must be %q", ModeExclude)
	}
	normalized := Policy{
		Mode:                 mode,
		ExcludedFamilies:     normalizeTokens(policy.ExcludedFamilies),
		ExcludedAssetClasses: normalizeTokens(policy.ExcludedAssetClasses),
		ExcludedKinds:        normalizeTokens(policy.ExcludedKinds),
		ExcludedResourceURNs: normalizeLiteralValues(policy.ExcludedResourceURNs),
	}
	if err := validateValues("excluded_families", normalized.ExcludedFamilies); err != nil {
		return Policy{}, err
	}
	if err := validateValues("excluded_asset_classes", normalized.ExcludedAssetClasses); err != nil {
		return Policy{}, err
	}
	if err := validateValues("excluded_kinds", normalized.ExcludedKinds); err != nil {
		return Policy{}, err
	}
	if err := validateValues("excluded_resource_urns", normalized.ExcludedResourceURNs); err != nil {
		return Policy{}, err
	}
	resources, err := normalizeResources(policy.ExcludedResources)
	if err != nil {
		return Policy{}, err
	}
	normalized.ExcludedResources = resources
	if normalized.Empty() {
		normalized.Mode = ""
	}
	return normalized, nil
}

// Empty reports whether the policy has no exclusions.
func (p Policy) Empty() bool {
	return len(p.ExcludedFamilies) == 0 &&
		len(p.ExcludedAssetClasses) == 0 &&
		len(p.ExcludedKinds) == 0 &&
		len(p.ExcludedResourceURNs) == 0 &&
		len(p.ExcludedResources) == 0
}

// ExcludesFamily returns true when a runtime family should be skipped before source IO.
func (p Policy) ExcludesFamily(sourceID string, family string) bool {
	if p.Empty() {
		return false
	}
	candidates := familyCandidates(sourceID, family)
	for _, value := range append(append([]string{}, p.ExcludedFamilies...), p.ExcludedAssetClasses...) {
		if candidates[scopeFamilyToken(sourceID, value)] {
			return true
		}
	}
	for _, kind := range p.ExcludedKinds {
		if candidates[scopeFamilyToken(sourceID, kind)] {
			return true
		}
	}
	return false
}

// ExcludesEvent returns true when a concrete event should be dropped before projection.
func (p Policy) ExcludesEvent(kind string, id string, attributes map[string]string) bool {
	if p.Empty() {
		return false
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	for _, excluded := range p.ExcludedKinds {
		if strings.EqualFold(excluded, kind) {
			return true
		}
	}
	urns := eventURNs(attributes)
	for _, excludedURN := range p.ExcludedResourceURNs {
		if urns[excludedURN] {
			return true
		}
	}
	ids := eventIDs(id, attributes, urns)
	types := eventTypes(kind, attributes)
	for _, resource := range p.ExcludedResources {
		if resource.URN != "" && urns[resource.URN] {
			return true
		}
		if resource.Type != "" && resource.ID != "" && types[strings.ToLower(resource.Type)] && ids[resource.ID] {
			return true
		}
	}
	return false
}

func normalizeTokens(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.ToLower(strings.TrimSpace(value))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func normalizeLiteralValues(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func validateValues(field string, values []string) error {
	if len(values) > maxScopeValues {
		return fmt.Errorf("resource scope %s has too many values", field)
	}
	for _, value := range values {
		if len(value) > maxScopeValueLength {
			return fmt.Errorf("resource scope %s value is too long", field)
		}
	}
	return nil
}

func normalizeResources(values []ResourceSelector) ([]ResourceSelector, error) {
	if len(values) > maxScopeValues {
		return nil, fmt.Errorf("resource scope excluded_resources has too many values")
	}
	out := make([]ResourceSelector, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		next := ResourceSelector{
			URN:    strings.TrimSpace(value.URN),
			Type:   strings.ToLower(strings.TrimSpace(value.Type)),
			ID:     strings.TrimSpace(value.ID),
			Reason: strings.TrimSpace(value.Reason),
		}
		if next.URN == "" && next.Type == "" && next.ID == "" && next.Reason == "" {
			continue
		}
		if len(next.URN) > maxScopeValueLength || len(next.Type) > maxScopeValueLength || len(next.ID) > maxScopeValueLength {
			return nil, fmt.Errorf("resource scope excluded_resources value is too long")
		}
		if len(next.Reason) > maxScopeReasonLength {
			return nil, fmt.Errorf("resource scope excluded_resources reason is too long")
		}
		if next.URN == "" && (next.Type == "" || next.ID == "") {
			return nil, fmt.Errorf("resource scope excluded_resources entries require urn or type and id")
		}
		key := next.URN + "\x00" + next.Type + "\x00" + next.ID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, next)
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].URN + out[i].Type + out[i].ID
		right := out[j].URN + out[j].Type + out[j].ID
		return left < right
	})
	return out, nil
}

func familyCandidates(sourceID string, family string) map[string]bool {
	sourceID = strings.ToLower(strings.TrimSpace(sourceID))
	family = strings.ToLower(strings.TrimSpace(family))
	candidates := map[string]bool{}
	if family == "" {
		return candidates
	}
	candidates[family] = true
	if sourceID != "" {
		candidates[sourceID+"."+family] = true
		candidates[sourceID+"_"+family] = true
	}
	return candidates
}

func scopeFamilyToken(sourceID string, value string) string {
	token := strings.ToLower(strings.TrimSpace(value))
	sourceID = strings.ToLower(strings.TrimSpace(sourceID))
	if sourceID != "" {
		token = strings.TrimPrefix(token, sourceID+".")
		token = strings.TrimPrefix(token, sourceID+"_")
	}
	if index := strings.LastIndex(token, "."); index >= 0 && index < len(token)-1 {
		token = token[index+1:]
	}
	return token
}

func eventURNs(attributes map[string]string) map[string]bool {
	keys := []string{"urn", "asset_urn", "resource_urn", "primary_resource_urn", "target_urn", "entity_urn", "exposed_resource_urn", "graph_root_urn", "graph_path_urn"}
	urns := map[string]bool{}
	for _, key := range keys {
		for _, value := range splitAttributeValues(attributes[key]) {
			if strings.HasPrefix(value, "urn:cerebro:") {
				urns[value] = true
			}
		}
	}
	return urns
}

func eventIDs(id string, attributes map[string]string, urns map[string]bool) map[string]bool {
	ids := map[string]bool{}
	for _, value := range splitAttributeValues(id) {
		ids[value] = true
	}
	for _, key := range []string{"id", "asset_id", "resource_id", "resource_name", "target_id", "entity_id"} {
		for _, value := range splitAttributeValues(attributes[key]) {
			ids[value] = true
		}
	}
	for urn := range urns {
		parts := strings.Split(urn, ":")
		if len(parts) > 0 {
			ids[parts[len(parts)-1]] = true
		}
	}
	return ids
}

func eventTypes(kind string, attributes map[string]string) map[string]bool {
	types := map[string]bool{}
	for _, value := range splitAttributeValues(kind) {
		types[strings.ToLower(value)] = true
	}
	for _, key := range []string{"kind", "asset_type", "resource_type", "entity_type", "target_type"} {
		for _, value := range splitAttributeValues(attributes[key]) {
			types[strings.ToLower(value)] = true
		}
	}
	return types
}

func splitAttributeValues(value string) []string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\t' })
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
