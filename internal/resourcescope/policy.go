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

// SelectorFromURN returns the exact-resource selector represented by a
// Cerebro inventory URN. The URN itself is the source of truth; type/id are
// added so runtimes can filter raw events before projection when they expose
// provider identifiers instead of a projected URN.
func SelectorFromURN(urn string, reason string) ResourceSelector {
	urn = strings.TrimSpace(urn)
	selector := ResourceSelector{URN: urn, Reason: strings.TrimSpace(reason)}
	parts := strings.Split(urn, ":")
	if strings.HasPrefix(urn, "urn:cerebro:") && len(parts) >= 5 {
		selector.Type = parts[len(parts)-2]
		selector.ID = parts[len(parts)-1]
	}
	return selector
}

// AddExcludedResource returns a policy that excludes the concrete resource.
func AddExcludedResource(policy Policy, selector ResourceSelector) (Policy, error) {
	if strings.TrimSpace(selector.URN) != "" {
		policy.ExcludedResourceURNs = append(policy.ExcludedResourceURNs, selector.URN)
	}
	policy.ExcludedResources = append(policy.ExcludedResources, selector)
	return Normalize(policy)
}

// RemoveExcludedResource returns a policy with the concrete resource exclusion removed.
func RemoveExcludedResource(policy Policy, selector ResourceSelector) (Policy, error) {
	normalized, err := Normalize(Policy{ExcludedResources: []ResourceSelector{selector}})
	if err != nil {
		return Policy{}, err
	}
	if len(normalized.ExcludedResources) == 0 {
		return Normalize(policy)
	}
	target := normalized.ExcludedResources[0]
	targetURN := strings.TrimSpace(target.URN)
	urns := make([]string, 0, len(policy.ExcludedResourceURNs))
	for _, urn := range policy.ExcludedResourceURNs {
		if strings.TrimSpace(urn) == targetURN {
			continue
		}
		urns = append(urns, urn)
	}
	resources := make([]ResourceSelector, 0, len(policy.ExcludedResources))
	for _, resource := range policy.ExcludedResources {
		if sameResourceSelector(resource, target) {
			continue
		}
		resources = append(resources, resource)
	}
	policy.ExcludedResourceURNs = urns
	policy.ExcludedResources = resources
	return Normalize(policy)
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
	pairs := eventResourcePairs(kind, id, attributes, urns)
	for _, resource := range p.ExcludedResources {
		if resource.URN != "" && urns[resource.URN] {
			return true
		}
		if resource.Type != "" && resource.ID != "" {
			for _, key := range resourcePairKeys(resource.Type, resource.ID) {
				if pairs[key] {
					return true
				}
			}
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

func sameResourceSelector(left ResourceSelector, right ResourceSelector) bool {
	leftNormalized, err := normalizeResources([]ResourceSelector{left})
	if err != nil || len(leftNormalized) == 0 {
		return false
	}
	rightNormalized, err := normalizeResources([]ResourceSelector{right})
	if err != nil || len(rightNormalized) == 0 {
		return false
	}
	left = leftNormalized[0]
	right = rightNormalized[0]
	if left.URN != "" && right.URN != "" {
		return left.URN == right.URN
	}
	return left.Type != "" && left.ID != "" && left.Type == right.Type && left.ID == right.ID
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

func eventResourcePairs(kind string, id string, attributes map[string]string, urns map[string]bool) map[string]bool {
	pairs := map[string]bool{}
	addPairs := func(types []string, ids []string) {
		for _, typ := range types {
			for _, id := range ids {
				for _, key := range resourcePairKeys(typ, id) {
					pairs[key] = true
				}
			}
		}
	}
	addPairs(splitAttributeValues(kind), splitAttributeValues(id))
	addPairs(splitAttributeValues(attributes["kind"]), splitAttributeValues(attributes["id"]))
	addPairs(splitAttributeValues(attributes["asset_type"]), splitAttributeValues(attributes["asset_id"]))
	addPairs(splitAttributeValues(attributes["resource_type"]), splitAttributeValues(attributes["resource_id"]))
	addPairs(splitAttributeValues(attributes["resource_type"]), splitAttributeValues(attributes["resource_name"]))
	addPairs(splitAttributeValues(attributes["target_type"]), splitAttributeValues(attributes["target_id"]))
	addPairs(splitAttributeValues(attributes["entity_type"]), splitAttributeValues(attributes["entity_id"]))
	for urn := range urns {
		parts := strings.Split(urn, ":")
		if len(parts) >= 2 {
			addPairs([]string{parts[len(parts)-2]}, []string{parts[len(parts)-1]})
		}
	}
	return pairs
}

func resourcePairKeys(resourceType string, id string) []string {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	types := resourceTypeCandidates(resourceType)
	keys := make([]string, 0, len(types))
	for _, typ := range types {
		keys = append(keys, typ+"\x00"+id)
	}
	return keys
}

func resourceTypeCandidates(resourceType string) []string {
	normalized := strings.ToLower(strings.TrimSpace(resourceType))
	if normalized == "" {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	add := func(value string) {
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	add(normalized)
	if strings.Contains(normalized, ".") {
		add(strings.ReplaceAll(normalized, ".", "_"))
		return out
	}
	if index := strings.Index(normalized, "_"); index > 0 && index < len(normalized)-1 {
		add(normalized[:index] + "." + normalized[index+1:])
	}
	return out
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
