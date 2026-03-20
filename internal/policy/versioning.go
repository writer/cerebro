package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/setutil"
)

// PolicyEventType represents a policy lifecycle change.
type PolicyEventType string

const (
	PolicyEventLoaded     PolicyEventType = "loaded"
	PolicyEventCreated    PolicyEventType = "created"
	PolicyEventUpdated    PolicyEventType = "updated"
	PolicyEventDeleted    PolicyEventType = "deleted"
	PolicyEventRolledBack PolicyEventType = "rolled_back"
)

// PolicyEvent stores one immutable policy version event.
type PolicyEvent struct {
	PolicyID      string          `json:"policy_id"`
	Version       int             `json:"version"`
	Content       *Policy         `json:"content,omitempty"`
	EffectiveFrom time.Time       `json:"effective_from"`
	EffectiveTo   *time.Time      `json:"effective_to,omitempty"`
	EventType     PolicyEventType `json:"event_type"`
}

// PolicyFieldDiff captures one changed field between two policy definitions.
type PolicyFieldDiff struct {
	Field  string      `json:"field"`
	Before interface{} `json:"before,omitempty"`
	After  interface{} `json:"after,omitempty"`
}

// PolicyDiff describes semantic changes between two policy definitions.
type PolicyDiff struct {
	PolicyID    string            `json:"policy_id,omitempty"`
	FromVersion int               `json:"from_version,omitempty"`
	ToVersion   int               `json:"to_version,omitempty"`
	Changed     bool              `json:"changed"`
	FieldDiffs  []PolicyFieldDiff `json:"field_diffs,omitempty"`
}

// PolicyDryRunImpact summarizes behavioral deltas for a policy change without persistence.
type PolicyDryRunImpact struct {
	PolicyID           string   `json:"policy_id"`
	AssetCount         int      `json:"asset_count"`
	BeforeMatches      int      `json:"before_matches"`
	AfterMatches       int      `json:"after_matches"`
	AddedFindingIDs    []string `json:"added_finding_ids,omitempty"`
	RemovedFindingIDs  []string `json:"removed_finding_ids,omitempty"`
	AddedResourceIDs   []string `json:"added_resource_ids,omitempty"`
	RemovedResourceIDs []string `json:"removed_resource_ids,omitempty"`
}

func clonePolicy(p *Policy) *Policy {
	if p == nil {
		return nil
	}
	payload, err := json.Marshal(p)
	if err != nil {
		copy := *p
		return &copy
	}
	var copy Policy
	if err := json.Unmarshal(payload, &copy); err != nil {
		copy = *p
	}
	return &copy
}

func clonePolicyEvent(event PolicyEvent) PolicyEvent {
	copy := event
	copy.Content = clonePolicy(event.Content)
	if event.EffectiveTo != nil {
		ts := *event.EffectiveTo
		copy.EffectiveTo = &ts
	}
	return copy
}

func (e *Engine) appendPolicyEventLocked(policyID string, p *Policy, effectiveFrom time.Time, effectiveTo *time.Time, eventType PolicyEventType) {
	if e.history == nil {
		e.history = make(map[string][]PolicyEvent)
	}

	event := PolicyEvent{
		PolicyID:      policyID,
		Version:       p.Version,
		Content:       clonePolicy(p),
		EffectiveFrom: effectiveFrom.UTC(),
		EffectiveTo:   nil,
		EventType:     eventType,
	}
	if effectiveTo != nil {
		ts := effectiveTo.UTC()
		event.EffectiveTo = &ts
	}

	e.history[policyID] = append(e.history[policyID], event)
}

func (e *Engine) closeActivePolicyEventLocked(policyID string, closedAt time.Time) {
	history := e.history[policyID]
	if len(history) == 0 {
		return
	}

	for i := len(history) - 1; i >= 0; i-- {
		if history[i].EffectiveTo == nil {
			ts := closedAt.UTC()
			history[i].EffectiveTo = &ts
			e.history[policyID] = history
			return
		}
	}
}

func (e *Engine) nextPolicyVersionLocked(policyID string) int {
	maxVersion := 0
	if current, ok := e.policies[policyID]; ok && current != nil && current.Version > maxVersion {
		maxVersion = current.Version
	}
	for _, event := range e.history[policyID] {
		if event.Version > maxVersion {
			maxVersion = event.Version
		}
	}
	return maxVersion + 1
}

// ListPolicyVersions returns policy history for one policy in ascending version order.
func (e *Engine) ListPolicyVersions(policyID string) []PolicyEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	history := e.history[policyID]
	if len(history) == 0 {
		return nil
	}

	result := make([]PolicyEvent, 0, len(history))
	for _, event := range history {
		result = append(result, clonePolicyEvent(event))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Version < result[j].Version })
	return result
}

// GetPolicyVersion returns one specific policy version.
func (e *Engine) GetPolicyVersion(policyID string, version int) (*PolicyEvent, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, event := range e.history[policyID] {
		if event.Version == version {
			copy := clonePolicyEvent(event)
			return &copy, true
		}
	}
	return nil, false
}

// DiffPolicyVersions computes a semantic diff between two historical versions.
func (e *Engine) DiffPolicyVersions(policyID string, fromVersion, toVersion int) (*PolicyDiff, error) {
	fromEvent, ok := e.GetPolicyVersion(policyID, fromVersion)
	if !ok {
		return nil, fmt.Errorf("policy version not found: %s@%d", policyID, fromVersion)
	}
	toEvent, ok := e.GetPolicyVersion(policyID, toVersion)
	if !ok {
		return nil, fmt.Errorf("policy version not found: %s@%d", policyID, toVersion)
	}

	diff := DiffPolicies(fromEvent.Content, toEvent.Content)
	diff.PolicyID = policyID
	diff.FromVersion = fromVersion
	diff.ToVersion = toVersion
	return &diff, nil
}

// RollbackPolicy restores the policy content from a previous version and appends a new pinned version.
func (e *Engine) RollbackPolicy(policyID string, version int) (*Policy, error) {
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, fmt.Errorf("policy id required")
	}
	if version <= 0 {
		return nil, fmt.Errorf("version must be positive")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	var source *Policy
	for _, event := range e.history[policyID] {
		if event.Version == version && event.Content != nil {
			source = clonePolicy(event.Content)
			break
		}
	}
	if source == nil {
		return nil, fmt.Errorf("policy version not found: %s@%d", policyID, version)
	}

	now := time.Now().UTC()
	source.ID = policyID
	source.Version = e.nextPolicyVersionLocked(policyID)
	source.LastModified = now
	source.PinnedVersion = version
	source.ConditionFormat = normalizeConditionFormat(source.ConditionFormat)
	if err := e.syncConditionProgramsLocked(source); err != nil {
		return nil, err
	}
	if _, exists := e.policies[policyID]; exists {
		e.closeActivePolicyEventLocked(policyID, now)
	}

	e.policies[policyID] = clonePolicy(source)
	e.appendPolicyEventLocked(policyID, source, now, nil, PolicyEventRolledBack)

	return clonePolicy(source), nil
}

// DiffPolicies computes a semantic field-by-field diff between two policy definitions.
func DiffPolicies(before, after *Policy) PolicyDiff {
	diff := PolicyDiff{
		PolicyID:   firstNonEmptyPolicyID(before, after),
		Changed:    false,
		FieldDiffs: make([]PolicyFieldDiff, 0),
	}

	fields := []struct {
		name string
		get  func(*Policy) interface{}
	}{
		{name: "name", get: func(p *Policy) interface{} { return strings.TrimSpace(p.Name) }},
		{name: "description", get: func(p *Policy) interface{} { return strings.TrimSpace(p.Description) }},
		{name: "query", get: func(p *Policy) interface{} { return strings.TrimSpace(p.Query) }},
		{name: "effect", get: func(p *Policy) interface{} { return strings.TrimSpace(p.Effect) }},
		{name: "principal", get: func(p *Policy) interface{} { return strings.TrimSpace(p.Principal) }},
		{name: "action", get: func(p *Policy) interface{} { return strings.TrimSpace(p.Action) }},
		{name: "resource", get: func(p *Policy) interface{} { return strings.TrimSpace(p.Resource) }},
		{name: "conditions", get: func(p *Policy) interface{} { return normalizeStringSlice(p.Conditions) }},
		{name: "condition_format", get: func(p *Policy) interface{} { return normalizeConditionFormat(p.ConditionFormat) }},
		{name: "severity", get: func(p *Policy) interface{} { return strings.TrimSpace(p.Severity) }},
		{name: "tags", get: func(p *Policy) interface{} { return normalizeStringSlice(p.Tags) }},
		{name: "raw", get: func(p *Policy) interface{} { return strings.TrimSpace(p.Raw) }},
		{name: "control_id", get: func(p *Policy) interface{} { return strings.TrimSpace(p.ControlID) }},
		{name: "remediation", get: func(p *Policy) interface{} { return strings.TrimSpace(p.Remediation) }},
		{name: "remediation_steps", get: func(p *Policy) interface{} { return normalizeStringSlice(p.RemediationSteps) }},
		{name: "risk_categories", get: func(p *Policy) interface{} { return normalizeStringSlice(p.RiskCategories) }},
		{name: "frameworks", get: func(p *Policy) interface{} { return normalizeFrameworks(p.Frameworks) }},
		{name: "mitre_attack", get: func(p *Policy) interface{} { return normalizeMitreMappings(p.MitreAttack) }},
		{name: "pinned_version", get: func(p *Policy) interface{} { return p.PinnedVersion }},
	}

	for _, field := range fields {
		beforeValue := policyFieldValue(before, field.get)
		afterValue := policyFieldValue(after, field.get)
		if reflect.DeepEqual(beforeValue, afterValue) {
			continue
		}
		diff.Changed = true
		diff.FieldDiffs = append(diff.FieldDiffs, PolicyFieldDiff{
			Field:  field.name,
			Before: beforeValue,
			After:  afterValue,
		})
	}

	return diff
}

// DryRunPolicyChange evaluates policy behavior on assets without mutating or persisting findings.
func (e *Engine) DryRunPolicyChange(ctx context.Context, current, candidate *Policy, assets []map[string]interface{}) (*PolicyDryRunImpact, error) {
	if candidate == nil {
		return nil, fmt.Errorf("candidate policy required")
	}

	beforeFindings, err := e.evaluatePolicyAgainstAssets(ctx, current, assets)
	if err != nil {
		return nil, err
	}
	afterFindings, err := e.evaluatePolicyAgainstAssets(ctx, candidate, assets)
	if err != nil {
		return nil, err
	}

	addedIDs := make([]string, 0)
	removedIDs := make([]string, 0)
	addedResourceSet := make(map[string]struct{})
	removedResourceSet := make(map[string]struct{})

	for findingID, resourceID := range afterFindings {
		if _, existed := beforeFindings[findingID]; existed {
			continue
		}
		addedIDs = append(addedIDs, findingID)
		if strings.TrimSpace(resourceID) != "" {
			addedResourceSet[resourceID] = struct{}{}
		}
	}

	for findingID, resourceID := range beforeFindings {
		if _, stillExists := afterFindings[findingID]; stillExists {
			continue
		}
		removedIDs = append(removedIDs, findingID)
		if strings.TrimSpace(resourceID) != "" {
			removedResourceSet[resourceID] = struct{}{}
		}
	}

	sort.Strings(addedIDs)
	sort.Strings(removedIDs)

	return &PolicyDryRunImpact{
		PolicyID:           strings.TrimSpace(candidate.ID),
		AssetCount:         len(assets),
		BeforeMatches:      len(beforeFindings),
		AfterMatches:       len(afterFindings),
		AddedFindingIDs:    addedIDs,
		RemovedFindingIDs:  removedIDs,
		AddedResourceIDs:   setutil.SortedStrings(addedResourceSet),
		RemovedResourceIDs: setutil.SortedStrings(removedResourceSet),
	}, nil
}

func (e *Engine) evaluatePolicyAgainstAssets(ctx context.Context, p *Policy, assets []map[string]interface{}) (map[string]string, error) {
	result := make(map[string]string)
	if p == nil {
		return result, nil
	}

	policyID := strings.TrimSpace(p.ID)
	if policyID == "" {
		policyID = "candidate"
	}
	preparedEngine := NewEngine()
	preparedEngine.AddPolicy(p)
	preparedPolicy, ok := preparedEngine.GetPolicy(policyID)
	if !ok {
		return result, nil
	}

	for _, asset := range assets {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if len(asset) == 0 || !policyAppliesToAssetTable(p, asset) {
			continue
		}
		if violation := preparedEngine.checkAssetViolation(preparedPolicy, asset); violation == "" {
			continue
		}
		findingID := fmt.Sprintf("%s-%v", policyID, asset["_cq_id"])
		result[findingID] = extractResourceID(asset)
	}

	return result, nil
}

func policyAppliesToAssetTable(p *Policy, asset map[string]interface{}) bool {
	assetTable, _ := asset["_cq_table"].(string)
	assetTable = strings.ToLower(strings.TrimSpace(assetTable))
	if assetTable == "" || strings.TrimSpace(p.Resource) == "" {
		return true
	}

	tables := resourceToTables(p.Resource)
	if len(tables) == 0 {
		return false
	}
	if hasWildcardTable(tables) {
		return true
	}
	for _, table := range tables {
		if table == assetTable {
			return true
		}
	}
	return false
}

func firstNonEmptyPolicyID(before, after *Policy) string {
	if after != nil && strings.TrimSpace(after.ID) != "" {
		return strings.TrimSpace(after.ID)
	}
	if before != nil {
		return strings.TrimSpace(before.ID)
	}
	return ""
}

func policyFieldValue(p *Policy, getter func(*Policy) interface{}) interface{} {
	if p == nil {
		return nil
	}
	return getter(p)
}

func normalizeStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, strings.TrimSpace(value))
	}
	return result
}

func normalizeFrameworks(frameworks []FrameworkMapping) []FrameworkMapping {
	if len(frameworks) == 0 {
		return nil
	}
	result := make([]FrameworkMapping, 0, len(frameworks))
	for _, mapping := range frameworks {
		result = append(result, FrameworkMapping{
			Name:     strings.TrimSpace(mapping.Name),
			Controls: normalizeStringSlice(mapping.Controls),
		})
	}
	return result
}

func normalizeMitreMappings(mappings []MitreMapping) []MitreMapping {
	if len(mappings) == 0 {
		return nil
	}
	result := make([]MitreMapping, 0, len(mappings))
	for _, mapping := range mappings {
		result = append(result, MitreMapping{
			Tactic:    strings.TrimSpace(mapping.Tactic),
			Technique: strings.TrimSpace(mapping.Technique),
		})
	}
	return result
}
