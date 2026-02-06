// Package policy implements a policy engine for evaluating cloud security policies
// against cloud resources. Policies define security requirements using a declarative
// format inspired by AWS Cedar policy language.
//
// The engine supports:
//   - Loading policies from JSON files organized by category (aws, gcp, azure, etc.)
//   - Real-time evaluation of policies against cloud asset data
//   - Generation of security findings with severity ratings
//   - Condition-based matching for flexible policy definitions
//
// Policies use permit/forbid effects to define what configurations are allowed
// or prohibited. When a resource violates a "forbid" policy, a finding is generated.
//
// Example policy structure:
//
//	{
//	  "id": "s3-public-access",
//	  "name": "S3 Bucket Public Access",
//	  "description": "S3 buckets should not allow public access",
//	  "effect": "forbid",
//	  "resource": "aws::s3::bucket",
//	  "conditions": ["public_access_block_enabled == false"],
//	  "severity": "critical"
//	}
//
// Example usage:
//
//	engine := policy.NewEngine()
//	engine.LoadPolicies("policies/")
//	findings, _ := engine.EvaluateAsset(ctx, s3BucketData)
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Engine is the core policy evaluation engine. It maintains an in-memory cache
// of policies and provides methods for evaluating cloud resources against
// those policies to identify security violations.
//
// The engine is thread-safe and supports concurrent policy evaluation.
type Engine struct {
	policies map[string]*Policy // Policies indexed by ID
	mu       sync.RWMutex       // Protects policies map
}

// Policy defines a security policy rule. Policies specify what configurations
// are permitted or forbidden for cloud resources.
//
// The Effect field determines whether matching resources are allowed ("permit")
// or generate violations ("forbid"). Conditions are evaluated against resource
// attributes to determine if the policy matches.
type Policy struct {
	ID          string   `json:"id"`            // Unique policy identifier
	Name        string   `json:"name"`          // Human-readable policy name
	Description string   `json:"description"`   // Detailed description of policy intent
	Effect      string   `json:"effect"`        // "permit" or "forbid"
	Principal   string   `json:"principal"`     // Who the policy applies to (optional)
	Action      string   `json:"action"`        // What action is being evaluated
	Resource    string   `json:"resource"`      // Resource type pattern (e.g., "aws::s3::bucket")
	Conditions  []string `json:"conditions"`    // Conditions that must be true for policy to match
	Severity    string   `json:"severity"`      // critical, high, medium, low
	Tags        []string `json:"tags"`          // Tags for categorization
	Raw         string   `json:"raw,omitempty"` // Raw Cedar policy text (optional)

	// External control mapping
	ControlID string `json:"control_id,omitempty"` // External control ID for reference

	// Remediation guidance
	Remediation      string   `json:"remediation,omitempty"`       // Markdown remediation guidance
	RemediationSteps []string `json:"remediation_steps,omitempty"` // Step-by-step remediation

	// Risk categorization
	RiskCategories []string `json:"risk_categories,omitempty"` // EXTERNAL_EXPOSURE, UNPROTECTED_DATA, etc.

	// Compliance framework mappings
	Frameworks []FrameworkMapping `json:"frameworks,omitempty"`

	// MITRE ATT&CK mapping
	MitreAttack []MitreMapping `json:"mitre_attack,omitempty"`
}

// FrameworkMapping maps a policy to a compliance framework's controls
type FrameworkMapping struct {
	Name     string   `json:"name"`     // Framework name (e.g., "CIS Controls v8", "NIST 800-53")
	Controls []string `json:"controls"` // Control IDs within the framework
}

// MitreMapping maps a policy to MITRE ATT&CK tactics and techniques
type MitreMapping struct {
	Tactic    string `json:"tactic"`    // ATT&CK tactic (e.g., "Initial Access")
	Technique string `json:"technique"` // ATT&CK technique ID (e.g., "T1190")
}

// Risk category constants for security findings
const (
	RiskExternalExposure      = "EXTERNAL_EXPOSURE"
	RiskExternalAttackSurface = "EXTERNAL_ATTACK_SURFACE"
	RiskUnprotectedData       = "UNPROTECTED_DATA"
	RiskUnprotectedPrincipal  = "UNPROTECTED_PRINCIPAL"
	RiskVulnerability         = "VULNERABILITY"
	RiskMisconfiguration      = "MISCONFIGURATION"
	RiskIdentityRisk          = "IDENTITY_RISK"
	RiskDataExfiltration      = "DATA_EXFILTRATION"
	RiskLateralMovement       = "LATERAL_MOVEMENT"
	RiskPrivilegeEscalation   = "PRIVILEGE_ESCALATION"
)

type EvalRequest struct {
	Principal map[string]interface{} `json:"principal"`
	Action    string                 `json:"action"`
	Resource  map[string]interface{} `json:"resource"`
	Context   map[string]interface{} `json:"context"`
}

type EvalResponse struct {
	Decision string   `json:"decision"` // "allow", "deny"
	Matched  []string `json:"matched"`  // policy IDs that matched
	Reasons  []string `json:"reasons"`
}

type Finding struct {
	ID          string                 `json:"id"`
	PolicyID    string                 `json:"policy_id"`
	PolicyName  string                 `json:"policy_name"`
	Severity    string                 `json:"severity"`
	Resource    map[string]interface{} `json:"resource"`
	Description string                 `json:"description"`
	Remediation string                 `json:"remediation"`

	// Enhanced fields
	Title          string   `json:"title,omitempty"`
	ControlID      string   `json:"control_id,omitempty"`      // External control ID
	RiskCategories []string `json:"risk_categories,omitempty"` // Risk categorization
	ResourceType   string   `json:"resource_type,omitempty"`
	ResourceID     string   `json:"resource_id,omitempty"`
	ResourceName   string   `json:"resource_name,omitempty"`

	// Compliance mapping
	Frameworks  []FrameworkMapping `json:"frameworks,omitempty"`
	MitreAttack []MitreMapping     `json:"mitre_attack,omitempty"`
}

func NewEngine() *Engine {
	return &Engine{
		policies: make(map[string]*Policy),
	}
}

func (e *Engine) LoadPolicies(dir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	registry := NewComplianceRegistry()

	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		var policyDef Policy
		if err := json.Unmarshal(data, &policyDef); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		if len(policyDef.Frameworks) == 0 {
			policyDef.Frameworks = MapPolicyToFrameworks(&policyDef, registry)
		}
		if len(policyDef.RiskCategories) == 0 {
			policyDef.RiskCategories = InferRiskCategories(&policyDef)
		}
		if len(policyDef.MitreAttack) == 0 {
			policyDef.MitreAttack = InferMitreAttack(&policyDef)
		}

		e.policies[policyDef.ID] = &policyDef
		return nil
	})
}

func (e *Engine) AddPolicy(p *Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[p.ID] = p
}

func (e *Engine) GetPolicy(id string) (*Policy, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.policies[id]
	return p, ok
}

func (e *Engine) ListPolicies() []*Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Policy, 0, len(e.policies))
	for _, p := range e.policies {
		result = append(result, p)
	}
	return result
}

// ColumnsForTable returns the set of top-level asset columns referenced by
// conditions in policies that apply to the given table. This is used for
// column projection in Snowflake queries. Always includes metadata columns.
func (e *Engine) ColumnsForTable(table string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	cols := map[string]struct{}{
		"_cq_id":        {},
		"_cq_sync_time": {},
	}

	lower := strings.ToLower(table)
	for _, p := range e.policies {
		policyTable := mapResourceToTable(p.Resource)
		if policyTable != "" && policyTable != lower {
			continue
		}
		for _, cond := range p.Conditions {
			if field := extractConditionField(cond); field != "" {
				top := strings.SplitN(field, ".", 2)[0]
				cols[strings.ToLower(top)] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(cols))
	for c := range cols {
		result = append(result, c)
	}
	sort.Strings(result)
	return result
}

func extractConditionField(condition string) string {
	condition = strings.TrimSpace(condition)
	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		if parts := strings.SplitN(condition, op, 2); len(parts) == 2 {
			return strings.TrimSpace(parts[0])
		}
	}
	if strings.Contains(condition, " contains ") {
		parts := strings.SplitN(condition, " contains ", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[0])
		}
	}
	if strings.HasSuffix(condition, " not exists") {
		return strings.TrimSpace(strings.TrimSuffix(condition, " not exists"))
	}
	if strings.HasSuffix(condition, " exists") {
		return strings.TrimSpace(strings.TrimSuffix(condition, " exists"))
	}
	return ""
}

func (e *Engine) Evaluate(ctx context.Context, req *EvalRequest) (*EvalResponse, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	resp := &EvalResponse{
		Decision: "allow",
		Matched:  make([]string, 0),
		Reasons:  make([]string, 0),
	}

	for _, p := range e.policies {
		if matches := e.matchPolicy(p, req); matches {
			resp.Matched = append(resp.Matched, p.ID)
			if p.Effect == "forbid" {
				resp.Decision = "deny"
				resp.Reasons = append(resp.Reasons, fmt.Sprintf("policy %s: %s", p.ID, p.Description))
			}
		}
	}

	return resp, nil
}

func (e *Engine) EvaluateAsset(ctx context.Context, asset map[string]interface{}) ([]Finding, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var findings []Finding

	// Get the asset's table name for filtering applicable policies
	assetTable := ""
	if t, ok := asset["_cq_table"].(string); ok {
		assetTable = strings.ToLower(t)
	}

	for _, p := range e.policies {
		// Only apply policies whose resource type maps to this asset's table
		if assetTable != "" && p.Resource != "" {
			policyTable := mapResourceToTable(p.Resource)
			// If policy has a specific resource type:
			// - If it maps to a known table, only apply if table matches
			// - If it doesn't map (unknown type), skip it for this asset
			if policyTable == "" {
				continue // Unknown resource type - don't apply to all assets
			}
			if policyTable != assetTable {
				continue // Policy doesn't apply to this asset type
			}
		}

		if violation := e.checkAssetViolation(p, asset); violation != "" {
			// Extract resource identifiers
			resourceID := extractResourceID(asset)
			resourceName := extractResourceName(asset)

			findings = append(findings, Finding{
				ID:             fmt.Sprintf("%s-%v", p.ID, asset["_cq_id"]),
				PolicyID:       p.ID,
				PolicyName:     p.Name,
				Title:          p.Name,
				Severity:       p.Severity,
				Resource:       asset,
				Description:    violation,
				Remediation:    p.Remediation,
				ControlID:      p.ControlID,
				RiskCategories: p.RiskCategories,
				ResourceType:   p.Resource,
				ResourceID:     resourceID,
				ResourceName:   resourceName,
				Frameworks:     p.Frameworks,
				MitreAttack:    p.MitreAttack,
			})
		}
	}

	return findings, nil
}

// mapResourceToTable maps high-level resource types to specific asset tables
// Uses the shared ResourceToTableMapping for consistency
func mapResourceToTable(resourceType string) string {
	// Direct table name references (e.g., already a table name)
	if strings.Contains(resourceType, "_") {
		return strings.ToLower(resourceType)
	}

	// Look up in the shared mapping (try exact match first)
	if tables, ok := ResourceToTableMapping[resourceType]; ok && len(tables) > 0 {
		return tables[0]
	}

	// Try lowercase (resource types in mapping are lowercase)
	lowerResource := strings.ToLower(resourceType)
	if tables, ok := ResourceToTableMapping[lowerResource]; ok && len(tables) > 0 {
		return tables[0]
	}

	return ""
}

func (e *Engine) matchPolicy(p *Policy, req *EvalRequest) bool {
	if p.Action != "*" && p.Action != req.Action {
		return false
	}
	return true
}

func (e *Engine) checkAssetViolation(p *Policy, asset map[string]interface{}) string {
	// All conditions must match for a violation (AND logic)
	if len(p.Conditions) == 0 {
		return ""
	}
	for _, cond := range p.Conditions {
		if !evaluateCondition(cond, asset) {
			return "" // If any condition doesn't match, no violation
		}
	}
	return p.Description // All conditions matched - violation
}

func evaluateCondition(condition string, asset map[string]interface{}) bool {
	condition = strings.TrimSpace(condition)

	// Handle OR (any sub-condition true -> true)
	if strings.Contains(condition, " OR ") {
		parts := strings.Split(condition, " OR ")
		for _, part := range parts {
			if evaluateCondition(strings.TrimSpace(part), asset) {
				return true
			}
		}
		return false
	}

	// Handle AND (all sub-conditions true -> true)
	if strings.Contains(condition, " AND ") {
		parts := strings.Split(condition, " AND ")
		for _, part := range parts {
			if !evaluateCondition(strings.TrimSpace(part), asset) {
				return false
			}
		}
		return true
	}

	// Handle equality (==)
	if parts := strings.SplitN(condition, "==", 2); len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		expected := strings.TrimSpace(parts[1])
		val := getNestedValue(asset, field)
		return compareValues(val, expected, "==")
	}

	// Handle inequality (!=)
	if parts := strings.SplitN(condition, "!=", 2); len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		expected := strings.TrimSpace(parts[1])
		val := getNestedValue(asset, field)
		return compareValues(val, expected, "!=")
	}

	// Handle greater than (>)
	if parts := strings.SplitN(condition, ">", 2); len(parts) == 2 && !strings.Contains(parts[0], "<") {
		field := strings.TrimSpace(parts[0])
		expected := strings.TrimSpace(parts[1])
		val := getNestedValue(asset, field)
		return compareValues(val, expected, ">")
	}

	// Handle less than (<)
	if parts := strings.SplitN(condition, "<", 2); len(parts) == 2 && !strings.Contains(parts[0], ">") {
		field := strings.TrimSpace(parts[0])
		expected := strings.TrimSpace(parts[1])
		val := getNestedValue(asset, field)
		return compareValues(val, expected, "<")
	}

	// Handle contains
	if strings.Contains(condition, " contains ") {
		parts := strings.SplitN(condition, " contains ", 2)
		if len(parts) == 2 {
			field := strings.TrimSpace(parts[0])
			substring := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
			val := getNestedValue(asset, field)
			if s, ok := val.(string); ok {
				return strings.Contains(s, substring)
			}
		}
	}

	// Handle not contains
	if strings.Contains(condition, " not contains ") {
		parts := strings.SplitN(condition, " not contains ", 2)
		if len(parts) == 2 {
			field := strings.TrimSpace(parts[0])
			substring := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
			val := getNestedValue(asset, field)
			if s, ok := val.(string); ok {
				return !strings.Contains(s, substring)
			}
			return true // field missing or not a string -> doesn't contain
		}
	}

	// Handle starts_with
	if strings.Contains(condition, " starts_with ") {
		parts := strings.SplitN(condition, " starts_with ", 2)
		if len(parts) == 2 {
			field := strings.TrimSpace(parts[0])
			prefix := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
			val := getNestedValue(asset, field)
			if s, ok := val.(string); ok {
				return strings.HasPrefix(s, prefix)
			}
		}
	}

	// Handle exists check
	if strings.HasSuffix(condition, " exists") {
		field := strings.TrimSpace(strings.TrimSuffix(condition, " exists"))
		val := getNestedValue(asset, field)
		return val != nil
	}

	// Handle not exists check
	if strings.HasSuffix(condition, " not exists") {
		field := strings.TrimSpace(strings.TrimSuffix(condition, " not exists"))
		val := getNestedValue(asset, field)
		return val == nil
	}

	return false
}

// getNestedValue retrieves a value from nested maps using dot notation
// e.g., "config.public_access.enabled" -> asset["config"]["public_access"]["enabled"]
// Handles JSON strings and URL-encoded JSON strings from Snowflake VARIANT columns
func getNestedValue(asset map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	var current interface{} = asset

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = getFieldCaseInsensitive(v, part)
		case string:
			parsed := tryParseJSON(v)
			if parsed == nil {
				return nil
			}
			current = parsed
			// Re-process this part against the parsed value
			if m, ok := current.(map[string]interface{}); ok {
				current = getFieldCaseInsensitive(m, part)
			} else if arr, ok := current.([]interface{}); ok {
				// For arrays, find any element that has this field
				var found interface{}
				for _, elem := range arr {
					if m, ok := elem.(map[string]interface{}); ok {
						if val := getFieldCaseInsensitive(m, part); val != nil {
							found = val
							break
						}
					}
				}
				current = found
			} else {
				return nil
			}
		case []interface{}:
			// For arrays, find any element that has this field
			var found interface{}
			for _, elem := range v {
				if m, ok := elem.(map[string]interface{}); ok {
					if val := getFieldCaseInsensitive(m, part); val != nil {
						found = val
						break
					}
				}
			}
			current = found
		default:
			return nil
		}
	}

	return current
}

func tryParseJSON(s string) interface{} {
	// Try URL-decoding first (Snowflake stores some values URL-encoded)
	if strings.Contains(s, "%7B") || strings.Contains(s, "%22") {
		decoded, err := url.QueryUnescape(s)
		if err == nil {
			s = decoded
		}
	}
	// Remove surrounding quotes if present
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if len(s) == 0 || (s[0] != '{' && s[0] != '[') {
		return nil
	}
	var result interface{}
	if err := json.Unmarshal([]byte(s), &result); err != nil {
		return nil
	}
	return result
}

// getFieldCaseInsensitive looks up a field in a map, trying exact match first, then case-insensitive
func getFieldCaseInsensitive(m map[string]interface{}, key string) interface{} {
	// Try exact match first
	if v, ok := m[key]; ok {
		return v
	}
	// Try uppercase (common for Snowflake)
	if v, ok := m[strings.ToUpper(key)]; ok {
		return v
	}
	// Try lowercase
	if v, ok := m[strings.ToLower(key)]; ok {
		return v
	}
	// Try case-insensitive search
	keyLower := strings.ToLower(key)
	for k, v := range m {
		if strings.ToLower(k) == keyLower {
			return v
		}
	}
	return nil
}

// compareValues compares an asset value against an expected value
func compareValues(val interface{}, expected string, operator string) bool {
	if val == nil {
		// nil handling: nil == "nil" or nil == "null" is true
		if operator == "==" {
			return expected == "nil" || expected == "null" || expected == ""
		}
		return operator == "!="
	}

	// Handle boolean comparison
	if b, ok := val.(bool); ok {
		expectedBool := expected == "true" || expected == "1"
		switch operator {
		case "==":
			return b == expectedBool
		case "!=":
			return b != expectedBool
		}
	}

	// Handle numeric comparison
	if f, ok := toFloat64(val); ok {
		if ef, err := parseFloat64(expected); err == nil {
			switch operator {
			case "==":
				return f == ef
			case "!=":
				return f != ef
			case ">":
				return f > ef
			case "<":
				return f < ef
			}
		}
	}

	// Default string comparison
	strVal := fmt.Sprintf("%v", val)
	// Strip quotes from both actual and expected values (Snowflake VARIANT columns include quotes)
	strVal = strings.Trim(strVal, "\"'")
	expected = strings.Trim(expected, "\"'")

	switch operator {
	case "==":
		return strVal == expected
	case "!=":
		return strVal != expected
	}

	return false
}

func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

func parseFloat64(s string) (float64, error) {
	s = strings.TrimSpace(s)
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

// extractResourceID extracts the resource identifier from an asset
func extractResourceID(asset map[string]interface{}) string {
	// Try common ID fields in order of preference (case-insensitive for Snowflake)
	keys := []string{"arn", "_cq_id", "id", "resource_id", "instance_id", "role_id", "user_id", "bucket_name", "function_name", "name", "uid"}
	for _, key := range keys {
		if val := getFieldCaseInsensitive(asset, key); val != nil {
			if str, ok := val.(string); ok && str != "" {
				return strings.Trim(str, "\"") // Strip Snowflake quotes
			}
		}
	}
	return ""
}

// extractResourceName extracts the resource name from an asset
func extractResourceName(asset map[string]interface{}) string {
	// Try common name fields (case-insensitive for Snowflake)
	keys := []string{"name", "role_name", "user_name", "bucket_name", "function_name", "instance_id", "display_name", "title"}
	for _, key := range keys {
		if val := getFieldCaseInsensitive(asset, key); val != nil {
			if str, ok := val.(string); ok && str != "" {
				return strings.Trim(str, "\"") // Strip Snowflake quotes
			}
		}
	}
	return ""
}
