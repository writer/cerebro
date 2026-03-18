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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Engine is the core policy evaluation engine. It maintains an in-memory cache
// of policies and provides methods for evaluating cloud resources against
// those policies to identify security violations.
//
// The engine is thread-safe and supports concurrent policy evaluation.
type Engine struct {
	policies    map[string]*Policy       // Policies indexed by ID
	history     map[string][]PolicyEvent // Version history indexed by policy ID
	celPrograms map[string][]cel.Program // Compiled CEL programs indexed by policy ID
	celEnv      *cel.Env                 // Shared CEL environment for condition validation/eval
	mu          sync.RWMutex             // Protects policies/history maps
}

// Policy defines a security policy rule. Policies specify what configurations
// are permitted or forbidden for cloud resources.
//
// The Effect field determines whether matching resources are allowed ("permit")
// or generate violations ("forbid"). Conditions are evaluated against resource
// attributes to determine if the policy matches.
type Policy struct {
	ID              string    `json:"id"`                         // Unique policy identifier
	Version         int       `json:"version,omitempty"`          // Monotonic policy version
	LastModified    time.Time `json:"last_modified,omitempty"`    // Last policy change timestamp (UTC)
	PinnedVersion   int       `json:"pinned_version,omitempty"`   // Source version used for rollback pinning
	Name            string    `json:"name"`                       // Human-readable policy name
	Description     string    `json:"description"`                // Detailed description of policy intent
	Query           string    `json:"query,omitempty"`            // Optional SQL query-based policy definition
	Effect          string    `json:"effect"`                     // "permit" or "forbid"
	Principal       string    `json:"principal"`                  // Who the policy applies to (optional)
	Action          string    `json:"action"`                     // What action is being evaluated
	Resource        string    `json:"resource"`                   // Resource type pattern (e.g., "aws::s3::bucket")
	Conditions      []string  `json:"conditions"`                 // Conditions that must be true for policy to match
	ConditionFormat string    `json:"condition_format,omitempty"` // "legacy" or "cel"
	Severity        string    `json:"severity"`                   // critical, high, medium, low
	Tags            []string  `json:"tags"`                       // Tags for categorization
	Raw             string    `json:"raw,omitempty"`              // Raw Cedar policy text (optional)

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
	MustValidateStartupMappings()
	celEnv, err := newPolicyConditionEnv()
	if err != nil {
		panic(fmt.Sprintf("initialize CEL environment: %v", err))
	}

	return &Engine{
		policies:    make(map[string]*Policy),
		history:     make(map[string][]PolicyEvent),
		celPrograms: make(map[string][]cel.Program),
		celEnv:      celEnv,
	}
}

func (e *Engine) LoadPolicies(dir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = make(map[string]*Policy)
	e.history = make(map[string][]PolicyEvent)
	e.celPrograms = make(map[string][]cel.Program)
	if err := e.ensureConditionEnvLocked(); err != nil {
		return err
	}

	registry := NewComplianceRegistry()
	seenPolicyFiles := make(map[string]string)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		data, err := os.ReadFile(path) // #nosec G304,G122 -- path is discovered via filepath.Walk under configured policy directory
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		if isPolicyMetadataFile(data) {
			return nil
		}

		var policyDef Policy
		if err := json.Unmarshal(data, &policyDef); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		if err := validateLoadedPolicy(&policyDef, path); err != nil {
			return err
		}
		if err := validatePolicyConditionProgramsWithEnv(e.celEnv, &policyDef); err != nil {
			return fmt.Errorf("invalid policy %s (%s): %w", path, policyDef.ID, err)
		}

		if existingPath, exists := seenPolicyFiles[policyDef.ID]; exists {
			return fmt.Errorf("duplicate policy id %q found in %s and %s", policyDef.ID, existingPath, path)
		}
		seenPolicyFiles[policyDef.ID] = path

		if len(policyDef.Frameworks) == 0 {
			policyDef.Frameworks = MapPolicyToFrameworks(&policyDef, registry)
		}
		if len(policyDef.RiskCategories) == 0 {
			policyDef.RiskCategories = InferRiskCategories(&policyDef)
		}
		if len(policyDef.MitreAttack) == 0 {
			policyDef.MitreAttack = InferMitreAttack(&policyDef)
		}

		if policyDef.Version <= 0 {
			policyDef.Version = 1
		}
		if policyDef.LastModified.IsZero() {
			policyDef.LastModified = info.ModTime().UTC()
			if policyDef.LastModified.IsZero() {
				policyDef.LastModified = time.Now().UTC()
			}
		} else {
			policyDef.LastModified = policyDef.LastModified.UTC()
		}

		stored := clonePolicy(&policyDef)
		e.policies[policyDef.ID] = stored
		if err := e.syncConditionProgramsLocked(stored); err != nil {
			return fmt.Errorf("register policy %s (%s): %w", path, policyDef.ID, err)
		}
		e.appendPolicyEventLocked(policyDef.ID, stored, policyDef.LastModified, nil, PolicyEventLoaded)
		return nil
	})
	if err != nil {
		return err
	}

	explicitOnly, err := ExplicitMappingsOnlyFromEnv()
	if err != nil {
		return fmt.Errorf("parse %s: %w", explicitMappingsOnlyEnv, err)
	}
	if !explicitOnly {
		return nil
	}

	unmapped := unmappedPolicyResources(e.policies)
	if len(unmapped) == 0 {
		return nil
	}

	sample := unmapped
	if len(sample) > 10 {
		sample = sample[:10]
	}

	return fmt.Errorf("explicit mapping mode enabled with %d unmapped policy resources (sample: %s)", len(unmapped), strings.Join(sample, ", "))
}

func isPolicyMetadataFile(data []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}

	if _, ok := raw["controls"]; !ok {
		return false
	}

	_, hasID := raw["id"]
	_, hasResource := raw["resource"]
	_, hasConditions := raw["conditions"]
	_, hasQuery := raw["query"]

	return !hasID && !hasResource && !hasConditions && !hasQuery
}

func validateLoadedPolicy(policyDef *Policy, path string) error {
	policyDef.ID = strings.TrimSpace(policyDef.ID)
	policyDef.Name = strings.TrimSpace(policyDef.Name)
	policyDef.Description = strings.TrimSpace(policyDef.Description)
	policyDef.Resource = strings.TrimSpace(policyDef.Resource)
	policyDef.Query = strings.TrimSpace(policyDef.Query)
	policyDef.Severity = normalizeSeverity(policyDef.Severity)
	policyDef.ConditionFormat = normalizeConditionFormat(policyDef.ConditionFormat)

	missing := make([]string, 0, 4)
	if policyDef.ID == "" {
		missing = append(missing, "id")
	}
	if policyDef.Name == "" {
		missing = append(missing, "name")
	}
	if policyDef.Description == "" {
		missing = append(missing, "description")
	}
	if policyDef.Severity == "" {
		missing = append(missing, "severity")
	}
	if len(missing) > 0 {
		return fmt.Errorf("invalid policy %s: missing required field(s): %s", path, strings.Join(missing, ", "))
	}

	if !isValidSeverity(policyDef.Severity) {
		return fmt.Errorf("invalid policy %s (%s): unsupported severity %q (allowed: critical, high, medium, low)", path, policyDef.ID, policyDef.Severity)
	}
	if !validConditionFormat(policyDef.ConditionFormat) {
		return fmt.Errorf("invalid policy %s (%s): unsupported condition_format %q (allowed: legacy, cel)", path, policyDef.ID, policyDef.ConditionFormat)
	}

	hasQuery := policyDef.Query != ""
	hasResource := policyDef.Resource != ""
	hasConditions := len(policyDef.Conditions) > 0

	switch {
	case hasQuery && (hasResource || hasConditions):
		return fmt.Errorf("invalid policy %s (%s): query policies cannot include resource or conditions", path, policyDef.ID)
	case hasQuery:
		return nil
	case hasResource && hasConditions:
		return nil
	default:
		return fmt.Errorf("invalid policy %s (%s): policy must define either query OR resource+conditions", path, policyDef.ID)
	}
}

func (e *Engine) ValidatePolicyDefinition(policyDef *Policy) error {
	if policyDef == nil {
		return fmt.Errorf("policy is required")
	}
	copy := clonePolicy(policyDef)
	if err := validateLoadedPolicy(copy, "inline policy"); err != nil {
		return err
	}
	return e.validatePolicyConditionPrograms(copy)
}

func normalizeSeverity(severity string) string {
	return strings.ToLower(strings.TrimSpace(severity))
}

func isValidSeverity(severity string) bool {
	switch severity {
	case "critical", "high", "medium", "low":
		return true
	default:
		return false
	}
}

func (e *Engine) AddPolicy(p *Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p == nil {
		return
	}

	policyID := strings.TrimSpace(p.ID)
	if policyID == "" {
		return
	}

	now := time.Now().UTC()
	stored := clonePolicy(p)
	stored.ID = policyID
	stored.LastModified = now
	stored.ConditionFormat = normalizeConditionFormat(stored.ConditionFormat)

	if existing, ok := e.policies[policyID]; ok {
		stored.Version = existing.Version + 1
		if err := e.syncConditionProgramsLocked(stored); err != nil {
			return
		}
		e.closeActivePolicyEventLocked(policyID, now)
		e.appendPolicyEventLocked(policyID, stored, now, nil, PolicyEventUpdated)
	} else {
		if stored.Version <= 0 {
			stored.Version = 1
		}
		if err := e.syncConditionProgramsLocked(stored); err != nil {
			return
		}
		e.appendPolicyEventLocked(policyID, stored, now, nil, PolicyEventCreated)
	}

	e.policies[policyID] = stored
}

func (e *Engine) UpdatePolicy(id string, p *Policy) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.policies[id]; !ok {
		return false
	}

	now := time.Now().UTC()
	stored := clonePolicy(p)
	stored.ID = id
	stored.Version = e.nextPolicyVersionLocked(id)
	stored.LastModified = now
	stored.PinnedVersion = 0
	stored.ConditionFormat = normalizeConditionFormat(stored.ConditionFormat)
	if err := e.syncConditionProgramsLocked(stored); err != nil {
		return false
	}

	e.closeActivePolicyEventLocked(id, now)
	e.appendPolicyEventLocked(id, stored, now, nil, PolicyEventUpdated)
	e.policies[id] = stored
	return true
}

func (e *Engine) DeletePolicy(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.policies[id]; !ok {
		return false
	}

	existing := clonePolicy(e.policies[id])
	now := time.Now().UTC()
	e.closeActivePolicyEventLocked(id, now)
	if existing != nil {
		delete(e.celPrograms, id)
		existing.Version = e.nextPolicyVersionLocked(id)
		existing.LastModified = now
		effectiveTo := now
		e.appendPolicyEventLocked(id, existing, now, &effectiveTo, PolicyEventDeleted)
	}
	delete(e.policies, id)
	return true
}

func (e *Engine) GetPolicy(id string) (*Policy, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.policies[id]
	if !ok {
		return nil, false
	}
	return clonePolicy(p), true
}

func (e *Engine) ListPolicies() []*Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Policy, 0, len(e.policies))
	for _, p := range e.policies {
		result = append(result, clonePolicy(p))
	}
	return result
}

// UnmappedPolicyResources returns resource types used by loaded policies that
// are not explicitly present in ResourceToTableMapping.
func (e *Engine) UnmappedPolicyResources() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return unmappedPolicyResources(e.policies)
}

func unmappedPolicyResources(policies map[string]*Policy) []string {
	registry := GlobalMappingRegistry()
	missing := make(map[string]struct{})

	for _, p := range policies {
		for _, resource := range splitPolicyResourceParts(p.Resource) {
			if _, ok := registry.Get(resource); !ok {
				missing[resource] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(missing))
	for resource := range missing {
		result = append(result, resource)
	}
	sort.Strings(result)
	return result
}

func splitPolicyResourceParts(resource string) []string {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return nil
	}

	parts := strings.Split(resource, "|")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "*" {
			continue
		}
		result = append(result, part)
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
		if p.Resource != "" {
			tables := resourceToTables(p.Resource)
			if len(tables) == 0 {
				continue
			}
			matches := hasWildcardTable(tables)
			if !matches {
				for _, t := range tables {
					if t == lower {
						matches = true
						break
					}
				}
			}
			if !matches {
				continue
			}
		}
		for _, cond := range p.Conditions {
			for _, field := range extractConditionFields(cond) {
				top := topLevelConditionField(field)
				if top == "" {
					continue
				}
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

func extractConditionFields(condition string) []string {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return nil
	}

	condition = normalizeLogicalOperators(condition)

	condition = trimOuterParens(condition)

	if parts := splitTopLevel(condition, " OR "); len(parts) > 1 {
		fields := make([]string, 0, len(parts))
		for _, part := range parts {
			fields = append(fields, extractConditionFields(part)...)
		}
		return fields
	}

	if parts := splitTopLevel(condition, " AND "); len(parts) > 1 {
		fields := make([]string, 0, len(parts))
		for _, part := range parts {
			fields = append(fields, extractConditionFields(part)...)
		}
		return fields
	}

	if field, _, _, ok := parseAnyCondition(condition); ok {
		return []string{strings.TrimSpace(field)}
	}

	if field, _, _, ok := parseInCondition(condition); ok {
		return []string{strings.TrimSpace(field)}
	}

	if field, _, _, ok := parseMatchesCondition(condition); ok {
		return []string{strings.TrimSpace(field)}
	}

	if field, _, _, ok := parseContainsCondition(condition); ok {
		return []string{strings.TrimSpace(field)}
	}

	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		if parts := strings.SplitN(condition, op, 2); len(parts) == 2 {
			return []string{strings.TrimSpace(parts[0])}
		}
	}
	if parts := splitTopLevelFold(condition, " starts_with "); len(parts) == 2 {
		return []string{strings.TrimSpace(parts[0])}
	}
	if strings.Contains(strings.ToLower(condition), " contains ") {
		parts := splitTopLevelFold(condition, " contains ")
		if len(parts) == 2 {
			return []string{strings.TrimSpace(parts[0])}
		}
	}
	lower := strings.ToLower(condition)
	if strings.HasSuffix(lower, " not exists") {
		return []string{strings.TrimSpace(condition[:len(condition)-len(" not exists")])}
	}
	if strings.HasSuffix(lower, " exists") {
		return []string{strings.TrimSpace(condition[:len(condition)-len(" exists")])}
	}

	return nil
}

func topLevelConditionField(field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return ""
	}

	field = trimOuterParens(field)
	if field == "" {
		return ""
	}

	parts := splitPath(field)
	if len(parts) == 0 {
		return field
	}

	return parts[0]
}

func (e *Engine) Evaluate(ctx context.Context, req *EvalRequest) (*EvalResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	action := ""
	if req != nil {
		action = req.Action
	}
	_, span := otel.Tracer("cerebro.policy").Start(ctx, "policy.evaluate",
		trace.WithAttributes(
			attribute.String("policy.action", strings.TrimSpace(action)),
		),
	)
	defer span.End()
	if req == nil {
		err := fmt.Errorf("eval request is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

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

	span.SetAttributes(
		attribute.Int("policy.count", len(e.policies)),
		attribute.Int("policy.matched_count", len(resp.Matched)),
		attribute.String("policy.decision", resp.Decision),
	)

	return resp, nil
}

func (e *Engine) EvaluateAsset(ctx context.Context, asset map[string]interface{}) ([]Finding, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	assetType, _ := asset["type"].(string)
	assetTableName, _ := asset["_cq_table"].(string)
	_, span := otel.Tracer("cerebro.policy").Start(ctx, "policy.evaluate_asset",
		trace.WithAttributes(
			attribute.String("asset.type", strings.TrimSpace(assetType)),
			attribute.String("asset.table", strings.TrimSpace(assetTableName)),
		),
	)
	defer span.End()

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
			tables := resourceToTables(p.Resource)
			if len(tables) == 0 {
				continue // Unknown resource type - don't apply to all assets
			}
			matches := hasWildcardTable(tables)
			if !matches {
				for _, t := range tables {
					if t == assetTable {
						matches = true
						break
					}
				}
			}
			if !matches {
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

	span.SetAttributes(
		attribute.Int("policy.count", len(e.policies)),
		attribute.Int("policy.findings_count", len(findings)),
	)

	return findings, nil
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
	switch normalizeConditionFormat(p.ConditionFormat) {
	case ConditionFormatCEL:
		if !e.evaluateCELConditions(p, asset) {
			return ""
		}
	default:
		for _, cond := range p.Conditions {
			if !evaluateCondition(cond, asset) {
				return "" // If any condition doesn't match, no violation
			}
		}
	}
	return p.Description // All conditions matched - violation
}

func evaluateCondition(condition string, asset map[string]interface{}) bool {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return false
	}

	condition = normalizeLogicalOperators(condition)

	condition = trimOuterParens(condition)

	// Handle OR (any sub-condition true -> true)
	if parts := splitTopLevel(condition, " OR "); len(parts) > 1 {
		for _, part := range parts {
			if evaluateCondition(part, asset) {
				return true
			}
		}
		return false
	}

	// Handle AND (all sub-conditions true -> true)
	if parts := splitTopLevel(condition, " AND "); len(parts) > 1 {
		for _, part := range parts {
			if !evaluateCondition(part, asset) {
				return false
			}
		}
		return true
	}

	if field, inner, negated, ok := parseAnyCondition(condition); ok {
		match := anyValueMatches(getNestedValue(asset, field), inner)
		if negated {
			return !match
		}
		return match
	}

	if field, values, negated, ok := parseInCondition(condition); ok {
		match := valueInList(getNestedValue(asset, field), values)
		if negated {
			return !match
		}
		return match
	}

	if field, pattern, negated, ok := parseMatchesCondition(condition); ok {
		match := valueMatchesPattern(getNestedValue(asset, field), pattern)
		if negated {
			return !match
		}
		return match
	}

	if field, expected, negated, ok := parseContainsCondition(condition); ok {
		match := evaluateContainsCondition(asset, field, expected)
		if negated {
			return !match
		}
		return match
	}

	if field, expected, operator, ok := parseComparisonCondition(condition); ok {
		val := getNestedValue(asset, field)
		return compareValues(val, expected, operator)
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

	// Handle not exists check
	lower := strings.ToLower(condition)
	if strings.HasSuffix(lower, " not exists") {
		field := strings.TrimSpace(condition[:len(condition)-len(" not exists")])
		val := getNestedValue(asset, field)
		return val == nil
	}
	// Handle exists check
	if strings.HasSuffix(lower, " exists") {
		field := strings.TrimSpace(condition[:len(condition)-len(" exists")])
		val := getNestedValue(asset, field)
		return val != nil
	}

	return false
}

func parseComparisonCondition(condition string) (string, string, string, bool) {
	for _, operator := range []string{">=", "<=", "==", "!=", ">", "<"} {
		if parts := splitTopLevel(condition, operator); len(parts) == 2 {
			field := strings.TrimSpace(parts[0])
			expected := strings.TrimSpace(parts[1])
			if field == "" || expected == "" {
				return "", "", "", false
			}
			return field, expected, operator, true
		}
	}
	return "", "", "", false
}

func normalizeLogicalOperators(condition string) string {
	if condition == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(condition))
	inSingle := false
	inDouble := false

	for i := 0; i < len(condition); i++ {
		char := condition[i]
		switch char {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		}

		if !inSingle && !inDouble && i+1 < len(condition) {
			next := condition[i+1]
			if char == '|' && next == '|' {
				builder.WriteString(" OR ")
				i++
				continue
			}
			if char == '&' && next == '&' {
				builder.WriteString(" AND ")
				i++
				continue
			}
		}

		builder.WriteByte(char)
	}

	return builder.String()
}

func splitTopLevel(condition string, delimiter string) []string {
	return splitTopLevelInternal(condition, delimiter, false)
}

func splitTopLevelFold(condition string, delimiter string) []string {
	return splitTopLevelInternal(condition, delimiter, true)
}

func splitTopLevelInternal(condition string, delimiter string, fold bool) []string {
	if delimiter == "" {
		return []string{condition}
	}

	var parts []string
	depth := 0
	inSingle := false
	inDouble := false
	start := 0
	limit := len(condition) - len(delimiter)

	for i := 0; i < len(condition); i++ {
		char := condition[i]
		switch char {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '(':
			if !inSingle && !inDouble {
				depth++
			}
		case ')':
			if !inSingle && !inDouble && depth > 0 {
				depth--
			}
		}

		if depth != 0 || inSingle || inDouble {
			continue
		}
		if i > limit {
			continue
		}
		if matchDelimiter(condition, delimiter, i, fold) {
			parts = append(parts, strings.TrimSpace(condition[start:i]))
			i += len(delimiter) - 1
			start = i + 1
		}
	}

	parts = append(parts, strings.TrimSpace(condition[start:]))
	return parts
}

func matchDelimiter(condition string, delimiter string, index int, fold bool) bool {
	if index+len(delimiter) > len(condition) {
		return false
	}
	segment := condition[index : index+len(delimiter)]
	if fold {
		return strings.EqualFold(segment, delimiter)
	}
	return segment == delimiter
}

func trimOuterParens(condition string) string {
	for {
		condition = strings.TrimSpace(condition)
		if len(condition) < 2 || condition[0] != '(' || condition[len(condition)-1] != ')' {
			return condition
		}
		if !isOuterParens(condition) {
			return condition
		}
		condition = strings.TrimSpace(condition[1 : len(condition)-1])
	}
}

func isOuterParens(condition string) bool {
	depth := 0
	inSingle := false
	inDouble := false
	for i := 0; i < len(condition); i++ {
		char := condition[i]
		switch char {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '(':
			if !inSingle && !inDouble {
				depth++
			}
		case ')':
			if !inSingle && !inDouble {
				depth--
				if depth == 0 && i != len(condition)-1 {
					return false
				}
				if depth < 0 {
					return false
				}
			}
		}
	}
	return depth == 0
}

func parseAnyCondition(condition string) (string, string, bool, bool) {
	if parts := splitTopLevelFold(condition, " NOT ANY "); len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		inner := trimOuterParens(strings.TrimSpace(parts[1]))
		return field, inner, true, field != "" && inner != ""
	}
	if parts := splitTopLevelFold(condition, " ANY "); len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		inner := trimOuterParens(strings.TrimSpace(parts[1]))
		return field, inner, false, field != "" && inner != ""
	}
	return "", "", false, false
}

func parseInCondition(condition string) (string, []string, bool, bool) {
	if parts := splitTopLevelFold(condition, " NOT IN "); len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		values := parseListValues(parts[1])
		return field, values, true, field != "" && len(values) > 0
	}
	if parts := splitTopLevelFold(condition, " IN "); len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		values := parseListValues(parts[1])
		return field, values, false, field != "" && len(values) > 0
	}
	return "", nil, false, false
}

func parseListValues(list string) []string {
	list = strings.TrimSpace(list)
	if list == "" {
		return nil
	}
	if isOuterParens(list) {
		list = trimOuterParens(list)
	}
	if list == "" {
		return nil
	}

	parts := splitListTokens(list)
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		values = append(values, trimQuotes(trimmed))
	}
	return values
}

func splitListTokens(list string) []string {
	var parts []string
	start := 0
	inSingle := false
	inDouble := false
	for i := 0; i < len(list); i++ {
		switch list[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case ',':
			if !inSingle && !inDouble {
				parts = append(parts, strings.TrimSpace(list[start:i]))
				start = i + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(list[start:]))
	return parts
}

func parseMatchesCondition(condition string) (string, string, bool, bool) {
	if parts := splitTopLevelFold(condition, " NOT MATCHES "); len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		pattern := strings.TrimSpace(parts[1])
		return field, pattern, true, field != "" && pattern != ""
	}
	if parts := splitTopLevelFold(condition, " MATCHES "); len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		pattern := strings.TrimSpace(parts[1])
		return field, pattern, false, field != "" && pattern != ""
	}
	return "", "", false, false
}

func parseContainsCondition(condition string) (string, string, bool, bool) {
	if parts := splitTopLevelFold(condition, " NOT CONTAINS "); len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		return field, value, true, field != "" && value != ""
	}
	if parts := splitTopLevelFold(condition, " CONTAINS "); len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		return field, value, false, field != "" && value != ""
	}
	return "", "", false, false
}

func evaluateContainsCondition(asset map[string]interface{}, field string, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return false
	}

	if !isQuoted(expected) && isOuterParens(expected) {
		inner := trimOuterParens(expected)
		return anyValueMatches(getNestedValue(asset, field), inner)
	}

	return valueContains(getNestedValue(asset, field), trimQuotes(expected))
}

func anyValueMatches(value interface{}, condition string) bool {
	if value == nil {
		return false
	}

	switch typed := value.(type) {
	case []interface{}:
		for _, item := range typed {
			if anyValueMatches(item, condition) {
				return true
			}
		}
		return false
	case map[string]interface{}:
		return evaluateCondition(condition, typed)
	case string:
		parsed := tryParseJSON(typed)
		if parsed != nil {
			return anyValueMatches(parsed, condition)
		}
		return false
	default:
		return false
	}
}

func valueInList(value interface{}, list []string) bool {
	if value == nil {
		return false
	}

	switch typed := value.(type) {
	case []interface{}:
		for _, item := range typed {
			if valueInList(item, list) {
				return true
			}
		}
		return false
	case []string:
		for _, item := range typed {
			if valueInList(item, list) {
				return true
			}
		}
		return false
	default:
		for _, expected := range list {
			if compareValues(typed, expected, "==") {
				return true
			}
		}
		return false
	}
}

func valueMatchesPattern(value interface{}, pattern string) bool {
	pattern = trimQuotes(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}

	return matchRegexValue(value, re)
}

func matchRegexValue(value interface{}, re *regexp.Regexp) bool {
	if value == nil {
		return false
	}

	switch typed := value.(type) {
	case []interface{}:
		for _, item := range typed {
			if matchRegexValue(item, re) {
				return true
			}
		}
		return false
	case []string:
		for _, item := range typed {
			if re.MatchString(item) {
				return true
			}
		}
		return false
	case string:
		return re.MatchString(typed)
	case map[string]interface{}:
		serialized, err := json.Marshal(typed)
		if err != nil {
			return false
		}
		return re.Match(serialized)
	default:
		return re.MatchString(fmt.Sprintf("%v", value))
	}
}

func valueContains(value interface{}, substring string) bool {
	if value == nil || substring == "" {
		return false
	}

	switch typed := value.(type) {
	case []interface{}:
		for _, item := range typed {
			if valueContains(item, substring) {
				return true
			}
		}
		return false
	case []string:
		for _, item := range typed {
			if strings.Contains(item, substring) {
				return true
			}
		}
		return false
	case string:
		return strings.Contains(typed, substring)
	case map[string]interface{}:
		serialized, err := json.Marshal(typed)
		if err != nil {
			return false
		}
		return strings.Contains(string(serialized), substring)
	default:
		return strings.Contains(fmt.Sprintf("%v", value), substring)
	}
}

func trimQuotes(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		first := value[0]
		last := value[len(value)-1]
		if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
			return value[1 : len(value)-1]
		}
	}
	return strings.Trim(value, "\"'")
}

func isQuoted(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 2 {
		return false
	}
	first := value[0]
	last := value[len(value)-1]
	return (first == '\'' && last == '\'') || (first == '"' && last == '"')
}

// getNestedValue retrieves a value from nested maps using dot notation
// e.g., "config.public_access.enabled" -> asset["config"]["public_access"]["enabled"]
// Handles JSON strings and URL-encoded JSON strings from Snowflake VARIANT columns
func getNestedValue(asset map[string]interface{}, path string) interface{} {
	parts := splitPath(path)
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

func splitPath(path string) []string {
	if path == "" {
		return nil
	}

	var parts []string
	var buf strings.Builder
	inBracket := false
	inQuote := false
	var quote byte

	flush := func() {
		if buf.Len() == 0 {
			return
		}
		segment := strings.TrimSpace(buf.String())
		if segment != "" {
			parts = append(parts, segment)
		}
		buf.Reset()
	}

	for i := 0; i < len(path); i++ {
		char := path[i]
		if inBracket {
			if inQuote {
				if char == quote {
					inQuote = false
				} else {
					buf.WriteByte(char)
				}
				continue
			}

			switch char {
			case '\'', '"':
				inQuote = true
				quote = char
			case ']':
				flush()
				inBracket = false
			case '[':
				continue
			default:
				buf.WriteByte(char)
			}
			continue
		}

		switch char {
		case '.':
			flush()
		case '[':
			flush()
			inBracket = true
		default:
			buf.WriteByte(char)
		}
	}

	flush()
	return parts
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
			case ">=":
				return f >= ef
			case "<=":
				return f <= ef
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
