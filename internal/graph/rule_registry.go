package graph

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// RuleCategory groups rules by their focus area
type RuleCategory string

const (
	RuleCategoryCore       RuleCategory = "core"
	RuleCategoryAWS        RuleCategory = "aws"
	RuleCategoryGCP        RuleCategory = "gcp"
	RuleCategoryAzure      RuleCategory = "azure"
	RuleCategoryKubernetes RuleCategory = "kubernetes"
	RuleCategoryCICD       RuleCategory = "cicd"
	RuleCategoryIdentity   RuleCategory = "identity"
	RuleCategoryNetwork    RuleCategory = "network"
	RuleCategoryData       RuleCategory = "data"
)

// RuleMetadata provides additional context about a rule
type RuleMetadata struct {
	ID          string
	Name        string
	Category    RuleCategory
	Provider    string   // aws, gcp, azure, k8s, or empty for cross-cloud
	MITREIDs    []string // MITRE ATT&CK technique IDs
	CISControls []string // CIS benchmark control IDs
	Enabled     bool
}

// RegisteredRule wraps a rule with its metadata
type RegisteredRule struct {
	Rule     *ToxicCombinationRule
	Metadata RuleMetadata
}

// RuleRegistry manages toxic combination rules with automatic registration
type RuleRegistry struct {
	mu         sync.RWMutex
	rules      map[string]*RegisteredRule
	byCategory map[RuleCategory][]*RegisteredRule
	byProvider map[string][]*RegisteredRule
}

var (
	globalRegistry     *RuleRegistry
	globalRegistryOnce sync.Once
)

// GlobalRegistry returns the singleton rule registry
func GlobalRegistry() *RuleRegistry {
	globalRegistryOnce.Do(func() {
		globalRegistry = NewRuleRegistry()
	})
	return globalRegistry
}

// NewRuleRegistry creates a new rule registry
func NewRuleRegistry() *RuleRegistry {
	return &RuleRegistry{
		rules:      make(map[string]*RegisteredRule),
		byCategory: make(map[RuleCategory][]*RegisteredRule),
		byProvider: make(map[string][]*RegisteredRule),
	}
}

// Register adds a rule to the registry with validation
func (r *RuleRegistry) Register(rule *ToxicCombinationRule, meta RuleMetadata) error {
	if err := r.validateRule(rule, meta); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.rules[meta.ID]; exists {
		return fmt.Errorf("rule with ID %q already registered", meta.ID)
	}

	registered := &RegisteredRule{
		Rule:     rule,
		Metadata: meta,
	}

	r.rules[meta.ID] = registered
	r.byCategory[meta.Category] = append(r.byCategory[meta.Category], registered)
	if meta.Provider != "" {
		r.byProvider[meta.Provider] = append(r.byProvider[meta.Provider], registered)
	}

	return nil
}

// MustRegister registers a rule and panics on error (for use in init())
func (r *RuleRegistry) MustRegister(rule *ToxicCombinationRule, meta RuleMetadata) {
	if err := r.Register(rule, meta); err != nil {
		panic(fmt.Sprintf("failed to register rule %s: %v", meta.ID, err))
	}
}

// validateRule ensures a rule is properly configured
func (r *RuleRegistry) validateRule(rule *ToxicCombinationRule, meta RuleMetadata) error {
	var errs []string

	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	if meta.ID == "" {
		errs = append(errs, "metadata ID is required")
	}
	if rule.ID == "" {
		errs = append(errs, "rule ID is required")
	}
	if meta.ID != "" && rule.ID != "" && meta.ID != rule.ID {
		errs = append(errs, fmt.Sprintf("metadata ID %q does not match rule ID %q", meta.ID, rule.ID))
	}
	if rule.Name == "" {
		errs = append(errs, "rule name is required")
	}
	if meta.Name == "" {
		errs = append(errs, "metadata name is required")
	}
	if rule.Description == "" {
		errs = append(errs, "rule description is required")
	}
	if rule.Detector == nil {
		errs = append(errs, "rule detector function is required")
	}
	if rule.Severity == "" {
		errs = append(errs, "rule severity is required")
	}
	if meta.Category == "" {
		errs = append(errs, "rule category is required")
	}

	// Validate severity is a known value
	switch rule.Severity {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		// valid
	default:
		errs = append(errs, fmt.Sprintf("unknown severity %q", rule.Severity))
	}

	// Validate category is known
	switch meta.Category {
	case RuleCategoryCore, RuleCategoryAWS, RuleCategoryGCP, RuleCategoryAzure,
		RuleCategoryKubernetes, RuleCategoryCICD, RuleCategoryIdentity,
		RuleCategoryNetwork, RuleCategoryData:
		// valid
	default:
		errs = append(errs, fmt.Sprintf("unknown category %q", meta.Category))
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// GetRule returns a rule by ID
func (r *RuleRegistry) GetRule(id string) (*RegisteredRule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rule, ok := r.rules[id]
	return rule, ok
}

// GetAllRules returns all registered rules
func (r *RuleRegistry) GetAllRules() []*RegisteredRule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rules := make([]*RegisteredRule, 0, len(r.rules))
	for _, rule := range r.rules {
		rules = append(rules, rule)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Metadata.ID < rules[j].Metadata.ID
	})
	return rules
}

// GetEnabledRules returns only enabled rules
func (r *RuleRegistry) GetEnabledRules() []*ToxicCombinationRule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var rules []*ToxicCombinationRule
	for _, reg := range r.rules {
		if reg.Metadata.Enabled {
			rules = append(rules, reg.Rule)
		}
	}
	return rules
}

// GetRulesByCategory returns rules in a category
func (r *RuleRegistry) GetRulesByCategory(category RuleCategory) []*RegisteredRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byCategory[category]
}

// GetRulesByProvider returns rules for a specific cloud provider
func (r *RuleRegistry) GetRulesByProvider(provider string) []*RegisteredRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byProvider[provider]
}

// Stats returns registration statistics
func (r *RuleRegistry) Stats() RegistryStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := RegistryStats{
		TotalRules:   len(r.rules),
		ByCategory:   make(map[RuleCategory]int),
		ByProvider:   make(map[string]int),
		BySeverity:   make(map[Severity]int),
		EnabledCount: 0,
	}

	for _, reg := range r.rules {
		stats.ByCategory[reg.Metadata.Category]++
		if reg.Metadata.Provider != "" {
			stats.ByProvider[reg.Metadata.Provider]++
		}
		stats.BySeverity[reg.Rule.Severity]++
		if reg.Metadata.Enabled {
			stats.EnabledCount++
		}
	}

	return stats
}

// RegistryStats contains statistics about registered rules
type RegistryStats struct {
	TotalRules   int
	EnabledCount int
	ByCategory   map[RuleCategory]int
	ByProvider   map[string]int
	BySeverity   map[Severity]int
}

// Validate checks all registered rules are properly configured
func (r *RuleRegistry) Validate() []error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var errs []error

	// Check for duplicate IDs (shouldn't happen due to registration check, but verify)
	seen := make(map[string]bool)
	for id := range r.rules {
		if seen[id] {
			errs = append(errs, fmt.Errorf("duplicate rule ID: %s", id))
		}
		seen[id] = true
	}

	// Verify minimum coverage per category
	minRulesPerCategory := map[RuleCategory]int{
		RuleCategoryCore:       3,
		RuleCategoryAWS:        3,
		RuleCategoryGCP:        3,
		RuleCategoryAzure:      2,
		RuleCategoryKubernetes: 3,
	}

	for category, minCount := range minRulesPerCategory {
		if count := len(r.byCategory[category]); count < minCount {
			errs = append(errs, fmt.Errorf("category %s has %d rules, minimum required is %d", category, count, minCount))
		}
	}

	return errs
}

// ExpectedRules lists rule IDs that MUST be registered
// This ensures no rules are accidentally removed
var ExpectedRules = []string{
	// Core rules
	"TC001", "TC002", "TC003", "TC004", "TC005", "TC006", "TC007", "TC008", "TC009", "TC010",
	// AWS rules
	"TC-AWS-001", "TC-AWS-002", "TC-AWS-003", "TC-AWS-004", "TC-AWS-005", "TC-AWS-006", "TC-AWS-007",
	// GCP rules
	"TC-GCP-001", "TC-GCP-002", "TC-GCP-003", "TC-GCP-004",
	// Azure rules
	"TC-AZURE-001", "TC-AZURE-002",
	// Kubernetes rules
	"TC-K8S-001", "TC-K8S-002", "TC-K8S-003", "TC-K8S-004",
	// CI/CD rules
	"TC-CICD-001", "TC-CICD-002",
	// Business rules
	"TC-BIZ-001", "TC-BIZ-002", "TC-BIZ-003", "TC-BIZ-004", "TC-BIZ-005",
}

// VerifyExpectedRules checks that all expected rules are registered
func (r *RuleRegistry) VerifyExpectedRules() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var missing []string
	for _, id := range ExpectedRules {
		if _, exists := r.rules[id]; !exists {
			missing = append(missing, id)
		}
	}
	return missing
}
