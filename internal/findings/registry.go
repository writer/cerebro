package findings

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/primitives"
)

// Rule evaluates replayed runtime events and emits persisted findings.
//
// The interface deliberately keeps source-specific detection logic out of Service so new
// platform findings can be added by registration instead of by adding more hardcoded branches
// to the replay path.
type Rule interface {
	primitives.Rule
	SupportsRuntime(*cerebrov1.SourceRuntime) bool
	Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error)
}

// Registry indexes finding rules by their stable identifier.
type Registry struct {
	rules map[string]Rule
}

// GraphRuleCatalogEntry is one server-registered, bounded graph rule query.
// It is intended for internal duplicate-coverage checks, not API responses.
type GraphRuleCatalogEntry struct {
	RuleID            string
	Request           ports.CypherQueryRequest
	Signature         GraphRuleCoverageSignature
	SemanticsComplete bool
}

var graphRuleEntityTypePattern = regexp.MustCompile(`(?i)entity_type\s*(?::|=)\s*['"]([^'"]+)['"]`)

var builtinRegistry *Registry

func init() {
	registry, err := newBuiltinRegistry()
	if err != nil {
		panic(fmt.Sprintf("build builtin finding registry: %v", err))
	}
	builtinRegistry = registry
}

// NewRegistry constructs a finding rule registry and rejects duplicate or invalid specs.
func NewRegistry(rules ...Rule) (*Registry, error) {
	indexed := make(map[string]Rule, len(rules))
	for _, rule := range rules {
		if rule == nil {
			return nil, fmt.Errorf("finding rule is required")
		}
		spec := rule.Spec()
		if spec == nil {
			return nil, fmt.Errorf("finding rule spec is required")
		}
		id := strings.TrimSpace(spec.GetId())
		if id == "" {
			return nil, fmt.Errorf("finding rule id is required")
		}
		if _, exists := indexed[id]; exists {
			return nil, fmt.Errorf("duplicate finding rule id %q", id)
		}
		if metadataRule, ok := rule.(MetadataRule); ok {
			metadata := metadataRule.RuleMetadata()
			if !metadata.IsZero() {
				if err := metadata.Validate(); err != nil {
					return nil, fmt.Errorf("finding rule %q metadata: %w", id, err)
				}
			}
		}
		indexed[id] = rule
	}
	return &Registry{rules: indexed}, nil
}

// Builtin returns the in-process finding rule registry for the rewrite skeleton.
//
// Keeping the built-in catalog in one place makes the current platform surface discoverable
// to clients and gives future rule packages one consistent registration seam.
func Builtin() *Registry {
	return builtinRegistry
}

func newBuiltinRegistry() (*Registry, error) {
	return NewRegistry(flattenRulePacks(builtinRulePacks())...)
}

// Get returns a registered finding rule by ID.
func (r *Registry) Get(id string) (Rule, bool) {
	if r == nil {
		return nil, false
	}
	rule, ok := r.rules[strings.TrimSpace(id)]
	return rule, ok
}

// List returns all registered rule specs sorted by ID.
func (r *Registry) List() []*cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	ids := make([]string, 0, len(r.rules))
	for id := range r.rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	specs := make([]*cerebrov1.RuleSpec, 0, len(ids))
	for _, id := range ids {
		specs = append(specs, r.rules[id].Spec())
	}
	return specs
}

// ForRuntime returns the registered rules that support one runtime, sorted by rule ID.
func (r *Registry) ForRuntime(runtime *cerebrov1.SourceRuntime) []Rule {
	if r == nil || runtime == nil {
		return nil
	}
	specs := r.List()
	rules := make([]Rule, 0, len(specs))
	for _, spec := range specs {
		rule, ok := r.rules[strings.TrimSpace(spec.GetId())]
		if !ok || !rule.SupportsRuntime(runtime) {
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}

// GraphRuleCatalog returns bounded QueryFor output for every registered graph
// rule in deterministic rule-ID order. It fails closed instead of silently
// omitting an unbounded rule from duplicate-coverage checks.
func (r *Registry) GraphRuleCatalog(tenantID string, limit int) ([]GraphRuleCatalogEntry, error) {
	if r == nil {
		return nil, fmt.Errorf("finding rule registry is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" || limit <= 0 {
		return nil, fmt.Errorf("tenant id and positive catalog limit are required")
	}
	ids := make([]string, 0, len(r.rules))
	for id := range r.rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	entries := make([]GraphRuleCatalogEntry, 0, len(ids))
	runtime := &cerebrov1.SourceRuntime{TenantId: tenantID}
	for _, id := range ids {
		graphRule, ok := r.rules[id].(GraphRule)
		if !ok {
			continue
		}
		request := graphRule.QueryFor(runtime)
		if strings.TrimSpace(request.Query) == "" {
			continue
		}
		if request.RowLimit <= 0 || request.RowLimit > ports.MaxCypherQueryRows {
			return nil, fmt.Errorf("graph rule %q returned unbounded row limit %d", id, request.RowLimit)
		}
		signatures, complete := graphRuleCoverageSignatures(r.rules[id], request)
		if len(signatures) == 0 {
			return nil, fmt.Errorf("graph rule %q has no server-minted coverage semantics", id)
		}
		for index, signature := range signatures {
			entries = append(entries, GraphRuleCatalogEntry{RuleID: fmt.Sprintf("%s:%d", id, index), Request: request, Signature: signature, SemanticsComplete: complete})
			if len(entries) > limit {
				return nil, fmt.Errorf("graph rule catalog exceeds limit %d", limit)
			}
		}
	}
	return entries, nil
}

func graphRuleCoverageSignatures(rule Rule, request ports.CypherQueryRequest) ([]GraphRuleCoverageSignature, bool) {
	if provider, ok := rule.(GraphRuleCoverageSemantics); ok {
		if signatures := provider.GraphRuleCoverageSignatures(); len(signatures) != 0 {
			return signatures, true
		}
	}
	seen := map[string]struct{}{}
	var entityTypes []string
	for _, match := range graphRuleEntityTypePattern.FindAllStringSubmatch(request.Query, -1) {
		entityType := strings.ToLower(strings.TrimSpace(match[1]))
		if entityType != "" {
			if _, exists := seen[entityType]; !exists {
				seen[entityType] = struct{}{}
				entityTypes = append(entityTypes, entityType)
			}
		}
	}
	sort.Strings(entityTypes)
	if len(entityTypes) == 0 {
		return nil, false
	}
	return []GraphRuleCoverageSignature{{RequiredEntityTypes: entityTypes}}, false
}
