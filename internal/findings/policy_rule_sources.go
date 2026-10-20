package findings

import "sort"

// PolicyRuleSource is the authored declarative shape of one compiled policy
// rule, exposed so catalogs can show matchers and guidance without reloading
// the policies tree at runtime.
type PolicyRuleSource struct {
	Definition        RuleDefinition
	Summary           string
	Remediation       string
	RemediationSteps  []string
	RelPath           string
	Category          string
	Resource          string
	ResourceType      string
	EvidenceMode      string
	Conditions        []string
	Query             string
	GraphQuery        string
	GraphRowLimit     int
	GraphParams       map[string]any
	GraphSourceKinds  []string
	GraphColumns      []string
	RiskStatement     string
	RemediationIntent string
	Enabled           bool
}

// BuiltinPolicyRuleSources returns every compiled policy rule sorted by ID.
func BuiltinPolicyRuleSources() []PolicyRuleSource {
	sources := make([]PolicyRuleSource, 0, len(generatedPolicyRuleCatalog))
	for _, config := range generatedPolicyRuleCatalog {
		sources = append(sources, PolicyRuleSource{
			Definition:        applyBuiltinRuleAuditDepth(cloneRuleDefinition(config.Definition)),
			Summary:           config.Summary,
			Remediation:       config.Remediation,
			RemediationSteps:  cloneStringSlice(config.RemediationSteps),
			RelPath:           config.RelPath,
			Category:          config.Category,
			Resource:          config.Resource,
			ResourceType:      config.ResourceType,
			EvidenceMode:      config.EvidenceMode,
			Conditions:        cloneStringSlice(config.Conditions),
			Query:             config.Query,
			GraphQuery:        config.Graph.Query,
			GraphRowLimit:     config.Graph.RowLimit,
			GraphParams:       cloneAnyMap(config.Graph.Params),
			GraphSourceKinds:  cloneStringSlice(config.Graph.SourceKinds),
			GraphColumns:      cloneStringSlice(config.Graph.RequiredColumns),
			RiskStatement:     config.RiskStatement,
			RemediationIntent: config.RemediationIntent,
			Enabled:           config.Enabled,
		})
	}
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].Definition.ID < sources[j].Definition.ID
	})
	return sources
}
