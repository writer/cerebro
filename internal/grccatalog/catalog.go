// Package grccatalog defines the bounded, allowlisted set of GRC report
// sources that custom dashboards and the report builder can query. It is the
// "semantic catalog": each source maps to one existing, tenant-scoped,
// row-limited GRC read endpoint and declares the parameters a caller may bind.
//
// This is deliberately NOT a general-purpose query engine. There are no
// free-form dimensions, measures, joins, or ad-hoc filters. Callers pick a
// named source from the catalog and supply values for its declared parameters,
// which keeps the surface bounded and within the limits documented in
// docs/engineering/non-goals.md ("The graph is not a general-purpose graph
// database product"). Aggregation, traversal, and tenant scoping stay in the
// underlying GRC handlers; this package only validates the request shape.
package grccatalog

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Errors returned by ValidateWidgetQuery. Callers map these to HTTP 400.
var (
	// ErrUnknownSource indicates the query referenced a source that is not in
	// the catalog allowlist.
	ErrUnknownSource = errors.New("unknown report source")

	// ErrInvalidQuery indicates the query referenced an unknown parameter, a
	// malformed value, a missing required parameter, or an out-of-range limit.
	ErrInvalidQuery = errors.New("invalid report query")
)

// Parameter value types understood by the validator.
const (
	ParamString = "string"
	ParamEnum   = "enum"
	ParamInt    = "int"
	ParamBool   = "bool"
)

// DefaultLimit and MaxLimit mirror the bounds enforced by the GRC read
// handlers so the catalog advertises the same row caps it dispatches under.
const (
	DefaultLimit uint32 = 100
	MaxLimit     uint32 = 500
)

// Param describes one allowlisted query parameter for a source.
type Param struct {
	ID            string   `json:"id"`
	Type          string   `json:"type"`
	Required      bool     `json:"required,omitempty"`
	Scope         bool     `json:"scope,omitempty"`
	AllowedValues []string `json:"allowed_values,omitempty"`
	Description   string   `json:"description,omitempty"`
}

// Source describes one bounded, tenant-scoped GRC read endpoint that a widget
// may bind to. Method and Path identify the backing endpoint; Params is the
// closed set of inputs a caller may supply.
type Source struct {
	ID             string   `json:"id"`
	Domain         string   `json:"domain"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Method         string   `json:"method"`
	Path           string   `json:"path"`
	Params         []Param  `json:"params"`
	Visualizations []string `json:"visualizations"`
	DefaultLimit   uint32   `json:"default_limit"`
	MaxLimit       uint32   `json:"max_limit"`
	CacheScope     string   `json:"cache_scope,omitempty"`
	Exportable     bool     `json:"exportable,omitempty"`
}

// WidgetQuery is a request to read one catalog source with bound parameters.
type WidgetQuery struct {
	SourceID string            `json:"source_id"`
	Params   map[string]string `json:"params,omitempty"`
	Limit    uint32            `json:"limit,omitempty"`
}

var (
	catalog      = buildCatalog()
	catalogIndex = indexCatalog(catalog)
)

// Catalog returns a copy of the report source catalog.
func Catalog() []Source {
	out := make([]Source, len(catalog))
	copy(out, catalog)
	return out
}

// Lookup returns the catalog source with the given id.
func Lookup(id string) (Source, bool) {
	source, ok := catalogIndex[strings.TrimSpace(id)]
	return source, ok
}

// ValidateWidgetQuery checks that a query references a known source and only
// binds declared parameters with well-typed values, within the source's row
// limit. It does not execute anything; tenant scoping and data access remain
// the responsibility of the dispatched GRC handler.
func ValidateWidgetQuery(query WidgetQuery) error {
	source, ok := Lookup(query.SourceID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownSource, strings.TrimSpace(query.SourceID))
	}
	allowed := make(map[string]Param, len(source.Params))
	for _, param := range source.Params {
		allowed[param.ID] = param
	}
	for key, value := range query.Params {
		key = strings.TrimSpace(key)
		param, ok := allowed[key]
		if !ok {
			return fmt.Errorf("%w: source %q does not support parameter %q", ErrInvalidQuery, source.ID, key)
		}
		if err := validateParamValue(param, value); err != nil {
			return err
		}
	}
	for _, param := range source.Params {
		if !param.Required {
			continue
		}
		if strings.TrimSpace(query.Params[param.ID]) == "" {
			return fmt.Errorf("%w: source %q requires parameter %q", ErrInvalidQuery, source.ID, param.ID)
		}
	}
	maxLimit := source.MaxLimit
	if maxLimit == 0 {
		maxLimit = MaxLimit
	}
	if query.Limit > maxLimit {
		return fmt.Errorf("%w: limit must be <= %d", ErrInvalidQuery, maxLimit)
	}
	return nil
}

func validateParamValue(param Param, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	switch param.Type {
	case ParamInt:
		if _, err := strconv.Atoi(trimmed); err != nil {
			return fmt.Errorf("%w: parameter %q must be an integer", ErrInvalidQuery, param.ID)
		}
	case ParamBool:
		if _, err := strconv.ParseBool(trimmed); err != nil {
			return fmt.Errorf("%w: parameter %q must be a boolean", ErrInvalidQuery, param.ID)
		}
	case ParamEnum:
		for _, candidate := range param.AllowedValues {
			if trimmed == candidate {
				return nil
			}
		}
		return fmt.Errorf("%w: parameter %q must be one of %s", ErrInvalidQuery, param.ID, strings.Join(param.AllowedValues, ", "))
	}
	return nil
}

func indexCatalog(sources []Source) map[string]Source {
	index := make(map[string]Source, len(sources))
	for _, source := range sources {
		index[source.ID] = source
	}
	return index
}

// runtimeScopeParams are the runtime-selection inputs honored by GRC reads that
// resolve a set of source runtimes before querying (findings, controls,
// evidence, trends). tenant_id and limit are intentionally excluded: tenant is
// always resolved from the authenticated principal, and limit is a dedicated
// WidgetQuery field clamped to the source maximum. Each parameter here is
// consumed by the backing handler; the catalog never advertises an input the
// handler ignores.
func runtimeScopeParams() []Param {
	return []Param{
		{ID: "runtime_id", Type: ParamString, Scope: true, Description: "Restrict to one source runtime."},
		{ID: "runtime_ids", Type: ParamString, Scope: true, Description: "Restrict to a comma-separated set of source runtimes."},
		sourceScopeParam(),
	}
}

// sourceScopeParam restricts a read to one source family. It is honored both by
// the runtime-scoped reads and by the inventory reads, which pass it through to
// the graph query service.
func sourceScopeParam() Param {
	return Param{ID: "source_id", Type: ParamString, Scope: true, Description: "Restrict to one source family."}
}

func withRuntimeScope(params ...Param) []Param {
	return append(runtimeScopeParams(), params...)
}

func vendorListParams() []Param {
	return withRuntimeScope(
		Param{ID: "q", Type: ParamString, Description: "Free-text vendor search."},
		Param{ID: "risk_level", Type: ParamEnum, AllowedValues: []string{"critical", "high", "medium", "low", "unknown", "all"}, Description: "Filter by normalized vendor risk level."},
		Param{ID: "review_state", Type: ParamEnum, AllowedValues: []string{"current", "due_soon", "overdue", "not_scheduled", "all"}, Description: "Filter by security review state."},
		Param{ID: "owner_state", Type: ParamEnum, AllowedValues: []string{"assigned", "missing", "all"}, Description: "Filter by vendor owner assignment."},
	)
}

func buildCatalog() []Source {
	return []Source{
		{
			ID:          "findings",
			Domain:      "findings",
			Title:       "Findings",
			Description: "Risk-inbox findings grouped for review, filterable by status, severity, rule, framework, and age.",
			Method:      "GET",
			Path:        "/grc/findings",
			Params: withRuntimeScope(
				Param{ID: "status", Type: ParamString, Description: "Lifecycle status filter, or \"all\" for every status."},
				Param{ID: "finding_id", Type: ParamString, Description: "Restrict to one finding."},
				Param{ID: "rule_id", Type: ParamString, Description: "Restrict to findings from one rule."},
				Param{ID: "severity", Type: ParamString, Description: "Severity filter (critical, high, medium, low)."},
				Param{ID: "resource_urn", Type: ParamString, Description: "Restrict to findings on one resource URN."},
				Param{ID: "event_id", Type: ParamString, Description: "Restrict to findings from one event."},
				Param{ID: "policy_id", Type: ParamString, Description: "Restrict to findings from one policy."},
				Param{ID: "framework", Type: ParamString, Description: "Restrict to findings mapped to one framework."},
				Param{ID: "age_min_days", Type: ParamInt, Description: "Minimum finding age in days."},
				Param{ID: "age_max_days", Type: ParamInt, Description: "Maximum finding age in days."},
				Param{ID: "sla_status", Type: ParamString, Description: "SLA posture filter (e.g. overdue)."},
			),
			Visualizations: []string{"table", "metric"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "findings",
			Exportable:     true,
		},
		{
			ID:             "controls",
			Domain:         "controls",
			Title:          "Control posture",
			Description:    "Open findings grouped into control posture rows with evidence counts.",
			Method:         "GET",
			Path:           "/grc/controls",
			Params:         runtimeScopeParams(),
			Visualizations: []string{"table", "metric"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "findings",
			Exportable:     true,
		},
		{
			ID:          "evidence",
			Domain:      "evidence",
			Title:       "Evidence",
			Description: "Evidence records linked to findings, runs, rules, or a graph root.",
			Method:      "GET",
			Path:        "/grc/evidence",
			Params: withRuntimeScope(
				Param{ID: "finding_id", Type: ParamString, Description: "Restrict to evidence for one finding."},
				Param{ID: "run_id", Type: ParamString, Description: "Restrict to evidence from one evaluation run."},
				Param{ID: "rule_id", Type: ParamString, Description: "Restrict to evidence from one rule."},
				Param{ID: "graph_root_urn", Type: ParamString, Description: "Restrict to evidence anchored at one graph root URN."},
			),
			Visualizations: []string{"table"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "evidence",
		},
		{
			ID:          "policy-lifecycle",
			Domain:      "policies",
			Title:       "Policy lifecycle",
			Description: "Policy templates, versions, approvals, attestations, exceptions, reminders, and control mappings.",
			Method:      "GET",
			Path:        "/grc/policy-lifecycle",
			Params: []Param{
				{ID: "runtime_id", Type: ParamString, Scope: true, Description: "Restrict to one source runtime."},
				sourceScopeParam(),
			},
			Visualizations: []string{"table", "metric"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "graph",
		},
		{
			ID:          "trends",
			Domain:      "trends",
			Title:       "Finding trends",
			Description: "Time-bucketed finding counts and aging, optionally compared to the prior period.",
			Method:      "GET",
			Path:        "/grc/trends",
			Params: withRuntimeScope(
				Param{ID: "days", Type: ParamInt, Description: "Lookback window in days (1-366)."},
				Param{ID: "interval", Type: ParamEnum, AllowedValues: []string{"day", "week", "month"}, Description: "Bucket interval."},
				Param{ID: "severity", Type: ParamString, Description: "Severity filter (critical, high, medium, low)."},
				Param{ID: "framework", Type: ParamString, Description: "Restrict to findings mapped to one framework."},
				Param{ID: "compare", Type: ParamBool, Description: "Include a comparison against the previous period."},
			),
			Visualizations: []string{"chart", "metric", "table"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "findings",
		},
		{
			ID:             "frameworks",
			Domain:         "controls",
			Title:          "Frameworks",
			Description:    "The supported compliance framework catalog.",
			Method:         "GET",
			Path:           "/grc/frameworks",
			Params:         nil,
			Visualizations: []string{"table"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
		},
		{
			ID:          "control-coverage",
			Domain:      "controls",
			Title:       "Control coverage",
			Description: "Framework control coverage posture for the tenant.",
			Method:      "GET",
			Path:        "/grc/control-coverage",
			Params: []Param{
				{ID: "profile", Type: ParamString, Description: "Restrict to one builtin control profile."},
			},
			Visualizations: []string{"table", "metric"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "findings",
		},
		{
			ID:          "inventory-assets",
			Domain:      "inventory",
			Title:       "Inventory assets",
			Description: "Governed asset inventory with finding and evidence context.",
			Method:      "GET",
			Path:        "/grc/inventory/assets",
			Params: []Param{
				sourceScopeParam(),
				{ID: "category_id", Type: ParamString, Description: "Restrict to assets in one inventory category."},
				{ID: "entity_type", Type: ParamString, Description: "Restrict to one entity type."},
				{ID: "q", Type: ParamString, Description: "Free-text asset search."},
				{ID: "scope_state", Type: ParamString, Description: "Filter by inventory scope state."},
				{ID: "review_state", Type: ParamString, Description: "Filter by review disposition."},
				{ID: "accountability_state", Type: ParamString, Description: "Filter by accountability state."},
			},
			Visualizations: []string{"table"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "inventory",
		},
		{
			ID:             "vendors",
			Domain:         "vendors",
			Title:          "Vendors",
			Description:    "Canonical vendor rows with owners, review dates, contract counts, assurance counts, and open risk.",
			Method:         "GET",
			Path:           "/grc/vendors",
			Params:         vendorListParams(),
			Visualizations: []string{"table", "metric"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "vendors",
			Exportable:     true,
		},
		{
			ID:          "vendor-detail",
			Domain:      "vendors",
			Title:       "Vendor detail",
			Description: "One vendor packet with linked contracts, reviews, questionnaires, assurance records, findings, evidence, and graph context.",
			Method:      "GET",
			Path:        "/grc/vendors/{vendorID}",
			Params: withRuntimeScope(
				Param{ID: "vendor_id", Type: ParamString, Required: true, Description: "Vendor ID or encoded Cerebro vendor URN."},
			),
			Visualizations: []string{"table"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "vendors",
		},
		{
			ID:          "vendor-discoveries",
			Domain:      "vendors",
			Title:       "Vendor discoveries",
			Description: "Discovered vendor candidates with source status and local approve, reject, ignore, or link decisions.",
			Method:      "GET",
			Path:        "/grc/vendor-discoveries",
			Params: withRuntimeScope(
				Param{ID: "q", Type: ParamString, Description: "Free-text discovery search."},
				Param{ID: "status", Type: ParamEnum, AllowedValues: []string{"discovered", "approved", "rejected", "ignored", "linked", "all"}, Description: "Filter by source-emitted discovery status."},
				Param{ID: "decision_state", Type: ParamEnum, AllowedValues: []string{"discovered", "approved", "rejected", "ignored", "linked", "all"}, Description: "Filter by effective local decision state."},
			),
			Visualizations: []string{"table", "metric"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "vendors",
			Exportable:     true,
		},
		{
			ID:             "vendor-risk-queue",
			Domain:         "vendors",
			Title:          "Vendor risk queue",
			Description:    "Vendor rows for owner gaps, overdue reviews, due-soon reviews, and high residual risk work.",
			Method:         "GET",
			Path:           "/grc/vendors",
			Params:         vendorListParams(),
			Visualizations: []string{"table", "metric"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "vendors",
			Exportable:     true,
		},
		{
			ID:          "inventory-categories",
			Domain:      "inventory",
			Title:       "Inventory categories",
			Description: "Asset inventory grouped by category.",
			Method:      "GET",
			Path:        "/grc/inventory/categories",
			Params: []Param{
				sourceScopeParam(),
			},
			Visualizations: []string{"table", "metric"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "inventory",
		},
	}
}
