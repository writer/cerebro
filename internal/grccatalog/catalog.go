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

// scopeParams are the shared, tenant-safe scoping inputs honored by every
// runtime-scoped GRC read. tenant_id and limit are intentionally excluded:
// tenant is always resolved from the authenticated principal, and limit is a
// dedicated WidgetQuery field clamped to the source maximum.
func scopeParams() []Param {
	return []Param{
		{ID: "runtime_id", Type: ParamString, Scope: true, Description: "Restrict to one source runtime."},
		{ID: "runtime_ids", Type: ParamString, Scope: true, Description: "Restrict to a comma-separated set of source runtimes."},
		{ID: "source_id", Type: ParamString, Scope: true, Description: "Restrict to one source family."},
	}
}

func withScope(params ...Param) []Param {
	return append(scopeParams(), params...)
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
			Params: withScope(
				Param{ID: "status", Type: ParamString, Description: "Lifecycle status filter, or \"all\" for every status."},
				Param{ID: "finding_id", Type: ParamString, Description: "Restrict to one finding."},
				Param{ID: "rule_id", Type: ParamString, Description: "Restrict to findings from one rule."},
				Param{ID: "severity", Type: ParamString, Description: "Severity filter (critical, high, medium, low)."},
				Param{ID: "resource_urn", Type: ParamString, Description: "Restrict to findings on one resource URN."},
				Param{ID: "event_id", Type: ParamString, Description: "Restrict to findings from one event."},
				Param{ID: "policy_id", Type: ParamString, Description: "Restrict to findings from one policy."},
				Param{ID: "framework", Type: ParamString, Description: "Restrict to findings mapped to one framework."},
				Param{ID: "min_age_days", Type: ParamInt, Description: "Minimum finding age in days."},
				Param{ID: "max_age_days", Type: ParamInt, Description: "Maximum finding age in days."},
				Param{ID: "sla_status", Type: ParamString, Description: "SLA posture filter (e.g. overdue)."},
			),
			Visualizations: []string{"table", "metric"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "findings",
			Exportable:     true,
		},
		{
			ID:          "controls",
			Domain:      "controls",
			Title:       "Control posture",
			Description: "Open findings grouped into control posture rows with evidence counts.",
			Method:      "GET",
			Path:        "/grc/controls",
			Params: withScope(
				Param{ID: "status", Type: ParamString, Description: "Lifecycle status filter, or \"all\" for every status."},
			),
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
			Params: withScope(
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
			ID:          "trends",
			Domain:      "trends",
			Title:       "Finding trends",
			Description: "Time-bucketed finding counts and aging, optionally compared to the prior period.",
			Method:      "GET",
			Path:        "/grc/trends",
			Params: withScope(
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
			ID:             "control-coverage",
			Domain:         "controls",
			Title:          "Control coverage",
			Description:    "Framework control coverage posture for the tenant.",
			Method:         "GET",
			Path:           "/grc/control-coverage",
			Params:         withScope(),
			Visualizations: []string{"table", "metric"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "findings",
		},
		{
			ID:             "inventory-assets",
			Domain:         "inventory",
			Title:          "Inventory assets",
			Description:    "Governed asset inventory with finding and evidence context.",
			Method:         "GET",
			Path:           "/grc/inventory/assets",
			Params:         withScope(),
			Visualizations: []string{"table"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "inventory",
		},
		{
			ID:             "inventory-categories",
			Domain:         "inventory",
			Title:          "Inventory categories",
			Description:    "Asset inventory grouped by category.",
			Method:         "GET",
			Path:           "/grc/inventory/categories",
			Params:         withScope(),
			Visualizations: []string{"table", "metric"},
			DefaultLimit:   DefaultLimit,
			MaxLimit:       MaxLimit,
			CacheScope:     "inventory",
		},
	}
}
