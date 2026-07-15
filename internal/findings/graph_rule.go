package findings

import (
	"context"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

// GraphIngestRunStore supplies the projection checkpoint actually read by a
// graph-rule evaluation.
type GraphIngestRunStore interface {
	ListIngestRuns(context.Context, graphstore.IngestRunFilter) ([]graphstore.IngestRun, error)
}

// GraphRule evaluates the projected graph by issuing one bounded read-only Cypher query per
// runtime invocation. Unlike event rules, graph rules do not see the append log directly;
// they reason over the post-projection world model and emit findings from row sets.
//
// Implementations must keep queries deterministic and bounded: the store enforces a hard row
// cap, but rules should also include LIMIT clauses to keep latency predictable and to avoid
// surprising Neo4j cost profiles on large tenants.
type GraphRule interface {
	Rule
	QueryFor(*cerebrov1.SourceRuntime) ports.CypherQueryRequest
	EvaluateRows(context.Context, *cerebrov1.SourceRuntime, []ports.CypherRow) ([]*ports.FindingRecord, error)
}

// asGraphRule narrows a registered Rule into a GraphRule when supported.
func asGraphRule(rule Rule) (GraphRule, bool) {
	if rule == nil {
		return nil, false
	}
	graphRule, ok := rule.(GraphRule)
	return graphRule, ok
}

// ScopedStaleResolver is an optional GraphRule capability for rules whose query
// applies an internal per-scope cap (for example a per-account cap) that can drop
// matching rows for some scopes while leaving others fully represented. It lets the
// service auto-resolve stale findings for the fully-represented scopes instead of
// skipping stale-finding resolution for the whole (tenant, rule) just because the
// internal cap fired on one scope.
//
// It is only consulted when the global row limit was NOT hit. A row-limit truncation
// can drop entire scopes past the cutoff, so a scope's absence in that case is not
// evidence that it stopped matching; the service keeps the conservative global skip.
type ScopedStaleResolver interface {
	GraphRule
	// StaleResolutionScopeAttribute is the finding attribute that carries the scope
	// key the resolver groups on (for example "cloud_account_urn"). Open findings
	// whose attribute is missing are treated as out-of-scope and left untouched.
	StaleResolutionScopeAttribute() string
	// IncompleteStaleResolutionScopes returns the set of scope keys whose rows were
	// capped this evaluation, derived from the evaluated rows. A scope is incomplete
	// if any of its rows was dropped by the internal cap.
	IncompleteStaleResolutionScopes(rows []ports.CypherRow) map[string]struct{}
}
