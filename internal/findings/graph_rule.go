package findings

import (
	"context"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

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
