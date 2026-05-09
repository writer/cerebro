package findings

import (
	"context"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// GraphRuleRuntimePrefix labels the synthetic runtime_id stamped on graph-rule findings.
// Graph rules are tenant-scoped: their fingerprints collapse the same offender across every
// real runtime that could trigger them, so the persisted record cannot legitimately be tied
// to one source runtime. The synthetic id pins the row to a stable (tenant, rule) identity
// instead, which makes per-runtime list paths consistent across iterations.
const GraphRuleRuntimePrefix = "graph-rule:"

// graphRuleRuntimeID returns the synthetic runtime id that graph rules stamp on persisted
// findings. The id is deterministic per rule so multiple triggering runtimes converge on
// the same row instead of flipping it between source-specific runtime ids.
func graphRuleRuntimeID(ruleID string) string {
	return GraphRuleRuntimePrefix + strings.TrimSpace(ruleID)
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
