package findings

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// Public-principal entities are projected only as <provider>.public_principal
// (cloud.go, aws_compute.go). The exposure graph rules must anchor on that
// bounded entity_type set with an equality IN list so the (tenant_id,
// entity_type) range index drives the scan; an `ENDS WITH '.public_principal'`
// suffix predicate cannot use that index and forces a tenant-wide label scan
// that fans out into the rule's cross product.
func TestCloudExposureGraphRulesAnchorPublicPrincipalOnIndex(t *testing.T) {
	const indexedAnchor = "IN ['aws.public_principal', 'gcp.public_principal', 'azure.public_principal']"
	runtime := &cerebrov1.SourceRuntime{Id: "runtime", SourceId: "graph", TenantId: "writer"}
	rules := map[string]Rule{
		"cloud-exposed-privileged-compute-role":       newCloudExposedPrivilegedComputeRoleRule(),
		"cloud-public-exposure-privileged-principal":  newCloudPublicExposurePrivilegedPrincipalRule(),
		"cloud-current-public-exposure-review-needed": newCloudPublicResourceExposureGraphRule(),
	}
	for name, rule := range rules {
		t.Run(name, func(t *testing.T) {
			graphRule, ok := rule.(GraphRule)
			if !ok {
				t.Fatalf("%T does not implement GraphRule", rule)
			}
			query := graphRule.QueryFor(runtime).Query
			if strings.Contains(query, "ENDS WITH '.public_principal'") {
				t.Fatalf("query still uses non-indexable suffix predicate:\n%s", query)
			}
			if !strings.Contains(query, indexedAnchor) {
				t.Fatalf("query missing index-anchored public-principal predicate %q:\n%s", indexedAnchor, query)
			}
		})
	}
}

// ctxAwareGraphQuery blocks until the caller context is cancelled so a test can
// assert the per-rule query budget actually bounds an in-flight Cypher read.
type ctxAwareGraphQuery struct {
	*stubGraphStore
}

func (s *ctxAwareGraphQuery) ExecuteReadCypher(ctx context.Context, _ ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A single pathological graph rule must not be able to consume the entire
// orchestrator phase budget: the per-rule query timeout cancels its Cypher read
// and the run is recorded as failed without blocking the remaining rules.
func TestEvaluateSourceRuntimeGraphRulesEnforcesPerRuleQueryTimeout(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	store := &stubFindingStore{}
	graphStore := &ctxAwareGraphQuery{stubGraphStore: &stubGraphStore{}}
	rule := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "slow-rule"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n"},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).
		WithGraphQueryStore(graphStore).
		WithGraphRuleQueryTimeout(25 * time.Millisecond)

	started := time.Now()
	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: "runtime-okta"})
	elapsed := time.Since(started)
	if err == nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = nil, want per-rule deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("query ran for %v; per-rule timeout did not bound the read", elapsed)
	}
	if result == nil || len(result.Evaluations) != 1 {
		t.Fatalf("want one evaluation in partial result, got %#v", result)
	}
	if got := result.Evaluations[0].Run.GetStatus(); got != "failed" {
		t.Fatalf("Run.Status = %q, want failed", got)
	}
}

// WithGraphRuleQueryTimeout(0) falls back to the conservative package default
// rather than disabling the bound entirely.
func TestGraphRuleQueryBudgetFallsBackToDefault(t *testing.T) {
	t.Parallel()
	service := &Service{}
	if got := service.graphRuleQueryBudget(); got != defaultGraphRuleQueryTimeout {
		t.Fatalf("graphRuleQueryBudget() = %v, want default %v", got, defaultGraphRuleQueryTimeout)
	}
	service.WithGraphRuleQueryTimeout(90 * time.Second)
	if got := service.graphRuleQueryBudget(); got != 90*time.Second {
		t.Fatalf("graphRuleQueryBudget() = %v, want 90s override", got)
	}
}
