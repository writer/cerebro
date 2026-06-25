package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	graphstoreneo4j "github.com/writer/cerebro/internal/graphstore/neo4j"
	"github.com/writer/cerebro/internal/ports"
)

const explainSmokeTenant = "explain-smoke"

// graphRuleEntityIndexProbe is one tenant-scoped predicate shape that the hot graph rules
// rely on. Each probe is a single-node MATCH so the captured plan is unambiguous: the bolt
// driver does not faithfully surface the lhs of Apply/SemiApply operators, so the multi-hop
// rule queries (which use NOT EXISTS / OPTIONAL MATCH) cannot be asserted on directly.
type graphRuleEntityIndexProbe struct {
	name  string
	query string
}

// graphRuleEntityIndexProbes cover every Entity index ensureSchema adds for the hot rules:
// the (tenant_id, entity_type) composite and the (tenant_id, <typed prop>) range indexes.
// The shapes mirror what the rules reduce to (entity_type IN [...]/=, <typed prop> = true);
// the rule query-text guards in package findings pin that the rules emit those shapes.
var graphRuleEntityIndexProbes = []graphRuleEntityIndexProbe{
	{
		name:  "tenant+entity_type-in-public-principals",
		query: `MATCH (e:Entity {tenant_id: $tenant_id}) WHERE e.entity_type IN ['aws.public_principal', 'gcp.public_principal', 'azure.public_principal'] RETURN e.urn AS urn LIMIT 1`,
	},
	{
		name:  "tenant+entity_type-cloud-account",
		query: `MATCH (e:Entity {tenant_id: $tenant_id, entity_type: 'cloud.account'}) RETURN e.urn AS urn LIMIT 1`,
	},
	{
		name:  "tenant+internet_exposed",
		query: `MATCH (e:Entity {tenant_id: $tenant_id}) WHERE e.internet_exposed = true RETURN e.urn AS urn LIMIT 1`,
	},
	{
		name:  "tenant+is_privileged_identity",
		query: `MATCH (e:Entity {tenant_id: $tenant_id}) WHERE e.is_privileged_identity = true RETURN e.urn AS urn LIMIT 1`,
	},
	{
		name:  "tenant+mfa_disabled",
		query: `MATCH (e:Entity {tenant_id: $tenant_id}) WHERE e.mfa_disabled = true RETURN e.urn AS urn LIMIT 1`,
	},
}

// TestGraphRuleEntityIndexesAreSeekable proves that the Entity indexes the hot graph rules
// depend on are used as index seeks for the rules' tenant-scoped predicate shapes, rather
// than degrading to a full NodeByLabelScan/AllNodesScan on a large tenant. It seeds a
// multi-tenant fixture (so tenant_id is selective and a full Entity/relationship scan is
// visibly costlier than a seek) and skips unless CEREBRO_NEO4J_* is set, matching the other
// Neo4j-gated live tests.
func TestGraphRuleEntityIndexesAreSeekable(t *testing.T) {
	ctx := context.Background()
	store := openNeo4jLiveGraphStore(t, ctx)
	seedGraphRuleExplainFixture(t, ctx, store)

	for _, probe := range graphRuleEntityIndexProbes {
		t.Run(probe.name, func(t *testing.T) {
			plan, err := store.ExplainReadCypher(ctx, ports.CypherQueryRequest{
				Query:  probe.query,
				Params: map[string]any{"tenant_id": explainSmokeTenant},
			})
			if err != nil {
				t.Fatalf("ExplainReadCypher(%q) error = %v", probe.name, err)
			}
			if plan == nil || plan.Root == nil {
				t.Fatalf("ExplainReadCypher(%q) returned no plan", probe.name)
			}
			tree := renderCypherPlanTree(*plan.Root, 0)
			if !planHasOperatorPrefix(*plan.Root, "NodeIndexSeek") {
				t.Fatalf("probe %q has no NodeIndexSeek; its Entity index is unused:\n%s", probe.name, tree)
			}
			for _, scan := range []string{"AllNodesScan", "NodeByLabelScan"} {
				if planHasOperator(*plan.Root, scan) {
					t.Fatalf("probe %q plan contains %s; the predicate degraded to a full scan:\n%s", probe.name, scan, tree)
				}
			}
		})
	}
}

// planHasOperatorPrefix reports whether any operator in the plan tree starts with prefix
// (case-insensitive). Seek operators vary by Neo4j version (NodeIndexSeek,
// NodeIndexSeekByRange, NodeUniqueIndexSeek), so we match by prefix for stability.
func planHasOperatorPrefix(node ports.CypherPlanNode, prefix string) bool {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(node.Operator)), strings.ToLower(prefix)) {
		return true
	}
	for _, child := range node.Children {
		if planHasOperatorPrefix(child, prefix) {
			return true
		}
	}
	return false
}

func planHasOperator(node ports.CypherPlanNode, name string) bool {
	if strings.EqualFold(strings.TrimSpace(node.Operator), name) {
		return true
	}
	for _, child := range node.Children {
		if planHasOperator(child, name) {
			return true
		}
	}
	return false
}

func renderCypherPlanTree(node ports.CypherPlanNode, depth int) string {
	var builder strings.Builder
	builder.WriteString(strings.Repeat("  ", depth))
	builder.WriteString(strings.TrimSpace(node.Operator))
	if details, ok := node.Arguments["Details"]; ok {
		fmt.Fprintf(&builder, "  [%v]", details)
	}
	builder.WriteByte('\n')
	for _, child := range node.Children {
		builder.WriteString(renderCypherPlanTree(child, depth+1))
	}
	return builder.String()
}

// seedGraphRuleExplainFixture populates many synthetic tenants with noise Entity nodes
// and :RELATION edges, plus one target tenant carrying the entity types and typed
// properties the hot rules anchor on. EXPLAIN does not execute the query, but the planner
// relies on index/label statistics, so the fixture must make a full Entity label scan
// visibly costlier than a selective (tenant_id, ...) index seek: tenant_id is selective
// because the target tenant is a small fraction of all tenants, and the indexed entity
// types and typed properties are rare within it. The realistic topology also provides the
// nodes whose derived typed properties (internet_exposed, is_privileged_identity,
// mfa_disabled) the probes seek on.
func seedGraphRuleExplainFixture(t *testing.T, ctx context.Context, store *graphstoreneo4j.Store) {
	t.Helper()
	entityIn := func(tenantID, entityType, urn string, attributes map[string]string) {
		if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
			URN:        urn,
			TenantID:   tenantID,
			SourceID:   "aws",
			EntityType: entityType,
			Label:      urn,
			Attributes: attributes,
		}); err != nil {
			t.Fatalf("UpsertProjectedEntity(%q) error = %v", urn, err)
		}
	}
	linkIn := func(tenantID, from, relation, to string, attributes map[string]string) {
		if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID:   tenantID,
			SourceID:   "aws",
			FromURN:    from,
			Relation:   relation,
			ToURN:      to,
			Attributes: attributes,
		}); err != nil {
			t.Fatalf("UpsertProjectedLink(%s-[%s]->%s) error = %v", from, relation, to, err)
		}
	}
	entity := func(entityType, urn string, attributes map[string]string) {
		entityIn(explainSmokeTenant, entityType, urn, attributes)
	}
	link := func(from, relation, to string, attributes map[string]string) {
		linkIn(explainSmokeTenant, from, relation, to, attributes)
	}

	// Spread noise entities across many tenants so tenant_id is a selective predicate, and
	// chain them with many :RELATION edges so a full relationship token scan is expensive.
	const (
		noiseTenants           = 25
		noiseEntitiesPerTenant = 24
	)
	noiseRelations := []string{"can_reach", "belongs_to", "can_perform", "can_admin", "can_access"}
	for tenantIdx := 0; tenantIdx < noiseTenants; tenantIdx++ {
		tenantID := fmt.Sprintf("noise-tenant-%02d", tenantIdx)
		urns := make([]string, noiseEntitiesPerTenant)
		for entityIdx := 0; entityIdx < noiseEntitiesPerTenant; entityIdx++ {
			urn := fmt.Sprintf("urn:cerebro:%s:noise:%d", tenantID, entityIdx)
			urns[entityIdx] = urn
			entityIn(tenantID, "iam.principal.noise", urn, nil)
		}
		// Two interleaved chains roughly double the edge count per tenant.
		for entityIdx := 0; entityIdx+1 < len(urns); entityIdx++ {
			linkIn(tenantID, urns[entityIdx], noiseRelations[entityIdx%len(noiseRelations)], urns[entityIdx+1], nil)
		}
		for entityIdx := 0; entityIdx+2 < len(urns); entityIdx++ {
			linkIn(tenantID, urns[entityIdx], noiseRelations[(entityIdx+1)%len(noiseRelations)], urns[entityIdx+2], nil)
		}
	}

	// Cloud public-exposure / privileged-principal / exposed-compute topology.
	account := "urn:cerebro:explain-smoke:cloud_account:acct"
	publicPrincipal := "urn:cerebro:explain-smoke:aws_public_principal:internet"
	exposed := "urn:cerebro:explain-smoke:aws_network_interface:eni"
	principal := "urn:cerebro:explain-smoke:aws_user:admin"
	role := "urn:cerebro:explain-smoke:aws_role:admin-role"
	compute := "urn:cerebro:explain-smoke:aws_compute_instance:vm"
	permission := "urn:cerebro:explain-smoke:aws_iam_policy:administrator"
	entity("cloud.account", account, nil)
	entity("aws.public_principal", publicPrincipal, nil)
	entity("aws.network.interface", exposed, map[string]string{"internet_exposed": "true"})
	entity("aws.user", principal, map[string]string{"is_admin": "true"})
	entity("aws.role", role, map[string]string{"is_admin": "true"})
	entity("aws.compute.instance", compute, map[string]string{"internet_exposed": "true"})
	entity("aws.aws.iam.policy", permission, nil)
	link(publicPrincipal, "can_reach", exposed, map[string]string{"at": "2099-01-01T00:00:00Z"})
	link(exposed, "belongs_to", account, nil)
	link(compute, "belongs_to", account, nil)
	link(principal, "can_perform", permission, map[string]string{"is_admin": "true"})
	link(role, "can_admin", permission, nil)
	link(permission, "belongs_to", account, nil)

	// Identity privileged-no-MFA-with-sensitive-access topology.
	identity := "urn:cerebro:explain-smoke:okta_user:admin"
	sensitive := "urn:cerebro:explain-smoke:aws_s3_bucket:secrets"
	classification := "urn:cerebro:explain-smoke:data_classification:restricted"
	tag := "urn:cerebro:explain-smoke:asset_tag:crown-jewels"
	entity("okta.user", identity, map[string]string{"is_admin": "true", "mfa_enrolled": "false"})
	entity("aws.s3.bucket", sensitive, map[string]string{"internet_exposed": "true"})
	entity("data.classification", classification, nil)
	entity("asset.tag", tag, nil)
	link(identity, "can_access", sensitive, nil)
	link(sensitive, "classified_as", classification, nil)
	link(sensitive, "tagged_as", tag, nil)
}
