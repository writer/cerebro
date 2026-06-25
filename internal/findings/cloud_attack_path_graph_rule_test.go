package findings

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestCloudPublicExposurePrivilegedPrincipalGraphRule(t *testing.T) {
	rule := newCloudPublicExposurePrivilegedPrincipalRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-aws-effective-permission", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "effective_permission"}}
	if !rule.SupportsRuntime(runtime) {
		t.Fatalf("SupportsRuntime(effective_permission) = false, want true")
	}
	query := rule.QueryFor(runtime)
	if query.RowLimit != cloudPublicExposurePrivilegedPrincipalRowLimit || query.Params["tenant_id"] != "writer" {
		t.Fatalf("QueryFor() = %#v", query)
	}

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{{Values: map[string]any{
		"public_urn":             "urn:cerebro:writer:aws_public_principal:public_internet",
		"public_entity_type":     "aws.public_principal",
		"public_label":           "public internet",
		"exposed_urn":            "urn:cerebro:writer:aws_network_interface:eni-1",
		"exposed_entity_type":    "aws.network.interface",
		"exposed_label":          "prod-web",
		"account_urn":            "urn:cerebro:writer:cloud_account:123456789012",
		"account_label":          "123456789012",
		"principal_urn":          "urn:cerebro:writer:aws_user:admin@writer.com",
		"principal_entity_type":  "aws.user",
		"principal_label":        "admin@writer.com",
		"permission_urn":         "urn:cerebro:writer:aws_aws_iam_policy:AdministratorAccess",
		"permission_entity_type": "aws.aws.iam.policy",
		"permission_label":       "AdministratorAccess",
		"reach_relation":         "can_reach",
		"access_relation":        "can_perform",
		"access_attributes_json": `{"privilege_level":"admin"}`,
	}}})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.RuleID != cloudPublicExposurePrivilegedPrincipalRuleID || finding.Severity != "CRITICAL" {
		t.Fatalf("finding = %#v", finding)
	}
	if len(finding.GraphEvidenceRows) != 1 {
		t.Fatalf("len(GraphEvidenceRows) = %d, want 1", len(finding.GraphEvidenceRows))
	}
	if got := finding.Attributes["cloud_account_urn"]; got != "urn:cerebro:writer:cloud_account:123456789012" {
		t.Fatalf("cloud_account_urn = %q", got)
	}

	adminFindings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{{Values: map[string]any{
		"public_urn":             "urn:cerebro:writer:aws_public_principal:public_internet",
		"public_entity_type":     "aws.public_principal",
		"public_label":           "public internet",
		"exposed_urn":            "urn:cerebro:writer:aws_cloudfront_distribution:dist-1",
		"exposed_entity_type":    "aws.cloudfront.distribution",
		"exposed_label":          "cdn.writer.dev",
		"account_urn":            "urn:cerebro:writer:cloud_account:123456789012",
		"account_label":          "123456789012",
		"principal_urn":          "urn:cerebro:writer:aws_role:AdminRole",
		"principal_entity_type":  "aws.role",
		"principal_label":        "AdminRole",
		"permission_urn":         "urn:cerebro:writer:aws_admin_role:AdministratorAccess",
		"permission_entity_type": "aws.admin_role",
		"permission_label":       "AdministratorAccess",
		"reach_relation":         "can_reach",
		"access_relation":        "can_admin",
		"access_attributes_json": `{}`,
	}}})
	if err != nil {
		t.Fatalf("EvaluateRows(can_admin) error = %v", err)
	}
	if len(adminFindings) != 1 {
		t.Fatalf("len(adminFindings) = %d, want 1", len(adminFindings))
	}
	if got := adminFindings[0].Attributes["access_relation"]; got != "can_admin" {
		t.Fatalf("can_admin finding access_relation = %q", got)
	}
}

func TestCloudPublicExposurePrivilegedPrincipalGraphRuleSupportsJoinProducerRuntimes(t *testing.T) {
	rule := newCloudPublicExposurePrivilegedPrincipalRule().(GraphRule)
	for _, family := range []string{
		"effective_permission",
		"iam_role_assignment",
		"iam_role_trust",
		"public_endpoint",
		"resource_exposure",
		"env:CEREBRO_AWS_FAMILY",
	} {
		runtime := &cerebrov1.SourceRuntime{SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": family}}
		if !rule.SupportsRuntime(runtime) {
			t.Fatalf("SupportsRuntime(aws/%s) = false, want true", family)
		}
	}
	for sourceID, families := range map[string][]string{
		"azure": {"asset_metadata", "effective_permission", "iam_role_assignment", "resource_exposure", "virtual_machine"},
		"gcp":   {"asset_metadata", "cloud_run_service", "compute_instance", "effective_permission", "iam_role_assignment", "resource_exposure"},
	} {
		for _, family := range families {
			runtime := &cerebrov1.SourceRuntime{SourceId: sourceID, TenantId: "writer", Config: map[string]string{"family": family}}
			if !rule.SupportsRuntime(runtime) {
				t.Fatalf("SupportsRuntime(%s/%s) = false, want true", sourceID, family)
			}
		}
	}
	for _, runtime := range []*cerebrov1.SourceRuntime{
		{SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "cloudtrail"}},
		{SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "iam_user"}},
		{SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "user"}},
	} {
		if rule.SupportsRuntime(runtime) {
			t.Fatalf("SupportsRuntime(%s/%s) = true, want false", runtime.GetSourceId(), runtime.GetConfig()["family"])
		}
	}
}

func TestCloudPublicExposurePrivilegedPrincipalSignalsPerAccountCapTruncation(t *testing.T) {
	// The per-account cap must compare the full collected sizes against the cap and
	// surface graph_rule_truncated so the service skips stale-finding resolution when
	// it drops data; slicing before measuring would hide the capping and silently
	// auto-resolve still-active findings.
	rule := newCloudPublicExposurePrivilegedPrincipalRule().(GraphRule)
	query := rule.QueryFor(&cerebrov1.SourceRuntime{Id: "writer-aws-effective-permission", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "effective_permission"}})
	for _, fragment := range []string{
		"size(all_exposures) > $exposure_cap AS exposures_capped",
		"(exposures_capped OR size(all_grants) > $principal_cap) AS account_capped",
		"account_capped AS graph_rule_truncated",
	} {
		if !strings.Contains(query.Query, fragment) {
			t.Fatalf("QueryFor() missing per-account cap truncation fragment %q:\n%s", fragment, query.Query)
		}
	}
}

func TestCloudPublicExposurePrivilegedPrincipalScopedStaleResolution(t *testing.T) {
	// The rule groups stale resolution by cloud account so the per-account cap only
	// pins the accounts it actually truncated. The scope attribute must match the
	// finding attribute buildFinding writes ("cloud_account_urn"), and only capped
	// rows that carry an account become incomplete scopes.
	resolver := newCloudPublicExposurePrivilegedPrincipalRule().(ScopedStaleResolver)
	if got := resolver.StaleResolutionScopeAttribute(); got != "cloud_account_urn" {
		t.Fatalf("StaleResolutionScopeAttribute() = %q, want cloud_account_urn", got)
	}
	incomplete := resolver.IncompleteStaleResolutionScopes([]ports.CypherRow{
		{Values: map[string]any{"account_urn": "acct-capped", graphRuleTruncationColumn: true}},
		{Values: map[string]any{"account_urn": "acct-capped", graphRuleTruncationColumn: true}},
		{Values: map[string]any{"account_urn": "acct-string-capped", graphRuleTruncationColumn: "true"}},
		{Values: map[string]any{"account_urn": "acct-complete", graphRuleTruncationColumn: false}},
		{Values: map[string]any{graphRuleTruncationColumn: true}}, // capped row without an account: ignored
	})
	want := map[string]struct{}{"acct-capped": {}, "acct-string-capped": {}}
	if len(incomplete) != len(want) {
		t.Fatalf("IncompleteStaleResolutionScopes() = %v, want %v", incomplete, want)
	}
	for account := range want {
		if _, ok := incomplete[account]; !ok {
			t.Fatalf("IncompleteStaleResolutionScopes() missing capped account %q: %v", account, incomplete)
		}
	}
	if _, ok := incomplete["acct-complete"]; ok {
		t.Fatalf("IncompleteStaleResolutionScopes() included fully-represented account acct-complete: %v", incomplete)
	}
}

func TestCloudCurrentPublicExposureGraphRuleRequiresStampedRecentReachability(t *testing.T) {
	rule := newCloudPublicResourceExposureGraphRule().(GraphRule)
	query := rule.QueryFor(&cerebrov1.SourceRuntime{Id: "writer-aws-resource-exposure", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "resource_exposure"}})
	for _, fragment := range []string{
		`coalesce(reach.attributes_json, '') CONTAINS '"at":"'`,
		`datetime(split(split(coalesce(reach.attributes_json, ''), '"at":"')[1], '"')[0]) >= datetime() - duration('P30D')`,
	} {
		if !strings.Contains(query.Query, fragment) {
			t.Fatalf("QueryFor() missing reachability recency fragment %q:\n%s", fragment, query.Query)
		}
	}
	if strings.Contains(query.Query, `NOT coalesce(reach.attributes_json, '') CONTAINS '"at":"'`) {
		t.Fatalf("QueryFor() allows legacy unstamped reachability edges:\n%s", query.Query)
	}
}
