package findings

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestGitHubSelfHostedRunnerReviewRuleRetired(t *testing.T) {
	rule := newGitHubSelfHostedRunnerReviewRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleRetired || definition.Lifecycle.Anchor != AnchorNone {
		t.Fatalf("Lifecycle = %+v, want retired/none", definition.Lifecycle)
	}
	if definition.Maturity != RuleMaturityRetired {
		t.Fatalf("Maturity = %q, want %q", definition.Maturity, RuleMaturityRetired)
	}
	if _, ok := rule.(GraphRule); ok {
		t.Fatal("retired self-hosted runner review rule still implements GraphRule")
	}
	retirementRule, ok := rule.(openFindingRetirementRule)
	if !ok || !retirementRule.RetiresOpenFindings() {
		t.Fatal("retired self-hosted runner review rule does not retire open findings")
	}

	runtime := &cerebrov1.SourceRuntime{Id: "runtime", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}}
	records, err := rule.Evaluate(context.Background(), runtime, nil)
	if err != nil {
		t.Fatalf("Evaluate(retired runner review rule) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(retired runner review rule) returned %d findings, want 0", len(records))
	}
}

func TestCurrentStateGraphRulesEmitStableFindings(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}}
	for _, tc := range []struct {
		name    string
		rule    Rule
		runtime *cerebrov1.SourceRuntime
		row     ports.CypherRow
	}{
		{
			name:    "cloud exposure",
			rule:    newCloudPublicResourceExposureGraphRule(),
			runtime: &cerebrov1.SourceRuntime{Id: "aws-public", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "public_endpoint"}},
			row: ports.CypherRow{Values: map[string]any{
				"primary_urn":     "urn:cerebro:writer:aws_elastic_ip:eipalloc-1",
				"primary_label":   "eipalloc-1",
				"primary_type":    "aws.elastic.ip",
				"fingerprint_key": "urn:cerebro:writer:aws_elastic_ip:eipalloc-1",
				"severity":        "MEDIUM",
				"summary":         "Cloud resource eipalloc-1 is publicly exposed",
				"action":          "review",
				"resource_urns":   []any{"urn:cerebro:writer:aws_elastic_ip:eipalloc-1"},
			}},
		},
		{
			name:    "cloud exposed privileged compute",
			rule:    newCloudExposedPrivilegedComputeRoleRule(),
			runtime: &cerebrov1.SourceRuntime{Id: "aws-ecs", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "ecs_service"}},
			row: ports.CypherRow{Values: map[string]any{
				"primary_urn":     "urn:cerebro:writer:aws_ecs_service:orders",
				"primary_label":   "orders",
				"primary_type":    "aws.ecs.service",
				"fingerprint_key": "urn:cerebro:writer:aws_ecs_service:orders|urn:cerebro:writer:aws_role:ECSTaskRole|urn:cerebro:writer:aws_iam_policy:AdministratorAccess",
				"severity":        "CRITICAL",
				"summary":         "Publicly reachable compute workload orders runs as privileged role ECSTaskRole",
				"action":          "Remove unnecessary public reachability and reduce the compute runtime role privileges",
				"resource_urns": []any{
					"urn:cerebro:writer:aws_ecs_service:orders",
					"urn:cerebro:writer:aws_ecs_task_definition:orders:7",
					"urn:cerebro:writer:aws_role:ECSTaskRole",
					"urn:cerebro:writer:aws_iam_policy:AdministratorAccess",
				},
				"evidence": []any{
					map[string]any{"urn": "urn:cerebro:writer:aws_ecs_task_definition:orders:7", "label": "orders:7", "entity_type": "aws.ecs.task_definition", "relation": "depends_on", "attributes_json": `{}`},
					map[string]any{"urn": "urn:cerebro:writer:aws_role:ECSTaskRole", "label": "ECSTaskRole", "entity_type": "aws.role", "relation": "runs_as", "attributes_json": `{}`},
				},
			}},
		},
		{
			name:    "github credential",
			rule:    newGitHubProgrammaticCredentialReviewRule(),
			runtime: runtime,
			row: ports.CypherRow{Values: map[string]any{
				"primary_urn":     "urn:cerebro:writer:github_credential:deploy_key@repo",
				"primary_label":   "deploy_key",
				"primary_type":    "github.credential",
				"fingerprint_key": "urn:cerebro:writer:github_credential:deploy_key@repo",
				"severity":        "MEDIUM",
				"summary":         "GitHub programmatic access resource deploy_key needs owner/scope review",
				"action":          "review",
				"resource_urns":   []any{"urn:cerebro:writer:github_credential:deploy_key@repo"},
			}},
		},
		{
			name:    "okta threat insight not blocking",
			rule:    newOktaThreatInsightNotBlockingRule(),
			runtime: &cerebrov1.SourceRuntime{Id: "okta-ti", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "threat_insight"}},
			row: ports.CypherRow{Values: map[string]any{
				"primary_urn":     "urn:cerebro:writer:okta_threat_insight:example.okta.com",
				"primary_label":   "ThreatInsight",
				"primary_type":    "okta.threat_insight",
				"fingerprint_key": "urn:cerebro:writer:okta_threat_insight:example.okta.com",
				"severity":        "HIGH",
				"summary":         "Okta ThreatInsight is not set to block",
				"action":          "Set ThreatInsight action to block",
				"resource_urns":   []any{"urn:cerebro:writer:okta_threat_insight:example.okta.com"},
			}},
		},
		{
			name:    "okta authenticator weak factor",
			rule:    newOktaAuthenticatorWeakFactorRule(),
			runtime: &cerebrov1.SourceRuntime{Id: "okta-auth", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "authenticator"}},
			row: ports.CypherRow{Values: map[string]any{
				"primary_urn":     "urn:cerebro:writer:okta_authenticator:sms123",
				"primary_label":   "SMS",
				"primary_type":    "okta.authenticator",
				"fingerprint_key": "urn:cerebro:writer:okta_authenticator:sms123",
				"severity":        "MEDIUM",
				"summary":         "Okta authenticator SMS uses a phishing-susceptible factor type",
				"action":          "Migrate to phishing-resistant factors",
				"resource_urns":   []any{"urn:cerebro:writer:okta_authenticator:sms123"},
			}},
		},
		{
			name:    "github org owner review",
			rule:    newGitHubOrgOwnerConcentrationRule(),
			runtime: &cerebrov1.SourceRuntime{Id: "gh-inv", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "org_inventory"}},
			row: ports.CypherRow{Values: map[string]any{
				"primary_urn":     "urn:cerebro:writer:github_user:admin-user",
				"primary_label":   "admin-user",
				"primary_type":    "github.user",
				"fingerprint_key": "urn:cerebro:writer:github_user:admin-user",
				"severity":        "MEDIUM",
				"summary":         "GitHub org owner admin-user has unrestricted administrative access",
				"action":          "Validate business need for owner role",
				"resource_urns":   []any{"urn:cerebro:writer:github_user:admin-user"},
			}},
		},
		{
			name:    "s1 agent out of date",
			rule:    newSentinelOneAgentNotUpToDateRule(),
			runtime: &cerebrov1.SourceRuntime{Id: "s1-agent", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "agent"}},
			row: ports.CypherRow{Values: map[string]any{
				"primary_urn":     "urn:cerebro:writer:sentinelone_agent:agent-1",
				"primary_label":   "agent-1",
				"primary_type":    "sentinelone.agent",
				"fingerprint_key": "urn:cerebro:writer:sentinelone_agent:agent-1",
				"severity":        "MEDIUM",
				"summary":         "SentinelOne agent agent-1 is not up to date",
				"action":          "review",
				"resource_urns":   []any{"urn:cerebro:writer:sentinelone_agent:agent-1"},
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graphRule, ok := tc.rule.(GraphRule)
			if !ok {
				t.Fatalf("%T does not implement GraphRule", tc.rule)
			}
			if !graphRule.SupportsRuntime(tc.runtime) {
				t.Fatalf("SupportsRuntime(%+v) = false, want true", tc.runtime)
			}
			if query := graphRule.QueryFor(tc.runtime); strings.TrimSpace(query.Query) == "" || query.RowLimit == 0 {
				t.Fatalf("QueryFor returned empty query: %+v", query)
			}
			findings, err := graphRule.EvaluateRows(context.Background(), tc.runtime, []ports.CypherRow{tc.row})
			if err != nil {
				t.Fatalf("EvaluateRows error = %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("EvaluateRows returned %d findings, want 1", len(findings))
			}
			if findings[0].Fingerprint == "" || findings[0].Status != findingStatusOpen {
				t.Fatalf("finding missing stable fingerprint/status: %+v", findings[0])
			}
		})
	}
}

func TestCurrentStateGraphRuleQueriesUseEnrichedCurrentState(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
		want []string
	}{
		{
			name: "cloud exposure uses recent reachability edge and current attributes",
			rule: newCloudPublicResourceExposureGraphRule(),
			want: []string{"relation: 'can_reach'", ".public_principal", `"internet_exposed":"true"`, `duration('P30D')`, "WITH DISTINCT resource"},
		},
		{
			name: "cloud exposed privileged compute links reachability to runtime role privilege",
			rule: newCloudExposedPrivilegedComputeRoleRule(),
			want: []string{`entity_type: 'aws.ecs.task_definition'`, `relation: 'runs_as'`, `relation: 'depends_on'`, `relation: 'can_reach'`, `relation: 'member_of'`, `relation: 'attached_to'`, `access.relation IN ['can_admin', 'can_assume', 'can_impersonate', 'can_perform']`, `duration('P30D')`},
		},
		{
			name: "github credentials exclude inactive resources",
			rule: newGitHubProgrammaticCredentialReviewRule(),
			want: []string{`entity_type: 'github.credential'`, `"status":"inactive"`},
		},
		{
			name: "okta threat insight checks for blocking mode",
			rule: newOktaThreatInsightNotBlockingRule(),
			want: []string{`entity_type: 'okta.threat_insight'`, `"action":"block"`},
		},
		{
			name: "okta authenticator checks for weak factor keys",
			rule: newOktaAuthenticatorWeakFactorRule(),
			want: []string{`entity_type: 'okta.authenticator'`, `"status":"ACTIVE"`, `"key":"phone_number"`, `"key":"sms"`},
		},
		{
			name: "github org owner checks for admin role",
			rule: newGitHubOrgOwnerConcentrationRule(),
			want: []string{`entity_type: 'github.user'`, `"role":"admin"`},
		},
		{
			name: "sentinelone stale agents require active non-pending inventory",
			rule: newSentinelOneAgentNotUpToDateRule(),
			want: []string{`"is_active":"true"`, `"is_pending_uninstall":"true"`},
		},
		{
			name: "sentinelone threats use normalized status fields",
			rule: newSentinelOneUnmitigatedThreatRule(),
			want: []string{`"mitigation_status_norm":"not_mitigated"`, `"incident_status_norm":"resolved"`, `"automatically_resolved":"true"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graphRule, ok := tt.rule.(GraphRule)
			if !ok {
				t.Fatalf("%T does not implement GraphRule", tt.rule)
			}
			query := graphRule.QueryFor(&cerebrov1.SourceRuntime{Id: "runtime", SourceId: "graph", TenantId: "writer"})
			for _, want := range tt.want {
				if !strings.Contains(query.Query, want) {
					t.Fatalf("query missing %q:\n%s", want, query.Query)
				}
			}
		})
	}
}
