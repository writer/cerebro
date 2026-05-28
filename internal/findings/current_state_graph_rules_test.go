package findings

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

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
			name: "cloud exposure uses reachability edge",
			rule: newCloudPublicResourceExposureGraphRule(),
			want: []string{"relation: 'can_reach'", ".public_principal", "WITH DISTINCT resource"},
		},
		{
			name: "github credentials exclude inactive resources",
			rule: newGitHubProgrammaticCredentialReviewRule(),
			want: []string{`resource.entity_type = 'github.credential'`, `"status":"inactive"`},
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
