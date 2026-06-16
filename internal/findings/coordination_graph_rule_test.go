package findings

import (
	"context"
	"fmt"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestCoordinationGraphRuleSupportsRuntime(t *testing.T) {
	rule := newGRCSourceConcentratedOpenFindingsRule()
	if !rule.SupportsRuntime(&cerebrov1.SourceRuntime{TenantId: "writer", SourceId: "grc", Config: map[string]string{"family": "integration"}}) {
		t.Fatal("SupportsRuntime(grc integration) = false, want true")
	}
	if rule.SupportsRuntime(&cerebrov1.SourceRuntime{TenantId: "writer", SourceId: "grc", Config: map[string]string{"family": "document"}}) {
		t.Fatal("SupportsRuntime(grc document) = true, want false")
	}
}

func TestCoordinationGraphRuleQueryRequiresTenant(t *testing.T) {
	rule := newResourceMultipleOpenFindingsRule().(GraphRule)
	if got := rule.QueryFor(&cerebrov1.SourceRuntime{}); got.Query != "" {
		t.Fatalf("QueryFor(runtime without tenant) = %q, want empty", got.Query)
	}
	query := rule.QueryFor(&cerebrov1.SourceRuntime{TenantId: "writer"})
	if query.Query == "" {
		t.Fatal("QueryFor(runtime with tenant) returned empty query")
	}
	if query.Params["tenant_id"] != "writer" {
		t.Fatalf("tenant_id param = %#v, want writer", query.Params["tenant_id"])
	}
	if !strings.Contains(query.Query, "LIMIT $row_limit") {
		t.Fatalf("query missing LIMIT $row_limit: %s", query.Query)
	}
	if !strings.Contains(query.Query, "findings[0..20] | {urn: f.urn") {
		t.Fatalf("query does not cap related finding evidence: %s", query.Query)
	}
	if strings.Contains(query.Query, "+ [f IN findings") {
		t.Fatalf("query projects related finding anchors as ResourceURNs: %s", query.Query)
	}
	if !strings.Contains(query.Query, "ORDER BY finding.urn") {
		t.Fatalf("query does not deterministically order findings before capping: %s", query.Query)
	}
}

func TestCoordinationGraphRuleQueryOrdersFindingsBeforeSlice(t *testing.T) {
	for _, ruleID := range []string{
		"grc-source-integration-concentrated-open-findings",
		"graph-resource-multiple-open-findings",
	} {
		registry := Builtin()
		rule, ok := registry.Get(ruleID)
		if !ok {
			t.Fatalf("Builtin() missing rule %s", ruleID)
		}
		graphRule, ok := rule.(GraphRule)
		if !ok {
			t.Fatalf("rule %s is not a GraphRule", ruleID)
		}
		query := graphRule.QueryFor(&cerebrov1.SourceRuntime{TenantId: "writer"}).Query
		collectIdx := strings.Index(query, "collect(DISTINCT finding)")
		orderIdx := strings.Index(query, "ORDER BY finding.urn")
		if collectIdx < 0 || orderIdx < 0 || orderIdx > collectIdx {
			t.Fatalf("rule %s must ORDER BY finding.urn before collecting findings: %s", ruleID, query)
		}
	}
}

func TestReviewCoordinationGraphRulesHaveDirectCoverage(t *testing.T) {
	tests := []struct {
		name         string
		rule         Rule
		sourceID     string
		family       string
		querySnippet string
	}{
		{name: "github org owner", rule: newGitHubOrgOwnerConcentrationRule(), sourceID: "github", family: "org_inventory", querySnippet: `"role":"admin"`},
		{name: "github programmatic credential", rule: newGitHubProgrammaticCredentialReviewRule(), sourceID: "github", family: "audit", querySnippet: `"resource_type":"personal_access_token"`},
		{name: "okta oauth public client", rule: newOktaOAuthPublicClientReviewRule(), sourceID: "okta", family: "application", querySnippet: `"oauth_public_client":"true"`},
		{name: "okta weak authenticator", rule: newOktaAuthenticatorWeakFactorRule(), sourceID: "okta", family: "authenticator", querySnippet: `"key":"sms"`},
		{name: "okta threat insight", rule: newOktaThreatInsightNotBlockingRule(), sourceID: "okta", family: "threat_insight", querySnippet: `"action":"block"`},
		{name: "sentinelone stale agent", rule: newSentinelOneAgentNotUpToDateRule(), sourceID: "sentinelone", family: "agent", querySnippet: `"is_up_to_date":"false"`},
		{name: "sentinelone unmitigated threat", rule: newSentinelOneUnmitigatedThreatRule(), sourceID: "sentinelone", family: "threat", querySnippet: `"mitigation_status":"not_mitigated"`},
		{name: "cloud current public exposure", rule: newCloudPublicResourceExposureGraphRule(), sourceID: "aws", family: "resource_exposure", querySnippet: `"internet_exposed":"true"`},
		{name: "graph aws eni link missing", rule: newGraphAWSEC2ENILinkMissingRule(), sourceID: "graph", querySnippet: "attached_instance_id"},
		{name: "graph orphan node", rule: newGraphOrphanNonFindingNodeRule(), sourceID: "graph", querySnippet: "entity.entity_type <> 'finding'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graphRule, ok := tt.rule.(GraphRule)
			if !ok {
				t.Fatalf("rule %T is not a GraphRule", tt.rule)
			}
			runtime := &cerebrov1.SourceRuntime{Id: "runtime-1", TenantId: "writer", SourceId: tt.sourceID, Config: map[string]string{"family": tt.family}}
			if !tt.rule.SupportsRuntime(runtime) {
				t.Fatalf("SupportsRuntime(%s/%s) = false, want true", tt.sourceID, tt.family)
			}
			query := graphRule.QueryFor(runtime)
			if query.Query == "" {
				t.Fatal("QueryFor() returned empty query")
			}
			if query.Params["tenant_id"] != "writer" {
				t.Fatalf("tenant_id param = %#v, want writer", query.Params["tenant_id"])
			}
			if query.Params["row_limit"] != int64(coordinationGraphRowLimit) || query.RowLimit != coordinationGraphRowLimit {
				t.Fatalf("row limit = params:%#v request:%d, want %d", query.Params["row_limit"], query.RowLimit, coordinationGraphRowLimit)
			}
			if !strings.Contains(query.Query, "LIMIT $row_limit") {
				t.Fatalf("query missing LIMIT $row_limit: %s", query.Query)
			}
			if !strings.Contains(query.Query, tt.querySnippet) {
				t.Fatalf("query missing critical predicate %q: %s", tt.querySnippet, query.Query)
			}
			findings, err := graphRule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{{Values: map[string]any{
				"primary_urn":     "urn:cerebro:writer:resource:one",
				"primary_label":   "Resource One",
				"primary_type":    "resource",
				"fingerprint_key": "urn:cerebro:writer:resource:one",
				"summary":         "review finding",
				"resource_urns":   []any{"urn:cerebro:writer:resource:one"},
				"evidence":        []any{},
			}}})
			if err != nil {
				t.Fatalf("EvaluateRows() error = %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("len(findings) = %d, want 1", len(findings))
			}
			if findings[0].RuleID != tt.rule.Spec().GetId() {
				t.Fatalf("RuleID = %q, want %q", findings[0].RuleID, tt.rule.Spec().GetId())
			}
			if findings[0].TenantID != "writer" || findings[0].RuntimeID != "runtime-1" {
				t.Fatalf("finding scope = tenant %q runtime %q", findings[0].TenantID, findings[0].RuntimeID)
			}
		})
	}
}

func TestCoordinationGraphRuleEvaluateRowsBuildsFinding(t *testing.T) {
	rule := newGRCSourceConcentratedOpenFindingsRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc-integration", TenantId: "writer", SourceId: "grc", Config: map[string]string{"family": "integration"}}

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{{Values: map[string]any{
		"primary_urn":     "urn:cerebro:writer:source:vanta:integration:aws",
		"primary_label":   "AWS",
		"primary_type":    "source",
		"fingerprint_key": "urn:cerebro:writer:source:vanta:integration:aws",
		"severity":        "HIGH",
		"summary":         "Source integration has 5 open finding(s)",
		"action":          "Prioritize remediation at the source integration level",
		"resource_urns": []any{
			"urn:cerebro:writer:source:vanta:integration:aws",
			"urn:cerebro:writer:finding:one",
		},
		"evidence": []any{map[string]any{
			"urn":             "urn:cerebro:writer:finding:one",
			"label":           "Finding One",
			"entity_type":     "finding",
			"relation":        "has_finding",
			"attributes_json": `{"status":"open","rule_id":"example"}`,
		}},
	}}})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.RuleID != "grc-source-integration-concentrated-open-findings" || finding.Severity != "HIGH" || finding.Status != findingStatusOpen {
		t.Fatalf("finding metadata = %#v", finding)
	}
	if finding.Attributes["primary_resource_urn"] != "urn:cerebro:writer:source:vanta:integration:aws" {
		t.Fatalf("primary_resource_urn = %q", finding.Attributes["primary_resource_urn"])
	}
	if len(finding.ResourceURNs) != 1 || finding.ResourceURNs[0] != "urn:cerebro:writer:source:vanta:integration:aws" {
		t.Fatalf("ResourceURNs = %#v, want only the primary remediation anchor", finding.ResourceURNs)
	}
	if len(finding.GraphEvidenceRows) != 1 {
		t.Fatalf("len(GraphEvidenceRows) = %d, want 1", len(finding.GraphEvidenceRows))
	}
}

func TestCoordinationGraphRuleEvaluateRowsCapsResourceURNs(t *testing.T) {
	rule := newResourceMultipleOpenFindingsRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cosmo-survey-feedback", TenantId: "writer", SourceId: "cosmo", Config: map[string]string{"family": "survey_feedback"}}
	resourceURNs := []any{"urn:cerebro:writer:resource:one"}
	for i := 1; i <= coordinationGraphRelatedResourceLimit+5; i++ {
		resourceURNs = append(resourceURNs, fmt.Sprintf("urn:cerebro:writer:resource:related:%02d", i))
	}

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{{Values: map[string]any{
		"primary_urn":     "urn:cerebro:writer:resource:one",
		"primary_label":   "Resource One",
		"primary_type":    "resource",
		"fingerprint_key": "urn:cerebro:writer:resource:one",
		"severity":        "HIGH",
		"summary":         "Resource has many open finding(s)",
		"action":          "Coordinate remediation by the shared graph resource",
		"resource_urns":   resourceURNs,
		"evidence":        []any{},
	}}})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if got, want := len(findings[0].ResourceURNs), coordinationGraphRelatedResourceLimit+1; got != want {
		t.Fatalf("len(ResourceURNs) = %d, want %d: %#v", got, want, findings[0].ResourceURNs)
	}
}

func TestCoordinationGraphRuleEvaluateRowsDropsEvidenceFindingURNResources(t *testing.T) {
	rule := newResourceMultipleOpenFindingsRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cosmo-message", TenantId: "writer", SourceId: "cosmo", Config: map[string]string{"family": "message"}}

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{{Values: map[string]any{
		"primary_urn":     "urn:cerebro:writer:resource:one",
		"primary_label":   "Resource One",
		"primary_type":    "resource",
		"fingerprint_key": "urn:cerebro:writer:resource:one",
		"severity":        "HIGH",
		"summary":         "Resource has many open finding(s)",
		"action":          "Coordinate remediation by the shared graph resource",
		"resource_urns": []any{
			"urn:cerebro:writer:resource:one",
			"urn:cerebro:writer:finding:existing",
		},
		"evidence": []any{map[string]any{
			"urn":             "urn:cerebro:writer:finding:existing",
			"label":           "Existing finding",
			"entity_type":     "finding",
			"relation":        "has_finding",
			"attributes_json": `{"status":"open","rule_id":"example"}`,
		}},
	}}})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if got := findings[0].ResourceURNs; len(got) != 1 || got[0] != "urn:cerebro:writer:resource:one" {
		t.Fatalf("ResourceURNs = %#v, want only the primary remediation anchor", got)
	}
	if len(findings[0].GraphEvidenceRows) != 1 {
		t.Fatalf("len(GraphEvidenceRows) = %d, want evidence finding retained", len(findings[0].GraphEvidenceRows))
	}
}

func TestCoordinationGraphRuleMergeDropsHistoricalResourceOverflow(t *testing.T) {
	primaryURN := "urn:cerebro:writer:resource:one"
	existingURNs := []string{primaryURN}
	for i := 1; i <= coordinationGraphRelatedResourceLimit+10; i++ {
		existingURNs = append(existingURNs, fmt.Sprintf("urn:cerebro:writer:resource:old:%02d", i))
	}
	incomingURNs := []string{primaryURN}
	for i := 1; i <= coordinationGraphRelatedResourceLimit; i++ {
		incomingURNs = append(incomingURNs, fmt.Sprintf("urn:cerebro:writer:resource:fresh:%02d", i))
	}

	merged := mergeFindingEvidenceForUpsert(&ports.FindingRecord{
		RuleID:       "graph-resource-multiple-open-findings",
		ResourceURNs: existingURNs,
		EventIDs:     []string{"event-old"},
	}, &ports.FindingRecord{
		RuleID:       "graph-resource-multiple-open-findings",
		ResourceURNs: incomingURNs,
		EventIDs:     []string{"event-new"},
		Attributes: map[string]string{
			"primary_resource_urn": primaryURN,
		},
	})
	if got, want := len(merged.ResourceURNs), coordinationGraphRelatedResourceLimit+1; got != want {
		t.Fatalf("len(ResourceURNs) = %d, want %d: %#v", got, want, merged.ResourceURNs)
	}
	if containsString(merged.ResourceURNs, "urn:cerebro:writer:resource:old:01") {
		t.Fatalf("merged ResourceURNs carried historical overflow: %#v", merged.ResourceURNs)
	}
	if !containsString(merged.ResourceURNs, "urn:cerebro:writer:resource:fresh:20") {
		t.Fatalf("merged ResourceURNs missing capped fresh resource: %#v", merged.ResourceURNs)
	}
	if !containsString(merged.EventIDs, "event-old") || !containsString(merged.EventIDs, "event-new") {
		t.Fatalf("EventIDs = %#v, want historical and fresh IDs preserved", merged.EventIDs)
	}
}

func TestCoordinationGraphRulesAreRegistered(t *testing.T) {
	registry := Builtin()
	for _, id := range []string{
		"grc-source-integration-concentrated-open-findings",
		"grc-failing-control-test-unhealthy-integration",
		"grc-control-missing-evidence-coverage",
		"grc-document-needs-owner-or-upload",
		"grc-isolated-target-enrichment-gap",
		"finding-isolated-open-anchor",
		"graph-resource-multiple-open-findings",
	} {
		if _, ok := registry.Get(id); !ok {
			t.Fatalf("Builtin() missing rule %s", id)
		}
	}
}
