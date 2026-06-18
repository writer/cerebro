package findings

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestDeprovisionedOktaActiveCloudAccessRuleQueryScopesByTenant(t *testing.T) {
	rule := newDeprovisionedOktaActiveCloudAccessRule().(*deprovisionedOktaActiveCloudAccessRule)
	request := rule.QueryFor(&cerebrov1.SourceRuntime{Id: "writer-okta-user", SourceId: "okta", TenantId: "writer"})
	if request.Query == "" {
		t.Fatal("QueryFor() returned empty query for fully-populated runtime")
	}
	if got := request.Params["tenant_id"]; got != "writer" {
		t.Fatalf("Params[tenant_id] = %v, want writer", got)
	}
	if request.RowLimit != identityDeprovisionedOktaActiveCloudQueryLimit {
		t.Fatalf("RowLimit = %d, want %d", request.RowLimit, identityDeprovisionedOktaActiveCloudQueryLimit)
	}
	if !strings.Contains(request.Query, "principal.entity_type IN $principal_types") {
		t.Fatalf("Query does not scope joined principals to cloud/SaaS types:\n%s", request.Query)
	}
}

func TestDeprovisionedOktaActiveCloudAccessRuleSupportsRelevantRuntimes(t *testing.T) {
	rule := newDeprovisionedOktaActiveCloudAccessRule().(*deprovisionedOktaActiveCloudAccessRule)
	withFamily := func(sourceID, family string) *cerebrov1.SourceRuntime {
		return &cerebrov1.SourceRuntime{SourceId: sourceID, Config: map[string]string{"family": family}}
	}
	cases := map[string]struct {
		runtime *cerebrov1.SourceRuntime
		want    bool
	}{
		"okta user":                          {withFamily("okta", "user"), true},
		"aws cloudtrail":                     {withFamily("aws", "cloudtrail"), true},
		"aws effective permission":           {withFamily("aws", "effective_permission"), true},
		"google workspace role assignment":   {withFamily("google_workspace", "role_assignment"), true},
		"gcp iam role assignment":            {withFamily("gcp", "iam_role_assignment"), true},
		"azure directory role assignment":    {withFamily("azure", "directory_role_assignment"), true},
		"okta audit":                         {withFamily("okta", "audit"), false},
		"github audit covered by other rule": {withFamily("github", "audit"), false},
		"unrelated":                          {withFamily("sentinelone", "agent"), false},
		"nil runtime":                        {nil, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := rule.SupportsRuntime(tc.runtime); got != tc.want {
				t.Fatalf("SupportsRuntime() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDeprovisionedOktaActiveCloudAccessRuleEvaluateRowsBuildsFinding(t *testing.T) {
	rule := newDeprovisionedOktaActiveCloudAccessRule().(*deprovisionedOktaActiveCloudAccessRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-aws-cloudtrail", SourceId: "aws", TenantId: "writer"}
	now := time.Now().UTC()
	row := deprovisionedOktaActiveCloudRow(now)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if got := len(findings); got != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1", got)
	}
	finding := findings[0]
	if finding.RuleID != identityDeprovisionedOktaActiveCloudAccessRuleID {
		t.Fatalf("RuleID = %q, want %q", finding.RuleID, identityDeprovisionedOktaActiveCloudAccessRuleID)
	}
	if finding.Severity != "CRITICAL" {
		t.Fatalf("Severity = %q, want CRITICAL", finding.Severity)
	}
	if got := finding.Attributes["okta_status"]; got != "DEPROVISIONED" {
		t.Fatalf("okta_status = %q, want DEPROVISIONED", got)
	}
	if got := finding.Attributes["access_relations"]; got != grcOverlayAccessEdgeRelationCanAdmin {
		t.Fatalf("access_relations = %q, want %q", got, grcOverlayAccessEdgeRelationCanAdmin)
	}
	if got := finding.Attributes["graph_actions_allowed"]; got != "identity.okta.suspend_user" {
		t.Fatalf("graph_actions_allowed = %q, want only suspend action for deprovisioned identity finding", got)
	}
}

func TestDeprovisionedOktaActiveCloudAccessRuleRequiresFreshEmailBridgeAndAccess(t *testing.T) {
	rule := newDeprovisionedOktaActiveCloudAccessRule().(*deprovisionedOktaActiveCloudAccessRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-aws-cloudtrail", SourceId: "aws", TenantId: "writer"}
	now := time.Now().UTC()

	staleIdentity := deprovisionedOktaActiveCloudRow(now)
	staleIdentity.Values["principal_identity_attributes_json"] = deprovisionedOktaRuleEmailIdentityAttrs(now.Add(-90 * 24 * time.Hour))

	loginOnlyIdentity := deprovisionedOktaActiveCloudRow(now)
	loginOnlyIdentity.Values["principal_identity_attributes_json"] = deprovisionedOktaRuleLoginIdentityAttrs(now)

	noActionableAccess := deprovisionedOktaActiveCloudRow(now)
	noActionableAccess.Values["access_edges"] = []any{map[string]any{
		"relation":        grcOverlayAccessEdgeRelationActedOn,
		"resource_urn":    "urn:cerebro:writer:aws_bucket:prod",
		"resource_type":   "aws.s3.bucket",
		"resource_label":  "prod",
		"attributes_json": deprovisionedOktaActiveCloudJSON(map[string]string{"at": now.Add(-90 * 24 * time.Hour).Format(time.RFC3339)}),
	}}

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{staleIdentity, loginOnlyIdentity, noActionableAccess})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0: %#v", len(findings), findings)
	}
}

func deprovisionedOktaActiveCloudRow(now time.Time) ports.CypherRow {
	return ports.CypherRow{Values: map[string]any{
		"okta_user_urn":                      "urn:cerebro:writer:okta.user:alice",
		"okta_user_label":                    "alice@writer.com",
		"okta_attributes_json":               `{"status":"DEPROVISIONED"}`,
		"identity_urn":                       "urn:cerebro:writer:identity:email:alice@writer.com",
		"identity_label":                     "alice@writer.com",
		"principal_urn":                      "urn:cerebro:writer:aws.user:alice",
		"principal_label":                    "alice",
		"principal_entity_type":              grcOverlayEntityTypeAWSUser,
		"principal_attributes_json":          `{"email":"alice@writer.com"}`,
		"okta_identity_attributes_json":      deprovisionedOktaRuleEmailIdentityAttrs(now),
		"principal_identity_attributes_json": deprovisionedOktaRuleEmailIdentityAttrs(now),
		"access_edges": []any{map[string]any{
			"relation":        grcOverlayAccessEdgeRelationCanAdmin,
			"resource_urn":    "urn:cerebro:writer:aws_admin_role:admin",
			"resource_type":   "aws.admin_role",
			"resource_label":  "AdministratorAccess",
			"attributes_json": "{}",
		}},
	}}
}

func deprovisionedOktaActiveCloudJSON(payload map[string]string) string {
	data, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(data)
}
