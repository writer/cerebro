package findings

import (
	"context"
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
}

func TestCloudPublicExposurePrivilegedPrincipalGraphRuleRequiresEffectivePermissionRuntime(t *testing.T) {
	rule := newCloudPublicExposurePrivilegedPrincipalRule().(GraphRule)
	for _, runtime := range []*cerebrov1.SourceRuntime{
		{SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "public_endpoint"}},
		{SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "user"}},
	} {
		if rule.SupportsRuntime(runtime) {
			t.Fatalf("SupportsRuntime(%s/%s) = true, want false", runtime.GetSourceId(), runtime.GetConfig()["family"])
		}
	}
}
