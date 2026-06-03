package findings

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestCloudExposedPrivilegedComputeRoleGraphRuleSupportsAWSProducerRuntimes(t *testing.T) {
	rule := newCloudExposedPrivilegedComputeRoleRule().(GraphRule)
	for _, family := range []string{
		"ec2_instance",
		"lambda_function",
		"ecs_service",
		"ecs_task_definition",
		"effective_permission",
		"iam_role_assignment",
		"iam_role_trust",
		"public_endpoint",
		"resource_exposure",
	} {
		runtime := &cerebrov1.SourceRuntime{SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": family}}
		if !rule.SupportsRuntime(runtime) {
			t.Fatalf("SupportsRuntime(aws/%s) = false, want true", family)
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

func TestCloudExposedPrivilegedComputeRoleGraphRuleQueryShape(t *testing.T) {
	rule := newCloudExposedPrivilegedComputeRoleRule().(GraphRule)
	query := rule.QueryFor(&cerebrov1.SourceRuntime{Id: "writer-aws-ecs-service", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "ecs_service"}})
	if query.Params["tenant_id"] != "writer" || query.RowLimit != coordinationGraphRowLimit {
		t.Fatalf("QueryFor() = %#v", query)
	}
	for _, fragment := range []string{
		"aws.ecs.service",
		"aws.ecs.task_definition",
		"aws.lambda.function",
		"aws.ec2.instance",
		"relation: 'can_reach'",
		"relation: 'attached_to'",
		"relation: 'member_of'",
		"relation: 'depends_on'",
		"relation: 'runs_as'",
		"access.relation IN ['can_admin', 'can_assume', 'can_perform']",
		`"is_admin":"true"`,
		`"privilege_level":"admin"`,
		"AdministratorAccess",
		`"permission":"*"`,
		`duration('P30D')`,
		"LIMIT $row_limit",
	} {
		if !strings.Contains(query.Query, fragment) {
			t.Fatalf("QueryFor() missing %q:\n%s", fragment, query.Query)
		}
	}
}

func TestCloudExposedPrivilegedComputeRoleGraphRuleEvaluateRows(t *testing.T) {
	rule := newCloudExposedPrivilegedComputeRoleRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-aws-ecs-service", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "ecs_service"}}

	tests := []struct {
		name            string
		row             ports.CypherRow
		wantSeverity    string
		wantResourceURN string
	}{
		{
			name: "ecs service task role",
			row: ports.CypherRow{Values: map[string]any{
				"primary_urn":     "urn:cerebro:writer:aws_ecs_service:arn:aws:ecs:us-east-1:123456789012:service/prod/orders",
				"primary_label":   "orders",
				"primary_type":    "aws.ecs.service",
				"fingerprint_key": "urn:cerebro:writer:aws_ecs_service:arn:aws:ecs:us-east-1:123456789012:service/prod/orders|urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/ECSTaskRole|urn:cerebro:writer:aws_iam_policy:AdministratorAccess",
				"severity":        "CRITICAL",
				"summary":         "Publicly reachable compute workload orders runs as privileged role ECSTaskRole",
				"action":          "Remove unnecessary public reachability and reduce the compute runtime role privileges",
				"resource_urns": []any{
					"urn:cerebro:writer:aws_ecs_service:arn:aws:ecs:us-east-1:123456789012:service/prod/orders",
					"urn:cerebro:writer:aws_security_group:sg-public",
					"urn:cerebro:writer:aws_ecs_task_definition:arn:aws:ecs:us-east-1:123456789012:task-definition/orders:7",
					"urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/ECSTaskRole",
					"urn:cerebro:writer:aws_iam_policy:AdministratorAccess",
					"urn:cerebro:writer:cloud_account:123456789012",
				},
				"evidence": []any{
					map[string]any{"urn": "urn:cerebro:writer:aws_public_principal:public_internet", "label": "public internet", "entity_type": "aws.public_principal", "relation": "can_reach", "attributes_json": `{"at":"2026-04-23T00:00:00Z"}`},
					map[string]any{"urn": "urn:cerebro:writer:aws_security_group:sg-public", "label": "sg-public", "entity_type": "aws.security_group", "relation": "member_of", "attributes_json": `{"at":"2026-04-23T00:00:00Z"}`},
					map[string]any{"urn": "urn:cerebro:writer:aws_ecs_task_definition:arn:aws:ecs:us-east-1:123456789012:task-definition/orders:7", "label": "orders:7", "entity_type": "aws.ecs.task_definition", "relation": "depends_on", "attributes_json": `{}`},
					map[string]any{"urn": "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/ECSTaskRole", "label": "ECSTaskRole", "entity_type": "aws.role", "relation": "runs_as", "attributes_json": `{"role_usage":"task"}`},
					map[string]any{"urn": "urn:cerebro:writer:aws_iam_policy:AdministratorAccess", "label": "AdministratorAccess", "entity_type": "aws.iam.policy", "relation": "can_perform", "attributes_json": `{"privilege_level":"admin"}`},
				},
			}},
			wantSeverity:    "CRITICAL",
			wantResourceURN: "urn:cerebro:writer:aws_ecs_task_definition:arn:aws:ecs:us-east-1:123456789012:task-definition/orders:7",
		},
		{
			name: "ec2 instance role",
			row: ports.CypherRow{Values: map[string]any{
				"primary_urn":     "urn:cerebro:writer:aws_ec2_instance:i-1234567890abcdef0",
				"primary_label":   "prod-web",
				"primary_type":    "aws.ec2.instance",
				"fingerprint_key": "urn:cerebro:writer:aws_ec2_instance:i-1234567890abcdef0|urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/WebInstanceRole|urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/AdminRole",
				"severity":        "HIGH",
				"summary":         "Publicly reachable compute workload prod-web runs as privileged role WebInstanceRole",
				"action":          "Remove unnecessary public reachability and reduce the compute runtime role privileges",
				"resource_urns": []any{
					"urn:cerebro:writer:aws_ec2_instance:i-1234567890abcdef0",
					"urn:cerebro:writer:aws_network_interface:eni-1",
					"urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/WebInstanceRole",
					"urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/AdminRole",
					"urn:cerebro:writer:cloud_account:123456789012",
				},
				"evidence": []any{
					map[string]any{"urn": "urn:cerebro:writer:aws_network_interface:eni-1", "label": "eni-1", "entity_type": "aws.network.interface", "relation": "attached_to", "attributes_json": `{"at":"2026-04-23T00:00:00Z"}`},
					map[string]any{"urn": "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/WebInstanceRole", "label": "WebInstanceRole", "entity_type": "aws.role", "relation": "runs_as", "attributes_json": `{"role_usage":"primary"}`},
					map[string]any{"urn": "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/AdminRole", "label": "AdminRole", "entity_type": "aws.role", "relation": "can_assume", "attributes_json": `{}`},
				},
			}},
			wantSeverity:    "HIGH",
			wantResourceURN: "urn:cerebro:writer:aws_network_interface:eni-1",
		},
		{
			name: "lambda role",
			row: ports.CypherRow{Values: map[string]any{
				"primary_urn":     "urn:cerebro:writer:aws_lambda_function:arn:aws:lambda:us-east-1:123456789012:function:orders",
				"primary_label":   "orders",
				"primary_type":    "aws.lambda.function",
				"fingerprint_key": "urn:cerebro:writer:aws_lambda_function:arn:aws:lambda:us-east-1:123456789012:function:orders|urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/LambdaOrdersRole|urn:cerebro:writer:aws_scope:*",
				"severity":        "CRITICAL",
				"summary":         "Publicly reachable compute workload orders runs as privileged role LambdaOrdersRole",
				"action":          "Remove unnecessary public reachability and reduce the compute runtime role privileges",
				"resource_urns": []any{
					"urn:cerebro:writer:aws_lambda_function:arn:aws:lambda:us-east-1:123456789012:function:orders",
					"urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/LambdaOrdersRole",
					"urn:cerebro:writer:aws_scope:*",
					"urn:cerebro:writer:cloud_account:123456789012",
				},
				"evidence": []any{
					map[string]any{"urn": "urn:cerebro:writer:aws_public_principal:public_internet", "label": "public internet", "entity_type": "aws.public_principal", "relation": "can_reach", "attributes_json": `{"at":"2026-04-23T00:00:00Z"}`},
					map[string]any{"urn": "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/LambdaOrdersRole", "label": "LambdaOrdersRole", "entity_type": "aws.role", "relation": "runs_as", "attributes_json": `{"role_usage":"primary"}`},
					map[string]any{"urn": "urn:cerebro:writer:aws_scope:*", "label": "*", "entity_type": "aws.scope", "relation": "can_perform", "attributes_json": `{"permission":"*"}`},
				},
			}},
			wantSeverity:    "CRITICAL",
			wantResourceURN: "urn:cerebro:writer:aws_scope:*",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{tt.row})
			if err != nil {
				t.Fatalf("EvaluateRows() error = %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("len(findings) = %d, want 1", len(findings))
			}
			finding := findings[0]
			if finding.RuleID != cloudExposedPrivilegedComputeRoleRuleID || finding.Severity != tt.wantSeverity || finding.Status != findingStatusOpen {
				t.Fatalf("finding metadata = %#v", finding)
			}
			if !containsString(finding.ResourceURNs, tt.wantResourceURN) {
				t.Fatalf("ResourceURNs = %#v, want %q", finding.ResourceURNs, tt.wantResourceURN)
			}
			if len(finding.GraphEvidenceRows) == 0 {
				t.Fatalf("GraphEvidenceRows empty: %#v", finding)
			}
		})
	}
}
