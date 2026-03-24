package policy

import (
	"testing"
	"time"
)

func TestEvaluateConditionOperators(t *testing.T) {
	asset := map[string]interface{}{
		"role":          "admin",
		"ports":         []interface{}{"22", "443"},
		"name":          "service-admin",
		"tags":          []interface{}{"prod", "internal"},
		"open_port":     22,
		"cpu_threshold": 0.75,
		"rules": []interface{}{
			map[string]interface{}{
				"resources": []interface{}{"*"},
				"verbs":     []interface{}{"get"},
			},
			map[string]interface{}{
				"resources": []interface{}{"pods"},
				"verbs":     []interface{}{"list"},
			},
		},
		"status": map[string]interface{}{
			"addresses": []interface{}{
				map[string]interface{}{
					"type":    "ExternalIP",
					"address": "203.0.113.10",
				},
			},
		},
		"metadata": map[string]interface{}{
			"annotations": map[string]interface{}{
				"nginx.ingress.kubernetes.io/auth-type": nil,
			},
		},
		"service_account_email": "runner-compute@developer.gserviceaccount.com",
		"default_actions": []interface{}{
			map[string]interface{}{"type": "forward"},
			map[string]interface{}{"type": "redirect"},
		},
		"policy_document":      "allow:*",
		"identifiers":          []interface{}{"bucket", "alpha"},
		"created_at":           time.Now().Add(-72 * time.Hour).Format(time.RFC3339),
		"deployment_date":      time.Now().Add(-72 * time.Hour).Format(time.RFC3339),
		"risk_assessment_date": time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
		"training_data_config": map[string]interface{}{
			"s3_uri": "s3://public-bucket/dataset",
		},
		"bucket_inventory": []interface{}{
			map[string]interface{}{
				"name":          "public-bucket",
				"public_access": true,
			},
		},
	}

	tests := []struct {
		name      string
		condition string
		want      bool
	}{
		{
			name:      "in operator",
			condition: `list_value(path(resource, "status.addresses")).exists(item, cmp_eq(path(item, "type"), "ExternalIP") && !matches_value(path(item, "address"), "^10\\."))`,
			want:      true,
		},
		{
			name:      "not in operator",
			condition: `!in_list(path(resource, "role"), ["guest"])`,
			want:      true,
		},
		{
			name:      "in array",
			condition: `in_list(path(resource, "ports"), ["22", "3389"])`,
			want:      true,
		},
		{
			name:      "matches operator",
			condition: `matches_value(path(resource, "name"), ".*admin")`,
			want:      true,
		},
		{
			name:      "not matches operator",
			condition: `!matches_value(path(resource, "name"), "^test-")`,
			want:      true,
		},
		{
			name:      "matches array",
			condition: `matches_value(path(resource, "tags"), "prod")`,
			want:      true,
		},
		{
			name:      "any with contains",
			condition: `list_value(path(resource, "rules")).exists(item, contains_value(path(item, "resources"), "*") || contains_value(path(item, "verbs"), "*"))`,
			want:      true,
		},
		{
			name:      "not any",
			condition: `!list_value(path(resource, "rules")).exists(item, contains_value(path(item, "resources"), "secrets"))`,
			want:      true,
		},
		{
			name:      "nested any",
			condition: `list_value(path(resource, "status.addresses")).exists(item, cmp_eq(path(item, "type"), "ExternalIP") && !matches_value(path(item, "address"), "^10\\."))`,
			want:      true,
		},
		{
			name:      "bracketed key",
			condition: `cmp_eq(path(resource, "metadata.annotations['nginx.ingress.kubernetes.io/auth-type']"), null)`,
			want:      true,
		},
		{
			name:      "greater or equal numeric comparison",
			condition: `cmp_ge(path(resource, "open_port"), 22)`,
			want:      true,
		},
		{
			name:      "less or equal numeric comparison",
			condition: `cmp_le(path(resource, "cpu_threshold"), 1)`,
			want:      true,
		},
		{
			name:      "not exists true for missing field",
			condition: `!exists_path(resource, "metadata.annotations['missing']")`,
			want:      true,
		},
		{
			name:      "not exists false for existing field",
			condition: `!exists_path(resource, "role")`,
			want:      false,
		},
		{
			name:      "single equals comparison",
			condition: `cmp_eq(path(resource, "role"), "admin")`,
			want:      true,
		},
		{
			name:      "is null operator",
			condition: `cmp_eq(path(resource, "metadata.annotations['nginx.ingress.kubernetes.io/auth-type']"), null)`,
			want:      true,
		},
		{
			name:      "is not null operator",
			condition: `exists_path(resource, "deployment_date")`,
			want:      true,
		},
		{
			name:      "not contains object literal",
			condition: `!contains_value(path(resource, "default_actions"), {"type": "authenticate-oidc"})`,
			want:      true,
		},
		{
			name:      "contains literal in parens",
			condition: `contains_value(path(resource, "policy_document"), "*")`,
			want:      true,
		},
		{
			name:      "contains bare word in parens as literal",
			condition: `contains_value(path(resource, "identifiers"), "bucket")`,
			want:      true,
		},
		{
			name:      "ends with operator",
			condition: `ends_with_value(path(resource, "service_account_email"), "-compute@developer.gserviceaccount.com")`,
			want:      true,
		},
		{
			name:      "missing field reference compares as null",
			condition: `cmp_eq(path(resource, "metadata.annotations['nginx.ingress.kubernetes.io/auth-type']"), path(resource, "missing_field"))`,
			want:      true,
		},
		{
			name:      "field to field time comparison",
			condition: `cmp_gt(path(resource, "risk_assessment_date"), path(resource, "deployment_date"))`,
			want:      true,
		},
		{
			name:      "relative time comparison",
			condition: `cmp_lt(path(resource, "created_at"), "NOW() - INTERVAL '48 hours'")`,
			want:      true,
		},
		{
			name:      "references public bucket",
			condition: `references_public_bucket(resource, "training_data_config.s3_uri")`,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateConditionExpression(tt.condition, asset)
			if err != nil {
				t.Fatalf("evaluateConditionExpression(%q): %v", tt.condition, err)
			}
			if got != tt.want {
				t.Fatalf("condition %q: expected %v, got %v", tt.condition, tt.want, got)
			}
		})
	}
}
