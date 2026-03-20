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
			condition: "status.addresses ANY (type == 'ExternalIP' AND address NOT MATCHES '^10\\.')",
			want:      true,
		},
		{
			name:      "not in operator",
			condition: "role NOT IN ('guest')",
			want:      true,
		},
		{
			name:      "in array",
			condition: "ports IN ('22', '3389')",
			want:      true,
		},
		{
			name:      "matches operator",
			condition: "name MATCHES '.*admin'",
			want:      true,
		},
		{
			name:      "not matches operator",
			condition: "name NOT MATCHES '^test-'",
			want:      true,
		},
		{
			name:      "matches array",
			condition: "tags MATCHES 'prod'",
			want:      true,
		},
		{
			name:      "any with contains",
			condition: "rules ANY (resources CONTAINS '*' OR verbs CONTAINS '*')",
			want:      true,
		},
		{
			name:      "not any",
			condition: "rules NOT ANY (resources CONTAINS 'secrets')",
			want:      true,
		},
		{
			name:      "nested any",
			condition: `status.addresses ANY (type == 'ExternalIP' AND address NOT MATCHES '^10\.')`,
			want:      true,
		},
		{
			name:      "bracketed key",
			condition: "metadata.annotations['nginx.ingress.kubernetes.io/auth-type'] == null",
			want:      true,
		},
		{
			name:      "greater or equal numeric comparison",
			condition: "open_port >= 22",
			want:      true,
		},
		{
			name:      "less or equal numeric comparison",
			condition: "cpu_threshold <= 1",
			want:      true,
		},
		{
			name:      "not exists true for missing field",
			condition: "metadata.annotations['missing'] not exists",
			want:      true,
		},
		{
			name:      "not exists false for existing field",
			condition: "role not exists",
			want:      false,
		},
		{
			name:      "single equals comparison",
			condition: "role = 'admin'",
			want:      true,
		},
		{
			name:      "is null operator",
			condition: "metadata.annotations['nginx.ingress.kubernetes.io/auth-type'] IS NULL",
			want:      true,
		},
		{
			name:      "is not null operator",
			condition: "deployment_date IS NOT NULL",
			want:      true,
		},
		{
			name:      "not contains object literal",
			condition: "default_actions not contains { type: 'authenticate-oidc' }",
			want:      true,
		},
		{
			name:      "contains literal in parens",
			condition: "policy_document contains ('*')",
			want:      true,
		},
		{
			name:      "contains bare word in parens as literal",
			condition: "identifiers CONTAINS (bucket)",
			want:      true,
		},
		{
			name:      "ends with operator",
			condition: "service_account_email ends_with '-compute@developer.gserviceaccount.com'",
			want:      true,
		},
		{
			name:      "missing field reference compares as null",
			condition: "metadata.annotations['nginx.ingress.kubernetes.io/auth-type'] == missing_field",
			want:      true,
		},
		{
			name:      "field to field time comparison",
			condition: "risk_assessment_date > deployment_date",
			want:      true,
		},
		{
			name:      "relative time comparison",
			condition: "created_at < NOW() - INTERVAL '48 hours'",
			want:      true,
		},
		{
			name:      "references public bucket",
			condition: "training_data_config.s3_uri references bucket with public access",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evaluateCondition(tt.condition, asset); got != tt.want {
				t.Fatalf("condition %q: expected %v, got %v", tt.condition, tt.want, got)
			}
		})
	}
}
