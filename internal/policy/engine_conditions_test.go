package policy

import "testing"

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evaluateCondition(tt.condition, asset); got != tt.want {
				t.Fatalf("condition %q: expected %v, got %v", tt.condition, tt.want, got)
			}
		})
	}
}
