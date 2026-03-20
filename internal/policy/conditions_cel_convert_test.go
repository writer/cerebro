package policy

import (
	"testing"
	"time"
)

func TestConvertLegacyConditionsToCEL_RoundTripOperatorCoverage(t *testing.T) {
	asset := map[string]interface{}{
		"public":        true,
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

	conditions := []string{
		"public == true",
		"role NOT IN ('guest')",
		"ports IN ('22', '3389')",
		"name MATCHES '.*admin'",
		"name NOT MATCHES '^test-'",
		"rules ANY (resources CONTAINS '*' OR verbs CONTAINS '*')",
		"rules NOT ANY (resources CONTAINS 'secrets')",
		"metadata.annotations['nginx.ingress.kubernetes.io/auth-type'] == null",
		"open_port >= 22",
		"cpu_threshold <= 1",
		"metadata.annotations['missing'] not exists",
		"name starts_with 'service-'",
		"role = 'admin'",
		"metadata.annotations['nginx.ingress.kubernetes.io/auth-type'] IS NULL",
		"deployment_date IS NOT NULL",
		"default_actions not contains { type: 'authenticate-oidc' }",
		"policy_document contains ('*')",
		"identifiers CONTAINS (bucket)",
		"service_account_email ends_with '-compute@developer.gserviceaccount.com'",
		"metadata.annotations['nginx.ingress.kubernetes.io/auth-type'] == missing_field",
		"risk_assessment_date > deployment_date",
		"created_at < NOW() - INTERVAL '48 hours'",
		"training_data_config.s3_uri references bucket with public access",
	}

	for _, condition := range conditions {
		t.Run(condition, func(t *testing.T) {
			converted, err := ConvertLegacyConditionsToCEL([]string{condition})
			if err != nil {
				t.Fatalf("convert condition: %v", err)
			}

			engine := NewEngine()
			p := &Policy{
				ID:              "converted-" + condition,
				Name:            "Converted",
				Description:     "converted test",
				Severity:        "high",
				Resource:        "aws::s3::bucket",
				ConditionFormat: ConditionFormatCEL,
				Conditions:      converted,
			}
			engine.AddPolicy(p)

			got := engine.checkAssetViolation(p, asset) != ""
			want := evaluateCondition(condition, asset)
			if got != want {
				t.Fatalf("condition %q converted to %q: expected %v, got %v", condition, converted[0], want, got)
			}
		})
	}
}

func TestConvertLegacyConditionsToCEL_ContainsBareWordUsesLiteral(t *testing.T) {
	converted, err := ConvertLegacyConditionsToCEL([]string{"identifiers CONTAINS (bucket)"})
	if err != nil {
		t.Fatalf("convert condition: %v", err)
	}
	if len(converted) != 1 {
		t.Fatalf("expected 1 converted condition, got %d", len(converted))
	}
	want := `contains_value(path(resource, "identifiers"), "bucket")`
	if converted[0] != want {
		t.Fatalf("expected converted condition %q, got %q", want, converted[0])
	}
}

func TestConvertPolicyToCEL_UpdatesConditionFormat(t *testing.T) {
	p := &Policy{
		ID:          "legacy",
		Name:        "Legacy",
		Description: "legacy policy",
		Severity:    "high",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"public == true"},
	}

	converted, err := ConvertPolicyToCEL(p)
	if err != nil {
		t.Fatalf("ConvertPolicyToCEL failed: %v", err)
	}
	if converted.ConditionFormat != ConditionFormatCEL {
		t.Fatalf("expected condition format %q, got %q", ConditionFormatCEL, converted.ConditionFormat)
	}
	if len(converted.Conditions) != 1 || converted.Conditions[0] == p.Conditions[0] {
		t.Fatalf("expected converted CEL condition, got %#v", converted.Conditions)
	}
}
