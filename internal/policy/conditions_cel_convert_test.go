package policy

import "testing"

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
