package policy

import (
	"context"
	"testing"
)

func TestEngineUpdateAndDeletePolicy(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{
		ID:         "policy-1",
		Name:       "Old Name",
		Effect:     "forbid",
		Resource:   "aws::s3::bucket",
		Conditions: []string{"public == true"},
		Severity:   "high",
	})

	updated := &Policy{
		Name:       "Updated Name",
		Effect:     "forbid",
		Resource:   "aws::s3::bucket",
		Conditions: []string{"public == false"},
		Severity:   "critical",
	}

	if ok := engine.UpdatePolicy("policy-1", updated); !ok {
		t.Fatal("expected policy update to succeed")
	}

	got, ok := engine.GetPolicy("policy-1")
	if !ok {
		t.Fatal("expected updated policy to exist")
	}
	if got.ID != "policy-1" {
		t.Fatalf("expected policy ID to remain policy-1, got %s", got.ID)
	}
	if got.Name != "Updated Name" {
		t.Fatalf("expected updated name, got %s", got.Name)
	}
	if got.Severity != "critical" {
		t.Fatalf("expected updated severity critical, got %s", got.Severity)
	}

	if ok := engine.UpdatePolicy("missing", updated); ok {
		t.Fatal("expected update of missing policy to fail")
	}

	if ok := engine.DeletePolicy("policy-1"); !ok {
		t.Fatal("expected policy delete to succeed")
	}
	if _, ok := engine.GetPolicy("policy-1"); ok {
		t.Fatal("expected policy to be deleted")
	}
	if ok := engine.DeletePolicy("policy-1"); ok {
		t.Fatal("expected second delete to report missing policy")
	}
}

func TestPolicyCELConditions(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{
		ID:              "cel-policy",
		Name:            "CEL policy",
		Description:     "test",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		ConditionFormat: ConditionFormatCEL,
		Conditions: []string{
			"resource.public == true",
			"resource.name.startsWith('prod-')",
		},
		Severity: "high",
	})

	findings, err := engine.EvaluateAsset(context.Background(), map[string]interface{}{
		"_cq_id":    "bucket-1",
		"_cq_table": "aws_s3_buckets",
		"type":      "aws::s3::bucket",
		"public":    true,
		"name":      "prod-logs",
	})
	if err != nil {
		t.Fatalf("EvaluateAsset failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	findings, err = engine.EvaluateAsset(context.Background(), map[string]interface{}{
		"_cq_id":    "bucket-2",
		"_cq_table": "aws_s3_buckets",
		"type":      "aws::s3::bucket",
		"public":    true,
		"name":      "dev-logs",
	})
	if err != nil {
		t.Fatalf("EvaluateAsset failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestPolicyCELConditionsWithoutExplicitFormat(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{
		ID:          "implicit-cel-policy",
		Name:        "Implicit CEL policy",
		Description: "test",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions: []string{
			"resource.public == true",
			"resource.name.startsWith('prod-')",
		},
		Severity: "high",
	})

	p, ok := engine.GetPolicy("implicit-cel-policy")
	if !ok {
		t.Fatal("expected implicit CEL policy to be stored")
	}
	if p.ConditionFormat != ConditionFormatCEL {
		t.Fatalf("expected inferred CEL condition format, got %q", p.ConditionFormat)
	}

	findings, err := engine.EvaluateAsset(context.Background(), map[string]interface{}{
		"_cq_id":    "bucket-1",
		"_cq_table": "aws_s3_buckets",
		"type":      "aws::s3::bucket",
		"public":    true,
		"name":      "prod-logs",
	})
	if err != nil {
		t.Fatalf("EvaluateAsset failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestPublicVMPolicies(t *testing.T) {
	engine := NewEngine()

	// Load a subset of policies for testing
	engine.AddPolicy(&Policy{
		ID:          "vm-public-admin",
		Name:        "Publicly exposed VM with admin privileges",
		Description: "A publicly exposed virtual machine has administrative privileges",
		Effect:      "forbid",
		Resource:    "compute::instance",
		Conditions:  []string{"is_public == true", "has_admin_role == true"},
		Severity:    "critical",
	})

	tests := []struct {
		name         string
		asset        map[string]interface{}
		wantFindings int
	}{
		{
			name: "public VM with admin - violation",
			asset: map[string]interface{}{
				"_cq_id":         "vm-123",
				"type":           "compute::instance",
				"is_public":      "true",
				"has_admin_role": "true",
			},
			wantFindings: 1,
		},
		{
			name: "private VM with admin - no violation",
			asset: map[string]interface{}{
				"_cq_id":         "vm-456",
				"type":           "compute::instance",
				"is_public":      "false",
				"has_admin_role": "true",
			},
			wantFindings: 0,
		},
		{
			name: "public VM without admin - no violation",
			asset: map[string]interface{}{
				"_cq_id":         "vm-789",
				"type":           "compute::instance",
				"is_public":      "true",
				"has_admin_role": "false",
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := engine.EvaluateAsset(context.Background(), tt.asset)
			if err != nil {
				t.Fatalf("EvaluateAsset failed: %v", err)
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("expected %d findings, got %d", tt.wantFindings, len(findings))
			}
		})
	}
}

func TestSecretsDetection(t *testing.T) {
	engine := NewEngine()

	engine.AddPolicy(&Policy{
		ID:          "resource-cleartext-keys-privileged",
		Name:        "Resource with cleartext cloud keys granting high privileges",
		Description: "A resource contains cleartext cloud credentials that grant high privileges",
		Effect:      "forbid",
		Resource:    "*",
		Conditions:  []string{"has_cleartext_keys == true", "grants_high_privilege == true"},
		Severity:    "critical",
	})

	tests := []struct {
		name         string
		asset        map[string]interface{}
		wantFindings int
	}{
		{
			name: "cleartext keys with high privilege - violation",
			asset: map[string]interface{}{
				"_cq_id":                "secret-123",
				"has_cleartext_keys":    "true",
				"grants_high_privilege": "true",
			},
			wantFindings: 1,
		},
		{
			name: "no cleartext keys - no violation",
			asset: map[string]interface{}{
				"_cq_id":                "secret-456",
				"has_cleartext_keys":    "false",
				"grants_high_privilege": "true",
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := engine.EvaluateAsset(context.Background(), tt.asset)
			if err != nil {
				t.Fatalf("EvaluateAsset failed: %v", err)
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("expected %d findings, got %d", tt.wantFindings, len(findings))
			}
		})
	}
}

func TestIdentityPolicies(t *testing.T) {
	engine := NewEngine()

	engine.AddPolicy(&Policy{
		ID:          "aws-user-inactive-admin-no-mfa",
		Name:        "Inactive AWS user account with admin privileges and MFA disabled",
		Description: "An inactive AWS user with admin privileges does not have MFA enabled",
		Effect:      "forbid",
		Resource:    "aws::iam::user",
		Conditions:  []string{"has_admin_role == true", "mfa_enabled == false", "is_inactive == true"},
		Severity:    "critical",
	})

	tests := []struct {
		name         string
		asset        map[string]interface{}
		wantFindings int
	}{
		{
			name: "inactive admin without MFA - violation",
			asset: map[string]interface{}{
				"_cq_id":         "user-123",
				"type":           "aws::iam::user",
				"has_admin_role": "true",
				"mfa_enabled":    "false",
				"is_inactive":    "true",
			},
			wantFindings: 1,
		},
		{
			name: "active admin without MFA - no violation (not inactive)",
			asset: map[string]interface{}{
				"_cq_id":         "user-456",
				"type":           "aws::iam::user",
				"has_admin_role": "true",
				"mfa_enabled":    "false",
				"is_inactive":    "false",
			},
			wantFindings: 0,
		},
		{
			name: "inactive admin with MFA - no violation",
			asset: map[string]interface{}{
				"_cq_id":         "user-789",
				"type":           "aws::iam::user",
				"has_admin_role": "true",
				"mfa_enabled":    "true",
				"is_inactive":    "true",
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := engine.EvaluateAsset(context.Background(), tt.asset)
			if err != nil {
				t.Fatalf("EvaluateAsset failed: %v", err)
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("expected %d findings, got %d", tt.wantFindings, len(findings))
			}
		})
	}
}

func TestVulnerabilityPolicies(t *testing.T) {
	engine := NewEngine()

	engine.AddPolicy(&Policy{
		ID:          "log4shell-public",
		Name:        "Publicly exposed VM vulnerable to Log4Shell",
		Description: "A publicly exposed resource is vulnerable to Log4Shell",
		Effect:      "forbid",
		Resource:    "compute::instance",
		Conditions:  []string{"is_public == true", "has_log4shell == true"},
		Severity:    "critical",
	})

	engine.AddPolicy(&Policy{
		ID:          "cve-2024-6387",
		Name:        "Publicly exposed VM vulnerable to regreSSHion",
		Description: "A publicly exposed VM is vulnerable to OpenSSH RCE",
		Effect:      "forbid",
		Resource:    "compute::instance",
		Conditions:  []string{"is_public == true", "has_cve_2024_6387 == true"},
		Severity:    "critical",
	})

	tests := []struct {
		name         string
		asset        map[string]interface{}
		wantFindings int
	}{
		{
			name: "public VM with Log4Shell - violation",
			asset: map[string]interface{}{
				"_cq_id":        "vm-log4j",
				"type":          "compute::instance",
				"is_public":     "true",
				"has_log4shell": "true",
			},
			wantFindings: 1,
		},
		{
			name: "public VM with regreSSHion - violation",
			asset: map[string]interface{}{
				"_cq_id":            "vm-ssh",
				"type":              "compute::instance",
				"is_public":         "true",
				"has_cve_2024_6387": "true",
			},
			wantFindings: 1,
		},
		{
			name: "private VM with vulnerabilities - no violation",
			asset: map[string]interface{}{
				"_cq_id":            "vm-private",
				"type":              "compute::instance",
				"is_public":         "false",
				"has_log4shell":     "true",
				"has_cve_2024_6387": "true",
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := engine.EvaluateAsset(context.Background(), tt.asset)
			if err != nil {
				t.Fatalf("EvaluateAsset failed: %v", err)
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("expected %d findings, got %d", tt.wantFindings, len(findings))
			}
		})
	}
}

func TestStoragePolicies(t *testing.T) {
	engine := NewEngine()

	engine.AddPolicy(&Policy{
		ID:          "bucket-public-sensitive",
		Name:        "Publicly readable bucket contains sensitive data",
		Description: "A publicly readable storage bucket contains sensitive data findings",
		Effect:      "forbid",
		Resource:    "storage::bucket",
		Conditions:  []string{"is_public == true", "has_sensitive_data == true"},
		Severity:    "critical",
	})

	tests := []struct {
		name         string
		asset        map[string]interface{}
		wantFindings int
	}{
		{
			name: "public bucket with sensitive data - violation",
			asset: map[string]interface{}{
				"_cq_id":             "bucket-123",
				"type":               "storage::bucket",
				"is_public":          "true",
				"has_sensitive_data": "true",
			},
			wantFindings: 1,
		},
		{
			name: "private bucket with sensitive data - no violation",
			asset: map[string]interface{}{
				"_cq_id":             "bucket-456",
				"type":               "storage::bucket",
				"is_public":          "false",
				"has_sensitive_data": "true",
			},
			wantFindings: 0,
		},
		{
			name: "public bucket without sensitive data - no violation",
			asset: map[string]interface{}{
				"_cq_id":             "bucket-789",
				"type":               "storage::bucket",
				"is_public":          "true",
				"has_sensitive_data": "false",
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := engine.EvaluateAsset(context.Background(), tt.asset)
			if err != nil {
				t.Fatalf("EvaluateAsset failed: %v", err)
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("expected %d findings, got %d", tt.wantFindings, len(findings))
			}
		})
	}
}

func TestKubernetesPolicies(t *testing.T) {
	engine := NewEngine()

	engine.AddPolicy(&Policy{
		ID:          "k8s-wildcard-permissions",
		Name:        "Kubernetes role with wildcard permissions",
		Description: "A Kubernetes role uses wildcard permissions which grant overly broad access",
		Effect:      "forbid",
		Resource:    "k8s::cluster_role",
		Conditions:  []string{"has_wildcard_permissions == true"},
		Severity:    "high",
	})

	tests := []struct {
		name         string
		asset        map[string]interface{}
		wantFindings int
	}{
		{
			name: "role with wildcard permissions - violation",
			asset: map[string]interface{}{
				"_cq_id":                   "role-123",
				"type":                     "k8s::cluster_role",
				"has_wildcard_permissions": "true",
			},
			wantFindings: 1,
		},
		{
			name: "role without wildcard permissions - no violation",
			asset: map[string]interface{}{
				"_cq_id":                   "role-456",
				"type":                     "k8s::cluster_role",
				"has_wildcard_permissions": "false",
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := engine.EvaluateAsset(context.Background(), tt.asset)
			if err != nil {
				t.Fatalf("EvaluateAsset failed: %v", err)
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("expected %d findings, got %d", tt.wantFindings, len(findings))
			}
		})
	}
}

func TestLoadPoliciesFromDisk(t *testing.T) {
	engine := NewEngine()

	// Load policies from disk
	if err := engine.LoadPolicies("../../policies/cerebro"); err != nil {
		t.Fatalf("LoadPolicies failed: %v", err)
	}

	policies := engine.ListPolicies()
	if len(policies) == 0 {
		t.Error("expected policies to be loaded")
	}

	// Verify specific policies exist
	testCases := []string{
		"vm-public-admin",
		"bucket-public-sensitive",
		"log4shell-public",
		"aws-user-inactive-admin-no-mfa",
	}

	for _, policyID := range testCases {
		if _, ok := engine.GetPolicy(policyID); !ok {
			t.Errorf("expected policy %s to be loaded", policyID)
		}
	}
}
