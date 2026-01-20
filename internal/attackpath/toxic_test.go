package attackpath

import (
	"context"
	"testing"
)

func TestToxicCombinationDetector_CriticalPath(t *testing.T) {
	detector := NewToxicCombinationDetector()

	profiles := []ResourceRiskProfile{
		{
			ResourceID:   "arn:aws:ecs:us-east-1:123:task/abc",
			ResourceName: "my-service-task",
			ResourceType: "ecs_task_definition",
			Provider:     "aws",
			Region:       "us-east-1",
			RiskFactors: []RiskFactor{
				{Type: RiskFactorNetworkExposed, Description: "Public facing", Severity: RiskMedium},
				{Type: RiskFactorVulnerable, Description: "CVE-2024-1234", Severity: RiskCritical},
				{Type: RiskFactorDataAccess, Description: "S3 access", Severity: RiskMedium},
			},
		},
	}

	combos := detector.Detect(context.Background(), profiles)

	if len(combos) == 0 {
		t.Fatal("expected at least one toxic combination")
	}

	found := false
	for _, c := range combos {
		if c.Severity == RiskCritical {
			found = true
			t.Logf("Found critical combo: %s", c.Title)
		}
	}

	if !found {
		t.Error("expected critical severity toxic combination")
	}
}

func TestToxicCombinationDetector_ContainerSecrets(t *testing.T) {
	detector := NewToxicCombinationDetector()

	profiles := []ResourceRiskProfile{
		{
			ResourceID:   "deployment/my-app",
			ResourceName: "my-app",
			ResourceType: "deployment",
			Provider:     "kubernetes",
			RiskFactors: []RiskFactor{
				{Type: RiskFactorSecretsExposed, Description: "AWS keys in env", Severity: RiskHigh},
				{Type: RiskFactorHighPrivilege, Description: "Admin role", Severity: RiskHigh},
			},
		},
	}

	combos := detector.Detect(context.Background(), profiles)

	if len(combos) == 0 {
		t.Fatal("expected container secrets toxic combination")
	}

	if combos[0].Severity != RiskMedium {
		t.Errorf("expected medium severity, got %s", combos[0].Severity)
	}
}

func TestToxicCombinationDetector_NoMatch(t *testing.T) {
	detector := NewToxicCombinationDetector()

	profiles := []ResourceRiskProfile{
		{
			ResourceID:   "arn:aws:s3:::my-bucket",
			ResourceName: "my-bucket",
			ResourceType: "s3_bucket",
			Provider:     "aws",
			RiskFactors: []RiskFactor{
				{Type: RiskFactorNoLogging, Description: "No logging", Severity: RiskLow},
			},
		},
	}

	combos := detector.Detect(context.Background(), profiles)

	if len(combos) != 0 {
		t.Errorf("expected no toxic combinations, got %d", len(combos))
	}
}

func TestBuildRiskProfile(t *testing.T) {
	props := map[string]interface{}{
		"public":         true,
		"high_privilege": true,
		"sensitive_data": true,
		"privileged":     true,
		"secrets_in_env": true,
	}

	profile := BuildRiskProfile(
		"test-resource",
		"test-name",
		"ecs_task_definition",
		"aws",
		"us-east-1",
		props,
	)

	if len(profile.RiskFactors) != 5 {
		t.Errorf("expected 5 risk factors, got %d", len(profile.RiskFactors))
	}

	// Check that we have the expected factor types
	factorTypes := make(map[RiskFactorType]bool)
	for _, f := range profile.RiskFactors {
		factorTypes[f.Type] = true
	}

	expected := []RiskFactorType{
		RiskFactorNetworkExposed,
		RiskFactorHighPrivilege,
		RiskFactorSensitiveData,
		RiskFactorPrivilegedContainer,
		RiskFactorSecretsExposed,
	}

	for _, e := range expected {
		if !factorTypes[e] {
			t.Errorf("missing expected risk factor: %s", e)
		}
	}
}
