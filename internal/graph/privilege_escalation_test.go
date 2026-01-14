package graph

import (
	"testing"
)

func TestPrivilegeEscalationRegistry(t *testing.T) {
	// Verify all paths have required fields
	for _, path := range PrivilegeEscalationRegistry {
		if path.ID == "" {
			t.Errorf("path has empty ID")
		}
		if path.Name == "" {
			t.Errorf("path %s has empty Name", path.ID)
		}
		if path.Category == "" {
			t.Errorf("path %s has empty Category", path.ID)
		}
		if len(path.RequiredPerms) == 0 {
			t.Errorf("path %s has no required permissions", path.ID)
		}
		if path.Severity == "" {
			t.Errorf("path %s has empty Severity", path.ID)
		}
		if path.Exploitability < 0 || path.Exploitability > 1 {
			t.Errorf("path %s has invalid exploitability: %f", path.ID, path.Exploitability)
		}
	}
}

func TestGetPrivilegeEscalationByCategory(t *testing.T) {
	categories := []string{"self_escalation", "principal_access", "new_passrole", "existing_passrole", "credential_access"}

	for _, cat := range categories {
		paths := GetPrivilegeEscalationByCategory(cat)
		if len(paths) == 0 {
			t.Errorf("no paths found for category %s", cat)
		}

		for _, path := range paths {
			if path.Category != cat {
				t.Errorf("path %s has category %s, expected %s", path.ID, path.Category, cat)
			}
		}
	}
}

func TestGetPrivilegeEscalationByService(t *testing.T) {
	// IAM should have many paths
	iamPaths := GetPrivilegeEscalationByService("iam")
	if len(iamPaths) < 10 {
		t.Errorf("expected at least 10 IAM paths, got %d", len(iamPaths))
	}

	// Lambda should have some paths
	lambdaPaths := GetPrivilegeEscalationByService("lambda")
	if len(lambdaPaths) < 3 {
		t.Errorf("expected at least 3 Lambda paths, got %d", len(lambdaPaths))
	}
}

func TestDetectPrivilegeEscalationRisks(t *testing.T) {
	g := New()

	// Create a user with dangerous permissions
	user := &Node{
		ID:       "user1",
		Kind:     NodeKindUser,
		Name:     "dangerous-user",
		Provider: "aws",
		Properties: map[string]any{
			"permissions": []any{
				"iam:CreatePolicyVersion",
				"iam:AttachUserPolicy",
			},
		},
	}
	g.AddNode(user)

	risks := DetectPrivilegeEscalationRisks(g, "user1")
	if len(risks) < 2 {
		t.Errorf("expected at least 2 risks, got %d", len(risks))
	}

	// Verify risk details
	for _, risk := range risks {
		if risk.Principal.ID != "user1" {
			t.Errorf("risk has wrong principal: %s", risk.Principal.ID)
		}
		if risk.RiskScore <= 0 {
			t.Errorf("risk has invalid score: %f", risk.RiskScore)
		}
	}
}

func TestDetectPrivilegeEscalationPassRole(t *testing.T) {
	g := New()

	// Create a user with PassRole + Lambda permissions
	user := &Node{
		ID:       "lambda-user",
		Kind:     NodeKindUser,
		Name:     "lambda-deployer",
		Provider: "aws",
		Properties: map[string]any{
			"permissions": []any{
				"iam:PassRole",
				"lambda:CreateFunction",
				"lambda:InvokeFunction",
			},
		},
	}
	g.AddNode(user)

	risks := DetectPrivilegeEscalationRisks(g, "lambda-user")

	// Should detect PassRole + Lambda escalation
	found := false
	for _, risk := range risks {
		if risk.EscalationPath.ID == "PE015" {
			found = true
			break
		}
	}

	if !found {
		t.Error("failed to detect PassRole + Lambda privilege escalation")
	}
}

func TestPrivilegeEscalationCategories(t *testing.T) {
	categoryCount := make(map[string]int)
	for _, path := range PrivilegeEscalationRegistry {
		categoryCount[path.Category]++
	}

	// Verify we have paths in each category
	expectedCategories := map[string]int{
		"self_escalation":   5,
		"principal_access":  2,
		"new_passrole":      5,
		"existing_passrole": 3,
		"credential_access": 3,
	}

	for cat, minCount := range expectedCategories {
		actual := categoryCount[cat]
		if actual < minCount {
			t.Errorf("category %s has %d paths, expected at least %d", cat, actual, minCount)
		}
	}
}
