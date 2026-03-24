package policy

import (
	"strings"
	"testing"
)

func TestValidatePolicyDefinitionRejectsInvalidCELCondition(t *testing.T) {
	engine := NewEngine()

	err := engine.ValidatePolicyDefinition(&Policy{
		ID:              "invalid-cel",
		Name:            "Invalid CEL",
		Description:     "reject invalid CEL syntax",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		Conditions:      []string{"resource.public =="},
		ConditionFormat: ConditionFormatCEL,
		Severity:        "high",
	})
	if err == nil {
		t.Fatal("expected invalid CEL definition to fail validation")
	}
	if !strings.Contains(err.Error(), "invalid CEL condition") {
		t.Fatalf("expected invalid CEL error, got %v", err)
	}
}

func TestValidatePolicyConditionProgramsUsesReusableEnv(t *testing.T) {
	engine := NewEngine()
	if err := engine.ensureConditionEnvLocked(); err != nil {
		t.Fatalf("ensureConditionEnvLocked failed: %v", err)
	}
	if engine.celEnv == nil {
		t.Fatal("expected engine CEL env to be initialized")
	}

	env, err := engine.conditionEnvForValidation()
	if err != nil {
		t.Fatalf("conditionEnvForValidation failed: %v", err)
	}
	if env != engine.celEnv {
		t.Fatal("expected validation env to reuse initialized engine env")
	}

	policy := &Policy{
		ID:              "valid-cel",
		Name:            "Valid CEL",
		Description:     "accept valid CEL syntax",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		Conditions:      []string{"resource.public == true"},
		ConditionFormat: ConditionFormatCEL,
		Severity:        "high",
	}

	if err := engine.validatePolicyConditionPrograms(policy); err != nil {
		t.Fatalf("validatePolicyConditionPrograms failed: %v", err)
	}
	if err := validatePolicyConditionProgramsWithEnv(env, policy); err != nil {
		t.Fatalf("validatePolicyConditionProgramsWithEnv failed: %v", err)
	}
}
