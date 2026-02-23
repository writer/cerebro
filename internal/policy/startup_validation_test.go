package policy

import "testing"

func TestValidateStartupMappings(t *testing.T) {
	if err := ValidateStartupMappings(); err != nil {
		t.Fatalf("expected startup mapping validation to pass, got error: %v", err)
	}
}

func TestMustValidateStartupMappings(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("expected startup mapping validation not to panic, got: %v", recovered)
		}
	}()

	MustValidateStartupMappings()
}

func TestNewEngine_PerformsStartupValidation(t *testing.T) {
	engine := NewEngine()
	if engine == nil {
		t.Fatal("expected engine to be created")
	}
}
