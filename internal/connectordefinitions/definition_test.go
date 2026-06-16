package connectordefinitions

import "testing"

func TestNormalizeBuildsValidatedDefinition(t *testing.T) {
	definition, err := Normalize(Definition{
		TenantID:    "tenant-a",
		SourceID:    "Example API",
		DisplayName: "Example API",
		ConfigFields: []Field{{
			Key:      "base url",
			Label:    "Base URL",
			Required: true,
		}},
		Auth: AuthSpec{
			Model:             "bearer_token",
			SupportedStoreIDs: []string{"hashicorp_vault", "cerebro_vault"},
			CredentialFields: []Field{{
				Key:           "Token",
				Secret:        true,
				ReferenceOnly: true,
			}},
		},
		ResourceFamilies: []ResourceFamily{{
			ID:        "Assets",
			Path:      "/v1/assets",
			IDField:   "id",
			NameField: "name",
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if definition.ID != "tenant-a-example_api" {
		t.Fatalf("definition id = %q, want tenant-a-example_api", definition.ID)
	}
	if definition.Runtime != RuntimeJSONAPI || definition.Stage != StageDraft {
		t.Fatalf("runtime/stage = %q/%q, want json_api/draft", definition.Runtime, definition.Stage)
	}
	if definition.Validation.Status != ValidationReady {
		t.Fatalf("validation status = %q, want ready: %#v", definition.Validation.Status, definition.Validation.Checks)
	}
	if len(definition.Promotion.EligibleStages) != 1 || definition.Promotion.EligibleStages[0] != StageSandbox {
		t.Fatalf("eligible stages = %#v, want sandbox", definition.Promotion.EligibleStages)
	}
	if len(definition.ScopeOptions) != 1 || definition.ScopeOptions[0].ID != "assets" {
		t.Fatalf("scope options = %#v, want generated assets scope option", definition.ScopeOptions)
	}
}

func TestValidateBlocksUnsafeDynamicDefinition(t *testing.T) {
	definition, err := Normalize(Definition{
		ID:          "example",
		TenantID:    "tenant-a",
		SourceID:    "example",
		DisplayName: "Example",
		Runtime:     RuntimeJSONAPI,
		Auth: AuthSpec{
			Model: "api_key",
			CredentialFields: []Field{{
				Key:    "api_key",
				Secret: true,
			}},
		},
		ResourceFamilies: []ResourceFamily{{
			ID:      "assets",
			Path:    "https://api.example.test/v1/assets",
			Method:  "POST",
			IDField: "id",
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if definition.Validation.Status != ValidationBlocked {
		t.Fatalf("validation status = %q, want blocked", definition.Validation.Status)
	}
	var blocked []string
	for _, check := range definition.Validation.Checks {
		if check.Blocking {
			blocked = append(blocked, check.ID)
		}
	}
	if len(blocked) < 3 {
		t.Fatalf("blocking checks = %#v, want secret/path/method blockers", blocked)
	}
}

func TestPromoteMovesOneStageWhenReady(t *testing.T) {
	definition, err := Normalize(Definition{
		ID:          "example",
		TenantID:    "tenant-a",
		SourceID:    "example",
		DisplayName: "Example",
		Auth: AuthSpec{
			Model: "bearer_token",
			CredentialFields: []Field{{
				Key:           "token",
				Secret:        true,
				ReferenceOnly: true,
			}},
		},
		ResourceFamilies: []ResourceFamily{{
			ID:      "assets",
			Path:    "/v1/assets",
			IDField: "id",
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	result, err := Promote(definition, PromotionRequest{TargetStage: StageSandbox})
	if err != nil {
		t.Fatalf("Promote() error = %v", err)
	}
	if !result.Promoted || result.Definition.Stage != StageSandbox {
		t.Fatalf("promotion = %#v, want sandbox promotion", result)
	}
	if _, err := Promote(result.Definition, PromotionRequest{TargetStage: StageApproved}); err == nil {
		t.Fatal("Promote() error = nil, want one-stage transition error")
	}
}
