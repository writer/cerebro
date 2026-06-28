package testscaffold

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

func TestGenerateScaffold(t *testing.T) {
	definition := connectordefinitions.Definition{
		SourceID:    "test_provider",
		DisplayName: "Test Provider",
		Auth: connectordefinitions.AuthSpec{
			Model: "api_key",
		},
		Transport: &connectordefinitions.TransportSpec{
			BaseURL: "https://api.example.com",
			Verification: &connectordefinitions.VerificationSpec{
				Path:         "/healthcheck",
				Method:       "GET",
				ExpectStatus: []int{200},
			},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{
			{
				ID:             "users",
				Label:          "Users",
				Path:           "/v1/users",
				Method:         "GET",
				RecordSelector: "$.data[*]",
				IDField:        "user_id",
			},
			{
				ID:     "groups",
				Label:  "Groups",
				Path:   "/v1/groups",
				Method: "GET",
			},
			{
				ID:             "models",
				Label:          "Models",
				Path:           "/v1/models",
				Method:         "GET",
				RecordSelector: "$.resources[*]",
				IDField:        "metadata.id",
				NameField:      "entity.name",
			},
			{
				ID:             "balances",
				Label:          "Balances",
				Path:           "/v1/balances",
				Method:         "GET",
				RecordSelector: "$.balance_infos[*]",
				IDField:        "currency",
				NameField:      "currency",
			},
		},
	}

	result, err := Generate(definition)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if !strings.Contains(result.MockHandler, "newMockServer") {
		t.Error("expected mock server function")
	}
	if !strings.Contains(result.MockHandler, `/v1/users`) {
		t.Error("expected /v1/users handler")
	}
	if !strings.Contains(result.MockHandler, `/healthcheck`) {
		t.Error("expected /healthcheck handler")
	}
	if !strings.Contains(result.TestFile, "TestSourceCheck") {
		t.Error("expected TestSourceCheck function")
	}
	if !strings.Contains(result.TestFile, "TestSourceDiscover") {
		t.Error("expected TestSourceDiscover function")
	}
	if !strings.Contains(result.TestFile, `"api_key"`) {
		t.Error("expected api_key config")
	}

	if _, ok := result.Fixtures["users.json"]; !ok {
		t.Error("expected users.json fixture")
	}
	if _, ok := result.Fixtures["groups.json"]; !ok {
		t.Error("expected groups.json fixture")
	}
	if !strings.Contains(result.Fixtures["users.json"], "fixture-users-001") {
		t.Errorf("expected fixture user_id, got:\n%s", result.Fixtures["users.json"])
	}
	var balancesFixture struct {
		BalanceInfos []map[string]any `json:"balance_infos"`
	}
	if err := json.Unmarshal([]byte(result.Fixtures["balances.json"]), &balancesFixture); err != nil {
		t.Fatalf("unmarshal balances fixture: %v", err)
	}
	if len(balancesFixture.BalanceInfos) != 1 {
		t.Fatalf("balances fixture records = %d, want 1", len(balancesFixture.BalanceInfos))
	}
	if got := balancesFixture.BalanceInfos[0]["currency"]; got != "fixture-balances-001" {
		t.Fatalf("balances fixture currency = %v, want fixture ID", got)
	}

	var modelsFixture struct {
		Resources []map[string]any `json:"resources"`
	}
	if err := json.Unmarshal([]byte(result.Fixtures["models.json"]), &modelsFixture); err != nil {
		t.Fatalf("unmarshal models fixture: %v", err)
	}
	if len(modelsFixture.Resources) != 1 {
		t.Fatalf("models fixture resources = %d, want 1", len(modelsFixture.Resources))
	}
	model := modelsFixture.Resources[0]
	if _, ok := model["metadata.id"]; ok {
		t.Fatalf("models fixture used flat metadata.id key: %#v", model)
	}
	metadata, ok := model["metadata"].(map[string]any)
	if !ok || metadata["id"] != "fixture-models-001" {
		t.Fatalf("models fixture metadata = %#v, want nested id", model["metadata"])
	}
	entity, ok := model["entity"].(map[string]any)
	if !ok || entity["name"] != "Test Models" {
		t.Fatalf("models fixture entity = %#v, want nested name", model["entity"])
	}
}
