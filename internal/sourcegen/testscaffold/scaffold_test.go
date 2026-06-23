package testscaffold

import (
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
}
