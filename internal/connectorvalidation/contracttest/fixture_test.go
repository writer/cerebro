package contracttest

import (
	"context"
	"os"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

func TestValidateFixtureRunsCatalogRuntime(t *testing.T) {
	body, err := os.ReadFile("../testdata/cassettes/okta/users.json")
	if err != nil {
		t.Fatalf("ReadFile(okta fixture): %v", err)
	}
	result, err := ValidateFixture(context.Background(), testDefinition(), Fixture{
		SourceID:       "okta",
		ResourceFamily: "users",
		Ref:            "../testdata/cassettes/okta/users.json",
		Body:           body,
	})
	if err != nil {
		t.Fatalf("ValidateFixture() error = %v", err)
	}
	if result.EventCount != 1 {
		t.Fatalf("EventCount = %d, want 1", result.EventCount)
	}
}

func testDefinition() connectordefinitions.Definition {
	definition, err := connectordefinitions.Normalize(connectordefinitions.Definition{
		SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
		ID:            "builtin-okta",
		TenantID:      "builtin_catalog",
		SourceID:      "okta",
		DisplayName:   "Okta",
		Auth: connectordefinitions.AuthSpec{
			Model: "bearer_token",
			CredentialFields: []connectordefinitions.Field{{
				Key:           "token",
				Secret:        true,
				ReferenceOnly: true,
				Required:      true,
			}},
		},
		Transport: &connectordefinitions.TransportSpec{
			BaseURL: "https://example.test",
			Verification: &connectordefinitions.VerificationSpec{
				Path: "/v1/users",
			},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "users",
			Path:           "/v1/users",
			Method:         "GET",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event: connectordefinitions.EventMappingSpec{
				Kind:                  "okta.users",
				SchemaRef:             "okta/users/v1",
				RequiredPayloadFields: []string{"id"},
			},
			Projection: &connectordefinitions.ProjectionSpec{
				Template: "identity_user",
				Fields: map[string]string{
					"user_id":      "id",
					"display_name": "name",
					"email":        "email",
					"status":       "status",
				},
			},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:          "cursor",
				CursorParam:   "cursor",
				PageSizeParam: "limit",
				PageSize:      100,
			},
			Coverage: []connectordefinitions.CoverageDimensionSpec{{
				Type:           "entity_family",
				Support:        "partial",
				HighValue:      true,
				EvidenceTypes:  []string{"source_snapshot"},
				ControlDomains: []string{"asset_inventory"},
			}},
		}},
	})
	if err != nil {
		panic(err)
	}
	return definition
}
