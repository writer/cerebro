package connectorvalidation

import (
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

func TestNormalizeEntryValidationDefaultsGeneratedFromDocs(t *testing.T) {
	validation := NormalizeEntryValidation("okta", ConnectorValidation{}, "supported")
	if validation.SourceID != "okta" {
		t.Fatalf("source_id = %q, want okta", validation.SourceID)
	}
	if validation.Grade != GradeGeneratedFromDocs {
		t.Fatalf("grade = %q, want %q", validation.Grade, GradeGeneratedFromDocs)
	}
	if len(validation.Evidence) != 1 || validation.Evidence[0].Type != "classifier_output" {
		t.Fatalf("evidence = %#v, want classifier output evidence", validation.Evidence)
	}
}

func TestLoadRegistryNormalizesFamilyGrades(t *testing.T) {
	registry, err := LoadRegistry([]byte(`
entries:
  - source_id: okta
    grade: fixture_validated
    evidence:
      - type: fixture
        ref: testdata/okta.json
        resource_family: users
    resource_families:
      - id: users
`))
	if err != nil {
		t.Fatalf("LoadRegistry() error = %v", err)
	}
	validation, ok := registry.BySourceID("okta")
	if !ok {
		t.Fatal("BySourceID(okta) = false, want true")
	}
	if got := FamilyGrade(validation, "users"); got != GradeFixtureValidated {
		t.Fatalf("FamilyGrade = %q, want fixture_validated", got)
	}
}

func TestValidateClaimRejectsGradeWithoutEvidence(t *testing.T) {
	errs := ValidateClaim(minimalDefinition(), ConnectorValidation{SourceID: "okta", Grade: GradeFixtureValidated})
	if len(errs) == 0 {
		t.Fatal("ValidateClaim() errors = nil, want missing evidence error")
	}
}

func minimalDefinition() connectordefinitions.Definition {
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
		}, {
			ID:             "groups",
			Path:           "/v1/groups",
			Method:         "GET",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event: connectordefinitions.EventMappingSpec{
				Kind:      "okta.groups",
				SchemaRef: "okta/groups/v1",
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
