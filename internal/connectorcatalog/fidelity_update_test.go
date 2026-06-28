package connectorcatalog

import (
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

func TestHardenDefinitionFidelityAddsExplicitGraphContracts(t *testing.T) {
	definition := connectordefinitions.Definition{
		SourceID:    "example_saas",
		DisplayName: "Example SaaS",
		Description: "Collects users.",
		Auth:        connectordefinitions.AuthSpec{Model: "bearer_token"},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:        "users",
			Label:     "Users",
			Path:      "/v1/users",
			IDField:   "id",
			NameField: "name",
			Projection: &connectordefinitions.ProjectionSpec{
				Template: "identity_user",
			},
		}},
	}

	hardened, changes := HardenDefinitionFidelity(definition)

	if len(changes) == 0 {
		t.Fatal("changes = 0, want hardening changes")
	}
	if got := wordCount(hardened.Description); got < 18 {
		t.Fatalf("description word count = %d, want detailed description: %q", got, hardened.Description)
	}
	family := hardened.ResourceFamilies[0]
	if family.Event.Kind != "example_saas.users" {
		t.Fatalf("event kind = %q, want example_saas.users", family.Event.Kind)
	}
	if family.Event.SchemaRef != "example_saas/users/v1" {
		t.Fatalf("schema ref = %q, want example_saas/users/v1", family.Event.SchemaRef)
	}
	if family.Event.URNKind != "example_saas_users" {
		t.Fatalf("urn kind = %q, want example_saas_users", family.Event.URNKind)
	}
	if len(family.Event.RequiredPayloadFields) != 1 || family.Event.RequiredPayloadFields[0] != "id" {
		t.Fatalf("required payload fields = %#v, want id", family.Event.RequiredPayloadFields)
	}
	if got := family.Projection.Fields["user_id"]; got != "id" {
		t.Fatalf("user_id field = %q, want id", got)
	}
	if got := family.Projection.Fields["display_name"]; got != "name" {
		t.Fatalf("display_name field = %q, want name", got)
	}
	if got := family.Projection.Fields["email"]; !strings.Contains(got, "email") {
		t.Fatalf("email field = %q, want email path", got)
	}
	if len(hardened.ScopeOptions) != 0 {
		t.Fatalf("scope options = %#v, want no committed generated options", hardened.ScopeOptions)
	}
}

func TestHardenDefinitionFidelityPreservesExistingProjectionFields(t *testing.T) {
	definition := connectordefinitions.Definition{
		SourceID:    "example_saas",
		DisplayName: "Example SaaS",
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:        "users",
			IDField:   "id",
			NameField: "name",
			Projection: &connectordefinitions.ProjectionSpec{
				Template: "identity_user",
				Fields: map[string]string{
					"user_id": "profile.uid",
				},
			},
		}},
	}

	hardened, _ := HardenDefinitionFidelity(definition)

	fields := hardened.ResourceFamilies[0].Projection.Fields
	if got := fields["user_id"]; got != "profile.uid" {
		t.Fatalf("user_id field = %q, want existing profile.uid", got)
	}
	if got := fields["display_name"]; got != "name" {
		t.Fatalf("display_name field = %q, want generated name mapping", got)
	}
}

func TestHardenDefinitionFidelityNormalizesGeneratedEventKind(t *testing.T) {
	definition := connectordefinitions.Definition{
		SourceID:    "example-saas",
		DisplayName: "Example SaaS",
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:        "audit-logs",
			IDField:   "id",
			NameField: "name",
		}},
	}

	hardened, _ := HardenDefinitionFidelity(definition)
	family := hardened.ResourceFamilies[0]

	if family.Event.Kind != "example_saas.audit_logs" {
		t.Fatalf("event kind = %q, want example_saas.audit_logs", family.Event.Kind)
	}
	if family.Event.URNKind != "example_saas_audit_logs" {
		t.Fatalf("urn kind = %q, want example_saas_audit_logs", family.Event.URNKind)
	}
	normalized, err := connectordefinitions.Normalize(hardened)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	for _, check := range normalized.Validation.Checks {
		if check.ID == "event_kind_audit-logs" && check.Status == connectordefinitions.ValidationBlocked {
			t.Fatalf("event kind validation is blocking after normalization: %#v", check)
		}
	}
}

func TestHardenDefinitionFidelityMakesShallowSourceReferenceDepth(t *testing.T) {
	definition := reviewDefinition("example_saas", "Example SaaS", []connectordefinitions.ResourceFamily{
		{
			ID:             "users",
			Label:          "Users",
			Path:           "/v1/users",
			Method:         "GET",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			NameField:      "name",
			Projection:     &connectordefinitions.ProjectionSpec{Template: "identity_user"},
			Coverage: []connectordefinitions.CoverageDimensionSpec{{
				Type:           "entity_family",
				Support:        "partial",
				HighValue:      true,
				EvidenceTypes:  []string{"source_snapshot"},
				ControlDomains: []string{"asset_inventory"},
			}},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:           "cursor",
				CursorParam:    "cursor",
				CursorJSONPath: "$.next_cursor",
			},
			DefaultEnabled: true,
		},
	})
	definition.Transport.Verification.ExpectStatus = []int{200}

	hardened, changes := HardenDefinitionFidelity(definition)
	normalized, err := connectordefinitions.Normalize(hardened)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	score, gaps := sourceFidelity(Entry{Definition: normalized})

	if len(changes) == 0 {
		t.Fatal("changes = 0, want hardening changes")
	}
	if score < fidelityReviewThreshold {
		t.Fatalf("score = %d, gaps = %#v, want at least %d", score, gaps, fidelityReviewThreshold)
	}
}
