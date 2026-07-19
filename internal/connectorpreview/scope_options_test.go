package connectorpreview

import (
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestScopeOptionsFromCoverage(t *testing.T) {
	contract := sourcecdk.CoverageContract{
		SourceID: "example",
		Dimensions: []sourcecdk.CoverageDimension{
			{ID: "users", Type: "identity", Title: "Users", Families: []string{"user"}, Support: sourcecdk.CoverageSupportSupported},
			{ID: "assets", Type: "asset", Title: "Assets", Families: []string{"asset"}, Support: sourcecdk.CoverageSupportSupported, HighValue: true},
			{ID: "planned", Type: "asset", Title: "Planned", Families: []string{"planned"}, Support: sourcecdk.CoverageSupportPlanned},
			{ID: "unsupported", Type: "asset", Title: "Unsupported", Families: []string{"x"}, Support: sourcecdk.CoverageSupportUnsupported},
			{ID: "nofam", Type: "asset", Title: "No Families", Support: sourcecdk.CoverageSupportSupported},
		},
	}
	options := ScopeOptionsFromCoverage(contract)
	if len(options) != 2 {
		t.Fatalf("expected 2 options after filtering, got %d: %#v", len(options), options)
	}
	// HighValue sorts first regardless of label.
	if options[0].ID != "assets" || !options[0].HighValue {
		t.Errorf("first option = %#v, want high-value assets", options[0])
	}
	if options[1].ID != "users" {
		t.Errorf("second option = %#v, want users", options[1])
	}
}

func TestScopeOptionsFromCoverageCopiesSlices(t *testing.T) {
	families := []string{"user"}
	contract := sourcecdk.CoverageContract{
		Dimensions: []sourcecdk.CoverageDimension{
			{ID: "users", Title: "Users", Families: families, Support: sourcecdk.CoverageSupportSupported},
		},
	}
	options := ScopeOptionsFromCoverage(contract)
	options[0].Families[0] = "mutated"
	if families[0] != "user" {
		t.Errorf("source families slice was mutated: %v", families)
	}
}

func TestScopeOptionsFromKinds(t *testing.T) {
	options := ScopeOptionsFromKinds([]string{"okta.user", "  ", "aws.iam_role", ""})
	if len(options) != 2 {
		t.Fatalf("expected 2 options, got %d: %#v", len(options), options)
	}
	// Sorted case-insensitively by label: "AWS IAM Role" < "Okta User".
	if options[0].ID != "aws.iam_role" {
		t.Errorf("first option = %#v, want aws.iam_role", options[0])
	}
	if options[0].Label != "AWS IAM Role" {
		t.Errorf("label = %q, want %q", options[0].Label, "AWS IAM Role")
	}
	if options[0].Type != "emitted_kind" || options[0].Support != sourcecdk.CoverageSupportSupported {
		t.Errorf("unexpected option shape: %#v", options[0])
	}
	if !reflect.DeepEqual(options[1].Families, []string{"okta.user"}) {
		t.Errorf("families = %#v, want [okta.user]", options[1].Families)
	}
}

func TestScopeOptionsFromDefinition(t *testing.T) {
	definition := connectordefinitions.Definition{
		ResourceFamilies: []connectordefinitions.ResourceFamily{
			{
				ID:    "identities",
				Label: "Identities",
				Coverage: []connectordefinitions.CoverageDimensionSpec{
					{ID: "users", Type: "identity", Title: "Users", Families: []string{"user"}, Support: sourcecdk.CoverageSupportSupported, HighValue: true, ControlRefs: []connectordefinitions.CoverageControlRefSpec{{FrameworkID: "soc2", FrameworkName: "SOC 2", ControlID: "CC6.1"}}},
					{ID: "gap", Type: "identity", Title: "Gap", Families: []string{"x"}, Support: sourcecdk.CoverageSupportUnsupported},
				},
			},
			{
				ID: "assets",
				Coverage: []connectordefinitions.CoverageDimensionSpec{
					// Empty title falls back to family label / derived label.
					{ID: "assets", Type: "asset", Families: []string{"asset"}, Support: sourcecdk.CoverageSupportSupported},
				},
			},
		},
	}
	options := ScopeOptionsFromDefinition(definition)
	if len(options) != 2 {
		t.Fatalf("expected 2 options, got %d: %#v", len(options), options)
	}
	// HighValue users sorts first.
	if options[0].ID != "users" || !options[0].HighValue {
		t.Errorf("first option = %#v, want high-value users", options[0])
	}
	if len(options[0].ControlRefs) != 1 || options[0].ControlRefs[0].ControlID != "CC6.1" {
		t.Errorf("control refs = %#v, want CC6.1", options[0].ControlRefs)
	}
	// Second family has no explicit label or title; derived from family ID.
	if options[1].ID != "assets" || options[1].Label != "Assets" {
		t.Errorf("second option = %#v, want assets labelled Assets", options[1])
	}
}

func TestFieldLabel(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"user_id", "User ID"},
		{"iam_role", "IAM Role"},
		{"sso_config", "SSO Config"},
		{"gcp_project", "GCP Project"},
		{"  ", ""},
		{"single", "Single"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := fieldLabel(tc.in); got != tc.want {
				t.Errorf("fieldLabel(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "x", "y"); got != "x" {
		t.Errorf("firstNonEmpty() = %q, want x", got)
	}
	if got := firstNonEmpty(""); got != "" {
		t.Errorf("firstNonEmpty() = %q, want empty", got)
	}
}

func TestControlRefsFromDefinition(t *testing.T) {
	refs := controlRefsFromDefinition([]connectordefinitions.CoverageControlRefSpec{
		{FrameworkID: "soc2", FrameworkName: "SOC 2", ControlID: "CC6.1"},
	})
	want := []sourcecdk.CoverageControlRef{{FrameworkID: "soc2", FrameworkName: "SOC 2", ControlID: "CC6.1"}}
	if !reflect.DeepEqual(refs, want) {
		t.Errorf("controlRefsFromDefinition() = %#v, want %#v", refs, want)
	}
}
