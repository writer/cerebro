package findings

import (
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

// TestFindingFilterSupportCoversRequest fails when a field is added to
// ports.ListFindingsRequest without deciding whether the stub finding store
// applies it.
//
// Without this, a new filter defaults to being silently dropped by the stub:
// fast tests keep passing while the Postgres store filters on something they
// never exercise. That is the failure mode that hid the application workspace
// scoping regression until the nightly Integration job caught it.
func TestFindingFilterSupportCoversRequest(t *testing.T) {
	structType := reflect.TypeOf(ports.ListFindingsRequest{})
	seen := map[string]struct{}{}

	var walk func(reflect.Type)
	walk = func(current reflect.Type) {
		for i := range current.NumField() {
			field := current.Field(i)
			if field.Anonymous && field.Type.Kind() == reflect.Struct {
				walk(field.Type)
				continue
			}
			seen[field.Name] = struct{}{}
			if _, ok := findingFilterSupport[field.Name]; !ok {
				t.Errorf(
					"ports.ListFindingsRequest.%s is unclassified: add it to findingFilterSupport, "+
						"either implemented in findingMatches or explicitly unsupported",
					field.Name,
				)
			}
		}
	}
	walk(structType)

	for name := range findingFilterSupport {
		if _, ok := seen[name]; !ok {
			t.Errorf("findingFilterSupport lists %q, which is no longer a ListFindingsRequest field", name)
		}
	}
}

// TestUnsupportedFindingFilterIsRejected pins the fail-closed behaviour: a
// filter the stub cannot apply must surface as an error, never as a silently
// unfiltered result set.
func TestUnsupportedFindingFilterIsRejected(t *testing.T) {
	supported := ports.ListFindingsRequest{TenantID: "writer", RuleID: "rule-a", Status: "open"}
	if field := unsupportedFindingFilter(supported); field != "" {
		t.Fatalf("unsupportedFindingFilter(supported) = %q, want \"\"", field)
	}

	for name, request := range map[string]ports.ListFindingsRequest{
		"SLAStatus":  {TenantID: "writer", RuleID: "rule-a", SLAStatus: "overdue"},
		"MinAgeDays": {TenantID: "writer", RuleID: "rule-a", FindingAgeRange: ports.FindingAgeRange{MinAgeDays: 7}},
		"MaxAgeDays": {TenantID: "writer", RuleID: "rule-a", FindingAgeRange: ports.FindingAgeRange{MaxAgeDays: 30}},
		"ProfilePredicate": {
			TenantID:         "writer",
			RuleID:           "rule-a",
			ProfilePredicate: ports.FindingProfilePredicate{RuleIDs: []string{"rule-b"}},
		},
	} {
		if field := unsupportedFindingFilter(request); field != name {
			t.Errorf("unsupportedFindingFilter(%s) = %q, want %q", name, field, name)
		}
	}

	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{}}
	if _, err := store.ListFindings(t.Context(), ports.ListFindingsRequest{
		TenantID:  "writer",
		RuleID:    "rule-a",
		SLAStatus: "overdue",
	}); err == nil {
		t.Fatal("ListFindings() with an unsupported filter returned no error, want a rejection")
	}
}
