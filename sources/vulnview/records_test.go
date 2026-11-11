package vulnview

import "testing"

// TestAttributesForFindingProvenanceIntegrations pins Contract C2: the
// importer flattens provenance.integrations/repositoryIntegrations (arrays
// of {kind,id}) into sorted, comma-joined "kind:id" event attributes, and
// provenance.integrationAttribution into a plain attribute, with every
// bounded attribute absent (not present-but-empty) when the export omits
// it -- so a later version that drops integration attribution retracts it
// (internal/sourceprojection/vulnview.go's owned-attribute mechanism)
// instead of leaving a stale empty value.
func TestAttributesForFindingProvenanceIntegrations(t *testing.T) {
	values := map[string]any{
		"findingId": "f1",
		"source":    "cloud_identity",
		"checkId":   "cloud_identity_excess_privilege",
		"status":    "open",
		"severity":  "high",
		"version":   float64(1),
		"provenance": map[string]any{
			"integrations": []any{
				map[string]any{"kind": "cloud_account", "id": "222222222222"},
				map[string]any{"kind": "cloud_account", "id": "111111111111"},
			},
			"repositoryIntegrations": []any{
				map[string]any{"kind": "github", "id": "gh-2"},
				map[string]any{"kind": "github", "id": "gh-1"},
			},
			"integrationAttribution": "run",
		},
	}
	attrs := attributesFor(familyFinding, record{ID: "f1", Values: values})
	if got := attrs["provenance_integrations"]; got != "cloud_account:111111111111,cloud_account:222222222222" {
		t.Fatalf("provenance_integrations = %q, want sorted cloud_account:111111111111,cloud_account:222222222222", got)
	}
	if got := attrs["provenance_repository_integrations"]; got != "github:gh-1,github:gh-2" {
		t.Fatalf("provenance_repository_integrations = %q, want sorted github:gh-1,github:gh-2", got)
	}
	if got := attrs["provenance_integration_attribution"]; got != "run" {
		t.Fatalf("provenance_integration_attribution = %q, want run", got)
	}
}

// TestAttributesForFindingProvenanceIntegrationsAbsentWhenNotExported pins
// the "not_applicable"/"unknown" cases (nuclei/caido/port/dns, and
// historical rows without provable attribution): absent source fields must
// never fabricate an identity, so every provenance_* key below is simply
// absent from the bounded attributes rather than present-but-empty.
func TestAttributesForFindingProvenanceIntegrationsAbsentWhenNotExported(t *testing.T) {
	values := map[string]any{
		"findingId": "f1",
		"source":    "nuclei",
		"checkId":   "exposed-panel",
		"status":    "open",
		"severity":  "high",
		"version":   float64(1),
	}
	attrs := attributesFor(familyFinding, record{ID: "f1", Values: values})
	for _, key := range []string{"provenance_integrations", "provenance_repository_integrations", "provenance_integration_attribution"} {
		if _, ok := attrs[key]; ok {
			t.Fatalf("attrs still carries %q: %#v", key, attrs)
		}
	}
}

// TestAttributesForFindingProvenanceIntegrationsSkipsIncompleteElements
// pins that an integration element missing kind or id never emits a
// malformed "kind:" or ":id" fragment; it is dropped rather than
// fabricated.
func TestAttributesForFindingProvenanceIntegrationsSkipsIncompleteElements(t *testing.T) {
	values := map[string]any{
		"findingId": "f1",
		"source":    "cloud_identity",
		"checkId":   "cloud_identity_excess_privilege",
		"status":    "open",
		"severity":  "high",
		"version":   float64(1),
		"provenance": map[string]any{
			"integrations": []any{
				map[string]any{"kind": "cloud_account", "id": "111111111111"},
				map[string]any{"kind": "cloud_account"},
				map[string]any{"id": "222222222222"},
			},
		},
	}
	attrs := attributesFor(familyFinding, record{ID: "f1", Values: values})
	if got := attrs["provenance_integrations"]; got != "cloud_account:111111111111" {
		t.Fatalf("provenance_integrations = %q, want cloud_account:111111111111", got)
	}
}
