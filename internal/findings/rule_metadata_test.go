package findings

import "testing"

func TestBuiltinRuleMetadataIsComplete(t *testing.T) {
	metadata := BuiltinRuleMetadata()
	if len(metadata) == 0 {
		t.Fatal("BuiltinRuleMetadata() = 0, want built-in rule metadata")
	}
	if errs := ValidateRuleMetadataCompleteness(metadata); len(errs) != 0 {
		t.Fatalf("ValidateRuleMetadataCompleteness() first error = %v (count=%d)", errs[0], len(errs))
	}
}

func TestBuiltinPublicDetectionCatalogIncludesGraphRules(t *testing.T) {
	catalog := BuiltinPublicDetectionCatalog()
	if len(catalog.Detections) == 0 {
		t.Fatal("BuiltinPublicDetectionCatalog() has no detections")
	}
	for _, detection := range catalog.Detections {
		if detection.ID == "cloud-public-exposure-privileged-principal" {
			if detection.EvaluationMode != "graph" {
				t.Fatalf("graph detection evaluation_mode = %q, want graph", detection.EvaluationMode)
			}
			return
		}
	}
	t.Fatal("BuiltinPublicDetectionCatalog() missing cloud graph rule")
}
