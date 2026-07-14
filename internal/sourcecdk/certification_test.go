package sourcecdk

import (
	"strings"
	"testing"
)

func TestLoadSourceCatalogCertification(t *testing.T) {
	catalog, err := LoadSourceCatalog([]byte(certificationCatalogYAML("provider_spec", "reference: https://provider.example/spec")))
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	if catalog.Certification == nil || catalog.Certification.Owner != "source-runtime" {
		t.Fatalf("Certification = %+v", catalog.Certification)
	}
	stored, ok := CatalogCertificationForSource("certification-test")
	if !ok || len(stored.Evidence) != 1 {
		t.Fatalf("CatalogCertificationForSource() = %+v, %t", stored, ok)
	}
	stored.Evidence[0].Families = append(stored.Evidence[0].Families, "mutated")
	again, _ := CatalogCertificationForSource("certification-test")
	if len(again.Evidence[0].Families) != 1 {
		t.Fatal("stored certification was mutated through returned clone")
	}
}

func TestLoadSourceCatalogCertificationRejectsInvalidProof(t *testing.T) {
	tests := map[string]string{
		"unknown evidence":      strings.Replace(certificationCatalogYAML("provider_spec", "reference: https://provider.example/spec"), "provider_spec", "trusted", 1),
		"invalid digest":        strings.Replace(certificationCatalogYAML("provider_spec", "reference: https://provider.example/spec"), strings.Repeat("0", 64), "bad", 1),
		"expired before review": strings.Replace(certificationCatalogYAML("provider_spec", "reference: https://provider.example/spec"), "2026-10-14", "2026-06-14", 1),
		"live state":            strings.Replace(certificationCatalogYAML("provider_spec", "reference: https://provider.example/spec"), "  evidence:", "  production_observed: true\n  evidence:", 1),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadSourceCatalog([]byte(data)); err == nil {
				t.Fatal("LoadSourceCatalog() error = nil")
			}
		})
	}
}

func certificationCatalogYAML(kind, locator string) string {
	return "id: certification-test\nname: Certification Test\ndescription: test\nemitted_kinds: [test.asset]\n" +
		"certification:\n  owner: source-runtime\n  reviewed_at: 2026-07-14T00:00:00Z\n  expires_at: 2026-10-14T00:00:00Z\n" +
		"  evidence:\n    - kind: " + kind + "\n      " + locator + "\n      digest: sha256:" + strings.Repeat("0", 64) + "\n      families: [assets]\n"
}
