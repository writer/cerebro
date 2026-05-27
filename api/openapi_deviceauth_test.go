package apicontract

import (
	"os"
	"strings"
	"testing"
)

func TestTelemetryIngestDocumentsDPoPContract(t *testing.T) {
	docBytes, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	section := openAPIPathSection(t, string(docBytes), "/platform/telemetry/ingest")
	for _, want := range []string{
		"name: DPoP",
		"`cnf.jkt`",
		"'401':",
		"dpop_required",
		"dpop_malformed",
		"dpop_invalid",
	} {
		if !strings.Contains(section, want) {
			t.Fatalf("telemetry ingest OpenAPI section missing %q:\n%s", want, section)
		}
	}
}

func openAPIPathSection(t *testing.T, doc string, path string) string {
	t.Helper()
	start := strings.Index(doc, "  "+path+":")
	if start < 0 {
		t.Fatalf("OpenAPI path %s not found", path)
	}
	rest := doc[start+1:]
	next := strings.Index(rest[1:], "\n  /")
	if next < 0 {
		return rest
	}
	return rest[:next+1]
}
