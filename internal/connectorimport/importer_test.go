package connectorimport

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/writer/cerebro/internal/connectorcatalog"
)

const exampleSpec = `{
  "openapi": "3.0.3",
  "info": {"title": "Example Provider", "version": "1.0.0", "description": "Example provider for tests."},
  "servers": [{"url": "https://api.example.com"}],
  "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
  "security": [{"bearerAuth": []}],
  "paths": {
    "/v1/users": {"get": {"operationId": "listUsers", "summary": "List users",
      "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "array", "items": {"type": "object", "properties": {"id": {"type": "string"}, "email": {"type": "string"}, "name": {"type": "string"}}}}}}}}}}}},
    "/v1/audit/events": {"get": {"operationId": "listAuditEvents", "summary": "List audit events",
      "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "array", "items": {"type": "object", "properties": {"id": {"type": "string"}, "event_type": {"type": "string"}, "actor_id": {"type": "string"}}}}}}}}}}}},
    "/v1/projects": {"get": {"operationId": "listProjects", "summary": "List projects",
      "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "array", "items": {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string"}}}}}}}}}}}}
  }
}`

func loadExample(t *testing.T) *openapi3.T {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(exampleSpec))
	if err != nil {
		t.Fatalf("load example spec: %v", err)
	}
	return doc
}

func TestGenerateTargetSupported(t *testing.T) {
	outcome := GenerateTarget(loadExample(t), Target{SourceID: "example_provider", Domain: "collaboration-productivity"})
	if outcome.Verdict != VerdictSupported {
		t.Fatalf("verdict = %q, missing = %v, err = %q", outcome.Verdict, outcome.MissingFeatures, outcome.Error)
	}
	if outcome.FamilyCount < 2 {
		t.Fatalf("family count = %d, want >= 2", outcome.FamilyCount)
	}
	if !outcome.CatalogReady() {
		t.Fatalf("expected catalog-ready outcome")
	}
}

func TestRenderedEntriesAreCatalogGenerateable(t *testing.T) {
	outcome := GenerateTarget(loadExample(t), Target{SourceID: "example_provider", Domain: "collaboration-productivity"})
	body, err := RenderCatalogEntries("Generated test entries.", []Outcome{outcome})
	if err != nil {
		t.Fatalf("render entries: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "example.yaml"), body, 0o600); err != nil {
		t.Fatalf("write entries: %v", err)
	}
	analysis, err := connectorcatalog.AnalyzeDir(dir, connectorcatalog.Options{DryRunSourcegen: true})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(analysis.Issues) != 0 {
		t.Fatalf("unexpected catalog issues: %v", analysis.Issues)
	}
	if len(analysis.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(analysis.Entries))
	}
	if got := analysis.Entries[0].Status; got != connectorcatalog.StatusGenerateable {
		t.Fatalf("status = %q, want %q", got, connectorcatalog.StatusGenerateable)
	}
	if got := analysis.Entries[0].Definition.SourceID; got != "example_provider" {
		t.Fatalf("source id = %q", got)
	}
}

func TestRenderCatalogEntryBlocksStripsEntriesKey(t *testing.T) {
	outcome := GenerateTarget(loadExample(t), Target{SourceID: "example_provider", Domain: "collaboration-productivity"})
	blocks, err := RenderCatalogEntryBlocks([]Outcome{outcome})
	if err != nil {
		t.Fatalf("render blocks: %v", err)
	}
	block, ok := blocks["example_provider"]
	if !ok {
		t.Fatalf("missing block for example_provider: %v", blocks)
	}
	if len(block) == 0 || block[0] != ' ' {
		t.Fatalf("expected indented list item, got %q", block)
	}
}

func TestSummarizeFunnel(t *testing.T) {
	outcomes := []Outcome{
		{SourceID: "a", Domain: "devops-ci-cd", Verdict: VerdictSupported, AuthModel: "bearer_token"},
		{SourceID: "b", Verdict: VerdictGenerationError, Error: "no sourcegen-ready GET list endpoints found"},
		{SourceID: "c", Verdict: VerdictExtensionRequired, AuthModel: "api_key", MissingFeatures: []string{"auth.api_key"}},
	}
	summary := Summarize(outcomes)
	if summary.Targets != 3 || summary.Supported != 1 || summary.GenerationError != 1 || summary.ExtensionNeeded != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if summary.YieldPercent < 33.0 || summary.YieldPercent > 33.4 {
		t.Fatalf("yield = %v, want ~33.3", summary.YieldPercent)
	}
	if summary.BlockingReasons["generation.no_list_endpoint"] != 1 {
		t.Fatalf("missing generation bucket: %v", summary.BlockingReasons)
	}
	if summary.BlockingReasons["auth.api_key"] != 1 {
		t.Fatalf("missing classifier feature: %v", summary.BlockingReasons)
	}
}
