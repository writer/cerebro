package sbom

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
)

func TestRenderCycloneDXJSONPreservesComponentsAndDependencies(t *testing.T) {
	doc := filesystemanalyzer.SBOMDocument{
		Format:      "cyclonedx-json",
		SpecVersion: "1.5",
		GeneratedAt: time.Date(2026, 3, 21, 18, 0, 0, 0, time.UTC),
		Components: []filesystemanalyzer.SBOMComponent{
			{
				BOMRef:           "pkg:npm/express@4.18.2",
				Type:             "library",
				Name:             "express",
				Version:          "4.18.2",
				PURL:             "pkg:npm/express@4.18.2",
				Ecosystem:        "npm",
				Location:         "package-lock.json",
				DirectDependency: true,
				DependencyDepth:  1,
			},
		},
		Dependencies: []filesystemanalyzer.SBOMDependency{
			{Ref: "pkg:npm/express@4.18.2", DependsOn: []string{"pkg:npm/body-parser@1.20.2"}},
		},
	}

	payload, contentType, err := Render(FormatCycloneDXJSON, SourceDescriptor{
		Name:        "image-scan",
		Namespace:   "image_scan",
		RunID:       "image_scan:1",
		GeneratedAt: doc.GeneratedAt,
	}, doc)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if contentType != "application/vnd.cyclonedx+json" {
		t.Fatalf("contentType = %q, want application/vnd.cyclonedx+json", contentType)
	}

	var rendered map[string]any
	if err := json.Unmarshal(payload, &rendered); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if rendered["bomFormat"] != "CycloneDX" {
		t.Fatalf("bomFormat = %#v, want CycloneDX", rendered["bomFormat"])
	}
	if rendered["specVersion"] != "1.5" {
		t.Fatalf("specVersion = %#v, want 1.5", rendered["specVersion"])
	}
	components, ok := rendered["components"].([]any)
	if !ok || len(components) != 1 {
		t.Fatalf("expected 1 component, got %#v", rendered["components"])
	}
	component := components[0].(map[string]any)
	if component["name"] != "express" || component["version"] != "4.18.2" {
		t.Fatalf("unexpected component %#v", component)
	}
	dependencies, ok := rendered["dependencies"].([]any)
	if !ok || len(dependencies) != 1 {
		t.Fatalf("expected 1 dependency, got %#v", rendered["dependencies"])
	}
	dep := dependencies[0].(map[string]any)
	if dep["ref"] != "pkg:npm/express@4.18.2" {
		t.Fatalf("unexpected dependency ref %#v", dep["ref"])
	}
}

func TestRenderSPDXJSONBuildsPackagesAndRelationships(t *testing.T) {
	doc := filesystemanalyzer.SBOMDocument{
		Format:      "cyclonedx-json",
		SpecVersion: "1.5",
		GeneratedAt: time.Date(2026, 3, 21, 18, 30, 0, 0, time.UTC),
		Components: []filesystemanalyzer.SBOMComponent{
			{
				BOMRef:   "pkg:golang/github.com/google/uuid@1.6.0",
				Type:     "library",
				Name:     "github.com/google/uuid",
				Version:  "1.6.0",
				PURL:     "pkg:golang/github.com/google/uuid@1.6.0",
				Location: "go.mod",
			},
			{
				BOMRef:   "app:golang/example.com/demo",
				Type:     "application",
				Name:     "example.com/demo",
				Version:  "1.0.0",
				Location: "go.mod",
			},
		},
		Dependencies: []filesystemanalyzer.SBOMDependency{
			{Ref: "app:golang/example.com/demo", DependsOn: []string{"pkg:golang/github.com/google/uuid@1.6.0"}},
		},
	}

	payload, contentType, err := Render(FormatSPDXJSON, SourceDescriptor{
		Name:        "repo-scan",
		Namespace:   "repo_scan",
		RunID:       "repo_scan:1",
		GeneratedAt: doc.GeneratedAt,
	}, doc)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if contentType != "application/spdx+json" {
		t.Fatalf("contentType = %q, want application/spdx+json", contentType)
	}

	var rendered map[string]any
	if err := json.Unmarshal(payload, &rendered); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if rendered["spdxVersion"] != "SPDX-2.3" {
		t.Fatalf("spdxVersion = %#v, want SPDX-2.3", rendered["spdxVersion"])
	}
	packages, ok := rendered["packages"].([]any)
	if !ok || len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %#v", rendered["packages"])
	}
	relationships, ok := rendered["relationships"].([]any)
	if !ok || len(relationships) < 3 {
		t.Fatalf("expected describe and dependency relationships, got %#v", rendered["relationships"])
	}
}
