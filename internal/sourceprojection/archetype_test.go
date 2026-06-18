package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectArchetypeVulnerabilityLinksRepoScanAndFinding(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "archetype-vulnerability-10",
		TenantId: "writer",
		SourceId: "archetype",
		Kind:     "archetype.vulnerability",
		Attributes: map[string]string{
			"vulnerability_id": "10",
			"scan_id":          "1",
			"repository_id":    "7",
			"owner":            "WriterInternal",
			"repo":             "Archetype",
			"severity":         "high",
			"category":         "ssrf",
			"file_path":        "app/main.py",
			"line_number":      "42",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 3 {
		t.Fatalf("Project().EntitiesProjected = %d, want 3", result.EntitiesProjected)
	}
	if result.LinksProjected != 3 {
		t.Fatalf("Project().LinksProjected = %d, want 3", result.LinksProjected)
	}
	repoURN := "urn:cerebro:writer:github_code_repository:WriterInternal/Archetype"
	scanURN := "urn:cerebro:writer:archetype_scan:1"
	findingURN := "urn:cerebro:writer:archetype_finding:10"
	if entity := state.entities[findingURN]; entity == nil || entity.EntityType != "archetype.finding" {
		t.Fatalf("finding entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, findingURN, relationBelongsTo, scanURN)
	assertProjectedLink(t, state, repoURN, relationHasEvidence, findingURN)
	assertProjectedLink(t, state, findingURN, relationAffects, repoURN)
}

func TestProjectArchetypeScanLinksRepositoryEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "archetype-scan-1",
		TenantId: "writer",
		SourceId: "archetype",
		Kind:     "archetype.scan",
		Attributes: map[string]string{
			"scan_id":       "1",
			"repository_id": "7",
			"owner":         "WriterInternal",
			"repo":          "Archetype",
			"status":        "completed",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	repoURN := "urn:cerebro:writer:github_code_repository:WriterInternal/Archetype"
	scanURN := "urn:cerebro:writer:archetype_scan:1"
	assertProjectedLink(t, state, repoURN, relationHasEvidence, scanURN)
	assertProjectedLink(t, state, scanURN, relationObservedOn, repoURN)
}
