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

func TestProjectArchetypeLibraryNoteLinksRepositoryContext(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "archetype-library-7-repository-commit-learning",
		TenantId: "writer",
		SourceId: "archetype",
		Kind:     "archetype.library_note",
		Attributes: map[string]string{
			"knowledge_slug":    "repository-commit-learning",
			"repository_id":     "7",
			"scan_id":           "1",
			"owner":             "WriterInternal",
			"repo":              "Archetype",
			"dominant_severity": "info",
		},
		Payload: []byte(`{"slug":"repository-commit-learning","title":"Repository commit learning","summary":"Archetype learned the latest repository head.","topics":["gitops","commits","librarian"]}`),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	repoURN := "urn:cerebro:writer:github_code_repository:WriterInternal/Archetype"
	noteURN := "urn:cerebro:writer:archetype_library_note:WriterInternal/Archetype:repository-commit-learning"
	scanURN := "urn:cerebro:writer:archetype_scan:1"
	if entity := state.entities[noteURN]; entity == nil || entity.EntityType != "archetype.library_note" {
		t.Fatalf("library note entity missing: %#v", entity)
	} else {
		if got := entity.Attributes["repository_id"]; got != "7" {
			t.Fatalf("repository_id attr = %q, want 7", got)
		}
		if got := entity.Attributes["repository"]; got != "WriterInternal/Archetype" {
			t.Fatalf("repository attr = %q, want WriterInternal/Archetype", got)
		}
		if got := entity.Attributes["title"]; got != "Repository commit learning" {
			t.Fatalf("title attr = %q, want Repository commit learning", got)
		}
		if got := entity.Attributes["topics"]; got != "gitops,commits,librarian" {
			t.Fatalf("topics attr = %q, want gitops,commits,librarian", got)
		}
		if got := entity.Attributes["dominant_severity"]; got != "info" {
			t.Fatalf("dominant_severity attr = %q, want info", got)
		}
	}
	if entity := state.entities[scanURN]; entity == nil || entity.EntityType != "archetype.scan" {
		t.Fatalf("scan entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, repoURN, relationHasEvidence, noteURN)
	assertProjectedLink(t, state, noteURN, relationBelongsTo, scanURN)
}

func TestProjectArchetypeLibraryNoteWithoutScanIDDoesNotCreateScan(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "archetype-library-7-repository-commit-learning",
		TenantId: "writer",
		SourceId: "archetype",
		Kind:     "archetype.library_note",
		Attributes: map[string]string{
			"knowledge_slug": "repository-commit-learning",
			"repository_id":  "7",
			"owner":          "WriterInternal",
			"repo":           "Archetype",
		},
		Payload: []byte(`{"slug":"repository-commit-learning","title":"Repository commit learning","summary":"Archetype learned the latest repository head."}`),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	repoURN := "urn:cerebro:writer:github_code_repository:WriterInternal/Archetype"
	noteURN := "urn:cerebro:writer:archetype_library_note:WriterInternal/Archetype:repository-commit-learning"
	phantomScanURN := "urn:cerebro:writer:archetype_scan"
	if entity := state.entities[phantomScanURN]; entity != nil {
		t.Fatalf("phantom scan entity = %#v, want none", entity)
	}
	assertProjectedLink(t, state, repoURN, relationHasEvidence, noteURN)
	assertProjectedLinkMissing(t, state, noteURN, relationBelongsTo, phantomScanURN)
}

func TestProjectArchetypeLibraryNoteEscapesSlugURNPart(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "archetype-library-7-security%3Asql-injection",
		TenantId: "writer",
		SourceId: "archetype",
		Kind:     "archetype.library_note",
		Attributes: map[string]string{
			"knowledge_slug": "security:sql-injection",
			"repository_id":  "7",
			"owner":          "WriterInternal",
			"repo":           "Archetype",
		},
		Payload: []byte(`{"slug":"security:sql-injection","title":"SQL injection context","summary":"Repository query handling context."}`),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	noteURN := "urn:cerebro:writer:archetype_library_note:WriterInternal/Archetype:security%3Asql-injection"
	unescapedURN := "urn:cerebro:writer:archetype_library_note:WriterInternal/Archetype:security:sql-injection"
	if entity := state.entities[noteURN]; entity == nil || entity.EntityType != "archetype.library_note" {
		t.Fatalf("escaped slug note entity missing: %#v", entity)
	}
	if entity := state.entities[unescapedURN]; entity != nil {
		t.Fatalf("unescaped slug entity = %#v, want none", entity)
	}
}
