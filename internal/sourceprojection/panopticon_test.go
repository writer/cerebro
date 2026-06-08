package sourceprojection

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type crossRepoPanopticonArchiveManifest struct {
	Archives []struct {
		Family string `json:"family"`
		Gzip   bool   `json:"gzip"`
		Path   string `json:"path"`
	} `json:"archives"`
}

type crossRepoPanopticonEvent struct {
	ID         string            `json:"id"`
	TenantID   string            `json:"tenant_id"`
	SourceID   string            `json:"source_id"`
	Kind       string            `json:"kind"`
	OccurredAt time.Time         `json:"occurred_at"`
	SchemaRef  string            `json:"schema_ref"`
	Payload    map[string]any    `json:"payload"`
	Attributes map[string]string `json:"attributes"`
}

func TestProjectPanopticonGeneratedCaseArchivePreservesEvidenceCASPointer(t *testing.T) {
	manifest := generatePanopticonCrossRepoArchives(t)
	var caseEvent crossRepoPanopticonEvent
	for _, archive := range manifest.Archives {
		if archive.Family != "case" || archive.Gzip {
			continue
		}
		caseEvent = readOneCrossRepoPanopticonEvent(t, archive.Path)
		break
	}
	if caseEvent.ID == "" {
		t.Fatal("generated Panopticon case archive not found")
	}

	payload, err := json.Marshal(caseEvent.Payload)
	if err != nil {
		t.Fatalf("marshal generated case payload: %v", err)
	}
	state := &projectionRecorder{}
	service := New(state, nil)
	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         caseEvent.ID,
		TenantId:   caseEvent.TenantID,
		SourceId:   caseEvent.SourceID,
		Kind:       caseEvent.Kind,
		SchemaRef:  caseEvent.SchemaRef,
		OccurredAt: timestamppb.New(caseEvent.OccurredAt),
		Payload:    payload,
		Attributes: caseEvent.Attributes,
	})
	if err != nil {
		t.Fatalf("Project(generated Panopticon case) error = %v", err)
	}
	if result.EntitiesProjected == 0 || result.LinksProjected == 0 {
		t.Fatalf("generated Panopticon case projected no graph context: entities=%d links=%d", result.EntitiesProjected, result.LinksProjected)
	}

	var pointer *ports.ProjectedEntity
	for _, entity := range state.entities {
		if entity.EntityType == "evidence.cas.pointer" {
			pointer = entity
			break
		}
	}
	if pointer == nil {
		t.Fatal("generated Panopticon case did not project an EvidenceCAS pointer entity")
	}
	if got := pointer.Attributes["evidence_cas_uri"]; got != "evidencecas://cases/42/evidence/triage.tar" {
		t.Fatalf("projected EvidenceCAS URI = %q", got)
	}
	if got := pointer.Attributes["sha256"]; got != "sha256:abc" {
		t.Fatalf("projected EvidenceCAS digest = %q", got)
	}
	if got := pointer.Attributes["chain_of_custody_present"]; got != "true" {
		t.Fatalf("projected chain_of_custody_present = %q", got)
	}
	serialized, err := json.Marshal(state.entities)
	if err != nil {
		t.Fatalf("marshal projected entities: %v", err)
	}
	for _, forbidden := range []string{"DO-NOT-EXPORT-CONTENTS", "DO-NOT-EXPORT-BYTES", "DO-NOT-EXPORT-INLINE", "DO-NOT-EXPORT-RAW"} {
		if strings.Contains(string(serialized), forbidden) {
			t.Fatalf("projected generated Panopticon archive included inline evidence bytes marker %q", forbidden)
		}
	}
}

func generatePanopticonCrossRepoArchives(t *testing.T) crossRepoPanopticonArchiveManifest {
	t.Helper()
	panopticonRepo := os.Getenv("PANOPTICON_REPO")
	if panopticonRepo == "" {
		panopticonRepo = filepath.Clean("../../../panopticon")
	}
	script := filepath.Join(panopticonRepo, "scripts", "generate_cerebro_contract_archives.py")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("Panopticon cross-repo archive generator not available at %s: %v", script, err)
	}
	outputDir := t.TempDir()
	cmd := exec.Command("python3", script, "--output-dir", outputDir)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generate Panopticon cross-repo archives: %v\n%s", err, out)
	}
	manifestPath := filepath.Join(outputDir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read generated Panopticon manifest: %v", err)
	}
	var manifest crossRepoPanopticonArchiveManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode generated Panopticon manifest: %v", err)
	}
	return manifest
}

func readOneCrossRepoPanopticonEvent(t *testing.T, path string) crossRepoPanopticonEvent {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated Panopticon archive %s: %v", path, err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("generated Panopticon archive %s has %d records, want 1", path, len(lines))
	}
	var event crossRepoPanopticonEvent
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatalf("decode generated Panopticon event: %v", err)
	}
	return event
}

func TestProjectPanopticonCaseBuildsLinkedGraphAndEvidencePointers(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 8, 12, 0, 0, 0, time.UTC)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "panopticon-case-event-1",
		TenantId:   "writer",
		SourceId:   "panopticon",
		Kind:       "panopticon.case",
		OccurredAt: timestamppb.New(occurred),
		Attributes: map[string]string{
			"case_id": "case-1",
			"status":  "investigating",
			"title":   "Credential exposure investigation",
		},
		Payload: mustJSON(t, map[string]any{
			"case_id": "case-1",
			"status":  "investigating",
			"title":   "Credential exposure investigation",
			"alerts": []map[string]any{{
				"alert_id": "alert-1",
				"title":    "Suspicious token use",
				"severity": "high",
				"status":   "open",
			}},
			"iocs": []map[string]any{{
				"ioc_id":   "ioc-1",
				"ioc_type": "domain",
				"value":    "evil.example",
			}},
			"assets": []map[string]any{{
				"asset_id":   "asset-1",
				"asset_type": "host",
				"name":       "prod-host-1",
			}},
			"evidence": []map[string]any{{
				"evidence_id":         "evidence-1",
				"evidence_cas":        "cas://objects/evidence-1",
				"sha256":              "abc123",
				"content_type":        "application/json",
				"inline_bytes":        "must-not-be-projected",
				"chain_of_custody":    []map[string]any{{"step": "captured", "actor": "panopticon"}},
				"chain_of_custody_id": "chain-1",
			}},
			"timeline": []map[string]any{{
				"event_id": "timeline-1",
				"title":    "Analyst opened case",
			}},
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected == 0 || result.LinksProjected == 0 {
		t.Fatalf("expected linked case projection, got entities=%d links=%d", result.EntitiesProjected, result.LinksProjected)
	}

	caseURN := "urn:cerebro:writer:panopticon_case:case-1"
	alertURN := "urn:cerebro:writer:panopticon_alert:alert-1"
	iocURN := "urn:cerebro:writer:panopticon_ioc:ioc-1"
	assetURN := "urn:cerebro:writer:panopticon_asset:asset-1"
	evidenceURN := "urn:cerebro:writer:evidence_cas_pointer:evidence-1"

	if entity := state.entities[caseURN]; entity == nil || entity.EntityType != "panopticon.case" {
		t.Fatalf("case entity missing or wrong type: %#v", entity)
	}
	if entity := state.entities[alertURN]; entity == nil || entity.EntityType != "panopticon.alert" {
		t.Fatalf("linked alert entity missing or wrong type: %#v", entity)
	}
	if entity := state.entities[iocURN]; entity == nil || entity.EntityType != "panopticon.ioc" {
		t.Fatalf("linked IOC entity missing or wrong type: %#v", entity)
	}
	if entity := state.entities[assetURN]; entity == nil || entity.EntityType != "panopticon.asset" {
		t.Fatalf("linked asset entity missing or wrong type: %#v", entity)
	}
	evidence := state.entities[evidenceURN]
	if evidence == nil || evidence.EntityType != "evidence.cas.pointer" {
		t.Fatalf("EvidenceCAS pointer entity missing or wrong type: %#v", evidence)
	}
	if got := evidence.Attributes["evidence_cas"]; got != "cas://objects/evidence-1" {
		t.Fatalf("EvidenceCAS pointer = %q, want cas://objects/evidence-1", got)
	}
	if got := evidence.Attributes["sha256"]; got != "abc123" {
		t.Fatalf("EvidenceCAS sha256 = %q, want abc123", got)
	}
	if got := evidence.Attributes["chain_of_custody_present"]; got != "true" {
		t.Fatalf("EvidenceCAS chain_of_custody_present = %q, want true", got)
	}
	for key, value := range evidence.Attributes {
		if strings.Contains(key, "bytes") || strings.Contains(value, "must-not-be-projected") {
			t.Fatalf("EvidenceCAS projected inline evidence bytes in %q=%q", key, value)
		}
	}

	assertProjectedLink(t, state, caseURN, relationContains, alertURN)
	assertProjectedLink(t, state, alertURN, relationBelongsTo, caseURN)
	assertProjectedLink(t, state, caseURN, relationHasEvidence, iocURN)
	assertProjectedLink(t, state, caseURN, relationContains, assetURN)
	assertProjectedLink(t, state, caseURN, relationHasEvidence, evidenceURN)
	assertProjectedLink(t, state, evidenceURN, relationBelongsTo, caseURN)

	for urn, entity := range state.entities {
		if strings.Contains(strings.ToLower(entity.EntityType), "finding") || strings.Contains(strings.ToLower(urn), ":finding") || strings.Contains(strings.ToLower(urn), "timeline") {
			t.Fatalf("raw Panopticon temporal data should not be promoted into findings/timeline entities: %s %#v", urn, entity)
		}
	}
}

func TestProjectPanopticonAlertAndIOCLinkToCasesAssetsAndEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-alert-event-1",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.alert",
		Attributes: map[string]string{
			"alert_id": "alert-1",
			"case_id":  "case-1",
			"severity": "critical",
			"status":   "open",
			"title":    "Suspicious domain observed",
		},
		Payload: mustJSON(t, map[string]any{
			"alert_id": "alert-1",
			"case_id":  "case-1",
			"severity": "critical",
			"status":   "open",
			"title":    "Suspicious domain observed",
			"iocs": []map[string]any{{
				"ioc_id":   "ioc-1",
				"ioc_type": "domain",
				"value":    "evil.example",
			}},
			"assets": []map[string]any{{
				"asset_id":   "asset-1",
				"asset_type": "host",
				"name":       "prod-host-1",
			}},
		}),
	})
	if err != nil {
		t.Fatalf("Project(alert) error = %v", err)
	}
	_, err = service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-ioc-event-1",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.ioc",
		Attributes: map[string]string{
			"ioc_id":   "ioc-1",
			"ioc_type": "domain",
			"value":    "evil.example",
			"case_id":  "case-1",
			"alert_id": "alert-1",
		},
		Payload: mustJSON(t, map[string]any{
			"ioc_id":   "ioc-1",
			"ioc_type": "domain",
			"value":    "evil.example",
			"case_id":  "case-1",
			"alert_id": "alert-1",
		}),
	})
	if err != nil {
		t.Fatalf("Project(ioc) error = %v", err)
	}

	alertURN := "urn:cerebro:writer:panopticon_alert:alert-1"
	caseURN := "urn:cerebro:writer:panopticon_case:case-1"
	iocURN := "urn:cerebro:writer:panopticon_ioc:ioc-1"
	assetURN := "urn:cerebro:writer:panopticon_asset:asset-1"

	assertProjectedLink(t, state, alertURN, relationBelongsTo, caseURN)
	assertProjectedLink(t, state, alertURN, relationHasEvidence, iocURN)
	assertProjectedLink(t, state, alertURN, relationObservedOn, assetURN)
	assertProjectedLink(t, state, iocURN, relationBelongsTo, caseURN)
	assertProjectedLink(t, state, alertURN, relationHasEvidence, iocURN)
}
