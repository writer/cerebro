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
	// #nosec G703 -- test-only optional local cross-repo fixture path.
	if _, err := os.Stat(script); err != nil {
		t.Skipf("Panopticon cross-repo archive generator not available at %s: %v", script, err)
	}
	outputDir := t.TempDir()
	// #nosec G204 G702 -- test-only optional local cross-repo fixture generator.
	cmd := exec.Command("python3", script, "--output-dir", outputDir)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generate Panopticon cross-repo archives: %v\n%s", err, out)
	}
	manifestPath := filepath.Join(outputDir, "manifest.json")
	// #nosec G304 -- manifest is read from this test's temporary output directory.
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
	// #nosec G304 -- path comes from the generated test manifest.
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
			"case_id":   "case-1",
			"status":    "investigating",
			"title":     "Credential exposure investigation",
			"alert_ids": "alert-4",
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

func TestProjectPanopticonCaseLinksScalarAlertIDs(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-case-event-scalar-alerts",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.case",
		Attributes: map[string]string{
			"case_id":   "case-1",
			"status":    "investigating",
			"title":     "Credential exposure investigation",
			"alert_ids": "alert-4",
		},
		Payload: mustJSON(t, map[string]any{
			"case_id":            "case-1",
			"upstream_alert_ids": []any{"alert-1", "alert-2", 12345},
			"related_alert_ids":  "alert-2, alert-3",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	caseURN := "urn:cerebro:writer:panopticon_case:case-1"
	for _, alertID := range []string{"alert-1", "alert-2", "alert-3", "alert-4", "12345"} {
		alertURN := "urn:cerebro:writer:panopticon_alert:" + alertID
		assertProjectedEntityType(t, state, alertURN, "panopticon.alert")
		assertProjectedLink(t, state, caseURN, relationContains, alertURN)
		assertProjectedLink(t, state, alertURN, relationBelongsTo, caseURN)
	}
}

func TestProjectPanopticonAlertBuildsEvidenceGraphContext(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-alert-event-1",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.alert",
		Attributes: map[string]string{
			"alert_id":                          "alert-1",
			"case_id":                           "case-1",
			"severity":                          "critical",
			"status":                            "closed",
			"title":                             "Suspicious domain observed",
			"closed_at":                         "2026-06-22T10:15:00Z",
			ports.EventAttributeSourceRuntimeID: "writer-panopticon-alerts",
		},
		Payload: mustJSON(t, map[string]any{
			"alert_id":  "alert-1",
			"case_id":   "case-1",
			"severity":  "critical",
			"status":    "closed",
			"title":     "Suspicious domain observed",
			"closed_at": "2026-06-22T10:15:00Z",
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
	if result.EntitiesProjected == 0 || result.LinksProjected == 0 {
		t.Fatalf("expected Panopticon alert evidence projection, got entities=%d links=%d", result.EntitiesProjected, result.LinksProjected)
	}
	alertURN := "urn:cerebro:writer:panopticon_alert:alert-1"
	caseURN := "urn:cerebro:writer:panopticon_case:case-1"
	iocURN := "urn:cerebro:writer:panopticon_ioc:ioc-1"
	assetURN := "urn:cerebro:writer:panopticon_asset:asset-1"
	assertProjectedEntityType(t, state, alertURN, "panopticon.alert")
	alert := state.entities[alertURN]
	if got := alert.Attributes["closed_at"]; got != "2026-06-22T10:15:00Z" {
		t.Fatalf("alert closed_at = %q, want closure timestamp", got)
	}
	if got := alert.Attributes[ports.EventAttributeSourceRuntimeID]; got != "writer-panopticon-alerts" {
		t.Fatalf("alert source_runtime_id = %q, want writer-panopticon-alerts", got)
	}
	assertProjectedEntityType(t, state, caseURN, "panopticon.case")
	if got := state.entities[caseURN].Attributes[ports.EventAttributeSourceRuntimeID]; got != "writer-panopticon-alerts" {
		t.Fatalf("case source_runtime_id = %q, want writer-panopticon-alerts", got)
	}
	assertProjectedEntityType(t, state, iocURN, "panopticon.ioc")
	assertProjectedEntityType(t, state, assetURN, "panopticon.asset")
	assertProjectedLink(t, state, caseURN, relationContains, alertURN)
	assertProjectedLink(t, state, alertURN, relationBelongsTo, caseURN)
	assertProjectedLink(t, state, alertURN, relationHasEvidence, iocURN)
	assertProjectedLink(t, state, alertURN, relationTargeted, assetURN)
	assertProjectedLink(t, state, assetURN, relationAffectedBy, alertURN)
}

func TestProjectPanopticonIOCLinksToCaseAndAlertEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
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

	assertProjectedLink(t, state, iocURN, relationBelongsTo, caseURN)
	assertProjectedLink(t, state, alertURN, relationHasEvidence, iocURN)
}

func TestProjectPanopticonAlertDoesNotInferSSHBruteForceAnchorsFromTitle(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-alert-event-ssh",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.alert",
		Attributes: map[string]string{
			"alert_id": "alert-ssh",
			"title":    "203.0.113.20 is performing SSH brute force attacks against i-0123456789abcdef0.",
			"severity": "high",
			"status":   "open",
		},
		Payload: mustJSON(t, map[string]any{
			"alert_id": "alert-ssh",
			"title":    "203.0.113.20 is performing SSH brute force attacks against i-0123456789abcdef0.",
		}),
	})
	if err != nil {
		t.Fatalf("Project(alert) error = %v", err)
	}
	if result.EntitiesProjected != 1 || result.LinksProjected != 0 {
		t.Fatalf("alert title-only projection = entities %d links %d, want only the alert entity", result.EntitiesProjected, result.LinksProjected)
	}
	assertProjectedEntityType(t, state, "urn:cerebro:writer:panopticon_alert:alert-ssh", "panopticon.alert")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:internet_ip:203.0.113.20")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:aws_ec2_instance:i-0123456789abcdef0")
}

func TestProjectPanopticonCaseEnrichesGitHubGCPAndIdentityAnchors(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-case-event-enrichment",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.case",
		Attributes: map[string]string{
			"case_id": "case-enrich",
			"title":   "GitHub secret scanning in repo ExampleOrg/example-service for GCP project example-dev",
			"status":  "open",
		},
		Payload: mustJSON(t, map[string]any{
			"case_id":                "case-enrich",
			"title":                  "GitHub secret scanning in repo ExampleOrg/example-service for GCP project example-dev",
			"github_code_repository": "https://github.com/ExampleOrg/example-service.git",
			"gcp_project_id":         "example-dev",
			"assignee_email":         "analyst@example.com",
		}),
	})
	if err != nil {
		t.Fatalf("Project(case) error = %v", err)
	}

	caseURN := "urn:cerebro:writer:panopticon_case:case-enrich"
	repoURN := "urn:cerebro:writer:github_code_repository:ExampleOrg/example-service"
	orgURN := "urn:cerebro:writer:github_org:ExampleOrg"
	accountURN := "urn:cerebro:writer:cloud_account:example-dev"
	identityURN := "urn:cerebro:writer:identity:email:analyst@example.com"
	identifierURN := "urn:cerebro:writer:identifier:email:analyst@example.com"

	assertProjectedEntityType(t, state, repoURN, "github.code.repository")
	assertProjectedEntityType(t, state, accountURN, "cloud.account")
	assertProjectedEntityType(t, state, identityURN, "identity.email")
	assertProjectedLink(t, state, repoURN, relationBelongsTo, orgURN)
	assertProjectedLink(t, state, caseURN, relationAssociatedWith, repoURN)
	assertProjectedLink(t, state, caseURN, relationAssociatedWith, accountURN)
	assertProjectedLink(t, state, caseURN, relationOwnedBy, identityURN)
	assertProjectedLink(t, state, caseURN, relationHasIdentifier, identifierURN)
}

func TestProjectPanopticonCaseEnrichesKubernetesAnchors(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-case-event-kubernetes",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.case",
		Attributes: map[string]string{
			"case_id": "case-k8s",
			"title":   "Tetragon: nc execution in wait-for-db init container (example-namespace/example-api-123)",
		},
		Payload: mustJSON(t, map[string]any{
			"case_id":              "case-k8s",
			"title":                "Tetragon: nc execution in wait-for-db init container (example-namespace/example-api-123)",
			"service_account_name": "example-api",
		}),
	})
	if err != nil {
		t.Fatalf("Project(case) error = %v", err)
	}

	caseURN := "urn:cerebro:writer:panopticon_case:case-k8s"
	workloadURN := "urn:cerebro:writer:kubernetes_workload:panopticon-inferred:example-namespace:Deployment/example-api-123"
	namespaceURN := "urn:cerebro:writer:kubernetes_namespace:panopticon-inferred:example-namespace"
	clusterURN := "urn:cerebro:writer:kubernetes_cluster:panopticon-inferred"
	serviceAccountURN := "urn:cerebro:writer:kubernetes_service_account:panopticon-inferred:example-namespace:example-api"

	assertProjectedEntityType(t, state, workloadURN, "kubernetes.workload")
	assertProjectedEntityType(t, state, namespaceURN, "kubernetes.namespace")
	assertProjectedEntityType(t, state, clusterURN, "kubernetes.cluster")
	assertProjectedEntityType(t, state, serviceAccountURN, "kubernetes.service_account")
	assertProjectedLink(t, state, caseURN, relationAssociatedWith, workloadURN)
	assertProjectedLink(t, state, workloadURN, relationBelongsTo, namespaceURN)
	assertProjectedLink(t, state, namespaceURN, relationBelongsTo, clusterURN)
	assertProjectedLink(t, state, workloadURN, relationRunsAs, serviceAccountURN)
}

func TestProjectPanopticonIOCEnrichesInternetAnchors(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-ioc-event-anchor",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.ioc",
		Attributes: map[string]string{
			"ioc_id":   "ioc-ip",
			"ioc_type": "ip",
			"value":    "203.0.113.10",
		},
		Payload: mustJSON(t, map[string]any{
			"ioc_id":   "ioc-ip",
			"ioc_type": "ip",
			"value":    "203.0.113.10",
		}),
	})
	if err != nil {
		t.Fatalf("Project(ioc) error = %v", err)
	}

	iocURN := "urn:cerebro:writer:panopticon_ioc:ioc-ip"
	ipURN := "urn:cerebro:writer:internet_ip:203.0.113.10"

	assertProjectedEntityType(t, state, ipURN, "internet.ip")
	assertProjectedLink(t, state, iocURN, relationRepresents, ipURN)
}

func TestProjectPanopticonAssetsStitchToCanonicalProviderAssets(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-case-event-asset-stitch",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.case",
		Attributes: map[string]string{
			"case_id": "case-asset-stitch",
			"title":   "Provider-backed assets",
		},
		Payload: mustJSON(t, map[string]any{
			"case_id": "case-asset-stitch",
			"assets": []map[string]any{
				{
					"asset_id":      "asset-sentinelone",
					"provider":      "sentinelone",
					"agent_id":      "agent-123",
					"computer_name": "writer-mac-1",
				},
				{
					"asset_id":  "asset-kolide",
					"provider":  "kolide",
					"device_id": "kolide-device-1",
					"hostname":  "kolide-host-1",
				},
				{
					"asset_id":           "asset-aws",
					"domain":             "123456789012",
					"internet_exposed":   "true",
					"owner":              "platform@writer.com",
					"public_endpoint":    "https://api.us-east-1.awsapprunner.com",
					"resource_provider":  "aws",
					"resource_id":        "arn:aws:apprunner:us-east-1:123456789012:service/api/0f2d1e",
					"resource_name":      "api",
					"role_arn":           "arn:aws:iam::123456789012:role/AppRunnerInstanceRole",
					"role_name":          "AppRunnerInstanceRole",
					"security_group_ids": "sg-app",
					"subnet_ids":         "subnet-app",
					"vpc_id":             "vpc-app",
				},
				{
					"asset_id":          "asset-aws-ec2-arn",
					"resource_provider": "aws",
					"resource_type":     "ec2_instance",
					"resource_arn":      "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
					"resource_id":       "i-0123456789abcdef0",
					"resource_name":     "prod-api-1",
				},
				{
					"asset_id":          "asset-aws-ec2-arn-only",
					"resource_provider": "aws",
					"resource_arn":      "arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef1234567890",
				},
				{
					"asset_id":                    "asset-azure",
					"identity_principal_id":       "principal-system-1",
					"internet_exposed":            "true",
					"owner":                       "Compute Team",
					"public_host":                 "vm-1.eastus.cloudapp.azure.com",
					"resource_provider":           "azure",
					"resource_type":               "Microsoft.Compute/virtualMachines",
					"resource_id":                 "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1",
					"resource_name":               "vm-1",
					"user_assigned_principal_ids": "principal-user-1",
				},
				{
					"asset_id":              "asset-gcp",
					"crown_jewel":           "true",
					"data_classification":   "restricted",
					"owner":                 "api-owner@writer.com",
					"public_endpoint":       "https://api-writer-prod.run.app",
					"resource_provider":     "gcp",
					"resource_id":           "//run.googleapis.com/projects/prod-project/locations/us-central1/services/api",
					"resource_name":         "api",
					"service_account_email": "api@prod-project.iam.gserviceaccount.com",
				},
				{
					"asset_id":          "asset-gcp-compute",
					"project_id":        "prod-project",
					"resource_provider": "gcp",
					"resource_type":     "compute_instance",
					"self_link":         "https://www.googleapis.com/compute/v1/projects/prod-project/zones/us-central1-a/instances/instance-1",
				},
				{
					"asset_id":          "asset-gcp-sql",
					"project_id":        "prod-project",
					"resource_provider": "gcp",
					"resource_type":     "cloud_sql_instance",
					"self_link":         "https://sqladmin.googleapis.com/sql/v1beta4/projects/prod-project/instances/sql-1",
				},
				{
					"asset_id":          "asset-gcp-gke",
					"project_id":        "prod-project",
					"resource_provider": "gcp",
					"resource_id":       "https://container.googleapis.com/v1/projects/prod-project/locations/us-central1/clusters/cluster-1",
				},
				{
					"asset_id":          "asset-gcp-bucket",
					"project_id":        "prod-project",
					"resource_provider": "gcp",
					"resource_type":     "gcs_bucket",
					"resource_id":       "//storage.googleapis.com/projects/_/buckets/prod-bucket",
					"resource_name":     "prod-bucket",
				},
				{
					"asset_id":          "asset-aws-resource-urn",
					"resource_provider": "aws",
					"resource_type":     "s3_bucket",
					"resource_urn":      "urn:cerebro:writer:aws_s3_bucket:prod-bucket",
					"resource_name":     "prod-bucket",
				},
				{
					"asset_id": "asset-kandji-explicit",
					"urn":      "urn:cerebro:writer:kandji_device:kandji-device-1",
					"name":     "kandji-mac-1",
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("Project(case) error = %v", err)
	}

	assertProjectedEntityType(t, state, "urn:cerebro:writer:sentinelone_agent:agent-123", "sentinelone.agent")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:kolide_device:kolide-device-1", "kolide.device")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:aws_apprunner_service:arn:aws:apprunner:us-east-1:123456789012:service/api/0f2d1e", "aws.apprunner.service")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:aws_ec2_instance:i-0123456789abcdef0", "aws.ec2.instance")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:aws_ec2_instance:i-0abcdef1234567890", "aws.ec2.instance")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:azure_virtual_machine:/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1", "azure.virtual.machine")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:gcp_cloud_run_service:projects/prod-project/locations/us-central1/services/api", "gcp.cloud.run.service")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:gcp_compute_instance:instance-1", "gcp.compute.instance")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:gcp_cloud_sql_instance:https://sqladmin.googleapis.com/sql/v1beta4/projects/prod-project/instances/sql-1", "gcp.cloud.sql.instance")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:gcp_gke_cluster:https://container.googleapis.com/v1/projects/prod-project/locations/us-central1/clusters/cluster-1", "gcp.gke.cluster")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:gcp_gcs_bucket:prod-bucket", "gcp.gcs.bucket")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:aws_s3_bucket:prod-bucket", "aws.s3.bucket")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:kandji_device:kandji-device-1", "kandji.device")

	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-sentinelone", relationRepresents, "urn:cerebro:writer:sentinelone_agent:agent-123")
	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-kolide", relationRepresents, "urn:cerebro:writer:kolide_device:kolide-device-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-aws", relationRepresents, "urn:cerebro:writer:aws_apprunner_service:arn:aws:apprunner:us-east-1:123456789012:service/api/0f2d1e")
	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-aws-ec2-arn", relationRepresents, "urn:cerebro:writer:aws_ec2_instance:i-0123456789abcdef0")
	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-aws-ec2-arn-only", relationRepresents, "urn:cerebro:writer:aws_ec2_instance:i-0abcdef1234567890")
	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-azure", relationRepresents, "urn:cerebro:writer:azure_virtual_machine:/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-gcp", relationRepresents, "urn:cerebro:writer:gcp_cloud_run_service:projects/prod-project/locations/us-central1/services/api")
	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-gcp-compute", relationRepresents, "urn:cerebro:writer:gcp_compute_instance:instance-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-gcp-sql", relationRepresents, "urn:cerebro:writer:gcp_cloud_sql_instance:https://sqladmin.googleapis.com/sql/v1beta4/projects/prod-project/instances/sql-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-gcp-gke", relationRepresents, "urn:cerebro:writer:gcp_gke_cluster:https://container.googleapis.com/v1/projects/prod-project/locations/us-central1/clusters/cluster-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-gcp-bucket", relationRepresents, "urn:cerebro:writer:gcp_gcs_bucket:prod-bucket")
	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-aws-resource-urn", relationRepresents, "urn:cerebro:writer:aws_s3_bucket:prod-bucket")
	assertProjectedLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-kandji-explicit", relationRepresents, "urn:cerebro:writer:kandji_device:kandji-device-1")

	assertProjectedLink(t, state, "urn:cerebro:writer:aws_apprunner_service:arn:aws:apprunner:us-east-1:123456789012:service/api/0f2d1e", relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_apprunner_service:arn:aws:apprunner:us-east-1:123456789012:service/api/0f2d1e", relationOwnedBy, "urn:cerebro:writer:owner:platform@writer.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_apprunner_service:arn:aws:apprunner:us-east-1:123456789012:service/api/0f2d1e", relationBelongsTo, "urn:cerebro:writer:aws_vpc:vpc-app")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_apprunner_service:arn:aws:apprunner:us-east-1:123456789012:service/api/0f2d1e", relationBelongsTo, "urn:cerebro:writer:aws_subnet:subnet-app")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_apprunner_service:arn:aws:apprunner:us-east-1:123456789012:service/api/0f2d1e", relationMemberOf, "urn:cerebro:writer:aws_security_group:sg-app")
	assertProjectedLink(t, state, "urn:cerebro:writer:azure_virtual_machine:/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1", relationBelongsTo, "urn:cerebro:writer:cloud_account:sub-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:azure_virtual_machine:/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1", relationBelongsTo, "urn:cerebro:writer:azure_resource_group:sub-1:rg-prod")
	assertProjectedLink(t, state, "urn:cerebro:writer:gcp_cloud_run_service:projects/prod-project/locations/us-central1/services/api", relationBelongsTo, "urn:cerebro:writer:cloud_account:prod-project")
	assertProjectedLink(t, state, "urn:cerebro:writer:gcp_cloud_run_service:projects/prod-project/locations/us-central1/services/api", relationHasClassification, "urn:cerebro:writer:data_classification:restricted")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:aws_public_principal:public_internet", relationCanReach, "urn:cerebro:writer:aws_apprunner_service:arn:aws:apprunner:us-east-1:123456789012:service/api/0f2d1e")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:aws_apprunner_service:arn:aws:apprunner:us-east-1:123456789012:service/api/0f2d1e", relationRunsAs, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/AppRunnerInstanceRole")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:azure_virtual_machine:/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1", relationRunsAs, "urn:cerebro:writer:azure_service_principal:principal-system-1")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:gcp_cloud_run_service:projects/prod-project/locations/us-central1/services/api", relationRunsAs, "urn:cerebro:writer:gcp_service_account:api@prod-project.iam.gserviceaccount.com")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:panopticon_asset:asset-aws-resource-urn", relationRepresents, "urn:cerebro:writer:aws_s3_bucket:urn:cerebro:writer:aws_s3_bucket:prod-bucket")
	assertProjectedStitchLinkAttribute(t, state, "urn:cerebro:writer:panopticon_asset:asset-aws", "urn:cerebro:writer:aws_apprunner_service:arn:aws:apprunner:us-east-1:123456789012:service/api/0f2d1e", "confidence", "0.99")
}

func TestProjectPanopticonAssetStitchingRejectsWeakAndCrossTenantMatches(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-case-event-asset-stitch-negative",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.case",
		Attributes: map[string]string{
			"case_id": "case-asset-stitch-negative",
			"title":   "Weak assets should remain Panopticon context",
		},
		Payload: mustJSON(t, map[string]any{
			"case_id": "case-asset-stitch-negative",
			"assets": []map[string]any{
				{
					"asset_id": "asset-host-only",
					"hostname": "prod-host-1.example.com",
					"ip":       "203.0.113.22",
				},
				{
					"asset_id": "asset-cross-tenant",
					"urn":      "urn:cerebro:other:sentinelone_agent:agent-999",
				},
				{
					"asset_id": "asset-disallowed-urn",
					"urn":      "urn:cerebro:writer:identity:email:owner@example.com",
				},
				{
					"asset_id": "asset-disallowed-aws-role",
					"urn":      "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/Admin",
				},
				{
					"asset_id": "asset-disallowed-gcp-service-account",
					"urn":      "urn:cerebro:writer:gcp_service_account:svc@prod-project.iam.gserviceaccount.com",
				},
				{
					"asset_id": "asset-disallowed-azure-principal",
					"urn":      "urn:cerebro:writer:azure_service_principal:principal-1",
				},
				{
					"asset_id":          "asset-disallowed-provider-principal",
					"resource_provider": "gcp",
					"resource_type":     "service_account",
					"resource_id":       "svc@prod-project.iam.gserviceaccount.com",
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("Project(case) error = %v", err)
	}

	assertPanopticonAssetHasNoCanonicalAssetLink(t, state, "urn:cerebro:writer:panopticon_asset:asset-host-only")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:panopticon_asset:asset-cross-tenant", relationRepresents, "urn:cerebro:other:sentinelone_agent:agent-999")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:panopticon_asset:asset-disallowed-urn", relationRepresents, "urn:cerebro:writer:identity:email:owner@example.com")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:panopticon_asset:asset-disallowed-aws-role", relationRepresents, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/Admin")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:panopticon_asset:asset-disallowed-gcp-service-account", relationRepresents, "urn:cerebro:writer:gcp_service_account:svc@prod-project.iam.gserviceaccount.com")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:panopticon_asset:asset-disallowed-azure-principal", relationRepresents, "urn:cerebro:writer:azure_service_principal:principal-1")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:panopticon_asset:asset-disallowed-provider-principal", relationRepresents, "urn:cerebro:writer:gcp_service_account:svc@prod-project.iam.gserviceaccount.com")
}

func TestProjectPanopticonDoesNotOvermatchOrdinaryProse(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-case-event-prose",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.case",
		Attributes: map[string]string{
			"case_id": "case-prose",
			"title":   "EDR reported lateral movement via cmd/powershell; security project roll-out delayed",
		},
		Payload: mustJSON(t, map[string]any{
			"case_id":       "case-prose",
			"title":         "EDR reported lateral movement via cmd/powershell; security project roll-out delayed",
			"agent_version": "1.2.3.4",
		}),
	})
	if err != nil {
		t.Fatalf("Project(case) error = %v", err)
	}

	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:github_code_repository:cmd/powershell")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:github_org:cmd")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:cloud_account:roll-out")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:internet_ip:1.2.3.4")
}

func TestProjectPanopticonSkipsSensitivePayloadContext(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-case-event-sensitive",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.case",
		Attributes: map[string]string{
			"case_id": "case-sensitive",
			"title":   "Sensitive payload context should stay unprojected",
		},
		Payload: mustJSON(t, map[string]any{
			"case_id": "case-sensitive",
			"client_secret": map[string]any{
				"note": "owner@example.com https://github.com/ExampleOrg/private-repo 203.0.113.55",
			},
			"api_key": "another-owner@example.com ExampleOrg/another-repo",
		}),
	})
	if err != nil {
		t.Fatalf("Project(case) error = %v", err)
	}

	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:identity:email:owner@example.com")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:identity:email:another-owner@example.com")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:github_code_repository:ExampleOrg/private-repo")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:github_code_repository:ExampleOrg/another-repo")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:internet_ip:203.0.113.55")
}

func TestProjectPanopticonEvidencePointerCorrelatesWithEvidenceCASObject(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-case-event-evidence-correlation",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.case",
		Attributes: map[string]string{
			"case_id": "case-corr",
			"status":  "investigating",
			"title":   "Evidence correlation",
		},
		Payload: mustJSON(t, map[string]any{
			"case_id": "case-corr",
			"status":  "investigating",
			"title":   "Evidence correlation",
			"evidence": []map[string]any{{
				"evidence_id":  "evidence-1",
				"evidence_cas": "evidencecas://cases/case-corr/evidence/triage.tar",
				"sha256":       "sha256:abc",
			}},
		}),
	}); err != nil {
		t.Fatalf("Project(case) error = %v", err)
	}

	// The Evidence CAS source independently projects the same evidence object.
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "evidence-cas-object-event-1",
		TenantId: "writer",
		SourceId: "evidence_cas",
		Kind:     "evidence_cas.object",
		Attributes: map[string]string{
			"evidence_id":         "evidence-1",
			"evidence_cas_uri":    "evidencecas://cases/case-corr/evidence/triage.tar",
			"evidence_cas_digest": "sha256:abc",
		},
	}); err != nil {
		t.Fatalf("Project(evidence_cas.object) error = %v", err)
	}
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "evidence-cas-object-event-uri",
		TenantId: "writer",
		SourceId: "evidence_cas",
		Kind:     "evidence_cas.object",
		Attributes: map[string]string{
			"evidence_id":         "evidencecas://cases/case-corr/evidence/triage.tar",
			"evidence_cas_uri":    "evidencecas://cases/case-corr/evidence/triage.tar",
			"evidence_cas_digest": "sha256:abc",
		},
	}); err != nil {
		t.Fatalf("Project(uri identity evidence_cas.object) error = %v", err)
	}

	pointerURN := "urn:cerebro:writer:evidence_cas_pointer:evidence-1"
	evidenceObjectURN := "urn:cerebro:writer:runtime_evidence:evidence-1"
	uriEvidenceObjectURN := "urn:cerebro:writer:runtime_evidence:evidencecas://cases/case-corr/evidence/triage.tar"

	pointer := state.entities[pointerURN]
	if pointer == nil || pointer.EntityType != "evidence.cas.pointer" {
		t.Fatalf("panopticon evidence pointer missing or wrong type: %#v", pointer)
	}
	if got := pointer.Attributes["evidence_cas_object_urn"]; got != evidenceObjectURN {
		t.Fatalf("evidence_cas_object_urn = %q, want %q", got, evidenceObjectURN)
	}
	if got, want := pointer.Attributes["evidence_cas_object_urns"], evidenceObjectURN+","+uriEvidenceObjectURN; got != want {
		t.Fatalf("evidence_cas_object_urns = %q, want %q", got, want)
	}
	if state.entities[evidenceObjectURN] == nil {
		t.Fatalf("Evidence CAS object projection %q missing for correlation join", evidenceObjectURN)
	}
	if state.entities[uriEvidenceObjectURN] == nil {
		t.Fatalf("Evidence CAS URI object projection %q missing for correlation join", uriEvidenceObjectURN)
	}
	assertProjectedLink(t, state, pointerURN, relationRepresents, evidenceObjectURN)
	assertProjectedLink(t, state, pointerURN, relationRepresents, uriEvidenceObjectURN)

	// Cross-tenant Evidence CAS objects must not be joined by the writer pointer.
	assertProjectedLinkMissing(t, state, pointerURN, relationRepresents, "urn:cerebro:other:runtime_evidence:evidence-1")
}

func assertProjectedEntityType(t *testing.T, recorder *projectionRecorder, urn string, entityType string) {
	t.Helper()
	entity := recorder.entities[urn]
	if entity == nil {
		t.Fatalf("projected entity %q missing", urn)
	}
	if entity.EntityType != entityType {
		t.Fatalf("projected entity %q type = %q, want %q", urn, entity.EntityType, entityType)
	}
}

func assertProjectedEntityMissing(t *testing.T, recorder *projectionRecorder, urn string) {
	t.Helper()
	if entity := recorder.entities[urn]; entity != nil {
		t.Fatalf("projected entity %q should be missing: %#v", urn, entity)
	}
}

func assertProjectedStitchLinkAttribute(t *testing.T, recorder *projectionRecorder, fromURN string, toURN string, key string, want string) {
	t.Helper()
	link := recorder.links[fromURN+"|"+relationRepresents+"|"+toURN]
	if link == nil {
		t.Fatalf("projected stitch link %q -> %q missing", fromURN, toURN)
	}
	if got := link.Attributes[key]; got != want {
		t.Fatalf("projected stitch link %q attribute %q = %q, want %q", fromURN, key, got, want)
	}
}

func assertPanopticonAssetHasNoCanonicalAssetLink(t *testing.T, recorder *projectionRecorder, assetURN string) {
	t.Helper()
	for _, link := range recorder.links {
		if link.FromURN != assetURN || link.Relation != relationRepresents {
			continue
		}
		parts := strings.Split(link.ToURN, ":")
		if len(parts) >= 4 && parts[0] == "urn" && parts[1] == "cerebro" && panopticonAllowedCanonicalAssetKind(parts[3]) {
			t.Fatalf("asset %q should not directly stitch to canonical asset %q; link=%#v", assetURN, link.ToURN, link)
		}
	}
}
