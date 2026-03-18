package graph

import (
	"testing"
	"time"
)

func TestWorkloadSecurityFacetUsesLatestVisibleScan(t *testing.T) {
	now := time.Date(2026, 3, 12, 18, 0, 0, 0, time.UTC)
	baseCreatedAt := time.Date(2026, 3, 9, 8, 0, 0, 0, time.UTC)
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet", CreatedAt: baseCreatedAt, UpdatedAt: baseCreatedAt})
	g.AddNode(&Node{
		ID:        "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
		Kind:      NodeKindInstance,
		Name:      "i-abc123",
		Provider:  "aws",
		Account:   "123456789012",
		Region:    "us-east-1",
		CreatedAt: baseCreatedAt,
		UpdatedAt: baseCreatedAt,
	})
	g.AddNode(&Node{ID: "arn:aws:iam::123456789012:role/admin", Kind: NodeKindRole, Name: "admin", Provider: "aws", Account: "123456789012", CreatedAt: baseCreatedAt, UpdatedAt: baseCreatedAt})
	g.AddNode(&Node{
		ID:       "arn:aws:rds:us-east-1:123456789012:db:prod",
		Kind:     NodeKindDatabase,
		Name:     "prod",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Properties: map[string]any{
			"contains_pii": true,
		},
		CreatedAt: baseCreatedAt,
		UpdatedAt: baseCreatedAt,
	})
	g.AddEdge(&Edge{ID: "internet->instance", Source: "internet", Target: "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow, CreatedAt: baseCreatedAt})
	g.AddEdge(&Edge{ID: "instance->role", Source: "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", Target: "arn:aws:iam::123456789012:role/admin", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow, CreatedAt: baseCreatedAt})
	g.AddEdge(&Edge{ID: "role->db", Source: "arn:aws:iam::123456789012:role/admin", Target: "arn:aws:rds:us-east-1:123456789012:db:prod", Kind: EdgeKindCanAdmin, Effect: EdgeEffectAllow, CreatedAt: baseCreatedAt})

	firstCompleted := time.Date(2026, 3, 10, 10, 0, 0, 0, time.UTC)
	secondCompleted := time.Date(2026, 3, 11, 10, 0, 0, 0, time.UTC)
	addWorkloadScanFixture(g, "workload_scan:first", "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", firstCompleted, &secondCompleted, 1, 1, 1)
	addWorkloadScanFixture(g, "workload_scan:second", "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", secondCompleted, nil, 0, 0, 0)
	g.BuildIndex()

	current, ok := GetEntityRecord(g, "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", now, now)
	if !ok {
		t.Fatal("expected current entity record")
	}
	currentFacet := findFacetByID(current.Facets, "workload_security")
	if currentFacet == nil {
		t.Fatalf("expected workload_security facet, got %#v", current.Facets)
	}
	if got := readString(currentFacet.Fields, "last_scan_id"); got != "workload_scan:second" {
		t.Fatalf("expected latest scan id workload_scan:second, got %q", got)
	}
	if got := readInt(currentFacet.Fields, "vulnerability_count"); got != 0 {
		t.Fatalf("expected current vulnerability count 0, got %d", got)
	}

	historical, ok := GetEntityRecord(g, "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", firstCompleted.Add(30*time.Minute), now)
	if !ok {
		t.Fatal("expected historical entity record")
	}
	historicalFacet := findFacetByID(historical.Facets, "workload_security")
	if historicalFacet == nil {
		t.Fatalf("expected historical workload_security facet, got %#v", historical.Facets)
	}
	if got := readString(historicalFacet.Fields, "last_scan_id"); got != "workload_scan:first" {
		t.Fatalf("expected historical scan id workload_scan:first, got %q", got)
	}
	if got := readInt(historicalFacet.Fields, "critical_vulnerability_count"); got != 1 {
		t.Fatalf("expected historical critical vulnerability count 1, got %d", got)
	}
	if !readBool(historicalFacet.Fields, "internet_exposed") {
		t.Fatalf("expected historical workload_security internet_exposed, got %#v", historicalFacet.Fields)
	}
	if got := readInt(historicalFacet.Fields, "admin_reachable_count"); got < 1 {
		t.Fatalf("expected admin_reachable_count >= 1, got %d", got)
	}
	if got := readInt(historicalFacet.Fields, "sensitive_data_path_count"); got < 1 {
		t.Fatalf("expected sensitive_data_path_count >= 1, got %d", got)
	}
}

func addWorkloadScanFixture(g *Graph, scanID, targetID string, completedAt time.Time, validTo *time.Time, vulnerabilityCount, criticalCount, kevCount int) {
	metadata := NormalizeWriteMetadata(
		completedAt,
		completedAt.Add(-15*time.Minute),
		validTo,
		"cerebro_workload_scan",
		"workload_scan:"+scanID,
		1.0,
		WriteMetadataDefaults{
			Now:             completedAt,
			RecordedAt:      completedAt,
			TransactionFrom: completedAt,
			SourceSystem:    "cerebro_workload_scan",
		},
	)
	properties := map[string]any{
		"scan_id":                         scanID,
		"target_id":                       targetID,
		"target_kind":                     string(NodeKindInstance),
		"provider":                        "aws",
		"status":                          "succeeded",
		"stage":                           "completed",
		"completed_at":                    completedAt.UTC().Format(time.RFC3339),
		"os_name":                         "Ubuntu",
		"os_version":                      "22.04",
		"os_architecture":                 "amd64",
		"package_count":                   12,
		"vulnerability_count":             vulnerabilityCount,
		"critical_vulnerability_count":    criticalCount,
		"high_vulnerability_count":        0,
		"medium_vulnerability_count":      0,
		"low_vulnerability_count":         0,
		"unknown_vulnerability_count":     0,
		"known_exploited_count":           kevCount,
		"exploitable_vulnerability_count": kevCount,
		"fixable_vulnerability_count":     vulnerabilityCount,
		"secret_count":                    0,
		"misconfiguration_count":          0,
		"malware_count":                   0,
		"finding_count":                   vulnerabilityCount,
	}
	metadata.ApplyTo(properties)
	g.AddNode(&Node{
		ID:         scanID,
		Kind:       NodeKindWorkloadScan,
		Name:       scanID,
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Risk:       workloadSecurityPrioritizedRisk(&Node{Properties: properties}, true, 1, 1, false),
		Properties: properties,
	})
	g.AddEdge(&Edge{
		ID:         "edge:" + scanID,
		Source:     targetID,
		Target:     scanID,
		Kind:       EdgeKindHasScan,
		Effect:     EdgeEffectAllow,
		Properties: metadata.PropertyMap(),
	})
}

func findFacetByID(facets []EntityFacetRecord, id string) *EntityFacetRecord {
	for i := range facets {
		if facets[i].ID == id {
			return &facets[i]
		}
	}
	return nil
}
