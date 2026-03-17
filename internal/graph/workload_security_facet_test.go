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

func TestWorkloadSecurityFacetWarnsForDarkRuntimeWorkload(t *testing.T) {
	now := time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC)
	g := New()
	g.AddNode(&Node{
		ID:        "workload:payments",
		Kind:      NodeKindWorkload,
		Name:      "payments",
		CreatedAt: now.Add(-2 * time.Hour),
		UpdatedAt: now.Add(-2 * time.Hour),
	})
	addWorkloadScanFixture(g, "workload_scan:payments", "workload:payments", now.Add(-30*time.Minute), nil, 0, 0, 0)
	g.BuildIndex()

	record, ok := GetEntityRecord(g, "workload:payments", now, now)
	if !ok {
		t.Fatal("expected workload entity record")
	}
	facet := findFacetByID(record.Facets, "workload_security")
	if facet == nil {
		t.Fatalf("expected workload_security facet, got %#v", record.Facets)
	}
	if facet.Assessment != "warn" {
		t.Fatalf("assessment = %q, want warn", facet.Assessment)
	}
	if facet.Summary != "No runtime observations recorded for this workload" {
		t.Fatalf("summary = %q", facet.Summary)
	}
	if !readBool(facet.Fields, "runtime_dark_workload") {
		t.Fatalf("expected runtime_dark_workload true, got %#v", facet.Fields)
	}
	if got := readInt(facet.Fields, "runtime_observation_count"); got != 0 {
		t.Fatalf("runtime_observation_count = %d, want 0", got)
	}
	if got := readFloat(facet.Fields, "runtime_risk_multiplier"); got != 1.2 {
		t.Fatalf("runtime_risk_multiplier = %v, want 1.2", got)
	}
}

func TestWorkloadSecurityFacetFailsOnRuntimeFindingSignals(t *testing.T) {
	now := time.Date(2026, 3, 16, 19, 0, 0, 0, time.UTC)
	g := New()
	g.AddNode(&Node{
		ID:        "workload:payments",
		Kind:      NodeKindWorkload,
		Name:      "payments",
		CreatedAt: now.Add(-2 * time.Hour),
		UpdatedAt: now.Add(-2 * time.Hour),
	})
	addWorkloadScanFixture(g, "workload_scan:payments", "workload:payments", now.Add(-30*time.Minute), nil, 0, 0, 0)

	observationObservedAt := now.Add(-10 * time.Minute)
	observationProperties := map[string]any{
		"observation_type": "runtime_alert",
		"summary":          "Suspicious runtime behavior",
		"source_system":    "falco",
		"observed_at":      observationObservedAt.Format(time.RFC3339),
		"valid_from":       observationObservedAt.Format(time.RFC3339),
	}
	g.AddNode(&Node{
		ID:         "observation:payments:alert",
		Kind:       NodeKindObservation,
		Name:       "Suspicious runtime behavior",
		Properties: observationProperties,
		CreatedAt:  observationObservedAt,
		UpdatedAt:  observationObservedAt,
	})
	g.AddEdge(&Edge{
		ID:        "workload:payments->observation:payments:alert:targets",
		Source:    "workload:payments",
		Target:    "observation:payments:alert",
		Kind:      EdgeKindTargets,
		Effect:    EdgeEffectAllow,
		CreatedAt: observationObservedAt,
	})

	evidenceObservedAt := now.Add(-9 * time.Minute)
	g.AddNode(&Node{
		ID:       "evidence:runtime_finding:payments",
		Kind:     NodeKindEvidence,
		Name:     "Suspicious runtime finding",
		Provider: "cerebro_runtime_detection",
		Properties: map[string]any{
			"evidence_type": "runtime_finding",
			"mitre_attack":  []string{"T1059", "T1041"},
			"observed_at":   evidenceObservedAt.Format(time.RFC3339),
			"valid_from":    evidenceObservedAt.Format(time.RFC3339),
		},
		CreatedAt: evidenceObservedAt,
		UpdatedAt: evidenceObservedAt,
	})
	g.AddEdge(&Edge{
		ID:        "evidence:runtime_finding:payments->observation:payments:alert:based_on",
		Source:    "evidence:runtime_finding:payments",
		Target:    "observation:payments:alert",
		Kind:      EdgeKindBasedOn,
		Effect:    EdgeEffectAllow,
		CreatedAt: evidenceObservedAt,
	})
	g.BuildIndex()

	record, ok := GetEntityRecord(g, "workload:payments", now, now)
	if !ok {
		t.Fatal("expected workload entity record")
	}
	facet := findFacetByID(record.Facets, "workload_security")
	if facet == nil {
		t.Fatalf("expected workload_security facet, got %#v", record.Facets)
	}
	if facet.Assessment != "fail" {
		t.Fatalf("assessment = %q, want fail", facet.Assessment)
	}
	if facet.Summary != "Runtime findings show active multi-technique behavior on this workload" {
		t.Fatalf("summary = %q", facet.Summary)
	}
	if got := readInt(facet.Fields, "runtime_observation_count"); got != 1 {
		t.Fatalf("runtime_observation_count = %d, want 1", got)
	}
	if got := readInt(facet.Fields, "runtime_finding_count"); got != 1 {
		t.Fatalf("runtime_finding_count = %d, want 1", got)
	}
	if got := readInt(facet.Fields, "runtime_mitre_technique_count"); got != 2 {
		t.Fatalf("runtime_mitre_technique_count = %d, want 2", got)
	}
	if got := readFloat(facet.Fields, "runtime_risk_multiplier"); got != 3.0 {
		t.Fatalf("runtime_risk_multiplier = %v, want 3.0", got)
	}
}

func TestWorkloadSecurityPrioritizedRiskPrefersReachableVulnerabilityCounts(t *testing.T) {
	unreachableCritical := &Node{Properties: map[string]any{
		"vulnerability_count":                    1,
		"critical_vulnerability_count":           1,
		"high_vulnerability_count":               0,
		"known_exploited_count":                  0,
		"reachable_vulnerability_count":          0,
		"reachable_critical_vulnerability_count": 0,
		"reachable_high_vulnerability_count":     0,
		"reachable_known_exploited_count":        0,
		"direct_reachable_vulnerability_count":   0,
	}}
	if got := workloadSecurityPrioritizedRisk(unreachableCritical, true, 1, 1, false); got != RiskHigh {
		t.Fatalf("expected unreachable critical vulnerability to downrank to high, got %q", got)
	}

	reachableCritical := &Node{Properties: map[string]any{
		"vulnerability_count":                    1,
		"critical_vulnerability_count":           1,
		"high_vulnerability_count":               0,
		"known_exploited_count":                  0,
		"reachable_vulnerability_count":          1,
		"reachable_critical_vulnerability_count": 1,
		"reachable_high_vulnerability_count":     0,
		"reachable_known_exploited_count":        0,
		"direct_reachable_vulnerability_count":   1,
	}}
	if got := workloadSecurityPrioritizedRisk(reachableCritical, true, 1, 1, false); got != RiskCritical {
		t.Fatalf("expected reachable critical vulnerability to remain critical, got %q", got)
	}

	reachableLow := &Node{Properties: map[string]any{
		"vulnerability_count":                    1,
		"critical_vulnerability_count":           0,
		"high_vulnerability_count":               0,
		"medium_vulnerability_count":             0,
		"low_vulnerability_count":                1,
		"known_exploited_count":                  0,
		"reachable_vulnerability_count":          1,
		"reachable_critical_vulnerability_count": 0,
		"reachable_high_vulnerability_count":     0,
		"reachable_known_exploited_count":        0,
		"direct_reachable_vulnerability_count":   1,
	}}
	if got := workloadSecurityPrioritizedRisk(reachableLow, false, 0, 0, false); got != RiskLow {
		t.Fatalf("expected reachable low vulnerability to remain low, got %q", got)
	}

	unreachableKEV := &Node{Properties: map[string]any{
		"vulnerability_count":                    1,
		"critical_vulnerability_count":           0,
		"high_vulnerability_count":               1,
		"medium_vulnerability_count":             0,
		"low_vulnerability_count":                0,
		"known_exploited_count":                  1,
		"reachable_vulnerability_count":          0,
		"reachable_critical_vulnerability_count": 0,
		"reachable_high_vulnerability_count":     0,
		"reachable_known_exploited_count":        0,
		"direct_reachable_vulnerability_count":   0,
	}}
	if got := workloadSecurityPrioritizedRisk(unreachableKEV, false, 0, 0, false); got != RiskCritical {
		t.Fatalf("expected known-exploited vulnerability to remain critical without reachability context, got %q", got)
	}

	zeroVulns := &Node{Properties: map[string]any{
		"vulnerability_count":                    0,
		"critical_vulnerability_count":           0,
		"high_vulnerability_count":               0,
		"medium_vulnerability_count":             0,
		"low_vulnerability_count":                0,
		"known_exploited_count":                  0,
		"reachable_vulnerability_count":          0,
		"reachable_critical_vulnerability_count": 0,
		"reachable_high_vulnerability_count":     0,
		"reachable_known_exploited_count":        0,
		"direct_reachable_vulnerability_count":   0,
	}}
	if got := workloadSecurityPrioritizedRisk(zeroVulns, false, 0, 0, false); got != RiskNone {
		t.Fatalf("expected zero-vulnerability scan to remain none, got %q", got)
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
