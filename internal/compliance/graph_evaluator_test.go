package compliance

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func TestEvaluateFrameworkUsesGraphAndFallbackSources(t *testing.T) {
	now := time.Date(2026, 3, 13, 15, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:        "arn:aws:s3:::customer-data",
		Kind:      graph.NodeKindBucket,
		Name:      "customer-data",
		Provider:  "aws",
		Account:   "123456789012",
		CreatedAt: now,
		Properties: map[string]any{
			"encrypted":           false,
			"public":              true,
			"block_public_acls":   false,
			"block_public_policy": false,
			"logging_enabled":     false,
			"versioning_status":   "Disabled",
			"contains_pii":        true,
			"data_classification": "restricted",
			"observed_at":         now,
			"valid_from":          now,
			"recorded_at":         now,
			"transaction_from":    now,
		},
	})

	framework := &Framework{
		ID:   "graph-mixed",
		Name: "Graph Mixed",
		Controls: []Control{
			{ID: "enc", Title: "Bucket encryption", PolicyIDs: []string{"aws-s3-bucket-encryption-enabled"}},
			{ID: "pub", Title: "Bucket public access", PolicyIDs: []string{"aws-s3-bucket-no-public-access"}},
			{ID: "log", Title: "Bucket logging", PolicyIDs: []string{"aws-s3-bucket-logging-enabled"}},
			{ID: "root", Title: "Root access keys", PolicyIDs: []string{"aws-iam-root-no-access-keys"}},
		},
	}

	report := EvaluateFramework(g, framework, EvaluationOptions{
		GeneratedAt:          now,
		OpenFindingsByPolicy: map[string]int{"aws-iam-root-no-access-keys": 1},
	})

	encryption := controlStatusByID(t, report, "enc")
	if encryption.Status != ControlStateFailing {
		t.Fatalf("expected bucket encryption control to fail, got %+v", encryption)
	}
	if encryption.EvaluationSource != ControlEvaluationSourceGraph {
		t.Fatalf("expected graph evaluation source, got %+v", encryption)
	}
	if encryption.FailCount != 1 || len(encryption.Evidence) == 0 || encryption.Evidence[0].EntityID != "arn:aws:s3:::customer-data" {
		t.Fatalf("expected graph evidence for failing bucket encryption control, got %+v", encryption)
	}

	publicAccess := controlStatusByID(t, report, "pub")
	if publicAccess.Status != ControlStateFailing || publicAccess.EvaluationSource != ControlEvaluationSourceGraph {
		t.Fatalf("expected graph-backed public-access failure, got %+v", publicAccess)
	}

	logging := controlStatusByID(t, report, "log")
	if logging.Status != ControlStateFailing || logging.EvaluationSource != ControlEvaluationSourceGraph {
		t.Fatalf("expected graph-backed logging failure, got %+v", logging)
	}

	root := controlStatusByID(t, report, "root")
	if root.Status != ControlStateFailing {
		t.Fatalf("expected root fallback failure, got %+v", root)
	}
	if root.EvaluationSource != ControlEvaluationSourceFindingsFallback {
		t.Fatalf("expected findings fallback source, got %+v", root)
	}

	if report.Summary.GraphEvaluatedControls != 3 {
		t.Fatalf("expected 3 graph-evaluated controls, got %+v", report.Summary)
	}
	if report.Summary.FallbackControls != 1 {
		t.Fatalf("expected 1 fallback control, got %+v", report.Summary)
	}
}

func TestEvaluateFrameworkSupportsSensitiveDataAndGCPControls(t *testing.T) {
	now := time.Date(2026, 3, 13, 16, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:        "arn:aws:s3:::restricted-data",
		Kind:      graph.NodeKindBucket,
		Name:      "restricted-data",
		Provider:  "aws",
		Account:   "123456789012",
		CreatedAt: now,
		Properties: map[string]any{
			"encrypted":           false,
			"public":              true,
			"block_public_acls":   false,
			"block_public_policy": false,
			"contains_pii":        true,
			"data_classification": "restricted",
			"observed_at":         now,
			"valid_from":          now,
			"recorded_at":         now,
			"transaction_from":    now,
		},
	})
	g.AddNode(&graph.Node{
		ID:        "serviceAccount:proj-1:runner@proj-1.iam.gserviceaccount.com",
		Kind:      graph.NodeKindServiceAccount,
		Name:      "runner@proj-1.iam.gserviceaccount.com",
		Provider:  "gcp",
		Account:   "proj-1",
		CreatedAt: now,
		Properties: map[string]any{
			"has_admin_role":      true,
			"has_access_keys":     true,
			"oldest_key_age_days": 120,
			"observed_at":         now,
			"valid_from":          now,
			"recorded_at":         now,
			"transaction_from":    now,
		},
	})

	framework := &Framework{
		ID:   "graph-breadth",
		Name: "Graph Breadth",
		Controls: []Control{
			{ID: "sensitive-encryption", Title: "Sensitive data encrypted", PolicyIDs: []string{"dspm-restricted-data-unencrypted"}},
			{ID: "sensitive-public", Title: "Sensitive data not public", PolicyIDs: []string{"dspm-confidential-data-public"}},
			{ID: "gcp-admin", Title: "No SA admin", PolicyIDs: []string{"gcp-iam-sa-no-admin-privileges"}},
			{ID: "gcp-keys", Title: "SA keys rotated", PolicyIDs: []string{"gcp-service-account-key-rotation"}},
		},
	}

	report := EvaluateFramework(g, framework, EvaluationOptions{GeneratedAt: now})

	for _, controlID := range []string{"sensitive-encryption", "sensitive-public", "gcp-admin", "gcp-keys"} {
		status := controlStatusByID(t, report, controlID)
		if status.Status != ControlStateFailing {
			t.Fatalf("expected %s to fail, got %+v", controlID, status)
		}
		if status.EvaluationSource != ControlEvaluationSourceGraph {
			t.Fatalf("expected %s to be graph-evaluated, got %+v", controlID, status)
		}
		if len(status.Evidence) == 0 {
			t.Fatalf("expected %s to have evidence, got %+v", controlID, status)
		}
	}
}

func TestEvaluateFrameworkTreatsUnknownGCPKeyRotationStateAsNonPassing(t *testing.T) {
	now := time.Date(2026, 3, 13, 16, 30, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:        "serviceAccount:proj-1:missing-has-keys@proj-1.iam.gserviceaccount.com",
		Kind:      graph.NodeKindServiceAccount,
		Name:      "missing-has-keys@proj-1.iam.gserviceaccount.com",
		Provider:  "gcp",
		Account:   "proj-1",
		CreatedAt: now,
		Properties: map[string]any{
			"oldest_key_age_days": 15,
			"observed_at":         now,
			"valid_from":          now,
			"recorded_at":         now,
			"transaction_from":    now,
		},
	})
	g.AddNode(&graph.Node{
		ID:        "serviceAccount:proj-1:missing-key-age@proj-1.iam.gserviceaccount.com",
		Kind:      graph.NodeKindServiceAccount,
		Name:      "missing-key-age@proj-1.iam.gserviceaccount.com",
		Provider:  "gcp",
		Account:   "proj-1",
		CreatedAt: now,
		Properties: map[string]any{
			"has_access_keys":  true,
			"observed_at":      now,
			"valid_from":       now,
			"recorded_at":      now,
			"transaction_from": now,
		},
	})

	framework := &Framework{
		ID:   "graph-gcp-key-unknown",
		Name: "Graph GCP Key Unknown",
		Controls: []Control{
			{ID: "gcp-keys", Title: "SA keys rotated", PolicyIDs: []string{"gcp-service-account-key-rotation"}},
		},
	}

	report := EvaluateFramework(g, framework, EvaluationOptions{GeneratedAt: now})
	status := controlStatusByID(t, report, "gcp-keys")
	if status.Status != ControlStatePartial {
		t.Fatalf("expected unknown key-rotation state to remain non-passing, got %+v", status)
	}
	if status.PassCount != 0 || status.FailCount != 0 {
		t.Fatalf("expected unknown key-rotation state to avoid pass/fail counts, got %+v", status)
	}
	if len(status.Evidence) != 0 {
		t.Fatalf("expected no evidence when key-rotation state is unknown, got %+v", status)
	}
}

func TestEvaluateFrameworkFallbackPassingDoesNotInventAssetCounts(t *testing.T) {
	now := time.Date(2026, 3, 13, 16, 35, 0, 0, time.UTC)
	report := EvaluateFramework(graph.New(), &Framework{
		ID:   "fallback-pass",
		Name: "Fallback Pass",
		Controls: []Control{{
			ID:        "root",
			Title:     "Root access keys",
			PolicyIDs: []string{"aws-iam-root-no-access-keys"},
		}},
	}, EvaluationOptions{GeneratedAt: now})

	status := controlStatusByID(t, report, "root")
	if status.Status != ControlStatePassing {
		t.Fatalf("expected findings-fallback control to pass with zero findings, got %+v", status)
	}
	if status.EvaluationSource != ControlEvaluationSourceFindingsFallback {
		t.Fatalf("expected findings fallback source, got %+v", status)
	}
	if status.PassCount != 0 || status.FailCount != 0 || status.TotalAssets != 0 {
		t.Fatalf("expected fallback control to avoid invented asset counts, got %+v", status)
	}
	if len(status.Evidence) != 1 || status.Evidence[0].Reason == "" {
		t.Fatalf("expected fallback evidence reason, got %+v", status.Evidence)
	}
}

func TestEvaluateFrameworkPrioritizesFailingEvidenceBeforeTruncation(t *testing.T) {
	now := time.Date(2026, 3, 13, 16, 45, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:        "arn:aws:s3:::late-failing-bucket",
		Kind:      graph.NodeKindBucket,
		Name:      "late-failing-bucket",
		Provider:  "aws",
		Account:   "123456789012",
		CreatedAt: now,
		Properties: map[string]any{
			"encrypted":        false,
			"observed_at":      now,
			"valid_from":       now,
			"recorded_at":      now,
			"transaction_from": now,
		},
	})

	policies := make([]string, 0, maxControlEvidence+6)
	for i := 0; i < maxControlEvidence+5; i++ {
		policies = append(policies, "unsupported-pass-"+string(rune('a'+(i%26)))+string(rune('a'+((i/26)%26))))
	}
	policies = append(policies, "aws-s3-bucket-encryption-enabled")
	framework := &Framework{
		ID:   "truncation",
		Name: "Truncation",
		Controls: []Control{
			{ID: "truncation-control", Title: "Truncation Control", PolicyIDs: policies},
		},
	}

	report := EvaluateFramework(g, framework, EvaluationOptions{GeneratedAt: now})
	status := controlStatusByID(t, report, "truncation-control")
	if status.Status != ControlStateFailing {
		t.Fatalf("expected control to fail, got %+v", status)
	}
	if len(status.Evidence) != maxControlEvidence {
		t.Fatalf("expected capped evidence length %d, got %d", maxControlEvidence, len(status.Evidence))
	}
	foundFailingEvidence := false
	for _, item := range status.Evidence {
		if item.PolicyID == "aws-s3-bucket-encryption-enabled" && item.Status == ControlStateFailing {
			foundFailingEvidence = true
			break
		}
	}
	if !foundFailingEvidence {
		t.Fatalf("expected failing evidence to survive truncation, got %+v", status.Evidence)
	}
}

func TestBuildAuditPackageFromReportIncludesEvidence(t *testing.T) {
	framework := &Framework{
		ID:      "pkg",
		Name:    "Package",
		Version: "1.0",
	}
	report := ComplianceReport{
		FrameworkID:   framework.ID,
		FrameworkName: framework.Name,
		GeneratedAt:   time.Date(2026, 3, 13, 17, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Summary: ComplianceSummary{
			TotalControls:   1,
			PassingControls: 0,
			FailingControls: 1,
		},
		Controls: []ControlStatus{{
			ControlID:        "1",
			Title:            "Control 1",
			Description:      "desc",
			Status:           ControlStateFailing,
			EvaluationSource: ControlEvaluationSourceGraph,
			LastEvaluated:    time.Date(2026, 3, 13, 17, 0, 0, 0, time.UTC).Format(time.RFC3339),
			PolicyIDs:        []string{"policy-1"},
			FailCount:        1,
			Evidence: []ControlEvidence{{
				EntityID: "bucket:1",
				FacetID:  "bucket_encryption",
				PolicyID: "policy-1",
				Status:   ControlStateFailing,
				Reason:   "Bucket encryption is disabled",
			}},
		}},
	}

	pkg := BuildAuditPackageFromReport(framework, report)
	if pkg.Summary.FailingControls != 1 {
		t.Fatalf("expected failing control count in export summary, got %+v", pkg.Summary)
	}
	if len(pkg.Controls) != 1 || len(pkg.Controls[0].Evidence) != 1 {
		t.Fatalf("expected control evidence in export package, got %+v", pkg.Controls)
	}
	if pkg.Controls[0].EvaluationSource != ControlEvaluationSourceGraph {
		t.Fatalf("expected evaluation source to carry into export, got %+v", pkg.Controls[0])
	}
	if len(pkg.Controls[0].Evidence) != 1 {
		t.Fatalf("expected one redacted failing evidence item, got %+v", pkg.Controls[0].Evidence)
	}
	if pkg.Controls[0].Evidence[0].EntityID != "" || pkg.Controls[0].Evidence[0].EntityName != "" || pkg.Controls[0].Evidence[0].EntityKind != "" || pkg.Controls[0].Evidence[0].FacetID != "" {
		t.Fatalf("expected exported evidence to redact per-entity fields, got %+v", pkg.Controls[0].Evidence[0])
	}
}

func TestRedactReportEvidenceRemovesPassingAndEntityFields(t *testing.T) {
	report := ComplianceReport{
		Controls: []ControlStatus{{
			ControlID: "1",
			Evidence: []ControlEvidence{
				{
					EntityID:   "bucket:1",
					EntityKind: "bucket",
					EntityName: "bucket-1",
					FacetID:    "bucket_encryption",
					PolicyID:   "policy-1",
					Status:     ControlStateFailing,
					Reason:     "Bucket encryption is disabled",
				},
				{
					EntityID:   "bucket:2",
					EntityKind: "bucket",
					EntityName: "bucket-2",
					FacetID:    "bucket_encryption",
					PolicyID:   "policy-1",
					Status:     ControlStatePassing,
					Reason:     "Bucket encryption is enabled",
				},
			},
		}},
	}

	redacted := RedactReportEvidence(report)
	if len(redacted.Controls) != 1 || len(redacted.Controls[0].Evidence) != 1 {
		t.Fatalf("expected redacted report to keep only non-passing evidence, got %+v", redacted.Controls)
	}
	item := redacted.Controls[0].Evidence[0]
	if item.EntityID != "" || item.EntityName != "" || item.EntityKind != "" || item.FacetID != "" {
		t.Fatalf("expected redacted report evidence to omit per-entity fields, got %+v", item)
	}
	if item.PolicyID != "policy-1" || item.Status != ControlStateFailing || item.Reason == "" {
		t.Fatalf("expected redacted report evidence to preserve policy/status/reason, got %+v", item)
	}
}

func controlStatusByID(t *testing.T, report ComplianceReport, id string) ControlStatus {
	t.Helper()
	for _, ctrl := range report.Controls {
		if ctrl.ControlID == id {
			return ctrl
		}
	}
	t.Fatalf("missing control %q in report %+v", id, report)
	return ControlStatus{}
}
