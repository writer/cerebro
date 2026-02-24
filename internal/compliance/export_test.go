package compliance

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestBuildAuditPackage(t *testing.T) {
	framework := &Framework{
		ID:      "pci-dss-4.0",
		Name:    "PCI DSS",
		Version: "4.0",
		Controls: []Control{
			{ID: "1.1", Title: "Control 1.1", Description: "desc", PolicyIDs: []string{"policy-a", "policy-b"}},
			{ID: "1.2", Title: "Control 1.2", Description: "desc", PolicyIDs: []string{"policy-c"}},
		},
	}

	now := time.Date(2026, 2, 24, 16, 15, 3, 0, time.UTC)
	pkg := BuildAuditPackage(framework, map[string]int{"policy-b": 2}, now)

	if pkg.Manifest.FrameworkID != framework.ID {
		t.Fatalf("framework id = %q, want %q", pkg.Manifest.FrameworkID, framework.ID)
	}
	if pkg.Manifest.GeneratedAt != "2026-02-24T16:15:03Z" {
		t.Fatalf("generated_at = %q", pkg.Manifest.GeneratedAt)
	}
	if pkg.Summary.TotalControls != 2 || pkg.Summary.FailingControls != 1 || pkg.Summary.PassingControls != 1 {
		t.Fatalf("unexpected summary: %+v", pkg.Summary)
	}

	if pkg.Controls[0].Status != "failing" {
		t.Fatalf("control 1 status = %q, want failing", pkg.Controls[0].Status)
	}
	if pkg.Controls[0].FindingCount != 2 {
		t.Fatalf("control 1 finding_count = %d, want 2", pkg.Controls[0].FindingCount)
	}
	if len(pkg.Controls[0].Findings) != 1 || pkg.Controls[0].Findings[0] != "policy-b" {
		t.Fatalf("control 1 findings = %#v", pkg.Controls[0].Findings)
	}

	if pkg.Controls[1].Status != "passing" {
		t.Fatalf("control 2 status = %q, want passing", pkg.Controls[1].Status)
	}
}

func TestRenderAuditPackageZIP(t *testing.T) {
	pkg := AuditPackage{
		Manifest: AuditManifest{FrameworkID: "cis-aws-1.5", FrameworkName: "CIS AWS", Version: "1.5", GeneratedAt: "2026-02-24T16:15:03Z", GeneratedBy: "cerebro"},
		Summary:  AuditSummary{TotalControls: 1, PassingControls: 1, FailingControls: 0},
		Controls: []AuditControlEvidence{{ControlID: "1.1", Title: "Control", Description: "desc", Status: "passing", Policies: []string{"policy-a"}}},
	}

	zipBytes, err := RenderAuditPackageZIP(pkg)
	if err != nil {
		t.Fatalf("RenderAuditPackageZIP() error = %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("zip reader error = %v", err)
	}

	if len(zr.File) != 3 {
		t.Fatalf("zip entries = %d, want 3", len(zr.File))
	}

	entries := map[string]*zip.File{}
	for _, file := range zr.File {
		entries[file.Name] = file
	}
	for _, name := range []string{"manifest.json", "summary.json", "controls.json"} {
		if _, ok := entries[name]; !ok {
			t.Fatalf("missing zip entry %q", name)
		}
	}

	manifestFile := entries["manifest.json"]
	rc, err := manifestFile.Open()
	if err != nil {
		t.Fatalf("open manifest: %v", err)
	}
	defer rc.Close()

	var manifest AuditManifest
	if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.FrameworkID != "cis-aws-1.5" {
		t.Fatalf("manifest framework id = %q", manifest.FrameworkID)
	}
}

func TestAuditPackageFilename(t *testing.T) {
	now := time.Date(2026, 2, 24, 16, 15, 3, 0, time.UTC)
	got := AuditPackageFilename("pci-dss-4.0", now)
	want := "cerebro-audit-pci-dss-4.0-20260224T161503Z.zip"
	if got != want {
		t.Fatalf("filename = %q, want %q", got, want)
	}
}
