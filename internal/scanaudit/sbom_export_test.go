package scanaudit

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/imagescan"
	"github.com/writer/cerebro/internal/reposcan"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/workloadscan"
)

func TestExportRecordIncludesSBOMArtifactsForImageScan(t *testing.T) {
	store := newTestExecutionStore(t)
	svc := NewService(store, Config{RetentionDays: 30})

	run := imagescan.RunRecord{
		ID:          "image_scan:sbom",
		Registry:    imagescan.RegistryECR,
		Status:      imagescan.RunStatusSucceeded,
		Stage:       imagescan.RunStageCompleted,
		Target:      imagescan.ScanTarget{Registry: imagescan.RegistryECR, Repository: "acme/platform", Tag: "1.2.3"},
		SubmittedAt: time.Date(2026, 3, 21, 19, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 3, 21, 19, 5, 0, 0, time.UTC),
		Analysis: &imagescan.AnalysisReport{
			Result: scanner.ContainerScanResult{},
			Catalog: &filesystemanalyzer.Report{
				SBOM: filesystemanalyzer.SBOMDocument{
					Format:      "cyclonedx-json",
					SpecVersion: "1.5",
					GeneratedAt: time.Date(2026, 3, 21, 19, 4, 0, 0, time.UTC),
					Components: []filesystemanalyzer.SBOMComponent{{
						BOMRef:   "pkg:npm/express@4.18.2",
						Type:     "library",
						Name:     "express",
						Version:  "4.18.2",
						PURL:     "pkg:npm/express@4.18.2",
						Location: "/app/package-lock.json",
					}},
				},
			},
		},
	}
	saveRunEnvelope(t, store, executionstore.NamespaceImageScan, run.ID, string(run.Registry), string(run.Status), string(run.Stage), run.SubmittedAt, run.UpdatedAt, run)

	pkg, err := svc.ExportRecord(context.Background(), executionstore.NamespaceImageScan, run.ID)
	if err != nil {
		t.Fatalf("ExportRecord: %v", err)
	}

	zipBytes, err := RenderExportPackageZIP(*pkg)
	if err != nil {
		t.Fatalf("RenderExportPackageZIP: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("zip payload invalid: %v", err)
	}
	entries := make(map[string]*zip.File, len(zr.File))
	for _, file := range zr.File {
		entries[file.Name] = file
	}
	for _, name := range []string{"sbom.cyclonedx.json", "sbom.spdx.json"} {
		if _, ok := entries[name]; !ok {
			t.Fatalf("missing sbom artifact %q", name)
		}
	}

	cyclone := readSBOMZipJSONEntry(t, entries["sbom.cyclonedx.json"])
	if cyclone["bomFormat"] != "CycloneDX" {
		t.Fatalf("unexpected cyclonedx payload %#v", cyclone)
	}
	spdx := readSBOMZipJSONEntry(t, entries["sbom.spdx.json"])
	if spdx["spdxVersion"] != "SPDX-2.3" {
		t.Fatalf("unexpected spdx payload %#v", spdx)
	}
}

func TestExportRecordMergesWorkloadVolumeSBOMArtifacts(t *testing.T) {
	store := newTestExecutionStore(t)
	svc := NewService(store, Config{})

	now := time.Date(2026, 3, 21, 20, 0, 0, 0, time.UTC)
	run := workloadscan.RunRecord{
		ID:          "workload_scan:sbom",
		Provider:    workloadscan.ProviderAWS,
		Status:      workloadscan.RunStatusSucceeded,
		Stage:       workloadscan.RunStageCompleted,
		Target:      workloadscan.VMTarget{Provider: workloadscan.ProviderAWS, AccountID: "123456789012", Region: "us-west-2", InstanceID: "i-123456"},
		ScannerHost: workloadscan.ScannerHost{HostID: "scanner-a", Region: "us-west-2"},
		SubmittedAt: now,
		UpdatedAt:   now.Add(time.Minute),
		Volumes: []workloadscan.VolumeScanRecord{
			{
				Source:    workloadscan.SourceVolume{ID: "vol-a"},
				Status:    workloadscan.RunStatusSucceeded,
				Stage:     workloadscan.RunStageCompleted,
				StartedAt: now,
				UpdatedAt: now.Add(30 * time.Second),
				Analysis: &workloadscan.AnalysisReport{
					Catalog: &filesystemanalyzer.Report{
						SBOM: filesystemanalyzer.SBOMDocument{
							Format:      "cyclonedx-json",
							SpecVersion: "1.5",
							GeneratedAt: now.Add(10 * time.Second),
							Components: []filesystemanalyzer.SBOMComponent{{
								BOMRef:   "pkg:npm/express@4.18.2",
								Type:     "library",
								Name:     "express",
								Version:  "4.18.2",
								PURL:     "pkg:npm/express@4.18.2",
								Location: "/mnt/root/package-lock.json",
							}},
						},
					},
				},
			},
			{
				Source:    workloadscan.SourceVolume{ID: "vol-b"},
				Status:    workloadscan.RunStatusSucceeded,
				Stage:     workloadscan.RunStageCompleted,
				StartedAt: now,
				UpdatedAt: now.Add(40 * time.Second),
				Analysis: &workloadscan.AnalysisReport{
					Catalog: &filesystemanalyzer.Report{
						SBOM: filesystemanalyzer.SBOMDocument{
							Format:      "cyclonedx-json",
							SpecVersion: "1.5",
							GeneratedAt: now.Add(20 * time.Second),
							Components: []filesystemanalyzer.SBOMComponent{{
								BOMRef:   "pkg:deb/openssl@3.0.2",
								Type:     "library",
								Name:     "openssl",
								Version:  "3.0.2",
								PURL:     "pkg:deb/ubuntu/openssl@3.0.2",
								Location: "/mnt/root/var/lib/dpkg/status",
							}},
						},
					},
				},
			},
		},
	}
	saveRunEnvelope(t, store, executionstore.NamespaceWorkloadScan, run.ID, string(run.Provider), string(run.Status), string(run.Stage), run.SubmittedAt, run.UpdatedAt, run)

	pkg, err := svc.ExportRecord(context.Background(), executionstore.NamespaceWorkloadScan, run.ID)
	if err != nil {
		t.Fatalf("ExportRecord: %v", err)
	}
	zipBytes, err := RenderExportPackageZIP(*pkg)
	if err != nil {
		t.Fatalf("RenderExportPackageZIP: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("zip payload invalid: %v", err)
	}
	var cyclonedx map[string]any
	for _, file := range zr.File {
		if file.Name != "sbom.cyclonedx.json" {
			continue
		}
		cyclonedx = readSBOMZipJSONEntry(t, file)
		break
	}
	if cyclonedx == nil {
		t.Fatal("expected sbom.cyclonedx.json entry")
	}
	components, ok := cyclonedx["components"].([]any)
	if !ok || len(components) != 2 {
		t.Fatalf("expected merged workload components, got %#v", cyclonedx["components"])
	}
}

func TestExportRecordIncludesSBOMArtifactsForRepoScan(t *testing.T) {
	store := newTestExecutionStore(t)
	svc := NewService(store, Config{})

	run := reposcan.RunRecord{
		ID:          "repo_scan:sbom",
		Status:      reposcan.RunStatusSucceeded,
		Stage:       reposcan.RunStageCompleted,
		Target:      reposcan.ScanTarget{RepoURL: "https://github.com/acme/platform.git", Ref: "main"},
		SubmittedAt: time.Date(2026, 3, 21, 21, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 3, 21, 21, 3, 0, 0, time.UTC),
		Descriptor:  &reposcan.RepositoryDescriptor{Repository: "github.com/acme/platform", CommitSHA: "deadbeef"},
		Analysis: &reposcan.AnalysisReport{
			Catalog: &filesystemanalyzer.Report{
				SBOM: filesystemanalyzer.SBOMDocument{
					Format:      "cyclonedx-json",
					SpecVersion: "1.5",
					GeneratedAt: time.Date(2026, 3, 21, 21, 2, 0, 0, time.UTC),
					Components: []filesystemanalyzer.SBOMComponent{{
						BOMRef:   "pkg:golang/github.com/google/uuid@1.6.0",
						Type:     "library",
						Name:     "github.com/google/uuid",
						Version:  "1.6.0",
						PURL:     "pkg:golang/github.com/google/uuid@1.6.0",
						Location: "go.mod",
					}},
				},
			},
		},
	}
	saveRunEnvelope(t, store, executionstore.NamespaceRepoScan, run.ID, "repo", string(run.Status), string(run.Stage), run.SubmittedAt, run.UpdatedAt, run)

	pkg, err := svc.ExportRecord(context.Background(), executionstore.NamespaceRepoScan, run.ID)
	if err != nil {
		t.Fatalf("ExportRecord: %v", err)
	}
	if len(pkg.SBOMs) != 2 {
		t.Fatalf("expected 2 sbom artifacts, got %#v", pkg.SBOMs)
	}
}

func readSBOMZipJSONEntry(t *testing.T, file *zip.File) map[string]any {
	t.Helper()
	rc, err := file.Open()
	if err != nil {
		t.Fatalf("Open(%s): %v", file.Name, err)
	}
	defer func() { _ = rc.Close() }()

	var payload map[string]any
	if err := json.NewDecoder(rc).Decode(&payload); err != nil {
		t.Fatalf("Decode(%s): %v", file.Name, err)
	}
	return payload
}
