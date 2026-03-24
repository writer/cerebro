package scanaudit

import (
	"context"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/imagescan"
	"github.com/writer/cerebro/internal/reposcan"
	"github.com/writer/cerebro/internal/scanner"
)

func TestServiceListUnifiedFindingsDeduplicatesImageNativeAndFilesystemVulnerabilities(t *testing.T) {
	store := newTestExecutionStore(t)
	svc := NewService(store, Config{})

	run := imagescan.RunRecord{
		ID:          "image_scan:dedup",
		Registry:    imagescan.RegistryECR,
		Status:      imagescan.RunStatusSucceeded,
		Stage:       imagescan.RunStageCompleted,
		Target:      imagescan.ScanTarget{Registry: imagescan.RegistryECR, Repository: "acme/platform", Tag: "1.2.3"},
		SubmittedAt: time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 3, 21, 12, 5, 0, 0, time.UTC),
		Analysis: &imagescan.AnalysisReport{
			NativeVulnerabilityCount:     1,
			FilesystemVulnerabilityCount: 1,
			Result: scanner.ContainerScanResult{
				Vulnerabilities: []scanner.ImageVulnerability{{
					ID:               "CVE-2026-0001",
					CVE:              "CVE-2026-0001",
					Severity:         "critical",
					Package:          "openssl",
					InstalledVersion: "1.0.0",
					FixedVersion:     "1.0.1",
					Description:      "native scan result",
				}},
			},
			Catalog: &filesystemanalyzer.Report{
				Vulnerabilities: []scanner.ImageVulnerability{{
					ID:               "CVE-2026-0001",
					CVE:              "CVE-2026-0001",
					Severity:         "critical",
					Package:          "openssl",
					InstalledVersion: "1.0.0",
					FixedVersion:     "1.0.1",
					Description:      "filesystem scan result",
				}},
			},
		},
	}
	saveRunEnvelope(t, store, executionstore.NamespaceImageScan, run.ID, string(run.Registry), string(run.Status), string(run.Stage), run.SubmittedAt, run.UpdatedAt, run)

	findings, err := svc.ListUnifiedFindings(context.Background(), UnifiedFindingListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListUnifiedFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 unified finding, got %#v", findings)
	}
	if findings[0].AssetKey != "acme/platform" {
		t.Fatalf("asset_key = %q, want acme/platform", findings[0].AssetKey)
	}
	if findings[0].OccurrenceCount != 2 {
		t.Fatalf("occurrence_count = %d, want 2", findings[0].OccurrenceCount)
	}
	if len(findings[0].DetectionKinds) != 2 || findings[0].DetectionKinds[0] != "filesystem" || findings[0].DetectionKinds[1] != "image_native" {
		t.Fatalf("unexpected detection kinds %#v", findings[0].DetectionKinds)
	}
}

func TestServiceListUnifiedFindingsCorrelatesRepoAndImageResultsByAssetKey(t *testing.T) {
	store := newTestExecutionStore(t)
	svc := NewService(store, Config{})

	observedAt := time.Date(2026, 3, 21, 13, 0, 0, 0, time.UTC)
	imageRun := imagescan.RunRecord{
		ID:          "image_scan:correlated",
		Registry:    imagescan.RegistryECR,
		Status:      imagescan.RunStatusSucceeded,
		Stage:       imagescan.RunStageCompleted,
		Target:      imagescan.ScanTarget{Registry: imagescan.RegistryECR, Repository: "acme/platform", Tag: "2.0.0"},
		SubmittedAt: observedAt,
		UpdatedAt:   observedAt.Add(time.Minute),
		Analysis: &imagescan.AnalysisReport{
			Result: scanner.ContainerScanResult{
				Vulnerabilities: []scanner.ImageVulnerability{{
					ID:               "CVE-2026-0002",
					CVE:              "CVE-2026-0002",
					Severity:         "high",
					Package:          "log4j-core",
					InstalledVersion: "2.14.0",
					FixedVersion:     "2.17.1",
				}},
			},
		},
	}
	repoRun := reposcan.RunRecord{
		ID:          "repo_scan:correlated",
		Status:      reposcan.RunStatusSucceeded,
		Stage:       reposcan.RunStageCompleted,
		Target:      reposcan.ScanTarget{RepoURL: "https://github.com/acme/platform.git", Ref: "main"},
		SubmittedAt: observedAt.Add(2 * time.Minute),
		UpdatedAt:   observedAt.Add(3 * time.Minute),
		Descriptor:  &reposcan.RepositoryDescriptor{Repository: "github.com/acme/platform", CommitSHA: "deadbeef"},
		Analysis: &reposcan.AnalysisReport{
			Catalog: &filesystemanalyzer.Report{
				Vulnerabilities: []scanner.ImageVulnerability{{
					ID:               "CVE-2026-0002",
					CVE:              "CVE-2026-0002",
					Severity:         "high",
					Package:          "log4j-core",
					InstalledVersion: "2.14.0",
					FixedVersion:     "2.17.1",
				}},
			},
		},
	}

	saveRunEnvelope(t, store, executionstore.NamespaceImageScan, imageRun.ID, string(imageRun.Registry), string(imageRun.Status), string(imageRun.Stage), imageRun.SubmittedAt, imageRun.UpdatedAt, imageRun)
	saveRunEnvelope(t, store, executionstore.NamespaceRepoScan, repoRun.ID, "iac", string(repoRun.Status), string(repoRun.Stage), repoRun.SubmittedAt, repoRun.UpdatedAt, repoRun)

	findings, err := svc.ListUnifiedFindings(context.Background(), UnifiedFindingListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListUnifiedFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 unified finding, got %#v", findings)
	}
	if findings[0].AssetKey != "acme/platform" {
		t.Fatalf("asset_key = %q, want acme/platform", findings[0].AssetKey)
	}
	if len(findings[0].Namespaces) != 2 || findings[0].Namespaces[0] != executionstore.NamespaceImageScan || findings[0].Namespaces[1] != executionstore.NamespaceRepoScan {
		t.Fatalf("unexpected namespaces %#v", findings[0].Namespaces)
	}
	if len(findings[0].ScanKinds) != 2 || findings[0].ScanKinds[0] != "image" || findings[0].ScanKinds[1] != "repo" {
		t.Fatalf("unexpected scan kinds %#v", findings[0].ScanKinds)
	}
}

func TestServiceListUnifiedFindingsKeepsDifferentAssetsSeparate(t *testing.T) {
	store := newTestExecutionStore(t)
	svc := NewService(store, Config{})

	firstRun := imagescan.RunRecord{
		ID:          "image_scan:first",
		Registry:    imagescan.RegistryECR,
		Status:      imagescan.RunStatusSucceeded,
		Stage:       imagescan.RunStageCompleted,
		Target:      imagescan.ScanTarget{Registry: imagescan.RegistryECR, Repository: "acme/platform", Tag: "1.0.0"},
		SubmittedAt: time.Date(2026, 3, 21, 10, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 3, 21, 10, 1, 0, 0, time.UTC),
		Analysis: &imagescan.AnalysisReport{
			Result: scanner.ContainerScanResult{
				Vulnerabilities: []scanner.ImageVulnerability{{
					ID:       "CVE-2026-0003",
					CVE:      "CVE-2026-0003",
					Severity: "medium",
					Package:  "busybox",
				}},
			},
		},
	}
	secondRun := imagescan.RunRecord{
		ID:          "image_scan:second",
		Registry:    imagescan.RegistryECR,
		Status:      imagescan.RunStatusSucceeded,
		Stage:       imagescan.RunStageCompleted,
		Target:      imagescan.ScanTarget{Registry: imagescan.RegistryECR, Repository: "acme/payments", Tag: "1.0.0"},
		SubmittedAt: time.Date(2026, 3, 21, 11, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 3, 21, 11, 1, 0, 0, time.UTC),
		Analysis: &imagescan.AnalysisReport{
			Result: scanner.ContainerScanResult{
				Vulnerabilities: []scanner.ImageVulnerability{{
					ID:       "CVE-2026-0003",
					CVE:      "CVE-2026-0003",
					Severity: "medium",
					Package:  "busybox",
				}},
			},
		},
	}

	saveRunEnvelope(t, store, executionstore.NamespaceImageScan, firstRun.ID, string(firstRun.Registry), string(firstRun.Status), string(firstRun.Stage), firstRun.SubmittedAt, firstRun.UpdatedAt, firstRun)
	saveRunEnvelope(t, store, executionstore.NamespaceImageScan, secondRun.ID, string(secondRun.Registry), string(secondRun.Status), string(secondRun.Stage), secondRun.SubmittedAt, secondRun.UpdatedAt, secondRun)

	findings, err := svc.ListUnifiedFindings(context.Background(), UnifiedFindingListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListUnifiedFindings: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 unified findings, got %#v", findings)
	}
	if findings[0].AssetKey == findings[1].AssetKey {
		t.Fatalf("expected distinct asset keys, got %#v", findings)
	}
}

func TestServiceListUnifiedFindingsIncludesIaCMisconfigurations(t *testing.T) {
	store := newTestExecutionStore(t)
	svc := NewService(store, Config{})

	run := reposcan.RunRecord{
		ID:          "repo_scan:iac",
		Status:      reposcan.RunStatusSucceeded,
		Stage:       reposcan.RunStageCompleted,
		Target:      reposcan.ScanTarget{RepoURL: "https://github.com/acme/platform.git", Ref: "main"},
		SubmittedAt: time.Date(2026, 3, 21, 14, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 3, 21, 14, 2, 0, 0, time.UTC),
		Descriptor:  &reposcan.RepositoryDescriptor{Repository: "github.com/acme/platform", CommitSHA: "beadfeed"},
		Analysis: &reposcan.AnalysisReport{
			Catalog: &filesystemanalyzer.Report{
				Misconfigurations: []filesystemanalyzer.ConfigFinding{{
					ID:           "cfg-1",
					Type:         "public_ingress",
					Severity:     "high",
					Title:        "Security group allows 0.0.0.0/0",
					Description:  "ingress open to the world",
					ResourceType: "aws_security_group",
					ArtifactType: "terraform",
					Path:         "infra/main.tf",
				}},
			},
		},
	}
	saveRunEnvelope(t, store, executionstore.NamespaceRepoScan, run.ID, "iac", string(run.Status), string(run.Stage), run.SubmittedAt, run.UpdatedAt, run)

	findings, err := svc.ListUnifiedFindings(context.Background(), UnifiedFindingListOptions{
		Kinds: []string{"misconfiguration"},
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListUnifiedFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 misconfiguration finding, got %#v", findings)
	}
	if findings[0].Kind != "misconfiguration" {
		t.Fatalf("kind = %q, want misconfiguration", findings[0].Kind)
	}
	if len(findings[0].DetectionKinds) != 1 || findings[0].DetectionKinds[0] != "iac" {
		t.Fatalf("unexpected detection kinds %#v", findings[0].DetectionKinds)
	}
}
