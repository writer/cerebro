package imagescan

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/scanner"
)

type fakeSweepRegistry struct {
	name         string
	host         string
	repositories []scanner.Repository
	tags         map[string][]scanner.ImageTag
	manifests    map[string]*scanner.ImageManifest
}

func (r *fakeSweepRegistry) Name() string { return r.name }
func (r *fakeSweepRegistry) RegistryHost() string {
	return r.host
}
func (r *fakeSweepRegistry) QualifyImageRef(repo, tag string) string {
	return r.host + "/" + repo + ":" + tag
}
func (r *fakeSweepRegistry) ListRepositories(context.Context) ([]scanner.Repository, error) {
	return append([]scanner.Repository(nil), r.repositories...), nil
}
func (r *fakeSweepRegistry) ListTags(_ context.Context, repo string) ([]scanner.ImageTag, error) {
	return append([]scanner.ImageTag(nil), r.tags[repo]...), nil
}
func (r *fakeSweepRegistry) GetManifest(_ context.Context, repo, ref string) (*scanner.ImageManifest, error) {
	manifest, ok := r.manifests[repo+"@"+ref]
	if !ok {
		return nil, fmt.Errorf("manifest not found for %s@%s", repo, ref)
	}
	return manifest, nil
}
func (r *fakeSweepRegistry) GetVulnerabilities(context.Context, string, string) ([]scanner.ImageVulnerability, error) {
	return nil, nil
}

func timePtr(ts time.Time) *time.Time {
	return &ts
}

func TestRunRegistrySweepScansOnlyNewDigestsAndMarksStaleImages(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "image-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 20, 21, 0, 0, 0, time.UTC)
	registry := &fakeSweepRegistry{
		name: "ecr",
		host: "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		repositories: []scanner.Repository{
			{Name: "payments"},
			{Name: "base"},
			{Name: "legacy"},
		},
		tags: map[string][]scanner.ImageTag{
			"payments": {{Name: "latest", Digest: "sha256:new", PushedAt: now.Add(-2 * 24 * time.Hour)}},
			"base":     {{Name: "stable", Digest: "sha256:known", PushedAt: now.Add(-10 * 24 * time.Hour)}},
			"legacy":   {{Name: "old", Digest: "sha256:stale", PushedAt: now.Add(-120 * 24 * time.Hour)}},
		},
		manifests: map[string]*scanner.ImageManifest{
			"payments@sha256:new": {Digest: "sha256:new", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
			"base@sha256:known":   {Digest: "sha256:known", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
			"legacy@sha256:stale": {Digest: "sha256:stale", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
			"payments@latest":     {Digest: "sha256:new", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
			"base@stable":         {Digest: "sha256:known", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
			"legacy@old":          {Digest: "sha256:stale", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
		},
	}

	previousCompleted := now.Add(-12 * time.Hour)
	if err := store.SaveRun(context.Background(), &RunRecord{
		ID:       "image_scan:existing",
		Registry: RegistryECR,
		Status:   RunStatusSucceeded,
		Stage:    RunStageCompleted,
		Target: ScanTarget{
			Registry:     RegistryECR,
			RegistryHost: registry.host,
			Repository:   "base",
			Tag:          "stable",
			Digest:       "sha256:known",
		},
		SubmittedAt: previousCompleted,
		UpdatedAt:   previousCompleted,
		CompletedAt: &previousCompleted,
		Manifest:    &scanner.ImageManifest{Digest: "sha256:known"},
	}); err != nil {
		t.Fatalf("seed previous run: %v", err)
	}

	runner := NewRunner(RunnerOptions{
		Store:      store,
		Registries: []scanner.RegistryClient{registry},
		Now: func() time.Time {
			return now
		},
	})

	report, err := runner.RunRegistrySweep(context.Background(), SweepRequest{
		Registry:   RegistryECR,
		StaleAfter: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("run registry sweep: %v", err)
	}
	if report.Scanned != 2 || report.Skipped != 1 || report.Stale != 1 {
		t.Fatalf("unexpected sweep counters: %#v", report)
	}
	if len(report.Items) != 3 {
		t.Fatalf("expected three inventory items, got %#v", report.Items)
	}
	itemsByRepo := make(map[string]SweepItem, len(report.Items))
	for _, item := range report.Items {
		itemsByRepo[item.Repository] = item
	}
	if item := itemsByRepo["base"]; item.SkipReason != "unchanged_digest" || item.ScanRunID != "" {
		t.Fatalf("expected unchanged digest skip for base, got %#v", item)
	}
	if item := itemsByRepo["legacy"]; !item.Stale || item.ScanRunID == "" {
		t.Fatalf("expected stale legacy image to be scanned, got %#v", item)
	}
	if item := itemsByRepo["payments"]; item.ScanRunID == "" || !item.ScanRequired {
		t.Fatalf("expected payments image to be scanned, got %#v", item)
	}
}

func TestRunRegistrySweepDedupesIdenticalDigestAcrossTags(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "image-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 20, 21, 0, 0, 0, time.UTC)
	registry := &fakeSweepRegistry{
		name: "ecr",
		host: "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		repositories: []scanner.Repository{
			{Name: "payments"},
		},
		tags: map[string][]scanner.ImageTag{
			"payments": {
				{Name: "latest", Digest: "sha256:shared", PushedAt: now},
				{Name: "prod", Digest: "sha256:shared", PushedAt: now.Add(-time.Minute)},
			},
		},
		manifests: map[string]*scanner.ImageManifest{
			"payments@sha256:shared": {Digest: "sha256:shared", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
			"payments@latest":        {Digest: "sha256:shared", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
			"payments@prod":          {Digest: "sha256:shared", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
		},
	}

	runner := NewRunner(RunnerOptions{
		Store:      store,
		Registries: []scanner.RegistryClient{registry},
		Now: func() time.Time {
			return now
		},
	})

	report, err := runner.RunRegistrySweep(context.Background(), SweepRequest{
		Registry: RegistryECR,
	})
	if err != nil {
		t.Fatalf("run registry sweep: %v", err)
	}
	if report.Scanned != 1 {
		t.Fatalf("expected one scan for shared digest, got %#v", report)
	}
	if len(report.Items) != 2 {
		t.Fatalf("expected two inventory items, got %#v", report.Items)
	}
	if report.Items[0].ScanRunID == "" {
		t.Fatalf("expected first item to have a scan run id, got %#v", report.Items[0])
	}
	if report.Items[1].SkipReason != "digest_already_planned" || report.Items[1].ScanRunID != report.Items[0].ScanRunID {
		t.Fatalf("expected second tag to reuse first scan, got %#v", report.Items[1])
	}
}

func TestRunRegistrySweepDoesNotReuseDigestAcrossDifferentRegistryHosts(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "image-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 20, 21, 0, 0, 0, time.UTC)
	registry := &fakeSweepRegistry{
		name: "ecr",
		host: "222222222222.dkr.ecr.us-east-1.amazonaws.com",
		repositories: []scanner.Repository{
			{Name: "payments"},
		},
		tags: map[string][]scanner.ImageTag{
			"payments": {{Name: "latest", Digest: "sha256:shared", PushedAt: now}},
		},
		manifests: map[string]*scanner.ImageManifest{
			"payments@sha256:shared": {Digest: "sha256:shared", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
			"payments@latest":        {Digest: "sha256:shared", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
		},
	}

	if err := store.SaveRun(context.Background(), &RunRecord{
		ID:       "image_scan:other-host",
		Registry: RegistryECR,
		Status:   RunStatusSucceeded,
		Stage:    RunStageCompleted,
		Target: ScanTarget{
			Registry:     RegistryECR,
			RegistryHost: "111111111111.dkr.ecr.us-east-1.amazonaws.com",
			Repository:   "payments",
			Tag:          "latest",
			Digest:       "sha256:shared",
		},
		SubmittedAt: now.Add(-time.Hour),
		UpdatedAt:   now.Add(-time.Hour),
		CompletedAt: timePtr(now.Add(-time.Hour)),
		Manifest:    &scanner.ImageManifest{Digest: "sha256:shared"},
	}); err != nil {
		t.Fatalf("seed other-host run: %v", err)
	}

	runner := NewRunner(RunnerOptions{
		Store:      store,
		Registries: []scanner.RegistryClient{registry},
		Now: func() time.Time {
			return now
		},
	})

	report, err := runner.RunRegistrySweep(context.Background(), SweepRequest{Registry: RegistryECR})
	if err != nil {
		t.Fatalf("run registry sweep: %v", err)
	}
	if report.Scanned != 1 || report.Skipped != 0 {
		t.Fatalf("expected different registry host digest to be scanned, got %#v", report)
	}
	if len(report.Items) != 1 || report.Items[0].ScanRunID == "" || !report.Items[0].ScanRequired {
		t.Fatalf("expected cross-host digest to produce a fresh scan item, got %#v", report.Items)
	}
}

func TestRunRegistrySweepSelectsRegistryClientByHost(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "image-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	east := &fakeSweepRegistry{
		name: "ecr",
		host: "111111111111.dkr.ecr.us-east-1.amazonaws.com",
		repositories: []scanner.Repository{
			{Name: "payments-east"},
		},
		tags: map[string][]scanner.ImageTag{
			"payments-east": {{Name: "latest", Digest: "sha256:east", PushedAt: now}},
		},
		manifests: map[string]*scanner.ImageManifest{
			"payments-east@sha256:east": {Digest: "sha256:east", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
			"payments-east@latest":      {Digest: "sha256:east", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
		},
	}
	west := &fakeSweepRegistry{
		name: "ecr",
		host: "222222222222.dkr.ecr.us-west-2.amazonaws.com",
		repositories: []scanner.Repository{
			{Name: "payments-west"},
		},
		tags: map[string][]scanner.ImageTag{
			"payments-west": {{Name: "latest", Digest: "sha256:west", PushedAt: now}},
		},
		manifests: map[string]*scanner.ImageManifest{
			"payments-west@sha256:west": {Digest: "sha256:west", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
			"payments-west@latest":      {Digest: "sha256:west", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
		},
	}

	runner := NewRunner(RunnerOptions{
		Store:      store,
		Registries: []scanner.RegistryClient{east, west},
		Now: func() time.Time {
			return now
		},
	})

	report, err := runner.RunRegistrySweep(context.Background(), SweepRequest{
		Registry:     RegistryECR,
		RegistryHost: east.host,
	})
	if err != nil {
		t.Fatalf("run registry sweep: %v", err)
	}
	if report.Scanned != 1 || len(report.Items) != 1 {
		t.Fatalf("expected one scanned east-host item, got %#v", report)
	}
	if got := report.Items[0].Repository; got != "payments-east" {
		t.Fatalf("expected east repository, got %#v", report.Items[0])
	}
}

func TestRunRegistrySweepDoesNotReuseDryRunDigests(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "image-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 20, 21, 0, 0, 0, time.UTC)
	registry := &fakeSweepRegistry{
		name: "ecr",
		host: "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		repositories: []scanner.Repository{
			{Name: "payments"},
		},
		tags: map[string][]scanner.ImageTag{
			"payments": {{Name: "latest", Digest: "sha256:known", PushedAt: now}},
		},
		manifests: map[string]*scanner.ImageManifest{
			"payments@sha256:known": {Digest: "sha256:known", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
			"payments@latest":       {Digest: "sha256:known", Config: scanner.ImageConfig{OS: "linux", Architecture: "amd64"}},
		},
	}

	if err := store.SaveRun(context.Background(), &RunRecord{
		ID:       "image_scan:dryrun",
		Registry: RegistryECR,
		Status:   RunStatusSucceeded,
		Stage:    RunStageCompleted,
		DryRun:   true,
		Target: ScanTarget{
			Registry:     RegistryECR,
			RegistryHost: registry.host,
			Repository:   "payments",
			Tag:          "latest",
			Digest:       "sha256:known",
		},
		SubmittedAt: now.Add(-time.Hour),
		UpdatedAt:   now.Add(-time.Hour),
		Manifest:    &scanner.ImageManifest{Digest: "sha256:known"},
	}); err != nil {
		t.Fatalf("seed dry run: %v", err)
	}

	runner := NewRunner(RunnerOptions{
		Store:      store,
		Registries: []scanner.RegistryClient{registry},
		Now: func() time.Time {
			return now
		},
	})

	report, err := runner.RunRegistrySweep(context.Background(), SweepRequest{Registry: RegistryECR})
	if err != nil {
		t.Fatalf("run registry sweep: %v", err)
	}
	if report.Scanned != 1 || report.Skipped != 0 {
		t.Fatalf("expected dry-run digest to be scanned for real, got %#v", report)
	}
	if len(report.Items) != 1 || report.Items[0].ScanRunID == "" || !report.Items[0].ScanRequired {
		t.Fatalf("expected actual scan item after prior dry run, got %#v", report.Items)
	}
}
