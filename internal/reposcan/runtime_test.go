package reposcan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/scanpolicy"
	"github.com/writer/cerebro/internal/scm"
)

type stubMaterializer struct {
	descriptor *RepositoryDescriptor
	checkout   *CheckoutArtifact
	err        error
}

func (m stubMaterializer) Materialize(context.Context, string, ScanTarget) (*RepositoryDescriptor, *CheckoutArtifact, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.descriptor, m.checkout, nil
}

func (stubMaterializer) Cleanup(context.Context, *CheckoutArtifact) error {
	return nil
}

func TestSQLiteRunStoreRoundTripAndEvents(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	run := &RunRecord{
		ID:          "repo_scan:test",
		Status:      RunStatusRunning,
		Stage:       RunStageAnalyze,
		Target:      ScanTarget{RepoURL: "https://github.com/acme/platform"},
		SubmittedAt: now,
		UpdatedAt:   now,
	}
	if err := store.SaveRun(context.Background(), run); err != nil {
		t.Fatalf("save run: %v", err)
	}
	event, err := store.AppendEvent(context.Background(), run.ID, RunEvent{
		Status:     run.Status,
		Stage:      run.Stage,
		Message:    "analysis started",
		RecordedAt: now,
	})
	if err != nil {
		t.Fatalf("append event: %v", err)
	}
	if event.Sequence != 1 {
		t.Fatalf("expected first event sequence 1, got %d", event.Sequence)
	}
	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load run: %v", err)
	}
	if loaded == nil || loaded.ID != run.ID {
		t.Fatalf("expected loaded run %q, got %#v", run.ID, loaded)
	}
	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 || events[0].Message != "analysis started" {
		t.Fatalf("unexpected stored events: %#v", events)
	}
}

func TestLocalMaterializerClonesRepoAndCapturesRevision(t *testing.T) {
	repoDir, head := createIaCTestRepo(t)
	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "checkouts"), scm.NewLocalClient(""))

	descriptor, checkout, err := materializer.Materialize(context.Background(), "repo_scan:test", ScanTarget{RepoURL: repoDir})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if descriptor == nil {
		t.Fatal("expected repository descriptor")
	}
	if descriptor.CommitSHA != head {
		t.Fatalf("expected commit %q, got %q", head, descriptor.CommitSHA)
	}
	if descriptor.RepoURL != repoDir {
		t.Fatalf("expected repo URL %q, got %q", repoDir, descriptor.RepoURL)
	}
	if descriptor.Repository != filepath.Base(repoDir) {
		t.Fatalf("expected repository %q, got %q", filepath.Base(repoDir), descriptor.Repository)
	}
	if checkout == nil || strings.TrimSpace(checkout.Path) == "" {
		t.Fatalf("expected checkout artifact, got %#v", checkout)
	}
	if _, err := os.Stat(filepath.Join(checkout.Path, "infra", "main.tf")); err != nil {
		t.Fatalf("expected cloned terraform file: %v", err)
	}
}

func TestLocalMaterializerCreatesRestrictedCheckoutParent(t *testing.T) {
	repoDir, _ := createIaCTestRepo(t)
	basePath := filepath.Join(t.TempDir(), "checkouts")
	materializer := NewLocalMaterializer(basePath, scm.NewLocalClient(""))

	_, _, err := materializer.Materialize(context.Background(), "repo_scan:test", ScanTarget{RepoURL: repoDir})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	info, err := os.Stat(basePath)
	if err != nil {
		t.Fatalf("stat checkout base: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("expected checkout base permissions 0750, got %04o", got)
	}
}

func TestRunnerPersistsIaCAnalysisAndCleansUpCheckout(t *testing.T) {
	repoDir, head := createIaCTestRepo(t)
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 20, 18, 0, 0, 0, time.UTC)
	runner := NewRunner(RunnerOptions{
		Store:        store,
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "checkouts"), scm.NewLocalClient("")),
		Analyzer:     FilesystemAnalyzer{},
		Now: func() time.Time {
			return now
		},
	})

	run, err := runner.RunRepositoryScan(context.Background(), ScanRequest{
		RequestedBy: "alice",
		Target:      ScanTarget{RepoURL: repoDir},
	})
	if err != nil {
		t.Fatalf("run repository scan: %v", err)
	}
	if run.Status != RunStatusSucceeded || run.Stage != RunStageCompleted {
		t.Fatalf("expected succeeded run, got status=%s stage=%s", run.Status, run.Stage)
	}
	if run.Descriptor == nil || run.Descriptor.CommitSHA != head {
		t.Fatalf("expected descriptor commit %q, got %#v", head, run.Descriptor)
	}
	if run.Analysis == nil {
		t.Fatal("expected analysis report")
	}
	if run.Analysis.Analyzer != "filesystem" {
		t.Fatalf("expected filesystem analyzer, got %q", run.Analysis.Analyzer)
	}
	if run.Analysis.IaCArtifactCount < 2 {
		t.Fatalf("expected IaC artifacts, got %#v", run.Analysis)
	}
	if run.Analysis.MisconfigurationCount < 1 {
		t.Fatalf("expected misconfigurations, got %#v", run.Analysis)
	}
	if run.Checkout == nil || run.Checkout.CleanedUpAt == nil {
		t.Fatalf("expected cleaned-up checkout artifact, got %#v", run.Checkout)
	}
	if _, err := os.Stat(run.Checkout.Path); !os.IsNotExist(err) {
		t.Fatalf("expected checkout path to be removed, got %v", err)
	}
	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load run: %v", err)
	}
	if loaded == nil || loaded.Status != RunStatusSucceeded {
		t.Fatalf("expected persisted succeeded run, got %#v", loaded)
	}
	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) < 4 {
		t.Fatalf("expected lifecycle events, got %#v", events)
	}
	if events[len(events)-1].Stage != RunStageCompleted {
		t.Fatalf("expected final completed event, got %#v", events[len(events)-1])
	}
}

func TestRunnerDryRunSkipsAnalysisButCapturesRevision(t *testing.T) {
	repoDir, head := createIaCTestRepo(t)
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	runner := NewRunner(RunnerOptions{
		Store:        store,
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "checkouts"), scm.NewLocalClient("")),
	})

	run, err := runner.RunRepositoryScan(context.Background(), ScanRequest{
		Target: ScanTarget{RepoURL: repoDir},
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("run repository scan: %v", err)
	}
	if run.Status != RunStatusSucceeded || run.Stage != RunStageCompleted {
		t.Fatalf("expected dry-run to succeed, got status=%s stage=%s", run.Status, run.Stage)
	}
	if run.Descriptor == nil || run.Descriptor.CommitSHA != head {
		t.Fatalf("expected dry-run descriptor commit %q, got %#v", head, run.Descriptor)
	}
	if run.Analysis != nil {
		t.Fatalf("expected no analysis for dry-run, got %#v", run.Analysis)
	}
	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	for _, event := range events {
		if event.Stage == RunStageAnalyze {
			t.Fatalf("expected dry-run to skip analyze stage, got %#v", events)
		}
	}
}

func TestRunnerSanitizesPersistedRepoURLs(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 21, 1, 0, 0, 0, time.UTC)
	rawURL := "https://buildbot:ghp_secret@example.com/acme/platform.git"
	wantURL := "https://example.com/acme/platform.git"

	runner := NewRunner(RunnerOptions{
		Store: store,
		Materializer: stubMaterializer{
			descriptor: &RepositoryDescriptor{
				RepoURL:    rawURL,
				Repository: "platform",
				CommitSHA:  "abc123",
			},
			checkout: &CheckoutArtifact{
				Path:           filepath.Join(t.TempDir(), "checkout"),
				MaterializedAt: now,
				Metadata: map[string]any{
					"repo_url": rawURL,
				},
			},
		},
		Now: func() time.Time {
			return now
		},
	})

	run, err := runner.RunRepositoryScan(context.Background(), ScanRequest{
		ID:       "repo_scan:sanitize-urls",
		Target:   ScanTarget{RepoURL: rawURL},
		DryRun:   true,
		Metadata: map[string]string{"source": "test"},
	})
	if err != nil {
		t.Fatalf("run repository scan: %v", err)
	}
	if run.Target.RepoURL != wantURL {
		t.Fatalf("expected sanitized target repo URL %q, got %q", wantURL, run.Target.RepoURL)
	}
	if run.Descriptor == nil || run.Descriptor.RepoURL != wantURL {
		t.Fatalf("expected sanitized descriptor repo URL %q, got %#v", wantURL, run.Descriptor)
	}
	if got, _ := run.Checkout.Metadata["repo_url"].(string); got != wantURL {
		t.Fatalf("expected sanitized checkout metadata repo URL %q, got %#v", wantURL, run.Checkout.Metadata)
	}

	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load run: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected persisted run")
	}
	if loaded.Target.RepoURL != wantURL {
		t.Fatalf("expected persisted target repo URL %q, got %q", wantURL, loaded.Target.RepoURL)
	}
	if loaded.Descriptor == nil || loaded.Descriptor.RepoURL != wantURL {
		t.Fatalf("expected persisted descriptor repo URL %q, got %#v", wantURL, loaded.Descriptor)
	}
	if got, _ := loaded.Checkout.Metadata["repo_url"].(string); got != wantURL {
		t.Fatalf("expected persisted checkout metadata repo URL %q, got %#v", wantURL, loaded.Checkout.Metadata)
	}
}

func TestRunnerSanitizesPersistedErrorsAndEvents(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	secretPath := filepath.Join(t.TempDir(), "checkouts", "repo_scan:secret")
	rawURL := "https://buildbot:ghp_secret@example.com/acme/platform.git"
	wantURL := "https://example.com/acme/platform.git"
	runner := NewRunner(RunnerOptions{
		Store: store,
		Materializer: stubMaterializer{
			err: fmt.Errorf("clone repository %s into %s: permission denied", rawURL, secretPath),
		},
	})

	run, err := runner.RunRepositoryScan(context.Background(), ScanRequest{
		ID:     "repo_scan:sanitize-error",
		Target: ScanTarget{RepoURL: rawURL},
	})
	if err == nil {
		t.Fatal("expected repository scan failure")
	}
	if run == nil {
		t.Fatal("expected failed run record")
	}
	if strings.Contains(run.Error, "buildbot:ghp_secret@") {
		t.Fatalf("expected run error to strip repo credentials, got %q", run.Error)
	}
	if strings.Contains(run.Error, secretPath) {
		t.Fatalf("expected run error to redact local checkout path, got %q", run.Error)
	}
	if !strings.Contains(run.Error, wantURL) {
		t.Fatalf("expected run error to retain sanitized repo URL %q, got %q", wantURL, run.Error)
	}
	if !strings.Contains(run.Error, "<redacted-path>") {
		t.Fatalf("expected run error to redact checkout path placeholder, got %q", run.Error)
	}

	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load run: %v", err)
	}
	if loaded == nil || loaded.Error != run.Error {
		t.Fatalf("expected persisted sanitized error %q, got %#v", run.Error, loaded)
	}

	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	foundFailure := false
	for _, event := range events {
		if event.Status != RunStatusFailed {
			continue
		}
		foundFailure = true
		if strings.Contains(event.Message, "buildbot:ghp_secret@") {
			t.Fatalf("expected failed event to strip repo credentials, got %q", event.Message)
		}
		if strings.Contains(event.Message, secretPath) {
			t.Fatalf("expected failed event to redact local checkout path, got %q", event.Message)
		}
		if !strings.Contains(event.Message, wantURL) || !strings.Contains(event.Message, "<redacted-path>") {
			t.Fatalf("expected failed event to retain sanitized URL and redacted path, got %q", event.Message)
		}
	}
	if !foundFailure {
		t.Fatalf("expected failed lifecycle event, got %#v", events)
	}
}

func TestRunnerRunRepositoryScanRejectsPolicyViolationsBeforePersistence(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	allowKeepCheckout := false
	policyEngine, err := scanpolicy.NewEngine([]scanpolicy.Policy{{
		ID:                "platform-repo-policy",
		ScanKinds:         []scanpolicy.Kind{scanpolicy.KindRepository},
		Teams:             []string{"platform"},
		RequiredMetadata:  []string{"team", "change_ticket"},
		AllowKeepCheckout: &allowKeepCheckout,
	}})
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}

	runner := NewRunner(RunnerOptions{
		Store:           store,
		PolicyEvaluator: policyEngine,
	})

	_, err = runner.RunRepositoryScan(context.Background(), ScanRequest{
		RequestedBy: "user:alice",
		Target: ScanTarget{
			RepoURL: "https://github.com/writer/cerebro.git",
		},
		KeepCheckout: true,
		Metadata: map[string]string{
			"team": "platform",
		},
	})
	if err == nil {
		t.Fatal("expected policy validation error")
	}

	var validationErr *scanpolicy.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected validation error, got %T", err)
	}

	runs, err := store.ListRuns(context.Background(), RunListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	if len(runs) != 0 {
		t.Fatalf("expected no persisted runs, got %d", len(runs))
	}
}

func createIaCTestRepo(t *testing.T) (string, string) {
	t.Helper()
	repoDir := t.TempDir()
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.email", "test@example.com")
	runGit(t, repoDir, "config", "user.name", "Test")
	mustWriteRepoFile(t, filepath.Join(repoDir, "infra", "main.tf"), strings.Join([]string{
		`resource "aws_security_group" "public" {`,
		`  ingress {`,
		`    cidr_blocks = ["0.0.0.0/0"]`,
		`  }`,
		`}`,
		`resource "aws_s3_bucket" "logs" {`,
		`  bucket = "prod-logs"`,
		`}`,
	}, "\n"))
	mustWriteRepoFile(t, filepath.Join(repoDir, "deploy", "service.yaml"), "apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n")
	runGit(t, repoDir, "add", ".")
	runGit(t, repoDir, "commit", "-m", "seed iac fixtures")
	head := strings.TrimSpace(runGitOutput(t, repoDir, "rev-parse", "HEAD"))
	return repoDir, head
}

func mustWriteRepoFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) // #nosec G204 -- test helper
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %s: %v", args, string(out), err)
	}
}

func runGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) // #nosec G204 -- test helper
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %s: %v", args, string(out), err)
	}
	return string(out)
}
