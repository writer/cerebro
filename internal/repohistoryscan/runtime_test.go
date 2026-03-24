package repohistoryscan

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

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/scanpolicy"
	"github.com/writer/cerebro/internal/scm"
)

type fakeHistoryScanner struct {
	result *filesystemanalyzer.GitHistoryScanResult
	err    error
}

func (s fakeHistoryScanner) ScanGitHistory(context.Context, string) (*filesystemanalyzer.GitHistoryScanResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

type sequenceHistoryScanner struct {
	results []*filesystemanalyzer.GitHistoryScanResult
	err     error
	calls   int
}

func (s *sequenceHistoryScanner) ScanGitHistory(context.Context, string) (*filesystemanalyzer.GitHistoryScanResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.calls >= len(s.results) {
		s.calls++
		return &filesystemanalyzer.GitHistoryScanResult{Engine: "sequence"}, nil
	}
	result := s.results[s.calls]
	s.calls++
	return result, nil
}

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
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-history-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	run := &RunRecord{
		ID:          "repo_history_scan:test",
		Status:      RunStatusRunning,
		Stage:       RunStageScan,
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
		Message:    "history scan started",
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
}

func TestRunnerFiltersFindingsToCommitsAfterSinceCommit(t *testing.T) {
	repoDir, firstCommit, secondCommit := createHistoryRepo(t)
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-history-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 20, 20, 0, 0, 0, time.UTC)
	runner := NewRunner(RunnerOptions{
		Store:        store,
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "checkouts"), scm.NewLocalClient("")),
		Scanner: fakeHistoryScanner{result: &filesystemanalyzer.GitHistoryScanResult{
			Engine: "gitleaks",
			Findings: []filesystemanalyzer.GitHistoryFinding{
				{
					Type:        "github_token",
					Severity:    "medium",
					Path:        ".env",
					Line:        1,
					Match:       "sha256:older",
					Description: "older token",
					CommitSHA:   firstCommit,
					AuthorName:  "Alice",
					AuthorEmail: "alice@example.com",
					CommittedAt: timePtr(now.Add(-45 * 24 * time.Hour)),
				},
				{
					Type:        "aws_access_key",
					Severity:    "medium",
					Path:        ".env",
					Line:        2,
					Match:       "sha256:newer",
					Description: "new token",
					CommitSHA:   secondCommit,
					AuthorName:  "Bob",
					AuthorEmail: "bob@example.com",
					CommittedAt: timePtr(now.Add(-5 * 24 * time.Hour)),
				},
			},
		}},
		Now: func() time.Time {
			return now
		},
	})

	run, err := runner.RunRepositoryHistoryScan(context.Background(), ScanRequest{
		Target: ScanTarget{
			RepoURL:     repoDir,
			SinceCommit: firstCommit,
		},
	})
	if err != nil {
		t.Fatalf("run repository history scan: %v", err)
	}
	if run.Status != RunStatusSucceeded || run.Stage != RunStageCompleted {
		t.Fatalf("expected succeeded run, got status=%s stage=%s", run.Status, run.Stage)
	}
	if run.Analysis == nil {
		t.Fatal("expected analysis report")
	}
	if len(run.Analysis.Findings) != 1 {
		t.Fatalf("expected only findings after since_commit, got %#v", run.Analysis.Findings)
	}
	finding := run.Analysis.Findings[0]
	if finding.CommitSHA != secondCommit {
		t.Fatalf("expected latest commit finding, got %#v", finding)
	}
	if finding.Severity != "high" {
		t.Fatalf("expected recent unverified secret to be elevated to high, got %#v", finding)
	}
	if run.Descriptor == nil || run.Descriptor.CommitSHA != secondCommit {
		t.Fatalf("expected head commit %q, got %#v", secondCommit, run.Descriptor)
	}
}

func TestRunnerElevatesVerifiedFindingsToCritical(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-history-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	repoDir, _, secondCommit := createHistoryRepo(t)
	now := time.Date(2026, 3, 20, 20, 0, 0, 0, time.UTC)
	runner := NewRunner(RunnerOptions{
		Store:        store,
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "checkouts"), scm.NewLocalClient("")),
		Scanner: fakeHistoryScanner{result: &filesystemanalyzer.GitHistoryScanResult{
			Engine: "gitleaks",
			Findings: []filesystemanalyzer.GitHistoryFinding{{
				Type:        "aws_access_key",
				Severity:    "high",
				Path:        ".env",
				Line:        1,
				Match:       "sha256:verified",
				Description: "verified token",
				CommitSHA:   secondCommit,
				Verified:    true,
			}},
		}},
		Now: func() time.Time {
			return now
		},
	})

	run, err := runner.RunRepositoryHistoryScan(context.Background(), ScanRequest{
		Target: ScanTarget{RepoURL: repoDir},
	})
	if err != nil {
		t.Fatalf("run repository history scan: %v", err)
	}
	if run.Analysis == nil || len(run.Analysis.Findings) != 1 {
		t.Fatalf("expected one finding, got %#v", run.Analysis)
	}
	if run.Analysis.Findings[0].Severity != "critical" {
		t.Fatalf("expected verified secret to be critical, got %#v", run.Analysis.Findings[0])
	}
}

func TestRunnerUsesLastSuccessfulCommitWhenSinceCommitOmitted(t *testing.T) {
	repoDir, firstCommit, secondCommit := createHistoryRepo(t)
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-history-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 21, 3, 0, 0, 0, time.UTC)
	scanner := &sequenceHistoryScanner{results: []*filesystemanalyzer.GitHistoryScanResult{
		{
			Engine: "sequence",
			Findings: []filesystemanalyzer.GitHistoryFinding{
				{Type: "github_token", Severity: "medium", Path: ".env", Line: 1, Match: "sha256:first", CommitSHA: firstCommit},
				{Type: "aws_access_key", Severity: "medium", Path: ".env", Line: 2, Match: "sha256:second", CommitSHA: secondCommit},
			},
		},
		{
			Engine: "sequence",
			Findings: []filesystemanalyzer.GitHistoryFinding{
				{Type: "github_token", Severity: "medium", Path: ".env", Line: 1, Match: "sha256:first", CommitSHA: firstCommit},
				{Type: "aws_access_key", Severity: "medium", Path: ".env", Line: 2, Match: "sha256:second", CommitSHA: secondCommit},
			},
		},
	}}
	runner := NewRunner(RunnerOptions{
		Store:        store,
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "checkouts"), scm.NewLocalClient("")),
		Scanner:      scanner,
		Now: func() time.Time {
			return now
		},
	})

	firstRun, err := runner.RunRepositoryHistoryScan(context.Background(), ScanRequest{
		Target: ScanTarget{RepoURL: repoDir},
	})
	if err != nil {
		t.Fatalf("first run repository history scan: %v", err)
	}
	if firstRun.Descriptor == nil || firstRun.Descriptor.CommitSHA != secondCommit {
		t.Fatalf("expected first run head %q, got %#v", secondCommit, firstRun.Descriptor)
	}

	mustWriteRepoFile(t, filepath.Join(repoDir, "secrets.txt"), "TOKEN=latest\n")
	runGit(t, repoDir, "add", "secrets.txt")
	runGit(t, repoDir, "commit", "-m", "latest secret")
	thirdCommit := strings.TrimSpace(runGitOutput(t, repoDir, "rev-parse", "HEAD"))
	scanner.results[1].Findings = append(scanner.results[1].Findings, filesystemanalyzer.GitHistoryFinding{
		Type:      "slack_token",
		Severity:  "medium",
		Path:      ".env",
		Line:      3,
		Match:     "sha256:third",
		CommitSHA: thirdCommit,
	})

	secondRun, err := runner.RunRepositoryHistoryScan(context.Background(), ScanRequest{
		Target: ScanTarget{RepoURL: repoDir},
	})
	if err != nil {
		t.Fatalf("second run repository history scan: %v", err)
	}
	if got := secondRun.Target.SinceCommit; got != secondCommit {
		t.Fatalf("expected resolved since_commit %q, got %q", secondCommit, got)
	}
	if secondRun.Analysis == nil || len(secondRun.Analysis.Findings) != 1 {
		t.Fatalf("expected incremental findings only, got %#v", secondRun.Analysis)
	}
	if secondRun.Analysis.Findings[0].CommitSHA != thirdCommit {
		t.Fatalf("expected only latest commit finding, got %#v", secondRun.Analysis.Findings[0])
	}
}

func TestRunnerSkipsScanWhenNoNewCommitsSinceLastSuccessfulRun(t *testing.T) {
	repoDir, _, secondCommit := createHistoryRepo(t)
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-history-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	scanner := &sequenceHistoryScanner{results: []*filesystemanalyzer.GitHistoryScanResult{{
		Engine: "sequence",
		Findings: []filesystemanalyzer.GitHistoryFinding{{
			Type:      "aws_access_key",
			Severity:  "medium",
			Path:      ".env",
			Line:      1,
			Match:     "sha256:first",
			CommitSHA: secondCommit,
		}},
	}}}
	runner := NewRunner(RunnerOptions{
		Store:        store,
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "checkouts"), scm.NewLocalClient("")),
		Scanner:      scanner,
	})

	if _, err := runner.RunRepositoryHistoryScan(context.Background(), ScanRequest{
		Target: ScanTarget{RepoURL: repoDir},
	}); err != nil {
		t.Fatalf("first run repository history scan: %v", err)
	}

	secondRun, err := runner.RunRepositoryHistoryScan(context.Background(), ScanRequest{
		Target: ScanTarget{RepoURL: repoDir},
	})
	if err != nil {
		t.Fatalf("second run repository history scan: %v", err)
	}
	if scanner.calls != 1 {
		t.Fatalf("expected unchanged head to skip scanner call, got %d calls", scanner.calls)
	}
	if secondRun.Target.SinceCommit != secondCommit {
		t.Fatalf("expected resolved since_commit %q, got %#v", secondCommit, secondRun.Target)
	}
	if secondRun.Analysis == nil || secondRun.Analysis.TotalFindings != 0 {
		t.Fatalf("expected empty incremental report, got %#v", secondRun.Analysis)
	}
	if got, _ := secondRun.Analysis.Metadata["scan_scope"].(string); got != "unchanged_head" {
		t.Fatalf("expected unchanged_head scan scope, got %#v", secondRun.Analysis)
	}
}

func TestPrioritizeFindingLowersRotatedSecretsToLow(t *testing.T) {
	now := time.Date(2026, 3, 21, 0, 0, 0, 0, time.UTC)
	finding := prioritizeFinding(filesystemanalyzer.GitHistoryFinding{
		Type:               "github_token",
		Severity:           "high",
		VerificationStatus: "rotated",
	}, now)
	if finding.Severity != "low" {
		t.Fatalf("expected rotated secret severity low, got %#v", finding)
	}
}

func TestRunnerDryRunSkipsHistoryScan(t *testing.T) {
	repoDir, _, secondCommit := createHistoryRepo(t)
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-history-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	runner := NewRunner(RunnerOptions{
		Store:        store,
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "checkouts"), scm.NewLocalClient("")),
	})

	run, err := runner.RunRepositoryHistoryScan(context.Background(), ScanRequest{
		Target: ScanTarget{RepoURL: repoDir},
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("run repository history scan: %v", err)
	}
	if run.Analysis != nil {
		t.Fatalf("expected dry-run to skip analysis, got %#v", run.Analysis)
	}
	if run.Descriptor == nil || run.Descriptor.CommitSHA != secondCommit {
		t.Fatalf("expected head commit %q, got %#v", secondCommit, run.Descriptor)
	}
}

func TestRunnerSanitizesPersistedRepoURLs(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-history-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 21, 1, 30, 0, 0, time.UTC)
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

	run, err := runner.RunRepositoryHistoryScan(context.Background(), ScanRequest{
		ID:       "repo_history_scan:sanitize-urls",
		Target:   ScanTarget{RepoURL: rawURL},
		DryRun:   true,
		Metadata: map[string]string{"source": "test"},
	})
	if err != nil {
		t.Fatalf("run repository history scan: %v", err)
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
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-history-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	secretPath := filepath.Join(t.TempDir(), "checkouts", "repo_history_scan:secret")
	rawURL := "https://buildbot:ghp_secret@example.com/acme/platform.git"
	wantURL := "https://example.com/acme/platform.git"
	runner := NewRunner(RunnerOptions{
		Store: store,
		Materializer: stubMaterializer{
			err: fmt.Errorf("clone repository %s into %s: permission denied", rawURL, secretPath),
		},
	})

	run, err := runner.RunRepositoryHistoryScan(context.Background(), ScanRequest{
		ID:     "repo_history_scan:sanitize-error",
		Target: ScanTarget{RepoURL: rawURL},
	})
	if err == nil {
		t.Fatal("expected repository history scan failure")
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

func TestRunnerRunRepositoryHistoryScanRejectsPolicyViolationsBeforePersistence(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-history-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	allowDryRun := false
	policyEngine, err := scanpolicy.NewEngine([]scanpolicy.Policy{{
		ID:          "platform-repo-history-policy",
		ScanKinds:   []scanpolicy.Kind{scanpolicy.KindRepositoryHistory},
		Teams:       []string{"platform"},
		AllowDryRun: &allowDryRun,
	}})
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}

	runner := NewRunner(RunnerOptions{
		Store:           store,
		PolicyEvaluator: policyEngine,
	})

	_, err = runner.RunRepositoryHistoryScan(context.Background(), ScanRequest{
		RequestedBy: "user:alice",
		Target: ScanTarget{
			RepoURL: "https://github.com/writer/cerebro.git",
		},
		DryRun: true,
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

func createHistoryRepo(t *testing.T) (string, string, string) {
	t.Helper()
	repoDir := t.TempDir()
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.email", "test@example.com")
	runGit(t, repoDir, "config", "user.name", "Test")

	mustWriteRepoFile(t, filepath.Join(repoDir, "secrets.txt"), "TOKEN=old\n")
	runGit(t, repoDir, "add", "secrets.txt")
	runGit(t, repoDir, "commit", "-m", "old secret")
	firstCommit := strings.TrimSpace(runGitOutput(t, repoDir, "rev-parse", "HEAD"))

	mustWriteRepoFile(t, filepath.Join(repoDir, "secrets.txt"), "TOKEN=new\n")
	runGit(t, repoDir, "add", "secrets.txt")
	runGit(t, repoDir, "commit", "-m", "new secret")
	secondCommit := strings.TrimSpace(runGitOutput(t, repoDir, "rev-parse", "HEAD"))

	return repoDir, firstCommit, secondCommit
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

func timePtr(ts time.Time) *time.Time {
	return &ts
}
