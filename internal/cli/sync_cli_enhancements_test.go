package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type syncEnhancementState struct {
	syncGCP                bool
	syncScope              string
	syncProjectsFile       string
	syncProjectInclude     string
	syncProjectExclude     string
	syncGCPProject         string
	syncGCPProjects        string
	syncGCPOrg             string
	syncGCPCredentialsFile string
	syncGCPImpersonateSA   string
	syncStrictExit         bool
	syncReportFile         string
	syncOutput             string
	syncAuthMode           string
}

func snapshotSyncEnhancementState() syncEnhancementState {
	return syncEnhancementState{
		syncGCP:                syncGCP,
		syncScope:              syncScope,
		syncProjectsFile:       syncProjectsFile,
		syncProjectInclude:     syncProjectInclude,
		syncProjectExclude:     syncProjectExclude,
		syncGCPProject:         syncGCPProject,
		syncGCPProjects:        syncGCPProjects,
		syncGCPOrg:             syncGCPOrg,
		syncGCPCredentialsFile: syncGCPCredentialsFile,
		syncGCPImpersonateSA:   syncGCPImpersonateSA,
		syncStrictExit:         syncStrictExit,
		syncReportFile:         syncReportFile,
		syncOutput:             syncOutput,
		syncAuthMode:           syncAuthMode,
	}
}

func restoreSyncEnhancementState(state syncEnhancementState) {
	syncGCP = state.syncGCP
	syncScope = state.syncScope
	syncProjectsFile = state.syncProjectsFile
	syncProjectInclude = state.syncProjectInclude
	syncProjectExclude = state.syncProjectExclude
	syncGCPProject = state.syncGCPProject
	syncGCPProjects = state.syncGCPProjects
	syncGCPOrg = state.syncGCPOrg
	syncGCPCredentialsFile = state.syncGCPCredentialsFile
	syncGCPImpersonateSA = state.syncGCPImpersonateSA
	syncStrictExit = state.syncStrictExit
	syncReportFile = state.syncReportFile
	syncOutput = state.syncOutput
	syncAuthMode = state.syncAuthMode
}

func TestApplySyncScopeDirectives_ParsesOrgScope(t *testing.T) {
	state := snapshotSyncEnhancementState()
	t.Cleanup(func() { restoreSyncEnhancementState(state) })

	syncGCP = true
	syncScope = "org:1234567890"
	syncGCPProject = ""
	syncGCPProjects = ""
	syncGCPOrg = ""
	syncProjectsFile = ""

	if err := applySyncScopeDirectives(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if syncGCPOrg != "1234567890" {
		t.Fatalf("expected org scope to populate syncGCPOrg, got %q", syncGCPOrg)
	}
}

func TestApplySyncScopeDirectives_RejectsNonGCP(t *testing.T) {
	state := snapshotSyncEnhancementState()
	t.Cleanup(func() { restoreSyncEnhancementState(state) })

	syncGCP = false
	syncScope = "project:test-project"

	err := applySyncScopeDirectives()
	if err == nil || !strings.Contains(err.Error(), "only with --gcp") {
		t.Fatalf("expected non-gcp scope validation error, got %v", err)
	}
}

func TestResolveExplicitGCPProjects_FromFileAndFilters(t *testing.T) {
	state := snapshotSyncEnhancementState()
	t.Cleanup(func() { restoreSyncEnhancementState(state) })

	tmpDir := t.TempDir()
	projectsPath := filepath.Join(tmpDir, "projects.txt")
	contents := "# selected projects\nproj-1,proj-2\nproj-3\n"
	if err := os.WriteFile(projectsPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write projects file: %v", err)
	}

	syncGCPProjects = "proj-2,proj-4"
	syncProjectsFile = projectsPath
	syncProjectInclude = "proj-1,proj-2,proj-4"
	syncProjectExclude = "proj-2"

	projects, err := resolveExplicitGCPProjects()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"proj-4", "proj-1"}
	if !reflect.DeepEqual(projects, want) {
		t.Fatalf("unexpected projects: got %v want %v", projects, want)
	}
}

func TestValidateGCPSyncAuthMode_WIFRequiresExternalAccount(t *testing.T) {
	state := snapshotSyncEnhancementState()
	t.Cleanup(func() { restoreSyncEnhancementState(state) })

	tmpDir := t.TempDir()
	credentialsPath := filepath.Join(tmpDir, "sa.json")
	if err := os.WriteFile(credentialsPath, []byte(`{"type":"service_account"}`), 0o600); err != nil {
		t.Fatalf("write credentials file: %v", err)
	}

	syncGCPCredentialsFile = credentialsPath
	err := validateGCPSyncAuthMode(syncAuthModeWIF)
	if err == nil || !strings.Contains(err.Error(), "external-account") {
		t.Fatalf("expected external-account validation error, got %v", err)
	}
}

func TestValidateGCPSyncAuthMode_WIFAcceptsExternalAccount(t *testing.T) {
	state := snapshotSyncEnhancementState()
	t.Cleanup(func() { restoreSyncEnhancementState(state) })

	tmpDir := t.TempDir()
	credentialsPath := filepath.Join(tmpDir, "wif.json")
	if err := os.WriteFile(credentialsPath, []byte(`{"type":"external_account"}`), 0o600); err != nil {
		t.Fatalf("write credentials file: %v", err)
	}

	syncGCPCredentialsFile = credentialsPath
	if err := validateGCPSyncAuthMode(syncAuthModeWIF); err != nil {
		t.Fatalf("unexpected wif validation error: %v", err)
	}
}

func TestStrictSyncSummaryError(t *testing.T) {
	state := snapshotSyncEnhancementState()
	t.Cleanup(func() { restoreSyncEnhancementState(state) })

	summary := syncSummary{TotalErrors: 2}
	syncStrictExit = false
	if err := strictSyncSummaryError(summary); err != nil {
		t.Fatalf("expected nil error with strict exit disabled, got %v", err)
	}

	syncStrictExit = true
	if err := strictSyncSummaryError(summary); err == nil {
		t.Fatal("expected strict exit error")
		return
	}
}

func TestWriteSyncReport_WritesJSON(t *testing.T) {
	state := snapshotSyncEnhancementState()
	t.Cleanup(func() { restoreSyncEnhancementState(state) })

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "sync-report.json")
	syncReportFile = reportPath

	payload := map[string]interface{}{"ok": true, "provider": "gcp"}
	if err := writeSyncReport(payload); err != nil {
		t.Fatalf("write sync report: %v", err)
	}

	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read sync report: %v", err)
	}

	content := string(raw)
	if !strings.Contains(content, `"ok": true`) {
		t.Fatalf("expected report payload, got %s", content)
	}
}
