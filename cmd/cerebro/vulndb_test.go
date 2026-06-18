package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/internal/vulndb"
)

func TestVulnDBInputClientRejectsLoopbackRemoteFeed(t *testing.T) {
	targetHit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHit = true
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	source := "HTTP" + strings.TrimPrefix(server.URL, "http")
	reader, err := (vulndbInputClient{}).Open(context.Background(), source, true)
	if reader != nil {
		_ = reader.Close()
	}
	if err == nil {
		t.Fatal("Open(loopback HTTP feed) error = nil, want unsafe destination rejection")
	}
	if !errors.Is(err, sourcehttp.ErrUnsafeHostAddress) {
		t.Fatalf("Open(loopback HTTP feed) error = %v, want unsafe destination rejection", err)
	}
	if targetHit {
		t.Fatal("Open(loopback HTTP feed) connected to loopback destination")
	}
}

func TestVulnDBInputClientRejectsUnsupportedURLSchemes(t *testing.T) {
	for _, source := range []string{"file:///tmp/osv.json", "file:/tmp/osv.json", "ftp://mirror.example/osv.json", "https:/mirror.example/osv.json"} {
		_, err := (vulndbInputClient{}).Open(context.Background(), source, true)
		if err == nil {
			t.Fatalf("Open(%q) error = nil, want unsupported scheme rejection", source)
		}
		if !errors.Is(err, errUnsupportedVulnDBURLScheme) {
			t.Fatalf("Open(%q) error = %v, want unsupported scheme", source, err)
		}
	}
}

func TestVulnDBInputClientTreatsWindowsDrivePathsAsLocalFiles(t *testing.T) {
	for _, source := range []string{`C:\feeds\osv.json`, "C:/feeds/osv.json"} {
		if scheme := vulnDBSourceScheme(source); scheme != "" {
			t.Fatalf("vulnDBSourceScheme(%q) = %q, want local path", source, scheme)
		}
		_, err := (vulndbInputClient{}).Open(context.Background(), source, true)
		if err == nil {
			t.Fatalf("Open(%q) error = nil, want local file open error", source)
		}
		if errors.Is(err, errUnsupportedVulnDBURLScheme) {
			t.Fatalf("Open(%q) error = %v, want local file error", source, err)
		}
	}
}

func TestVulnDBSourceSchemeLeavesDriveLetterPathsLocal(t *testing.T) {
	if got := vulnDBSourceScheme(`C:\feeds\osv.json`); got != "" {
		t.Fatalf("vulnDBSourceScheme(windows path) = %q, want local file path", got)
	}
	if got := vulnDBSourceScheme("ftp://mirror.example/osv.json"); got != "ftp" {
		t.Fatalf("vulnDBSourceScheme(ftp URL) = %q, want ftp", got)
	}
	if got := vulnDBSourceScheme("https:/mirror.example/osv.json"); got != "https" {
		t.Fatalf("vulnDBSourceScheme(malformed https URL) = %q, want https", got)
	}
}

func TestParseVulnDBOptionsSyncJobFields(t *testing.T) {
	options, err := parseVulnDBOptions([]string{
		"store=file",
		"job_id=osv-hourly",
		"feed_source=osv",
		"url=/tmp/osv.json",
		"interval=1h",
		"lease_ttl=5m",
		"limit=2",
		"allow_insecure_http=true",
	})
	if err != nil {
		t.Fatalf("parseVulnDBOptions() error = %v", err)
	}
	if options.StoreMode != "file" || options.JobID != "osv-hourly" || options.FeedSource != "osv" || options.Source != "/tmp/osv.json" {
		t.Fatalf("unexpected parsed options: %+v", options)
	}
	if options.JobInterval != time.Hour || options.JobLeaseTTL != 5*time.Minute || options.Limit != 2 || !options.AllowInsecureHTTP {
		t.Fatalf("unexpected parsed durations/flags: %+v", options)
	}
}

func TestParseVulnDBOptionsRejectsZeroInterval(t *testing.T) {
	if _, err := parseVulnDBOptions([]string{"interval=0s"}); err == nil {
		t.Fatal("parseVulnDBOptions() error = nil, want positive interval requirement")
	}
}

func TestPutVulnDBSyncJobStoresAbsoluteFilePath(t *testing.T) {
	ctx := context.Background()
	store := vulndb.NewMemoryStore()
	t.Chdir(t.TempDir())
	job, err := putVulnDBSyncJob(ctx, store, vulnDBOptions{
		JobID:       "osv-hourly",
		FeedSource:  vulndb.SourceOSV,
		Source:      "feeds/osv.json",
		JobInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("put sync job: %v", err)
	}
	if !filepath.IsAbs(job.FeedURL) || filepath.Base(job.FeedURL) != "osv.json" {
		t.Fatalf("FeedURL = %q, want absolute file path", job.FeedURL)
	}
}

func TestPutVulnDBSyncJobRejectsInsecureHTTPWithoutOptIn(t *testing.T) {
	ctx := context.Background()
	store := vulndb.NewMemoryStore()
	if _, err := putVulnDBSyncJob(ctx, store, vulnDBOptions{
		JobID:       "osv-hourly",
		FeedSource:  vulndb.SourceOSV,
		Source:      "http://localhost/osv.json",
		JobInterval: time.Hour,
	}); err == nil {
		t.Fatal("put sync job error = nil, want insecure HTTP rejection")
	}
	if _, ok, err := store.GetSyncJob(ctx, "osv-hourly"); err != nil || ok {
		t.Fatalf("stored insecure job ok=%v err=%v, want not persisted", ok, err)
	}
}

func TestPutVulnDBSyncJobRejectsUnsupportedURLSchemes(t *testing.T) {
	ctx := context.Background()
	store := vulndb.NewMemoryStore()
	for _, source := range []string{"file:///tmp/osv.json", "ftp://mirror.example/osv.json"} {
		if _, err := putVulnDBSyncJob(ctx, store, vulnDBOptions{
			JobID:       "osv-hourly",
			FeedSource:  vulndb.SourceOSV,
			Source:      source,
			JobInterval: time.Hour,
		}); err == nil {
			t.Fatalf("put sync job source %q error = nil, want unsupported scheme rejection", source)
		}
	}
}

func TestPutVulnDBSyncJobPreservesAllowInsecureHTTPWhenOmitted(t *testing.T) {
	ctx := context.Background()
	store := vulndb.NewMemoryStore()
	if _, err := putVulnDBSyncJob(ctx, store, vulnDBOptions{
		JobID:                     "osv-hourly",
		FeedSource:                vulndb.SourceOSV,
		Source:                    "http://localhost/osv.json",
		AllowInsecureHTTP:         true,
		AllowInsecureHTTPExplicit: true,
		JobInterval:               time.Hour,
	}); err != nil {
		t.Fatalf("put initial sync job: %v", err)
	}
	job, err := putVulnDBSyncJob(ctx, store, vulnDBOptions{
		JobID:       "osv-hourly",
		FeedSource:  vulndb.SourceOSV,
		Source:      "http://localhost/osv-updated.json",
		JobInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("put updated sync job: %v", err)
	}
	if !job.AllowInsecureHTTP {
		t.Fatal("AllowInsecureHTTP = false, want preserved true when option omitted")
	}
	job, err = putVulnDBSyncJob(ctx, store, vulnDBOptions{
		JobID:                     "osv-hourly",
		FeedSource:                vulndb.SourceOSV,
		Source:                    "https://localhost/osv-updated.json",
		AllowInsecureHTTP:         false,
		AllowInsecureHTTPExplicit: true,
		JobInterval:               time.Hour,
	})
	if err != nil {
		t.Fatalf("put explicit sync job update: %v", err)
	}
	if job.AllowInsecureHTTP {
		t.Fatal("AllowInsecureHTTP = true, want explicit false to clear")
	}
}

func TestRunVulnDBImportRecordsFailureState(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "vulndb.json")
	feedPath := filepath.Join(dir, "bad-osv.json")
	if err := os.WriteFile(feedPath, []byte(`[`), 0o600); err != nil {
		t.Fatalf("write bad feed: %v", err)
	}

	err := runVulnDB([]string{"import-osv", feedPath, "state_file=" + stateFile})
	if err == nil {
		t.Fatal("runVulnDB(import-osv) error = nil, want malformed feed error")
	}
	store, err := vulndb.NewFileStore(ctx, stateFile)
	if err != nil {
		t.Fatalf("open file store: %v", err)
	}
	state, ok, err := store.GetSyncState(ctx, vulndb.SourceOSV)
	if err != nil {
		t.Fatalf("get sync state: %v", err)
	}
	if !ok || state.LastError == "" || state.LastSyncedAt.IsZero() {
		t.Fatalf("sync state = ok:%v %+v, want recorded import failure", ok, state)
	}
}

func TestRunVulnDBImportUsageErrorDoesNotRecordFailureState(t *testing.T) {
	ctx := context.Background()
	stateFile := filepath.Join(t.TempDir(), "vulndb.json")
	err := runVulnDB([]string{"import-osv", "state_file=" + stateFile})
	if err == nil {
		t.Fatal("runVulnDB(import-osv) error = nil, want missing source usage error")
	}
	var usage usageError
	if !errors.As(err, &usage) {
		t.Fatalf("runVulnDB(import-osv) error = %v, want usage error", err)
	}
	store, err := vulndb.NewFileStore(ctx, stateFile)
	if err != nil {
		t.Fatalf("open file store: %v", err)
	}
	if _, ok, err := store.GetSyncState(ctx, vulndb.SourceOSV); err != nil || ok {
		t.Fatalf("sync state ok=%v err=%v, want no recorded usage failure", ok, err)
	}
}

func TestRunVulnDBSyncRecordsFailureState(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "vulndb.json")
	feedPath := filepath.Join(dir, "bad-nvd.json")
	if err := os.WriteFile(feedPath, []byte(`{"vulnerabilities":[`), 0o600); err != nil {
		t.Fatalf("write bad feed: %v", err)
	}

	err := runVulnDB([]string{"sync", "nvd=" + feedPath, "state_file=" + stateFile})
	if err == nil {
		t.Fatal("runVulnDB(sync) error = nil, want malformed feed error")
	}
	store, err := vulndb.NewFileStore(ctx, stateFile)
	if err != nil {
		t.Fatalf("open file store: %v", err)
	}
	state, ok, err := store.GetSyncState(ctx, vulndb.SourceNVD)
	if err != nil {
		t.Fatalf("get sync state: %v", err)
	}
	if !ok || state.LastError == "" || state.LastSyncedAt.IsZero() {
		t.Fatalf("sync state = ok:%v %+v, want recorded sync failure", ok, state)
	}
}

func TestParseVulnDBOptionsQueryFields(t *testing.T) {
	options, err := parseVulnDBOptions([]string{
		"id=cve-2026-12345",
		"ecosystem=NPM",
		"package=lodash",
		"version=4.17.20",
	})
	if err != nil {
		t.Fatalf("parseVulnDBOptions() error = %v", err)
	}
	if options.AdvisoryID != "cve-2026-12345" || options.Ecosystem != "NPM" || options.PackageName != "lodash" || options.PackageVersion != "4.17.20" {
		t.Fatalf("unexpected query options: %+v", options)
	}
}

func TestVulnDBGetAndMatchHelpersQuerySharedStore(t *testing.T) {
	ctx := context.Background()
	store := vulndb.NewMemoryStore()
	osv := `[{
		"id":"GHSA-AAAA-BBBB-CCCC",
		"aliases":["CVE-2026-11111"],
		"summary":"lodash vulnerability",
		"affected":[{
			"package":{"ecosystem":"npm","name":"lodash"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]
		}]
	}]`
	if _, err := vulndb.ImportOSV(ctx, store, strings.NewReader(osv)); err != nil {
		t.Fatalf("import osv: %v", err)
	}
	vulnerability, err := getVulnDBVulnerability(ctx, store, vulnDBOptions{AdvisoryID: "cve-2026-11111"})
	if err != nil {
		t.Fatalf("get vulnerability: %v", err)
	}
	if vulnerability.ID != "GHSA-AAAA-BBBB-CCCC" || vulnerability.Summary != "lodash vulnerability" {
		t.Fatalf("unexpected vulnerability: %+v", vulnerability)
	}
	matches, err := matchVulnDBPackage(ctx, store, vulnDBOptions{Ecosystem: "npm", PackageName: "lodash", PackageVersion: "4.17.20"})
	if err != nil {
		t.Fatalf("match package: %v", err)
	}
	if len(matches) != 1 || matches[0].Vulnerability.ID != "GHSA-AAAA-BBBB-CCCC" || matches[0].AffectedPackage.PackageName != "lodash" {
		t.Fatalf("unexpected matches: %+v", matches)
	}
}

func TestShouldUseStateVulnDBStoreHonorsExplicitStateFile(t *testing.T) {
	t.Setenv("CEREBRO_POSTGRES_DSN", "postgres://127.0.0.1:5432/cerebro?sslmode=disable")
	if shouldUseStateVulnDBStore(vulnDBOptions{StateFileExplicit: true, StateFile: "local.json"}) {
		t.Fatal("expected explicit state_file to keep file store in auto mode")
	}
	if !shouldUseStateVulnDBStore(vulnDBOptions{StateFileExplicit: true, StateFile: "local.json", StoreMode: "state"}) {
		t.Fatal("expected store=state to force configured state store")
	}
}
