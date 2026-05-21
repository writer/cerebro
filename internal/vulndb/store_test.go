package vulndb

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

func TestMemoryStoreAliasAndPackageMatching(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.UpsertVulnerability(ctx, Vulnerability{
		ID:      "GHSA-AAAA-BBBB-CCCC",
		Aliases: []string{"CVE-2026-12345"},
		Summary: "test advisory",
	}); err != nil {
		t.Fatalf("upsert vulnerability: %v", err)
	}
	if err := store.UpsertAffectedPackage(ctx, AffectedPackage{
		VulnerabilityID: "GHSA-AAAA-BBBB-CCCC",
		Ecosystem:       "npm",
		PackageName:     "lodash",
		Introduced:      "0",
		Fixed:           "4.17.21",
	}); err != nil {
		t.Fatalf("upsert affected package: %v", err)
	}

	vulnerability, ok, err := store.FindVulnerability(ctx, "cve-2026-12345")
	if err != nil {
		t.Fatalf("find alias: %v", err)
	}
	if !ok {
		t.Fatal("expected alias lookup to find vulnerability")
	}
	if vulnerability.ID != "GHSA-AAAA-BBBB-CCCC" {
		t.Fatalf("unexpected vulnerability id %q", vulnerability.ID)
	}

	matcher, err := NewMatcher(store)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"})
	if err != nil {
		t.Fatalf("match vulnerable version: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one match, got %d", len(matches))
	}

	matches, err = matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	if err != nil {
		t.Fatalf("match fixed version: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no fixed-version matches, got %d", len(matches))
	}
}

func TestMemoryStoreUpsertReplacesStaleAliases(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.UpsertVulnerability(ctx, Vulnerability{ID: "CVE-2026-12345", Aliases: []string{"GHSA-AAAA-BBBB-CCCC"}}); err != nil {
		t.Fatalf("initial upsert: %v", err)
	}
	if err := store.UpsertVulnerability(ctx, Vulnerability{ID: "CVE-2026-12345", Aliases: []string{"GHSA-DDDD-EEEE-FFFF"}}); err != nil {
		t.Fatalf("replacement upsert: %v", err)
	}
	if _, ok, err := store.FindVulnerability(ctx, "GHSA-AAAA-BBBB-CCCC"); err != nil || ok {
		t.Fatalf("stale alias lookup ok=%v err=%v, want not found", ok, err)
	}
	if _, ok, err := store.FindVulnerability(ctx, "GHSA-DDDD-EEEE-FFFF"); err != nil || !ok {
		t.Fatalf("new alias lookup ok=%v err=%v, want found", ok, err)
	}
}

func TestMatcherExcludesWithdrawnAdvisories(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.UpsertVulnerability(ctx, Vulnerability{
		ID:          "CVE-2026-99999",
		WithdrawnAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert withdrawn vulnerability: %v", err)
	}
	if err := store.UpsertAffectedPackage(ctx, AffectedPackage{
		VulnerabilityID:   "CVE-2026-99999",
		Ecosystem:         "pypi",
		PackageName:       "demo",
		VulnerableVersion: "1.2.3",
	}); err != nil {
		t.Fatalf("upsert affected package: %v", err)
	}
	matcher, err := NewMatcher(store)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "pypi", Name: "demo", Version: "1.2.3"})
	if err != nil {
		t.Fatalf("match exact version: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected withdrawn advisory to be excluded, got %d", len(matches))
	}
}

func TestMatcherComparesNonNumericVersionSegments(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.UpsertVulnerability(ctx, Vulnerability{ID: "CVE-2026-10001"}); err != nil {
		t.Fatalf("upsert vulnerability: %v", err)
	}
	if err := store.UpsertAffectedPackage(ctx, AffectedPackage{
		VulnerabilityID: "CVE-2026-10001",
		Ecosystem:       "apk",
		PackageName:     "demo",
		Introduced:      "0",
		Fixed:           "1.0-r1",
	}); err != nil {
		t.Fatalf("upsert affected package: %v", err)
	}
	matcher, err := NewMatcher(store)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "apk", Name: "demo", Version: "1.0-r0"})
	if err != nil {
		t.Fatalf("match revision before fixed: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected revision before fixed to match, got %+v", matches)
	}
	matches, err = matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "apk", Name: "demo", Version: "1.0-r1"})
	if err != nil {
		t.Fatalf("match fixed revision: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected fixed revision to be excluded, got %+v", matches)
	}
}

func TestFileStorePersistsSyncStateAndAdvisories(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vulndb.json")
	store, err := NewFileStore(ctx, path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	if err := store.UpsertVulnerability(ctx, Vulnerability{ID: "CVE-2026-22222", Aliases: []string{"GHSA-1111-2222-3333"}}); err != nil {
		t.Fatalf("upsert vulnerability: %v", err)
	}
	if err := store.UpsertAffectedPackage(ctx, AffectedPackage{
		VulnerabilityID:   "CVE-2026-22222",
		Ecosystem:         "golang",
		PackageName:       "example.com/mod",
		VulnerableVersion: "1.0.0",
	}); err != nil {
		t.Fatalf("upsert affected package: %v", err)
	}
	if err := store.PutSyncState(ctx, SyncState{Source: SourceOSV, Cursor: "next"}); err != nil {
		t.Fatalf("put sync state: %v", err)
	}

	reopened, err := NewFileStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen file store: %v", err)
	}
	stats, err := reopened.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Vulnerabilities != 1 || stats.AffectedPackages != 1 || stats.SyncSources != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	state, ok, err := reopened.GetSyncState(ctx, SourceOSV)
	if err != nil {
		t.Fatalf("get sync state: %v", err)
	}
	if !ok || state.Cursor != "next" {
		t.Fatalf("unexpected sync state: ok=%v state=%+v", ok, state)
	}
	if _, ok, err := reopened.FindVulnerability(ctx, "ghsa-1111-2222-3333"); err != nil || !ok {
		t.Fatalf("expected alias after reopen, ok=%v err=%v", ok, err)
	}
}

func TestMemoryStoreSyncStateNormalizesSource(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.PutSyncState(ctx, SyncState{Source: " OSV ", Cursor: "first"}); err != nil {
		t.Fatalf("put sync state: %v", err)
	}
	state, ok, err := store.GetSyncState(ctx, "osv")
	if err != nil {
		t.Fatalf("get sync state: %v", err)
	}
	if !ok || state.Source != SourceOSV || state.Cursor != "first" {
		t.Fatalf("unexpected normalized sync state: ok=%v state=%+v", ok, state)
	}
	if err := store.PutSyncState(ctx, SyncState{Source: "osv", Cursor: "second"}); err != nil {
		t.Fatalf("replace sync state: %v", err)
	}
	stats, err := store.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.SyncSources != 1 {
		t.Fatalf("stats.SyncSources = %d, want one normalized source", stats.SyncSources)
	}
	state, ok, err = store.GetSyncState(ctx, " OSV ")
	if err != nil {
		t.Fatalf("get replacement sync state: %v", err)
	}
	if !ok || state.Cursor != "second" {
		t.Fatalf("unexpected replacement sync state: ok=%v state=%+v", ok, state)
	}
}

func TestFileStoreSerializesConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vulndb.json")
	store, err := NewFileStore(ctx, path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				source := fmt.Sprintf("source-%d-%d", i, j)
				if err := store.PutSyncState(ctx, SyncState{Source: source}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent write failed: %v", err)
	}
	reopened, err := NewFileStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen file store: %v", err)
	}
	stats, err := reopened.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.SyncSources != 160 {
		t.Fatalf("stats.SyncSources = %d, want 160", stats.SyncSources)
	}
}

func TestImportOSVKEVAndEPSS(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	osv := `[
		{
			"id":"GHSA-AAAA-BBBB-CCCC",
			"aliases":["CVE-2026-11111"],
			"summary":"lodash vulnerability",
			"affected":[{
				"package":{"ecosystem":"npm","name":"lodash"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]
			}]
		}
	]`
	imported, err := ImportOSV(ctx, store, strings.NewReader(osv))
	if err != nil {
		t.Fatalf("import osv: %v", err)
	}
	if imported.Vulnerabilities != 1 || imported.AffectedPackages != 1 {
		t.Fatalf("unexpected osv import result: %+v", imported)
	}

	epss := "cve,epss,percentile\nCVE-2026-11111,0.42,0.98\n"
	if _, err := ImportEPSS(ctx, store, strings.NewReader(epss)); err != nil {
		t.Fatalf("import epss: %v", err)
	}
	kev := `{"vulnerabilities":[{"cveID":"CVE-2026-11111","vulnerabilityName":"Known exploit","requiredAction":"Apply updates","dueDate":"2026-06-01","knownRansomwareCampaignUse":"Known"}]}`
	if _, err := ImportCISAKEV(ctx, store, strings.NewReader(kev)); err != nil {
		t.Fatalf("import kev: %v", err)
	}

	vulnerability, ok, err := store.FindVulnerability(ctx, "GHSA-AAAA-BBBB-CCCC")
	if err != nil {
		t.Fatalf("find enriched vulnerability: %v", err)
	}
	if !ok {
		t.Fatal("expected enriched vulnerability")
	}
	if vulnerability.EPSS == nil || vulnerability.EPSS.Score != 0.42 || vulnerability.EPSS.Percentile != 0.98 {
		t.Fatalf("unexpected epss enrichment: %+v", vulnerability.EPSS)
	}
	if vulnerability.KEV == nil || !vulnerability.KEV.Listed || vulnerability.KEV.RequiredAction != "Apply updates" {
		t.Fatalf("unexpected kev enrichment: %+v", vulnerability.KEV)
	}
}

func TestImportOSVSinglePrettyPrintedAdvisory(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	osv := `{
		"id":"CVE-2026-55555",
		"summary":"single advisory",
		"affected":[{
			"package":{"ecosystem":"PyPI","name":"demo"},
			"versions":["1.2.3"]
		}]
	}`
	imported, err := ImportOSV(ctx, store, strings.NewReader(osv))
	if err != nil {
		t.Fatalf("import osv: %v", err)
	}
	if imported.Vulnerabilities != 1 || imported.AffectedPackages != 1 {
		t.Fatalf("unexpected osv import result: %+v", imported)
	}
	matcher, err := NewMatcher(store)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "pypi", Name: "demo", Version: "1.2.3"})
	if err != nil {
		t.Fatalf("match single advisory package: %v", err)
	}
	if len(matches) != 1 || matches[0].Vulnerability.ID != "CVE-2026-55555" {
		t.Fatalf("unexpected matches: %+v", matches)
	}
}

func TestImportOSVLargeJSONLAdvisory(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	osv := `{"id":"CVE-2026-55556","summary":"` + strings.Repeat("a", 70*1024) + `"}` + "\n" +
		`{"id":"CVE-2026-55557","summary":"small"}`
	imported, err := ImportOSV(ctx, store, strings.NewReader(osv))
	if err != nil {
		t.Fatalf("import large osv jsonl: %v", err)
	}
	if imported.Vulnerabilities != 2 {
		t.Fatalf("unexpected osv import result: %+v", imported)
	}
}

func TestImportOSVPreservesExistingEnrichment(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if _, err := ImportEPSS(ctx, store, strings.NewReader("cve,epss,percentile\nCVE-2026-33333,0.7,0.9\n")); err != nil {
		t.Fatalf("import epss: %v", err)
	}
	osv := `[{"id":"CVE-2026-33333","summary":"later osv import"}]`
	if _, err := ImportOSV(ctx, store, strings.NewReader(osv)); err != nil {
		t.Fatalf("import osv: %v", err)
	}
	vulnerability, ok, err := store.FindVulnerability(ctx, "CVE-2026-33333")
	if err != nil {
		t.Fatalf("find vulnerability: %v", err)
	}
	if !ok {
		t.Fatal("expected vulnerability")
	}
	if vulnerability.EPSS == nil || vulnerability.EPSS.Score != 0.7 {
		t.Fatalf("expected epss enrichment to survive osv import, got %+v", vulnerability.EPSS)
	}
}

func TestImportOSVMergesExistingAliasEnrichment(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if _, err := ImportEPSS(ctx, store, strings.NewReader("cve,epss,percentile\nCVE-2026-33334,0.8,0.95\n")); err != nil {
		t.Fatalf("import epss: %v", err)
	}
	osv := `[{
		"id":"GHSA-3333-4444-5555",
		"aliases":["CVE-2026-33334"],
		"summary":"later osv alias import",
		"affected":[{
			"package":{"ecosystem":"npm","name":"demo"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]
		}]
	}]`
	if _, err := ImportOSV(ctx, store, strings.NewReader(osv)); err != nil {
		t.Fatalf("import osv: %v", err)
	}
	stats, err := store.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Vulnerabilities != 1 {
		t.Fatalf("stats.Vulnerabilities = %d, want 1 merged advisory", stats.Vulnerabilities)
	}
	vulnerability, ok, err := store.FindVulnerability(ctx, "GHSA-3333-4444-5555")
	if err != nil {
		t.Fatalf("find ghsa alias: %v", err)
	}
	if !ok {
		t.Fatal("expected ghsa alias lookup")
	}
	if vulnerability.EPSS == nil || vulnerability.EPSS.Score != 0.8 {
		t.Fatalf("expected epss enrichment to survive alias merge, got %+v", vulnerability.EPSS)
	}
	matcher, err := NewMatcher(store)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "npm", Name: "demo", Version: "1.1.0"})
	if err != nil {
		t.Fatalf("match alias-merged package: %v", err)
	}
	if len(matches) != 1 || matches[0].Vulnerability.EPSS == nil {
		t.Fatalf("unexpected alias-merged matches: %+v", matches)
	}
}

func TestImportOSVMultiIntervalRanges(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	osv := `[{
		"id":"CVE-2026-33335",
		"summary":"multi interval advisory",
		"affected":[{
			"package":{"ecosystem":"npm","name":"interval-demo"},
			"ranges":[{"type":"SEMVER","events":[
				{"introduced":"0"},
				{"fixed":"1.0.0"},
				{"introduced":"2.0.0"},
				{"fixed":"2.5.0"}
			]}]
		}]
	}]`
	imported, err := ImportOSV(ctx, store, strings.NewReader(osv))
	if err != nil {
		t.Fatalf("import osv: %v", err)
	}
	if imported.AffectedPackages != 2 {
		t.Fatalf("imported.AffectedPackages = %d, want 2 intervals", imported.AffectedPackages)
	}
	matcher, err := NewMatcher(store)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	for _, version := range []string{"0.5.0", "2.1.0"} {
		matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "npm", Name: "interval-demo", Version: version})
		if err != nil {
			t.Fatalf("match vulnerable version %s: %v", version, err)
		}
		if len(matches) != 1 {
			t.Fatalf("matches for %s = %+v, want one", version, matches)
		}
	}
	for _, version := range []string{"1.5.0", "2.5.0"} {
		matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "npm", Name: "interval-demo", Version: version})
		if err != nil {
			t.Fatalf("match non-vulnerable version %s: %v", version, err)
		}
		if len(matches) != 0 {
			t.Fatalf("matches for %s = %+v, want none", version, matches)
		}
	}
}

func TestImportOSVReplacesStaleAffectedPackages(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	first := `[{
		"id":"CVE-2026-33336",
		"affected":[{
			"package":{"ecosystem":"npm","name":"stale-demo"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]
		}]
	}]`
	if _, err := ImportOSV(ctx, store, strings.NewReader(first)); err != nil {
		t.Fatalf("import initial osv: %v", err)
	}
	second := `[{
		"id":"CVE-2026-33336",
		"affected":[{
			"package":{"ecosystem":"npm","name":"stale-demo"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]
		}]
	}]`
	imported, err := ImportOSV(ctx, store, strings.NewReader(second))
	if err != nil {
		t.Fatalf("import replacement osv: %v", err)
	}
	if imported.AffectedPackages != 1 {
		t.Fatalf("imported.AffectedPackages = %d, want replacement row", imported.AffectedPackages)
	}
	stats, err := store.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.AffectedPackages != 1 {
		t.Fatalf("stats.AffectedPackages = %d, want stale row removed", stats.AffectedPackages)
	}
	matcher, err := NewMatcher(store)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "npm", Name: "stale-demo", Version: "1.5.0"})
	if err != nil {
		t.Fatalf("match stale range version: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected stale range to be removed, got %+v", matches)
	}
}

func TestImportNVDEnrichesExistingOSVAlias(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	osv := `[{"id":"GHSA-4444-5555-6666","aliases":["CVE-2026-44445"],"summary":"osv advisory"}]`
	if _, err := ImportOSV(ctx, store, strings.NewReader(osv)); err != nil {
		t.Fatalf("import osv: %v", err)
	}
	nvd := `{
		"vulnerabilities":[{
			"cve":{
				"id":"CVE-2026-44445",
				"descriptions":[{"lang":"en","value":"NVD alias description"}],
				"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}]},
				"configurations":[{
					"nodes":[{
						"cpeMatch":[{
							"vulnerable":true,
							"criteria":"cpe:2.3:a:demo:agent:*:*:*:*:*:*:*:*",
							"versionStartIncluding":"3.0.0",
							"versionEndExcluding":"3.1.0"
						}]
					}]
				}]
			}
		}]
	}`
	if _, err := ImportNVD(ctx, store, strings.NewReader(nvd)); err != nil {
		t.Fatalf("import nvd: %v", err)
	}
	stats, err := store.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Vulnerabilities != 1 {
		t.Fatalf("stats.Vulnerabilities = %d, want 1 merged advisory", stats.Vulnerabilities)
	}
	vulnerability, ok, err := store.FindVulnerability(ctx, "CVE-2026-44445")
	if err != nil {
		t.Fatalf("find cve alias: %v", err)
	}
	if !ok {
		t.Fatal("expected cve alias lookup")
	}
	if vulnerability.ID != "GHSA-4444-5555-6666" || vulnerability.CVSSScore != 7.5 || vulnerability.Severity != "HIGH" {
		t.Fatalf("unexpected merged nvd vulnerability: %+v", vulnerability)
	}
	matcher, err := NewMatcher(store)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "cpe:application", Name: "demo:agent", Version: "3.0.1"})
	if err != nil {
		t.Fatalf("match cpe alias package: %v", err)
	}
	if len(matches) != 1 || matches[0].Vulnerability.ID != "GHSA-4444-5555-6666" {
		t.Fatalf("unexpected cpe alias matches: %+v", matches)
	}
}

func TestImportNVDPreservesWithdrawnOSVAlias(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	osv := `[{
		"id":"GHSA-5555-6666-7777",
		"aliases":["CVE-2026-44446"],
		"withdrawn":"2026-05-01T00:00:00Z",
		"affected":[{
			"package":{"ecosystem":"npm","name":"withdrawn-demo"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]
		}]
	}]`
	if _, err := ImportOSV(ctx, store, strings.NewReader(osv)); err != nil {
		t.Fatalf("import withdrawn osv: %v", err)
	}
	nvd := `{
		"vulnerabilities":[{
			"cve":{
				"id":"CVE-2026-44446",
				"descriptions":[{"lang":"en","value":"NVD should not reactivate"}],
				"configurations":[{
					"nodes":[{
						"cpeMatch":[{
							"vulnerable":true,
							"criteria":"cpe:2.3:a:demo:withdrawn:*:*:*:*:*:*:*:*",
							"versionStartIncluding":"1.0.0",
							"versionEndExcluding":"2.0.0"
						}]
					}]
				}]
			}
		}]
	}`
	if _, err := ImportNVD(ctx, store, strings.NewReader(nvd)); err != nil {
		t.Fatalf("import nvd: %v", err)
	}
	vulnerability, ok, err := store.FindVulnerability(ctx, "CVE-2026-44446")
	if err != nil {
		t.Fatalf("find merged vulnerability: %v", err)
	}
	if !ok || vulnerability.WithdrawnAt.IsZero() {
		t.Fatalf("expected withdrawn merged vulnerability, ok=%v vulnerability=%+v", ok, vulnerability)
	}
	matcher, err := NewMatcher(store)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "cpe:application", Name: "demo:withdrawn", Version: "1.5.0"})
	if err != nil {
		t.Fatalf("match withdrawn cpe package: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected withdrawn alias to be excluded, got %+v", matches)
	}
}

func TestImportNVD(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	nvd := `{
		"vulnerabilities":[{
			"cve":{
				"id":"CVE-2026-44444",
				"published":"2026-05-01T00:00:00.000",
				"lastModified":"2026-05-02T00:00:00.000",
				"descriptions":[{"lang":"en","value":"NVD description"}],
				"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
				"references":[{"url":"https://example.com/advisory","source":"nvd","tags":["Vendor Advisory"]}],
				"configurations":[{
					"nodes":[{
						"cpeMatch":[{
							"vulnerable":true,
							"criteria":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
							"versionStartIncluding":"1.0.1",
							"versionEndExcluding":"1.0.2"
						},{
							"vulnerable":false,
							"criteria":"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"
						}]
					}]
				}]
			}
		}]
	}`
	imported, err := ImportNVD(ctx, store, strings.NewReader(nvd))
	if err != nil {
		t.Fatalf("import nvd: %v", err)
	}
	if imported.Vulnerabilities != 1 || imported.AffectedPackages != 1 {
		t.Fatalf("unexpected nvd import result: %+v", imported)
	}
	vulnerability, ok, err := store.FindVulnerability(ctx, "cve-2026-44444")
	if err != nil {
		t.Fatalf("find nvd vulnerability: %v", err)
	}
	if !ok {
		t.Fatal("expected nvd vulnerability")
	}
	if vulnerability.Summary != "NVD description" || vulnerability.Severity != "CRITICAL" || vulnerability.CVSSScore != 9.8 {
		t.Fatalf("unexpected nvd vulnerability: %+v", vulnerability)
	}
	if len(vulnerability.References) != 1 || vulnerability.References[0].Type != "Vendor Advisory" {
		t.Fatalf("unexpected references: %+v", vulnerability.References)
	}
	matcher, err := NewMatcher(store)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "cpe:application", Name: "openssl:openssl", Version: "1.0.1"})
	if err != nil {
		t.Fatalf("match nvd cpe range: %v", err)
	}
	if len(matches) != 1 || matches[0].Vulnerability.ID != "CVE-2026-44444" {
		t.Fatalf("unexpected vulnerable cpe matches: %+v", matches)
	}
	matches, err = matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "cpe:application", Name: "openssl:openssl", Version: "1.0.2"})
	if err != nil {
		t.Fatalf("match fixed nvd cpe range: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected fixed cpe version to be excluded, got %+v", matches)
	}
}

func TestImportNVDKeepsVersionStartExcludingExclusive(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	nvd := `{
		"vulnerabilities":[{
			"cve":{
				"id":"CVE-2026-44447",
				"configurations":[{
					"nodes":[{
						"cpeMatch":[{
							"vulnerable":true,
							"criteria":"cpe:2.3:a:demo:exclusive:*:*:*:*:*:*:*:*",
							"versionStartExcluding":"1.0.0",
							"versionEndExcluding":"1.0.2"
						}]
					}]
				}]
			}
		}]
	}`
	if _, err := ImportNVD(ctx, store, strings.NewReader(nvd)); err != nil {
		t.Fatalf("import nvd: %v", err)
	}
	matcher, err := NewMatcher(store)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "cpe:application", Name: "demo:exclusive", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("match exclusive lower boundary: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected exclusive lower boundary to be excluded, got %+v", matches)
	}
	matches, err = matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "cpe:application", Name: "demo:exclusive", Version: "1.0.1"})
	if err != nil {
		t.Fatalf("match inside exclusive range: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected inside exclusive range to match, got %+v", matches)
	}
}

func TestImportNVDSkipsConjunctiveConfigurations(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	nvd := `{
		"vulnerabilities":[{
			"cve":{
				"id":"CVE-2026-44448",
				"configurations":[{
					"nodes":[{
						"operator":"AND",
						"cpeMatch":[{
							"vulnerable":true,
							"criteria":"cpe:2.3:a:demo:platform_bound:*:*:*:*:*:*:*:*"
						},{
							"vulnerable":false,
							"criteria":"cpe:2.3:o:demo:required_os:*:*:*:*:*:*:*:*"
						}]
					}]
				}]
			}
		}]
	}`
	imported, err := ImportNVD(ctx, store, strings.NewReader(nvd))
	if err != nil {
		t.Fatalf("import nvd: %v", err)
	}
	if imported.AffectedPackages != 0 {
		t.Fatalf("affected packages = %d, want conjunctive configuration skipped", imported.AffectedPackages)
	}
	matcher, err := NewMatcher(store)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	matches, err := matcher.MatchPackage(ctx, PackageQuery{Ecosystem: "cpe:application", Name: "demo:platform_bound", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("match skipped conjunctive package: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no match for conjunctive platform-bound CPE, got %+v", matches)
	}
}

func TestImportEPSSReturnsCommentScanError(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if _, err := ImportEPSS(ctx, store, iotest.ErrReader(fmt.Errorf("read failed"))); err == nil {
		t.Fatal("ImportEPSS() error = nil, want scanner read failure")
	}
}

func TestValidateFeedURLTransportPolicy(t *testing.T) {
	if err := ValidateFeedURL("https://example.com/feed.json", false); err != nil {
		t.Fatalf("https feed should be allowed: %v", err)
	}
	if err := ValidateFeedURL("http://example.com/feed.json", false); err == nil {
		t.Fatal("expected http feed to be rejected without allow-insecure-http")
	}
	if err := ValidateFeedURL("http://example.com/feed.json", true); err != nil {
		t.Fatalf("http feed should be allowed with opt-in: %v", err)
	}
	if err := ValidateFeedURL("file:///tmp/feed.json", true); err == nil {
		t.Fatal("expected file URL to be rejected")
	}
}
