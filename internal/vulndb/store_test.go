package vulndb

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
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
				"references":[{"url":"https://example.com/advisory","source":"nvd","tags":["Vendor Advisory"]}]
			}
		}]
	}`
	imported, err := ImportNVD(ctx, store, strings.NewReader(nvd))
	if err != nil {
		t.Fatalf("import nvd: %v", err)
	}
	if imported.Vulnerabilities != 1 {
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
