package vulndb

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/filesystemanalyzer"
)

func TestServiceImportsOSVAndMatchesPackages(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	osv := `
{"id":"GHSA-test-0001","aliases":["CVE-2026-0001"],"summary":"lodash vulnerable","details":"Prototype pollution","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}
`
	report, err := service.ImportOSVJSON(context.Background(), "osv-test", strings.NewReader(osv))
	if err != nil {
		t.Fatalf("ImportOSVJSON: %v", err)
	}
	if report.Imported != 1 {
		t.Fatalf("expected 1 imported advisory, got %#v", report)
	}

	stats, err := service.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.VulnerabilityCount != 1 || stats.PackageRangeCount != 1 {
		t.Fatalf("unexpected stats: %#v", stats)
	}

	matches, err := service.MatchPackages(context.Background(), filesystemanalyzer.OSInfo{}, []filesystemanalyzer.PackageRecord{{
		Ecosystem: "npm",
		Name:      "lodash",
		Version:   "4.17.20",
	}})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 vulnerability match, got %#v", matches)
	}
	if matches[0].CVE != "CVE-2026-0001" {
		t.Fatalf("expected CVE alias to be primary id, got %#v", matches[0])
	}
	if matches[0].FixedVersion != "4.17.21" {
		t.Fatalf("expected fixed version 4.17.21, got %#v", matches[0])
	}
	if matches[0].Severity != "high" {
		t.Fatalf("expected high severity, got %#v", matches[0])
	}

	info, ok := service.LookupCVE("CVE-2026-0001")
	if !ok {
		t.Fatal("expected LookupCVE to find imported alias")
	}
	if info.InKEV {
		t.Fatalf("expected imported advisory to start without KEV flag, got %#v", info)
	}

	kev := `{"vulnerabilities":[{"cveID":"CVE-2026-0001"}]}`
	kevReport, err := service.ImportKEVJSON(context.Background(), "kev-test", strings.NewReader(kev))
	if err != nil {
		t.Fatalf("ImportKEVJSON: %v", err)
	}
	if kevReport.MatchedKEV != 1 {
		t.Fatalf("expected one KEV match, got %#v", kevReport)
	}

	epss := "cve,epss,percentile\nCVE-2026-0001,0.91,0.99\n"
	epssReport, err := service.ImportEPSSCSV(context.Background(), "epss-test", strings.NewReader(epss))
	if err != nil {
		t.Fatalf("ImportEPSSCSV: %v", err)
	}
	if epssReport.MatchedEPSS != 1 {
		t.Fatalf("expected one EPSS match, got %#v", epssReport)
	}

	info, ok = service.LookupCVE("CVE-2026-0001")
	if !ok {
		t.Fatal("expected LookupCVE after KEV/EPSS enrichment")
	}
	if !info.InKEV || !info.Exploitable {
		t.Fatalf("expected KEV/EPSS enrichment to make advisory exploitable, got %#v", info)
	}

	syncStates, err := service.ListSyncStates(context.Background())
	if err != nil {
		t.Fatalf("ListSyncStates: %v", err)
	}
	if len(syncStates) != 3 {
		t.Fatalf("expected 3 sync states, got %#v", syncStates)
	}
}

func TestServiceMatchPackagesSkipsWithdrawnAdvisories(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	withdrawn := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	osv := `
{"id":"GHSA-test-withdrawn","aliases":["CVE-2026-9999"],"summary":"withdrawn advisory","details":"duplicate record","database_specific":{"severity":"HIGH"},"withdrawn":"` + withdrawn + `","affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}
`
	report, err := service.ImportOSVJSON(context.Background(), "osv-test", strings.NewReader(osv))
	if err != nil {
		t.Fatalf("ImportOSVJSON: %v", err)
	}
	if report.Imported != 1 {
		t.Fatalf("expected 1 imported advisory, got %#v", report)
	}

	matches, err := service.MatchPackages(context.Background(), filesystemanalyzer.OSInfo{}, []filesystemanalyzer.PackageRecord{{
		Ecosystem: "npm",
		Name:      "lodash",
		Version:   "4.17.20",
	}})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected withdrawn advisory to be skipped, got %#v", matches)
	}
}

func TestServiceMatchesEcosystemRanges(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	osv := `
{"id":"GHSA-test-ecosystem","aliases":["CVE-2026-1001"],"summary":"lodash vulnerable","details":"Prototype pollution","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}
`
	if _, err := service.ImportOSVJSON(context.Background(), "osv-test", strings.NewReader(osv)); err != nil {
		t.Fatalf("ImportOSVJSON: %v", err)
	}

	matches, err := service.MatchPackages(context.Background(), filesystemanalyzer.OSInfo{}, []filesystemanalyzer.PackageRecord{{
		Ecosystem: "npm",
		Name:      "lodash",
		Version:   "4.17.20",
	}})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one ECOSYSTEM range match, got %#v", matches)
	}
}

func TestServiceMatchesAlpineAliasAsAPK(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	osv := `
{"id":"GHSA-test-alpine","aliases":["CVE-2026-2001"],"summary":"apk vulnerable","details":"alpine package advisory","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"Alpine","name":"busybox"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.18.5-r0"}]}]}]}
`
	if _, err := service.ImportOSVJSON(context.Background(), "osv-test", strings.NewReader(osv)); err != nil {
		t.Fatalf("ImportOSVJSON: %v", err)
	}

	matches, err := service.MatchPackages(context.Background(), filesystemanalyzer.OSInfo{}, []filesystemanalyzer.PackageRecord{{
		Ecosystem: "apk",
		Name:      "busybox",
		Version:   "3.18.4-r0",
	}})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected alpine/apk alias match, got %#v", matches)
	}
}

func TestServiceMatchesAPKRevisionAwareFixedVersion(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	revisionlessFixed := `
{"id":"GHSA-test-apk-fixed","aliases":["CVE-2026-2002"],"summary":"apk fixed at base version","details":"alpine package advisory","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"Alpine","name":"busybox"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.18.5"}]}]}]}
`
	if _, err := service.ImportOSVJSON(context.Background(), "osv-test", strings.NewReader(revisionlessFixed)); err != nil {
		t.Fatalf("ImportOSVJSON: %v", err)
	}

	matches, err := service.MatchPackages(context.Background(), filesystemanalyzer.OSInfo{}, []filesystemanalyzer.PackageRecord{{
		Ecosystem: "apk",
		Name:      "busybox",
		Version:   "3.18.5-r0",
	}})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected revision-aware comparison to treat 3.18.5-r0 as fixed, got %#v", matches)
	}

	revisionedFixed := `
{"id":"GHSA-test-apk-revision","aliases":["CVE-2026-2003"],"summary":"apk fixed at later revision","details":"alpine package advisory","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"Alpine","name":"busybox"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.18.5-r2"}]}]}]}
`
	if _, err := service.ImportOSVJSON(context.Background(), "osv-test-2", strings.NewReader(revisionedFixed)); err != nil {
		t.Fatalf("ImportOSVJSON second advisory: %v", err)
	}

	matches, err = service.MatchPackages(context.Background(), filesystemanalyzer.OSInfo{}, []filesystemanalyzer.PackageRecord{{
		Ecosystem: "apk",
		Name:      "busybox",
		Version:   "3.18.5-r1",
	}})
	if err != nil {
		t.Fatalf("MatchPackages second advisory: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected later apk revision to remain vulnerable, got %#v", matches)
	}
}

func TestServiceFiltersScopedCandidatesByDistribution(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	if err := store.UpsertAdvisory(context.Background(), Vulnerability{
		ID:       "GHSA-test-ubuntu",
		Aliases:  []string{"CVE-2026-2501"},
		Summary:  "ubuntu scoped advisory",
		Severity: "high",
	}, []AffectedPackage{{
		Ecosystem:           "deb",
		PackageName:         "openssl",
		RangeType:           "ECOSYSTEM",
		Introduced:          "0",
		Fixed:               "1.2.4",
		Distribution:        "ubuntu",
		DistributionVersion: "22.04",
	}}); err != nil {
		t.Fatalf("UpsertAdvisory ubuntu: %v", err)
	}
	if err := store.UpsertAdvisory(context.Background(), Vulnerability{
		ID:       "GHSA-test-debian",
		Aliases:  []string{"CVE-2026-2502"},
		Summary:  "debian scoped advisory",
		Severity: "high",
	}, []AffectedPackage{{
		Ecosystem:           "deb",
		PackageName:         "openssl",
		RangeType:           "ECOSYSTEM",
		Introduced:          "0",
		Fixed:               "1.2.4",
		Distribution:        "debian",
		DistributionVersion: "12",
	}}); err != nil {
		t.Fatalf("UpsertAdvisory debian: %v", err)
	}

	matches, err := service.MatchPackages(context.Background(), filesystemanalyzer.OSInfo{
		ID:        "ubuntu",
		VersionID: "22.04",
	}, []filesystemanalyzer.PackageRecord{{
		Ecosystem: "deb",
		Name:      "openssl",
		Version:   "1.2.3",
	}})
	if err != nil {
		t.Fatalf("MatchPackages ubuntu: %v", err)
	}
	if len(matches) != 1 || matches[0].CVE != "CVE-2026-2501" {
		t.Fatalf("expected only ubuntu-scoped advisory to match, got %#v", matches)
	}
}

func TestServiceSkipsUnparseableRangeBounds(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	osv := `
{"id":"GHSA-test-debian","aliases":["CVE-2026-3001"],"summary":"debian range advisory","details":"non-semver bound","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"npm","name":"leftpad"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:1.2.3-4"}]}]}]}
`
	if _, err := service.ImportOSVJSON(context.Background(), "osv-test", strings.NewReader(osv)); err != nil {
		t.Fatalf("ImportOSVJSON: %v", err)
	}

	matches, err := service.MatchPackages(context.Background(), filesystemanalyzer.OSInfo{}, []filesystemanalyzer.PackageRecord{{
		Ecosystem: "npm",
		Name:      "leftpad",
		Version:   "1.2.3",
	}})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected unparseable range bounds to fail closed, got %#v", matches)
	}
}
