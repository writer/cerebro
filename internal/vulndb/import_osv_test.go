package vulndb

import (
	"context"
	"strings"
	"testing"
)

func TestImportEPSSCSVRejectsOversizedInputs(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	previousBytes := maxEPSSImportBytes
	previousRows := maxEPSSImportRows
	maxEPSSImportBytes = 32
	maxEPSSImportRows = 2
	t.Cleanup(func() {
		maxEPSSImportBytes = previousBytes
		maxEPSSImportRows = previousRows
	})

	_, err = service.ImportEPSSCSV(context.Background(), "epss-test", strings.NewReader("cve,epss,percentile\nCVE-2026-0001,0.1,0.2\nCVE-2026-0002,0.2,0.3\n"))
	if err == nil {
		t.Fatal("expected oversized EPSS input to fail")
	}
	if !strings.Contains(err.Error(), "exceeded maximum") {
		t.Fatalf("expected maximum-bound error, got %v", err)
	}
}

func TestImportKEVJSONRejectsOversizedInputs(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	previousBytes := maxKEVImportBytes
	previousRows := maxKEVImportRows
	maxKEVImportBytes = 32
	maxKEVImportRows = 2
	t.Cleanup(func() {
		maxKEVImportBytes = previousBytes
		maxKEVImportRows = previousRows
	})

	_, err = service.ImportKEVJSON(context.Background(), "kev-test", strings.NewReader(`{"vulnerabilities":[{"cveID":"CVE-2026-0001"},{"cveID":"CVE-2026-0002"},{"cveID":"CVE-2026-0003"}]}`))
	if err == nil {
		t.Fatal("expected oversized KEV input to fail")
	}
	if !strings.Contains(err.Error(), "exceeded maximum") {
		t.Fatalf("expected maximum-bound error, got %v", err)
	}
}

func TestImportOSVJSONRejectsOversizedInputs(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	previousBytes := maxOSVImportBytes
	previousRows := maxOSVImportRows
	maxOSVImportBytes = 48
	maxOSVImportRows = 1
	t.Cleanup(func() {
		maxOSVImportBytes = previousBytes
		maxOSVImportRows = previousRows
	})

	_, err = service.ImportOSVJSON(context.Background(), "osv-test", strings.NewReader(`
{"id":"GHSA-test-0001","affected":[]}
{"id":"GHSA-test-0002","affected":[]}
`))
	if err == nil {
		t.Fatal("expected oversized OSV input to fail")
	}
	if !strings.Contains(err.Error(), "exceeded maximum") {
		t.Fatalf("expected maximum-bound error, got %v", err)
	}
}

func TestImportKEVJSONStreamsAndMatches(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	if err := store.UpsertAdvisory(context.Background(), Vulnerability{
		ID:      "GHSA-test-0001",
		Aliases: []string{"CVE-2026-0001"},
		Source:  "osv",
	}, nil); err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}

	report, err := service.ImportKEVJSON(context.Background(), "kev-test", strings.NewReader(`{"title":"KEV","vulnerabilities":[{"cveID":"CVE-2026-0001"},{"cveID":"CVE-2026-9999"}]}`))
	if err != nil {
		t.Fatalf("ImportKEVJSON: %v", err)
	}
	if report.Imported != 2 || report.MatchedKEV != 1 {
		t.Fatalf("expected streamed KEV import to count two records and match one advisory, got %#v", report)
	}
}

func TestImportOSVJSONRollsBackOnMalformedStream(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	_, err = service.ImportOSVJSON(context.Background(), "osv-test", strings.NewReader(`
{"id":"GHSA-test-0001","aliases":["CVE-2026-0001"],"summary":"valid","affected":[]}
{"id":"GHSA-test-0002"
`))
	if err == nil {
		t.Fatal("expected malformed OSV stream to fail")
	}
	if vuln, ok := service.LookupCVE("CVE-2026-0001"); ok || vuln != nil {
		t.Fatalf("expected malformed OSV import to roll back advisory writes, got %#v", vuln)
	}
	stats, err := service.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.VulnerabilityCount != 0 || stats.PackageRangeCount != 0 {
		t.Fatalf("expected malformed OSV import to leave database unchanged, got %#v", stats)
	}
	states, err := service.ListSyncStates(context.Background())
	if err != nil {
		t.Fatalf("ListSyncStates: %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("expected malformed OSV import to avoid sync-state writes, got %#v", states)
	}
}

func TestImportKEVJSONRollsBackOnMalformedStream(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	if err := store.UpsertAdvisory(context.Background(), Vulnerability{
		ID:      "GHSA-test-0001",
		Aliases: []string{"CVE-2026-0001"},
		Source:  "osv",
	}, nil); err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}

	var payload strings.Builder
	payload.WriteString(`{"vulnerabilities":[`)
	for i := 0; i < 1024; i++ {
		if i > 0 {
			payload.WriteByte(',')
		}
		cve := "CVE-2026-0001"
		if i > 0 {
			cve = "CVE-2026-9999"
		}
		payload.WriteString(`{"cveID":"` + cve + `"}`)
	}
	payload.WriteString(`,{"cveID":`)

	_, err = service.ImportKEVJSON(context.Background(), "kev-test", strings.NewReader(payload.String()))
	if err == nil {
		t.Fatal("expected malformed KEV stream to fail")
	}
	vuln, ok := service.LookupCVE("CVE-2026-0001")
	if !ok || vuln == nil {
		t.Fatal("expected seeded advisory lookup to succeed")
	}
	if vuln.InKEV {
		t.Fatalf("expected malformed KEV import to roll back enrichment, got %#v", vuln)
	}
	states, err := service.ListSyncStates(context.Background())
	if err != nil {
		t.Fatalf("ListSyncStates: %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("expected malformed KEV import to avoid sync-state writes, got %#v", states)
	}
}

func TestImportEPSSCSVSkipsCommentLines(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	if err := store.UpsertAdvisory(context.Background(), Vulnerability{
		ID:      "GHSA-test-0001",
		Aliases: []string{"CVE-2026-0001"},
		Source:  "osv",
	}, nil); err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}

	report, err := service.ImportEPSSCSV(context.Background(), "epss-test", strings.NewReader("# EPSS v4\ncve,epss,percentile\nCVE-2026-0001,0.91,0.99\n"))
	if err != nil {
		t.Fatalf("ImportEPSSCSV: %v", err)
	}
	if report.Imported != 1 || report.MatchedEPSS != 1 {
		t.Fatalf("expected comment-prefixed EPSS import to match one record, got %#v", report)
	}
}

func TestImportEPSSCSVRollsBackOnMalformedCSV(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	if err := store.UpsertAdvisory(context.Background(), Vulnerability{
		ID:      "GHSA-test-0001",
		Aliases: []string{"CVE-2026-0001"},
		Source:  "osv",
	}, nil); err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}

	_, err = service.ImportEPSSCSV(context.Background(), "epss-test", strings.NewReader("cve,epss,percentile\nCVE-2026-0001,0.91,0.99\n\"unterminated\n"))
	if err == nil {
		t.Fatal("expected malformed EPSS csv to fail")
	}
	vuln, ok := service.LookupCVE("CVE-2026-0001")
	if !ok || vuln == nil {
		t.Fatal("expected seeded advisory lookup to succeed")
	}
	if vuln.Exploitable {
		t.Fatalf("expected malformed EPSS import to roll back enrichment, got %#v", vuln)
	}
	states, err := service.ListSyncStates(context.Background())
	if err != nil {
		t.Fatalf("ListSyncStates: %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("expected malformed EPSS import to avoid sync-state writes, got %#v", states)
	}
}

func TestExtractOSVSeverityParsesCVSSVectors(t *testing.T) {
	severity, score := extractOSVSeverity(osvAdvisory{
		Severity: []osvSeverity{{
			Type:  "CVSS_V3",
			Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		}},
	})
	if severity != "critical" {
		t.Fatalf("expected critical severity from CVSS vector, got %q", severity)
	}
	if score < 9.8 {
		t.Fatalf("expected CVSS score near 9.8, got %f", score)
	}
}
