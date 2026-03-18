package vulndb

import (
	"testing"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
)

func TestDistributionVersionMatchesNonNumericVersions(t *testing.T) {
	if distributionVersionMatches("focal", "bionic") {
		t.Fatal("expected different codenames not to match")
	}
	if !distributionVersionMatches("focal", "focal") {
		t.Fatal("expected identical codenames to match")
	}
}

func TestDistributionVersionMatchesWhenInstalledVersionUnknown(t *testing.T) {
	if !distributionVersionMatches("", "22.04") {
		t.Fatal("expected unknown installed version to conservatively match scoped advisory")
	}
}

func TestFilterCandidatesForOSPrefersScopedMatchForSameVulnerability(t *testing.T) {
	filtered := filterCandidatesForOS([]candidateRecord{
		{
			Vulnerability: Vulnerability{ID: "GHSA-unscoped", Aliases: []string{"CVE-2026-9001"}},
			Affected:      AffectedPackage{Distribution: ""},
		},
		{
			Vulnerability: Vulnerability{ID: "GHSA-scoped", Aliases: []string{"CVE-2026-9001"}},
			Affected:      AffectedPackage{Distribution: "ubuntu", DistributionVersion: "22.04"},
		},
		{
			Vulnerability: Vulnerability{ID: "GHSA-other", Aliases: []string{"CVE-2026-9002"}},
			Affected:      AffectedPackage{Distribution: ""},
		},
	}, filesystemanalyzer.OSInfo{ID: "ubuntu", VersionID: "22.04"})

	if len(filtered) != 2 {
		t.Fatalf("expected scoped candidate and unrelated unscoped candidate, got %#v", filtered)
	}
	if got := primaryVulnerabilityID(filtered[0].Vulnerability); got != "CVE-2026-9001" {
		t.Fatalf("expected scoped vulnerability to be retained for duplicated CVE, got %q", got)
	}
	if got := filtered[0].Affected.Distribution; got != "ubuntu" {
		t.Fatalf("expected duplicated CVE to keep scoped candidate, got distribution %q", got)
	}
	if got := primaryVulnerabilityID(filtered[1].Vulnerability); got != "CVE-2026-9002" {
		t.Fatalf("expected unrelated unscoped candidate to remain, got %q", got)
	}
}
