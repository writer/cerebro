package postgres

import (
	"testing"

	"github.com/writer/cerebro/internal/vulndb"
)

func TestVulnDBAffectedPackageRowKeyNormalizesLookupFields(t *testing.T) {
	left := postgresAffectedPackageKey(vulndb.AffectedPackage{
		VulnerabilityID: "CVE-2026-12345",
		Ecosystem:       "NPM",
		PackageName:     " Lodash ",
		Introduced:      "0",
		Fixed:           "4.17.21",
	})
	right := postgresAffectedPackageKey(vulndb.AffectedPackage{
		VulnerabilityID: "CVE-2026-12345",
		Ecosystem:       "npm",
		PackageName:     "lodash",
		Introduced:      "0",
		Fixed:           "4.17.21",
	})
	if left != right {
		t.Fatalf("row keys differ after normalization: %q != %q", left, right)
	}
	if len(left) != 64 {
		t.Fatalf("row key length = %d, want sha256 hex", len(left))
	}
}

func TestNormalizedVulnDBAliasesIncludesCanonicalID(t *testing.T) {
	aliases := normalizedVulnAliases([]string{"cve-2026-12345", " cve-2026-12345 ", "ghsa-aaaa-bbbb-cccc"})
	if len(aliases) != 2 || aliases[0] != "CVE-2026-12345" || aliases[1] != "GHSA-AAAA-BBBB-CCCC" {
		t.Fatalf("aliases = %#v, want canonical plus unique aliases", aliases)
	}
}
