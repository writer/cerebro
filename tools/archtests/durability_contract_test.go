package archtests

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDurabilityContractDocumentsGraphRebuildSources(t *testing.T) {
	root := repoRoot(t)
	contract, err := os.ReadFile(filepath.Join(root, "docs", "DURABILITY_CONTRACT.md"))
	if err != nil {
		t.Fatalf("read docs/DURABILITY_CONTRACT.md: %v", err)
	}
	for _, marker := range []string{
		"Source runtime sync",
		"Workflow decisions, actions, and outcomes",
		"SDK/runtime claims",
		"Postgres claim state until claim events exist",
		"claim.v1.*",
		"Neo4j remains a projection",
	} {
		if !bytes.Contains(contract, []byte(marker)) {
			t.Fatalf("docs/DURABILITY_CONTRACT.md missing durability marker %q", marker)
		}
	}

	architecture, err := os.ReadFile(filepath.Join(root, "docs", "ARCHITECTURE.md"))
	if err != nil {
		t.Fatalf("read docs/ARCHITECTURE.md: %v", err)
	}
	for _, marker := range []string{
		"DURABILITY_CONTRACT.md",
		"SDK/runtime claim writes are currently Postgres-backed",
		"Neo4j remains a projection",
	} {
		if !bytes.Contains(architecture, []byte(marker)) {
			t.Fatalf("docs/ARCHITECTURE.md missing durability marker %q", marker)
		}
	}

	nonGoals, err := os.ReadFile(filepath.Join(root, "docs", "NON_GOALS.md"))
	if err != nil {
		t.Fatalf("read docs/NON_GOALS.md: %v", err)
	}
	for _, marker := range []string{
		"Neo4j is a projection, not a store of record",
		"Source runtime and workflow graph state",
		"SDK/runtime claim graph state",
		"DURABILITY_CONTRACT.md",
	} {
		if !bytes.Contains(nonGoals, []byte(marker)) {
			t.Fatalf("docs/NON_GOALS.md missing graph durability marker %q", marker)
		}
	}
}
