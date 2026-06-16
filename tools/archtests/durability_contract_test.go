package archtests

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestSourceSyncRecoveryContractDocumentsCommitOrdering(t *testing.T) {
	root := repoRoot(t)
	contract, err := os.ReadFile(filepath.Join(root, "docs", "SOURCE_SYNC_RECOVERY.md"))
	if err != nil {
		t.Fatalf("read docs/SOURCE_SYNC_RECOVERY.md: %v", err)
	}
	for _, marker := range []string{
		"append, project, then progress",
		"Persist runtime progress with `PutSourceRuntime` only after",
		"If projection fails after append",
		"transactional page ledger or outbox",
		"source_runtime.page_committed",
	} {
		if !bytes.Contains(contract, []byte(marker)) {
			t.Fatalf("docs/SOURCE_SYNC_RECOVERY.md missing source sync recovery marker %q", marker)
		}
	}

	durability, err := os.ReadFile(filepath.Join(root, "docs", "DURABILITY_CONTRACT.md"))
	if err != nil {
		t.Fatalf("read docs/DURABILITY_CONTRACT.md: %v", err)
	}
	for _, marker := range []string{
		"SOURCE_SYNC_RECOVERY.md",
		"transactional sync ledger or outbox",
	} {
		if !bytes.Contains(durability, []byte(marker)) {
			t.Fatalf("docs/DURABILITY_CONTRACT.md missing source sync recovery marker %q", marker)
		}
	}
}

func TestSourceRuntimeSyncCommitOrderingStaysAppendProjectProgress(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "internal", "sourceruntime", "service.go"))
	if err != nil {
		t.Fatalf("read internal/sourceruntime/service.go: %v", err)
	}
	syncBody := string(body)
	start := strings.Index(syncBody, "func (s *Service) Sync(")
	if start < 0 {
		t.Fatal("source runtime Sync implementation not found")
	}
	end := strings.Index(syncBody[start:], "func sourceRuntimeTelemetryErrorKind")
	if end < 0 {
		t.Fatal("source runtime Sync implementation end marker not found")
	}
	syncBody = syncBody[start : start+end]
	appendIndex := strings.Index(syncBody, "s.appendLog.Append(ctx, syncedEvent)")
	projectIndex := strings.Index(syncBody, "s.projector.Project(ctx, syncedEvent)")
	progressIndex := strings.Index(syncBody, "s.store.PutSourceRuntime(ctx, runtime)")
	committedTelemetryIndex := strings.Index(syncBody, "source_runtime.page_committed")
	if appendIndex < 0 || projectIndex < 0 || progressIndex < 0 || committedTelemetryIndex < 0 {
		t.Fatalf("source runtime Sync missing append/project/progress/page_committed markers")
	}
	if !(appendIndex < projectIndex && projectIndex < progressIndex && progressIndex < committedTelemetryIndex) {
		t.Fatalf("source runtime Sync commit order changed; want append before project before progress before page_committed telemetry")
	}
}
