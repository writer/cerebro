package cli

import (
	"testing"

	"github.com/writer/cerebro/internal/app"
)

type repoScanFlagState struct {
	stateFile    string
	checkoutBase string
}

func snapshotRepoScanFlagState() repoScanFlagState {
	return repoScanFlagState{
		stateFile:    repoScanStateFile,
		checkoutBase: repoScanCheckoutBasePath,
	}
}

func restoreRepoScanFlagState(state repoScanFlagState) {
	repoScanStateFile = state.stateFile
	repoScanCheckoutBasePath = state.checkoutBase
}

func TestRepoScanFlagsRegistered(t *testing.T) {
	for _, name := range []string{"state-file", "checkout-base"} {
		if flag := repoScanCmd.PersistentFlags().Lookup(name); flag == nil {
			t.Fatalf("expected flag %s to be registered", name)
		}
	}
}

func TestResolveRepoScanStateFileFallsBackToExecutionStore(t *testing.T) {
	state := snapshotRepoScanFlagState()
	t.Cleanup(func() { restoreRepoScanFlagState(state) })

	repoScanStateFile = ""

	got := resolveRepoScanStateFile(&app.Config{ExecutionStoreFile: "/tmp/cerebro-executions.db"})
	if got != "/tmp/cerebro-executions.db" {
		t.Fatalf("expected execution store fallback, got %q", got)
	}
}

func TestResolveRepoScanStateFilePrefersCLIOverride(t *testing.T) {
	state := snapshotRepoScanFlagState()
	t.Cleanup(func() { restoreRepoScanFlagState(state) })

	repoScanStateFile = "/tmp/override.db"

	got := resolveRepoScanStateFile(&app.Config{ExecutionStoreFile: "/tmp/cerebro-executions.db"})
	if got != "/tmp/override.db" {
		t.Fatalf("expected CLI override to win, got %q", got)
	}
}

func TestResolveRepoScanCheckoutBaseDefaults(t *testing.T) {
	state := snapshotRepoScanFlagState()
	t.Cleanup(func() { restoreRepoScanFlagState(state) })

	repoScanCheckoutBasePath = ""

	got := resolveRepoScanCheckoutBasePath()
	if got != ".cerebro/repo-scan/checkouts" {
		t.Fatalf("expected default checkout base, got %q", got)
	}
}
