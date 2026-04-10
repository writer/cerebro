package cli

import (
	"testing"

	"github.com/writer/cerebro/internal/app"
)

type repoSecretScanFlagState struct {
	stateFile      string
	checkoutBase   string
	gitleaksBinary string
	trufflehog     string
}

func snapshotRepoSecretScanFlagState() repoSecretScanFlagState {
	return repoSecretScanFlagState{
		stateFile:      repoSecretScanStateFile,
		checkoutBase:   repoSecretScanCheckoutBasePath,
		gitleaksBinary: repoSecretScanGitleaksBinary,
		trufflehog:     repoSecretScanTruffleHogBinary,
	}
}

func restoreRepoSecretScanFlagState(state repoSecretScanFlagState) {
	repoSecretScanStateFile = state.stateFile
	repoSecretScanCheckoutBasePath = state.checkoutBase
	repoSecretScanGitleaksBinary = state.gitleaksBinary
	repoSecretScanTruffleHogBinary = state.trufflehog
}

func TestRepoSecretScanFlagsRegistered(t *testing.T) {
	for _, name := range []string{"state-file", "checkout-base", "gitleaks-binary", "trufflehog-binary"} {
		if flag := repoSecretScanCmd.PersistentFlags().Lookup(name); flag == nil {
			t.Fatalf("expected flag %s to be registered", name)
			return
		}
	}
}

func TestResolveRepoSecretScanStateFileFallsBackToExecutionStore(t *testing.T) {
	state := snapshotRepoSecretScanFlagState()
	t.Cleanup(func() { restoreRepoSecretScanFlagState(state) })

	repoSecretScanStateFile = ""

	got := resolveRepoSecretScanStateFile(&app.Config{ExecutionStoreFile: "/tmp/cerebro-executions.db"})
	if got != "/tmp/cerebro-executions.db" {
		t.Fatalf("expected execution store fallback, got %q", got)
	}
}

func TestResolveRepoSecretScanGitleaksBinaryPrefersCLIOverride(t *testing.T) {
	state := snapshotRepoSecretScanFlagState()
	t.Cleanup(func() { restoreRepoSecretScanFlagState(state) })

	repoSecretScanGitleaksBinary = "/usr/local/bin/gitleaks"

	got := resolveRepoSecretScanGitleaksBinary()
	if got != "/usr/local/bin/gitleaks" {
		t.Fatalf("expected CLI override to win, got %q", got)
	}
}

func TestResolveRepoSecretScanTruffleHogBinaryPrefersCLIOverride(t *testing.T) {
	state := snapshotRepoSecretScanFlagState()
	t.Cleanup(func() { restoreRepoSecretScanFlagState(state) })

	repoSecretScanTruffleHogBinary = "/usr/local/bin/trufflehog"

	got := resolveRepoSecretScanTruffleHogBinary()
	if got != "/usr/local/bin/trufflehog" {
		t.Fatalf("expected CLI override to win, got %q", got)
	}
}
