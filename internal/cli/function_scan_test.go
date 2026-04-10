package cli

import (
	"testing"

	"github.com/writer/cerebro/internal/app"
)

type functionScanFlagState struct {
	trivyBinary    string
	gitleaksBinary string
	clamavBinary   string
}

func snapshotFunctionScanFlagState() functionScanFlagState {
	return functionScanFlagState{
		trivyBinary:    functionScanTrivyBinary,
		gitleaksBinary: functionScanGitleaksBinary,
		clamavBinary:   functionScanClamAVBinary,
	}
}

func restoreFunctionScanFlagState(state functionScanFlagState) {
	functionScanTrivyBinary = state.trivyBinary
	functionScanGitleaksBinary = state.gitleaksBinary
	functionScanClamAVBinary = state.clamavBinary
}

func TestFunctionScanFlagsRegistered(t *testing.T) {
	for _, name := range []string{"trivy-binary", "gitleaks-binary", "clamav-binary"} {
		if flag := functionScanCmd.PersistentFlags().Lookup(name); flag == nil {
			t.Fatalf("expected flag %s to be registered", name)
			return
		}
	}
}

func TestResolveFunctionScanClamAVBinaryFallsBackToEmptyOnWhitespaceConfig(t *testing.T) {
	state := snapshotFunctionScanFlagState()
	t.Cleanup(func() { restoreFunctionScanFlagState(state) })

	functionScanClamAVBinary = ""

	got := resolveFunctionScanClamAVBinary(&app.Config{FunctionScanClamAVBinary: "   "})
	if got != "" {
		t.Fatalf("expected empty default clamav binary, got %q", got)
	}
}

func TestResolveFunctionScanClamAVBinaryPrefersCLIOverride(t *testing.T) {
	state := snapshotFunctionScanFlagState()
	t.Cleanup(func() { restoreFunctionScanFlagState(state) })

	functionScanClamAVBinary = "/usr/local/bin/clamscan"

	got := resolveFunctionScanClamAVBinary(&app.Config{FunctionScanClamAVBinary: "/opt/clamscan"})
	if got != "/usr/local/bin/clamscan" {
		t.Fatalf("expected CLI override to win, got %q", got)
	}
}
