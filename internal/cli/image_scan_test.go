package cli

import (
	"testing"

	"github.com/writer/cerebro/internal/app"
)

type imageScanFlagState struct {
	trivyBinary    string
	gitleaksBinary string
	clamavBinary   string
}

func snapshotImageScanFlagState() imageScanFlagState {
	return imageScanFlagState{
		trivyBinary:    imageScanTrivyBinary,
		gitleaksBinary: imageScanGitleaksBinary,
		clamavBinary:   imageScanClamAVBinary,
	}
}

func restoreImageScanFlagState(state imageScanFlagState) {
	imageScanTrivyBinary = state.trivyBinary
	imageScanGitleaksBinary = state.gitleaksBinary
	imageScanClamAVBinary = state.clamavBinary
}

func TestImageScanFlagsRegistered(t *testing.T) {
	for _, name := range []string{"trivy-binary", "gitleaks-binary", "clamav-binary"} {
		if flag := imageScanCmd.PersistentFlags().Lookup(name); flag == nil {
			t.Fatalf("expected flag %s to be registered", name)
		}
	}
}

func TestResolveImageScanClamAVBinaryFallsBackToEmptyOnWhitespaceConfig(t *testing.T) {
	state := snapshotImageScanFlagState()
	t.Cleanup(func() { restoreImageScanFlagState(state) })

	imageScanClamAVBinary = ""

	got := resolveImageScanClamAVBinary(&app.Config{ImageScanClamAVBinary: "   "})
	if got != "" {
		t.Fatalf("expected empty default clamav binary, got %q", got)
	}
}

func TestResolveImageScanClamAVBinaryPrefersCLIOverride(t *testing.T) {
	state := snapshotImageScanFlagState()
	t.Cleanup(func() { restoreImageScanFlagState(state) })

	imageScanClamAVBinary = "/usr/local/bin/clamscan"

	got := resolveImageScanClamAVBinary(&app.Config{ImageScanClamAVBinary: "/opt/clamscan"})
	if got != "/usr/local/bin/clamscan" {
		t.Fatalf("expected CLI override to win, got %q", got)
	}
}
