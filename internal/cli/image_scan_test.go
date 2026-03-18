package cli

import (
	"testing"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/imagescan"
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

func TestImageScanTargetFromFlagsClearsDefaultTagWhenDigestProvided(t *testing.T) {
	originalRepository, originalTag, originalDigest := imageScanRepository, imageScanTag, imageScanDigest
	defer func() {
		imageScanRepository, imageScanTag, imageScanDigest = originalRepository, originalTag, originalDigest
	}()

	cmd := &cobra.Command{Use: "test-image-scan"}
	bindImageReferenceFlags(cmd)
	if err := cmd.ParseFlags([]string{"--repository", "repo", "--digest", "sha256:image"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	target := imageScanTargetFromFlags(cmd, imagescan.RegistryECR, "registry.example.com")
	if target.Tag != "" {
		t.Fatalf("expected default tag to be cleared for digest scans, got %q", target.Tag)
	}
	if target.Digest != "sha256:image" {
		t.Fatalf("expected digest to be preserved, got %q", target.Digest)
	}
}

func TestImageScanTargetFromFlagsKeepsExplicitTagWhenDigestProvided(t *testing.T) {
	originalRepository, originalTag, originalDigest := imageScanRepository, imageScanTag, imageScanDigest
	defer func() {
		imageScanRepository, imageScanTag, imageScanDigest = originalRepository, originalTag, originalDigest
	}()

	cmd := &cobra.Command{Use: "test-image-scan"}
	bindImageReferenceFlags(cmd)
	if err := cmd.ParseFlags([]string{"--repository", "repo", "--tag", "stable", "--digest", "sha256:image"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	target := imageScanTargetFromFlags(cmd, imagescan.RegistryECR, "registry.example.com")
	if target.Tag != "stable" {
		t.Fatalf("expected explicit tag to be preserved, got %q", target.Tag)
	}
	if target.Digest != "sha256:image" {
		t.Fatalf("expected digest to be preserved, got %q", target.Digest)
	}
}
