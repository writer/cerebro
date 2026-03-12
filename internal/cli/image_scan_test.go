package cli

import (
	"testing"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/imagescan"
)

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
