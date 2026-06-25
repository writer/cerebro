package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	findinganalysis "github.com/writer/cerebro/internal/findings"
)

func TestRejectSymlinkRejectsCatalogPath(t *testing.T) {
	root := t.TempDir()
	linkPath := filepath.Join(root, "public_detection_catalog.json")
	if err := os.Symlink(filepath.Join(root, "missing.json"), linkPath); err != nil {
		t.Skipf("Symlink() unsupported: %v", err)
	}
	if err := rejectSymlink(linkPath); err == nil {
		t.Fatal("rejectSymlink() error = nil, want symlink rejection")
	}
}

func TestGenerateCatalogPublishesSourceCoverageRefs(t *testing.T) {
	content, err := generateCatalog()
	if err != nil {
		t.Fatalf("generateCatalog() error = %v", err)
	}
	var catalog findinganalysis.PublicDetectionCatalog
	if err := json.Unmarshal(content, &catalog); err != nil {
		t.Fatalf("unmarshal generated catalog: %v", err)
	}
	for _, detection := range catalog.Detections {
		if detection.ID != "aws-s3-bucket-no-public-access" {
			continue
		}
		for _, ref := range detection.SourceCoverageRefs {
			if ref.SourceID == "aws" && ref.DimensionID == "s3_bucket" {
				return
			}
		}
		t.Fatalf("aws-s3-bucket-no-public-access source coverage refs = %#v, want aws/s3_bucket", detection.SourceCoverageRefs)
	}
	t.Fatal("generated catalog missing aws-s3-bucket-no-public-access")
}
