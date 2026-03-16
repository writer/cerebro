package workloadscan

import (
	"context"
	"path/filepath"
	"testing"
)

func TestLocalMounterMountRejectsUnsafeDevicePath(t *testing.T) {
	mounter := NewLocalMounter(t.TempDir())

	if _, err := mounter.Mount(context.Background(), VolumeAttachment{
		VolumeID:   "vol-1",
		DeviceName: " /tmp/not-a-device ",
	}, SourceVolume{}); err == nil {
		t.Fatal("expected mount to reject non-/dev device path")
	}
}

func TestLocalMounterValidateExistingMountPathRejectsEscape(t *testing.T) {
	basePath := t.TempDir()
	mounter := NewLocalMounter(basePath)

	if _, err := mounter.validateExistingMountPath(filepath.Join(basePath, "..", "escape")); err == nil {
		t.Fatal("expected mount path validation to reject paths outside base path")
	}
}
