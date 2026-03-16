package workloadscan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type LocalMounter struct {
	basePath     string
	mountBinary  string
	umountBinary string
}

func NewLocalMounter(basePath string) *LocalMounter {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		basePath = filepath.Join(".cerebro", "workload-scan", "mounts")
	}
	return &LocalMounter{
		basePath:     basePath,
		mountBinary:  "mount",
		umountBinary: "umount",
	}
}

func (m *LocalMounter) Mount(ctx context.Context, attachment VolumeAttachment, _ SourceVolume) (*MountedVolume, error) {
	if m == nil {
		return nil, fmt.Errorf("local mounter is nil")
	}
	devicePath := strings.TrimSpace(attachment.DeviceName)
	if devicePath == "" {
		return nil, fmt.Errorf("device path is required for local mount")
	}
	if !strings.HasPrefix(devicePath, "/dev/") || strings.ContainsAny(devicePath, " \t\n\r") {
		return nil, fmt.Errorf("device path %q is not an allowed local block device", devicePath)
	}
	mountPath, err := m.mountPathForVolume(attachment.VolumeID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(mountPath, 0750); err != nil {
		return nil, fmt.Errorf("create mount path %s: %w", mountPath, err)
	}

	// Enforce read-only at mount time because provider-level attachment APIs do not
	// consistently expose a cross-cloud read-only toggle.
	// #nosec G204 -- binary names are fixed by the mounter implementation and paths are validated above.
	cmd := exec.CommandContext(ctx, m.mountBinary, "-o", "ro", devicePath, mountPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("mount %s at %s: %w: %s", devicePath, mountPath, err, strings.TrimSpace(string(output)))
	}
	return &MountedVolume{
		VolumeID:   attachment.VolumeID,
		DevicePath: devicePath,
		MountPath:  mountPath,
		MountedAt:  time.Now().UTC(),
	}, nil
}

func (m *LocalMounter) Unmount(ctx context.Context, mount MountedVolume) error {
	if m == nil {
		return fmt.Errorf("local mounter is nil")
	}
	mountPath := strings.TrimSpace(mount.MountPath)
	if mountPath == "" {
		return fmt.Errorf("mount path is required for unmount")
	}
	resolvedMountPath, err := m.validateExistingMountPath(mountPath)
	if err != nil {
		return err
	}
	// #nosec G204 -- binary names are fixed by the mounter implementation and mount path is validated above.
	cmd := exec.CommandContext(ctx, m.umountBinary, resolvedMountPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unmount %s: %w: %s", resolvedMountPath, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m *LocalMounter) mountPathForVolume(volumeID string) (string, error) {
	basePath, err := filepath.Abs(m.basePath)
	if err != nil {
		return "", fmt.Errorf("resolve mount base path %s: %w", m.basePath, err)
	}
	mountPath := filepath.Join(basePath, sanitizePathComponent(volumeID))
	return m.validateExistingMountPath(mountPath)
}

func (m *LocalMounter) validateExistingMountPath(mountPath string) (string, error) {
	basePath, err := filepath.Abs(m.basePath)
	if err != nil {
		return "", fmt.Errorf("resolve mount base path %s: %w", m.basePath, err)
	}
	resolvedMountPath, err := filepath.Abs(mountPath)
	if err != nil {
		return "", fmt.Errorf("resolve mount path %s: %w", mountPath, err)
	}
	relative, err := filepath.Rel(basePath, resolvedMountPath)
	if err != nil {
		return "", fmt.Errorf("validate mount path %s: %w", resolvedMountPath, err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("mount path %s escapes base path %s", resolvedMountPath, basePath)
	}
	return resolvedMountPath, nil
}

func sanitizePathComponent(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "..", "-")
	return replacer.Replace(raw)
}
