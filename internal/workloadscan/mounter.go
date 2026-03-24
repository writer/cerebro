package workloadscan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type LocalMounter struct {
	basePath           string
	mountBinary        string
	umountBinary       string
	blkidBinary        string
	lsblkBinary        string
	ntfs3GBinary       string
	commandRunner      func(context.Context, string, ...string) ([]byte, error)
	filesystemDetector func(context.Context, VolumeAttachment, SourceVolume) string
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
		blkidBinary:  "blkid",
		lsblkBinary:  "lsblk",
		ntfs3GBinary: "ntfs-3g",
	}
}

func (m *LocalMounter) Mount(ctx context.Context, attachment VolumeAttachment, source SourceVolume) (*MountedVolume, error) {
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

	filesystemType := m.detectFilesystemType(ctx, attachment, source)
	driver, err := m.mountDevice(ctx, devicePath, mountPath, filesystemType)
	if err != nil {
		return nil, err
	}
	metadata := map[string]any{
		"filesystem":   filesystemType,
		"mount_driver": driver,
	}
	if strings.TrimSpace(filesystemType) == "" {
		delete(metadata, "filesystem")
	}
	return &MountedVolume{
		VolumeID:   attachment.VolumeID,
		DevicePath: devicePath,
		MountPath:  mountPath,
		MountedAt:  time.Now().UTC(),
		Metadata:   metadata,
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

func (m *LocalMounter) detectFilesystemType(ctx context.Context, attachment VolumeAttachment, source SourceVolume) string {
	if m == nil {
		return ""
	}
	if m.filesystemDetector != nil {
		return normalizeFilesystemType(m.filesystemDetector(ctx, attachment, source))
	}
	for _, key := range []string{"filesystem", "filesystem_type", "fstype"} {
		if fsType := normalizeFilesystemType(stringMetadata(source.Metadata, key)); fsType != "" {
			return fsType
		}
	}
	devicePath := strings.TrimSpace(attachment.DeviceName)
	if devicePath == "" {
		return ""
	}
	for _, probe := range []struct {
		name string
		args []string
	}{
		{name: m.blkidBinary, args: []string{"-o", "value", "-s", "TYPE", devicePath}},
		{name: m.lsblkBinary, args: []string{"-no", "FSTYPE", devicePath}},
	} {
		if strings.TrimSpace(probe.name) == "" {
			continue
		}
		output, err := m.runCommand(ctx, probe.name, probe.args...)
		if err != nil {
			continue
		}
		if fsType := normalizeFilesystemType(string(output)); fsType != "" {
			return fsType
		}
	}
	return ""
}

func (m *LocalMounter) mountDevice(ctx context.Context, devicePath, mountPath, filesystemType string) (string, error) {
	filesystemType = normalizeFilesystemType(filesystemType)
	if filesystemType == "ntfs" {
		if _, err := m.runCommand(ctx, m.mountBinary, "-t", "ntfs3", "-o", "ro", devicePath, mountPath); err == nil {
			return "ntfs3", nil
		} else {
			ntfs3Err := fmt.Errorf("mount %s at %s with ntfs3: %w", devicePath, mountPath, err)
			if _, fallbackErr := m.runCommand(ctx, m.ntfs3GBinary, "-o", "ro", devicePath, mountPath); fallbackErr == nil {
				return "ntfs-3g", nil
			} else {
				return "", errors.Join(ntfs3Err, fmt.Errorf("mount %s at %s with ntfs-3g: %w", devicePath, mountPath, fallbackErr))
			}
		}
	}
	if _, err := m.runCommand(ctx, m.mountBinary, "-o", "ro", devicePath, mountPath); err != nil {
		return "", fmt.Errorf("mount %s at %s: %w", devicePath, mountPath, err)
	}
	return "auto", nil
}

func (m *LocalMounter) runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if m != nil && m.commandRunner != nil {
		return m.commandRunner(ctx, name, args...)
	}
	// #nosec G204 -- binaries and arguments are fixed by the mounter implementation and validated earlier.
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func normalizeFilesystemType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "ntfs", "ntfs3":
		return "ntfs"
	default:
		return value
	}
}

func sanitizePathComponent(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "..", "-")
	return replacer.Replace(raw)
}
