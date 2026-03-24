package workloadscan

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
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

func TestLocalMounterMountUsesNTFS3ForDetectedNTFSVolume(t *testing.T) {
	basePath := t.TempDir()
	mounter := NewLocalMounter(basePath)
	mountPath, err := mounter.mountPathForVolume("vol-1")
	if err != nil {
		t.Fatalf("mount path for volume: %v", err)
	}

	var commands []string
	mounter.commandRunner = func(_ context.Context, name string, args ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		switch name {
		case "blkid":
			return []byte("ntfs\n"), nil
		case "mount":
			return nil, nil
		default:
			t.Fatalf("unexpected command %q", name)
			return nil, nil
		}
	}

	mount, err := mounter.Mount(context.Background(), VolumeAttachment{
		VolumeID:   "vol-1",
		DeviceName: "/dev/xvdf",
	}, SourceVolume{})
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}

	if len(commands) != 2 {
		t.Fatalf("expected probe and mount commands, got %v", commands)
	}
	if got, want := commands[0], "blkid -o value -s TYPE /dev/xvdf"; got != want {
		t.Fatalf("expected blkid probe %q, got %q", want, got)
	}
	if got, want := commands[1], "mount -t ntfs3 -o ro /dev/xvdf "+mountPath; got != want {
		t.Fatalf("expected ntfs3 mount %q, got %q", want, got)
	}
	if mount.Metadata["filesystem"] != "ntfs" {
		t.Fatalf("expected mounted filesystem metadata to be ntfs, got %#v", mount.Metadata)
	}
	if mount.Metadata["mount_driver"] != "ntfs3" {
		t.Fatalf("expected ntfs3 mount driver metadata, got %#v", mount.Metadata)
	}
}

func TestLocalMounterMountFallsBackToNTFS3GWhenNTFS3Fails(t *testing.T) {
	basePath := t.TempDir()
	mounter := NewLocalMounter(basePath)
	mountPath, err := mounter.mountPathForVolume("vol-2")
	if err != nil {
		t.Fatalf("mount path for volume: %v", err)
	}

	var commands []string
	mounter.commandRunner = func(_ context.Context, name string, args ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		switch name {
		case "blkid":
			return []byte("ntfs\n"), nil
		case "mount":
			return []byte("unknown filesystem type"), errors.New("exit status 32")
		case "ntfs-3g":
			return nil, nil
		default:
			t.Fatalf("unexpected command %q", name)
			return nil, nil
		}
	}

	mount, err := mounter.Mount(context.Background(), VolumeAttachment{
		VolumeID:   "vol-2",
		DeviceName: "/dev/xvdg",
	}, SourceVolume{})
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}

	if len(commands) != 3 {
		t.Fatalf("expected probe and two mount attempts, got %v", commands)
	}
	if got, want := commands[1], "mount -t ntfs3 -o ro /dev/xvdg "+mountPath; got != want {
		t.Fatalf("expected ntfs3 mount attempt %q, got %q", want, got)
	}
	if got, want := commands[2], "ntfs-3g -o ro /dev/xvdg "+mountPath; got != want {
		t.Fatalf("expected ntfs-3g fallback %q, got %q", want, got)
	}
	if mount.Metadata["mount_driver"] != "ntfs-3g" {
		t.Fatalf("expected ntfs-3g mount driver metadata, got %#v", mount.Metadata)
	}
}
