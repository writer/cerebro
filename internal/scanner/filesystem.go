package scanner

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

type FilesystemScanner interface {
	ScanFilesystem(ctx context.Context, rootfsPath string) (*ContainerScanResult, error)
}

// TrivyFilesystemScanner wraps `trivy fs` for filesystem-root scans.
type TrivyFilesystemScanner struct {
	binaryPath string
}

func NewTrivyFilesystemScanner(binaryPath string) *TrivyFilesystemScanner {
	if strings.TrimSpace(binaryPath) == "" {
		binaryPath = "trivy"
	}
	return &TrivyFilesystemScanner{binaryPath: binaryPath}
}

func (s *TrivyFilesystemScanner) ScanFilesystem(ctx context.Context, rootfsPath string) (*ContainerScanResult, error) {
	if strings.TrimSpace(s.binaryPath) == "" {
		return nil, fmt.Errorf("trivy binary path is required")
	}
	rootfsPath = strings.TrimSpace(rootfsPath)
	if rootfsPath == "" {
		return nil, fmt.Errorf("filesystem path is required")
	}
	if strings.ContainsAny(rootfsPath, "\r\n") {
		return nil, fmt.Errorf("filesystem path must not contain newlines")
	}
	absPath, err := filepath.Abs(rootfsPath)
	if err != nil {
		return nil, fmt.Errorf("resolve filesystem path %s: %w", rootfsPath, err)
	}

	cmd := exec.CommandContext(ctx, s.binaryPath, "fs", "--format", "json", absPath) // #nosec G204 -- fixed binary/arguments, no shell interpolation
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("trivy fs scan failed: %w: %s", err, string(output))
	}
	result, err := ParseTrivyOutput(output)
	if err != nil {
		return nil, err
	}
	result.Repository = absPath
	return result, nil
}
