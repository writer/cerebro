package functionscan

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	maxArtifactDownloadBytes   int64   = 512 << 20
	maxArchiveTotalBytes       int64   = 1 << 30
	maxArchiveEntryBytes       int64   = 256 << 20
	maxArchiveEntryCount       int64   = 100000
	maxArchiveCompressionRatio float64 = 1000
)

type ArchiveOpener func(ctx context.Context, artifact ArtifactRef) (io.ReadCloser, error)

type Materializer interface {
	Materialize(ctx context.Context, runID string, descriptor *FunctionDescriptor, open ArchiveOpener) (*FilesystemArtifact, []AppliedArtifact, error)
	Cleanup(ctx context.Context, artifact FilesystemArtifact) error
}

type LocalMaterializer struct {
	basePath string
	now      func() time.Time
}

func NewLocalMaterializer(basePath string) *LocalMaterializer {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		basePath = filepath.Join(".cerebro", "function-scan", "rootfs")
	}
	return &LocalMaterializer{basePath: basePath, now: time.Now}
}

func (m *LocalMaterializer) Materialize(ctx context.Context, runID string, descriptor *FunctionDescriptor, open ArchiveOpener) (artifact *FilesystemArtifact, applied []AppliedArtifact, err error) {
	if m == nil {
		return nil, nil, fmt.Errorf("local materializer is nil")
	}
	if descriptor == nil {
		return nil, nil, fmt.Errorf("function descriptor is required")
	}
	if open == nil {
		return nil, nil, fmt.Errorf("archive opener is required")
	}
	rootfsPath, err := m.rootfsPath(runID)
	if err != nil {
		return nil, nil, err
	}
	archiveDir, err := m.archiveDirPath(runID)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = os.RemoveAll(archiveDir) }()
	defer func() {
		if err != nil {
			_ = os.RemoveAll(rootfsPath)
		}
	}()
	if err := os.MkdirAll(rootfsPath, 0o750); err != nil {
		return nil, nil, fmt.Errorf("create rootfs path %s: %w", rootfsPath, err)
	}
	applied = make([]AppliedArtifact, 0, len(descriptor.Artifacts))
	var (
		fileCount int64
		byteSize  int64
	)
	for _, artifact := range descriptor.Artifacts {
		if err := ctx.Err(); err != nil {
			return nil, applied, err
		}
		record := AppliedArtifact{ID: strings.TrimSpace(artifact.ID), Kind: artifact.Kind, Format: artifact.Format}
		downloadedAt := m.now().UTC()
		record.DownloadedAt = &downloadedAt
		reader, err := open(ctx, artifact)
		if err != nil {
			return nil, applied, fmt.Errorf("open artifact %s: %w", artifact.ID, err)
		}
		archivePath, err := m.writeArchive(runID, artifact, reader)
		_ = reader.Close()
		if err != nil {
			return nil, applied, fmt.Errorf("persist artifact %s: %w", artifact.ID, err)
		}
		defer func(path string) { _ = os.Remove(path) }(archivePath)
		info, err := os.Stat(archivePath)
		if err == nil {
			record.Size = info.Size()
		}
		countDelta, byteDelta, err := applyArchive(rootfsPath, archivePath, artifact, fileCount, byteSize)
		if err != nil {
			return nil, applied, fmt.Errorf("apply artifact %s: %w", artifact.ID, err)
		}
		appliedAt := m.now().UTC()
		record.AppliedAt = &appliedAt
		applied = append(applied, record)
		fileCount += countDelta
		byteSize += byteDelta
	}
	artifact = &FilesystemArtifact{
		Path:           rootfsPath,
		MaterializedAt: m.now().UTC(),
		FileCount:      fileCount,
		ByteSize:       byteSize,
		Metadata: map[string]any{
			"artifact_count": len(descriptor.Artifacts),
			"layer_count":    len(descriptor.Layers),
			"archive_dir":    archiveDir,
		},
	}
	return artifact, applied, nil
}

func (m *LocalMaterializer) Cleanup(_ context.Context, artifact FilesystemArtifact) error {
	if m == nil {
		return fmt.Errorf("local materializer is nil")
	}
	rootfsPath := strings.TrimSpace(artifact.Path)
	if rootfsPath == "" {
		return nil
	}
	validated, err := m.validateExistingPath(rootfsPath)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(validated); err != nil {
		return fmt.Errorf("cleanup rootfs path %s: %w", validated, err)
	}
	if archiveDir, _ := artifact.Metadata["archive_dir"].(string); strings.TrimSpace(archiveDir) != "" {
		validatedArchiveDir, err := m.validateExistingPath(archiveDir)
		if err != nil {
			return err
		}
		if err := os.RemoveAll(validatedArchiveDir); err != nil {
			return fmt.Errorf("cleanup archive dir %s: %w", validatedArchiveDir, err)
		}
	}
	return nil
}

func (m *LocalMaterializer) writeArchive(runID string, artifact ArtifactRef, reader io.Reader) (string, error) {
	tempDir, err := m.archiveDirPath(runID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(tempDir, 0o750); err != nil {
		return "", fmt.Errorf("create archive temp dir: %w", err)
	}
	archivePath := filepath.Join(tempDir, sanitizePathComponent(artifact.ID)+".zip")
	file, err := os.OpenFile(archivePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- archivePath is constrained beneath the materializer base path.
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	written, err := io.Copy(file, io.LimitReader(reader, maxArtifactDownloadBytes+1))
	if err != nil {
		return "", err
	}
	if written > maxArtifactDownloadBytes {
		return "", fmt.Errorf("artifact %s exceeds max download size of %d bytes", artifact.ID, maxArtifactDownloadBytes)
	}
	return archivePath, nil
}

func applyArchive(rootfsPath, archivePath string, artifact ArtifactRef, existingFileCount, existingByteSize int64) (int64, int64, error) {
	if artifact.Format != "" && artifact.Format != ArchiveFormatZIP {
		return 0, 0, fmt.Errorf("unsupported archive format %s", artifact.Format)
	}
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = zr.Close() }()
	var (
		fileCount int64
		byteSize  int64
	)
	for _, entry := range zr.File {
		if !entry.FileInfo().IsDir() {
			if existingFileCount+fileCount+1 > maxArchiveEntryCount {
				return fileCount, byteSize, fmt.Errorf("zip entry count exceeds max of %d", maxArchiveEntryCount)
			}
			maxEntryBytesU64, err := int64ToUint64(maxArchiveEntryBytes)
			if err != nil {
				return fileCount, byteSize, err
			}
			if entry.UncompressedSize64 > maxEntryBytesU64 {
				return fileCount, byteSize, fmt.Errorf("zip entry %s exceeds max extracted size of %d bytes", entry.Name, maxArchiveEntryBytes)
			}
			if entry.CompressedSize64 > 0 && float64(entry.UncompressedSize64)/float64(entry.CompressedSize64) > maxArchiveCompressionRatio {
				return fileCount, byteSize, fmt.Errorf("zip entry %s exceeds max compression ratio of %.0f", entry.Name, maxArchiveCompressionRatio)
			}
			exceeds, err := exceedsArchiveSizeLimit(existingByteSize, byteSize, entry.UncompressedSize64)
			if err != nil {
				return fileCount, byteSize, err
			}
			if exceeds {
				return fileCount, byteSize, fmt.Errorf("extracted archive bytes exceed max of %d", maxArchiveTotalBytes)
			}
		}
		countDelta, byteDelta, err := applyZipEntry(rootfsPath, entry, maxArchiveEntryBytes)
		if err != nil {
			return fileCount, byteSize, err
		}
		fileCount += countDelta
		byteSize += byteDelta
	}
	return fileCount, byteSize, nil
}

func applyZipEntry(rootfsPath string, entry *zip.File, maxBytes int64) (int64, int64, error) {
	relPath := sanitizeArchivePath(entry.Name)
	if relPath == "" {
		return 0, 0, nil
	}
	parentPath, err := safePathNoFollow(rootfsPath, filepath.Dir(relPath), false)
	if err != nil {
		return 0, 0, err
	}
	if err := os.MkdirAll(parentPath, 0o750); err != nil {
		return 0, 0, err
	}
	targetPath, err := safePathNoFollow(rootfsPath, relPath, true)
	if err != nil {
		return 0, 0, err
	}
	mode := entry.Mode()
	if mode&os.ModeSymlink != 0 {
		return 0, 0, fmt.Errorf("zip entry %s contains unsupported symlink", entry.Name)
	}
	if entry.FileInfo().IsDir() {
		if err := removeReplaceableTarget(rootfsPath, relPath); err != nil {
			return 0, 0, err
		}
		if mode == 0 {
			mode = 0o750
		}
		return 0, 0, os.MkdirAll(targetPath, mode.Perm())
	}
	if err := removeReplaceableTarget(rootfsPath, relPath); err != nil {
		return 0, 0, err
	}
	if mode == 0 {
		mode = 0o640
	}
	rc, err := entry.Open()
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = rc.Close() }()
	file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm()) // #nosec G304 -- targetPath is constrained beneath the materialized rootfs and rejects symlink traversal.
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = file.Close() }()
	written, err := io.Copy(file, io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return 0, written, err
	}
	if written > maxBytes {
		return 0, written, fmt.Errorf("zip entry %s exceeds max extracted size of %d bytes", entry.Name, maxBytes)
	}
	return 1, written, nil
}

func (m *LocalMaterializer) rootfsPath(runID string) (string, error) {
	basePath, err := filepath.Abs(m.basePath)
	if err != nil {
		return "", fmt.Errorf("resolve rootfs base path %s: %w", m.basePath, err)
	}
	rootfsPath := filepath.Join(basePath, sanitizePathComponent(runID))
	return m.validateExistingPath(rootfsPath)
}

func (m *LocalMaterializer) archiveDirPath(runID string) (string, error) {
	basePath, err := filepath.Abs(m.basePath)
	if err != nil {
		return "", fmt.Errorf("resolve rootfs base path %s: %w", m.basePath, err)
	}
	archiveDir := filepath.Join(basePath, sanitizePathComponent(runID)+"-archives")
	return m.validateExistingPath(archiveDir)
}

func (m *LocalMaterializer) validateExistingPath(path string) (string, error) {
	basePath, err := filepath.Abs(m.basePath)
	if err != nil {
		return "", fmt.Errorf("resolve rootfs base path %s: %w", m.basePath, err)
	}
	resolvedPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve rootfs path %s: %w", path, err)
	}
	relative, err := filepath.Rel(basePath, resolvedPath)
	if err != nil {
		return "", fmt.Errorf("validate rootfs path %s: %w", resolvedPath, err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("rootfs path %s escapes base path %s", resolvedPath, basePath)
	}
	return resolvedPath, nil
}

func sanitizeArchivePath(raw string) string {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	raw = strings.TrimPrefix(raw, "/")
	raw = filepath.Clean(raw)
	if raw == "." || raw == "" {
		return ""
	}
	return raw
}

func safePathNoFollow(rootfsPath, relPath string, allowFinalSymlink bool) (string, error) {
	rootfsPath, err := filepath.Abs(rootfsPath)
	if err != nil {
		return "", err
	}
	relPath = sanitizeArchivePath(relPath)
	if relPath == "" {
		return rootfsPath, nil
	}
	parts := strings.Split(relPath, string(filepath.Separator))
	current := rootfsPath
	for idx, part := range parts {
		current = filepath.Join(current, part)
		relative, err := filepath.Rel(rootfsPath, current)
		if err != nil {
			return "", err
		}
		if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("path %s escapes rootfs %s", current, rootfsPath)
		}
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			isLast := idx == len(parts)-1
			if !isLast || !allowFinalSymlink {
				return "", fmt.Errorf("path %s traverses symlink component", current)
			}
		}
	}
	return current, nil
}

func removeReplaceableTarget(rootfsPath, relPath string) error {
	relPath = sanitizeArchivePath(relPath)
	if relPath == "" {
		return nil
	}
	root, err := os.OpenRoot(rootfsPath)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(relPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return root.Remove(relPath)
	}
	return root.RemoveAll(relPath)
}

func exceedsArchiveSizeLimit(existingByteSize, byteSize int64, entryByteSize uint64) (bool, error) {
	existingU64, err := int64ToUint64(existingByteSize)
	if err != nil {
		return false, err
	}
	currentU64, err := int64ToUint64(byteSize)
	if err != nil {
		return false, err
	}
	maxArchiveTotalBytesU64, err := int64ToUint64(maxArchiveTotalBytes)
	if err != nil {
		return false, err
	}
	if existingU64 > maxArchiveTotalBytesU64 || currentU64 > maxArchiveTotalBytesU64 {
		return true, nil
	}
	if currentU64 > maxArchiveTotalBytesU64-existingU64 {
		return true, nil
	}
	used := existingU64 + currentU64
	return entryByteSize > maxArchiveTotalBytesU64-used, nil
}

func int64ToUint64(value int64) (uint64, error) {
	if value < 0 {
		return 0, fmt.Errorf("negative size %d is not supported", value)
	}
	return uint64(value), nil
}

func sanitizePathComponent(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "..", "-")
	return replacer.Replace(raw)
}
