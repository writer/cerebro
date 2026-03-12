package imagescan

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/writer/cerebro/internal/scanner"
)

type BlobOpener func(ctx context.Context, digest string) (io.ReadCloser, error)

type Materializer interface {
	Materialize(ctx context.Context, runID string, manifest *scanner.ImageManifest, open BlobOpener) (*FilesystemArtifact, []LayerArtifact, error)
	Cleanup(ctx context.Context, artifact FilesystemArtifact) error
}

const (
	defaultMaterializedFileCount  = int64(100000)
	defaultMaterializedFileBytes  = int64(256 << 20)
	defaultMaterializedTotalBytes = int64(1 << 30)
)

type LocalMaterializer struct {
	basePath      string
	now           func() time.Time
	maxFileCount  int64
	maxFileBytes  int64
	maxTotalBytes int64
}

func NewLocalMaterializer(basePath string) *LocalMaterializer {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		basePath = filepath.Join(".cerebro", "image-scan", "rootfs")
	}
	return &LocalMaterializer{
		basePath:      basePath,
		now:           time.Now,
		maxFileCount:  defaultMaterializedFileCount,
		maxFileBytes:  defaultMaterializedFileBytes,
		maxTotalBytes: defaultMaterializedTotalBytes,
	}
}

func (m *LocalMaterializer) Materialize(ctx context.Context, runID string, manifest *scanner.ImageManifest, open BlobOpener) (*FilesystemArtifact, []LayerArtifact, error) {
	if m == nil {
		return nil, nil, fmt.Errorf("local materializer is nil")
	}
	if manifest == nil {
		return nil, nil, fmt.Errorf("image manifest is required")
	}
	if open == nil {
		return nil, nil, fmt.Errorf("blob opener is required")
	}
	rootfsPath, err := m.rootfsPath(runID)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(rootfsPath, 0o750); err != nil {
		return nil, nil, fmt.Errorf("create rootfs path %s: %w", rootfsPath, err)
	}

	layers := make([]LayerArtifact, 0, len(manifest.Layers))
	var (
		fileCount int64
		byteSize  int64
	)
	for _, layer := range manifest.Layers {
		if err := ctx.Err(); err != nil {
			return nil, layers, err
		}
		layerRecord, countDelta, byteDelta, err := m.applyLayer(ctx, rootfsPath, layer, open, fileCount, byteSize)
		if err != nil {
			return nil, layers, err
		}
		layers = append(layers, layerRecord)
		fileCount += countDelta
		byteSize += byteDelta
	}
	artifact := &FilesystemArtifact{
		Path:           rootfsPath,
		MaterializedAt: m.now().UTC(),
		FileCount:      fileCount,
		ByteSize:       byteSize,
		Metadata: map[string]any{
			"layer_count": len(manifest.Layers),
		},
	}
	return artifact, layers, nil
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
	return nil
}

func (m *LocalMaterializer) applyLayer(ctx context.Context, rootfsPath string, layer scanner.Layer, open BlobOpener, existingFileCount, existingByteSize int64) (LayerArtifact, int64, int64, error) {
	record := LayerArtifact{
		Digest:    strings.TrimSpace(layer.Digest),
		MediaType: strings.TrimSpace(layer.MediaType),
		Size:      layer.Size,
	}
	downloadedAt := m.now().UTC()
	record.DownloadedAt = &downloadedAt
	reader, err := open(ctx, layer.Digest)
	if err != nil {
		return record, 0, 0, fmt.Errorf("download layer %s: %w", layer.Digest, err)
	}
	defer func() { _ = reader.Close() }()

	tarReader, cleanup, err := layerTarReader(reader, layer.MediaType)
	if err != nil {
		return record, 0, 0, fmt.Errorf("open layer tar %s: %w", layer.Digest, err)
	}
	defer cleanup()

	var (
		fileCount int64
		byteSize  int64
	)
	for {
		if err := ctx.Err(); err != nil {
			return record, fileCount, byteSize, err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return record, fileCount, byteSize, fmt.Errorf("read layer %s: %w", layer.Digest, err)
		}
		countDelta, byteDelta, err := m.applyTarEntry(rootfsPath, header, tarReader, existingFileCount, fileCount, existingByteSize, byteSize)
		if err != nil {
			return record, fileCount, byteSize, fmt.Errorf("apply layer %s entry %s: %w", layer.Digest, header.Name, err)
		}
		fileCount += countDelta
		byteSize += byteDelta
	}
	appliedAt := m.now().UTC()
	record.AppliedAt = &appliedAt
	return record, fileCount, byteSize, nil
}

func layerTarReader(reader io.Reader, mediaType string) (*tar.Reader, func(), error) {
	buffered := bufio.NewReader(reader)
	if strings.Contains(strings.ToLower(mediaType), "gzip") {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, nil, err
		}
		return tar.NewReader(gz), func() { _ = gz.Close() }, nil
	}
	if strings.Contains(strings.ToLower(mediaType), "zstd") {
		decoder, err := zstd.NewReader(buffered)
		if err != nil {
			return nil, nil, err
		}
		return tar.NewReader(decoder), func() { decoder.Close() }, nil
	}
	magic, err := buffered.Peek(4)
	if err == nil && len(magic) >= 4 && magic[0] == 0x28 && magic[1] == 0xb5 && magic[2] == 0x2f && magic[3] == 0xfd {
		decoder, err := zstd.NewReader(buffered)
		if err != nil {
			return nil, nil, err
		}
		return tar.NewReader(decoder), func() { decoder.Close() }, nil
	}
	if err == nil && len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, nil, err
		}
		return tar.NewReader(gz), func() { _ = gz.Close() }, nil
	}
	return tar.NewReader(buffered), func() {}, nil
}

func (m *LocalMaterializer) applyTarEntry(rootfsPath string, header *tar.Header, reader io.Reader, existingFileCount, fileCount, existingByteSize, byteSize int64) (int64, int64, error) {
	relPath := sanitizeTarPath(header.Name)
	if relPath == "" {
		return 0, 0, nil
	}
	base := filepath.Base(relPath)
	dir := filepath.Dir(relPath)
	if strings.HasPrefix(base, ".wh.") {
		return 0, 0, applyWhiteout(rootfsPath, dir, base)
	}
	parentPath, err := safePathNoFollow(rootfsPath, dir, false)
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
	switch header.Typeflag {
	case tar.TypeDir:
		if err := removeReplaceableTarget(targetPath); err != nil {
			return 0, 0, err
		}
		mode, err := tarEntryMode(header.Mode)
		if err != nil {
			return 0, 0, err
		}
		return 0, 0, os.MkdirAll(targetPath, mode)
	case tar.TypeReg:
		if header.Size < 0 {
			return 0, 0, fmt.Errorf("tar entry size %d is invalid", header.Size)
		}
		if err := m.validateRegularFileLimits(header.Name, header.Size, existingFileCount, fileCount, existingByteSize, byteSize); err != nil {
			return 0, 0, err
		}
		if err := removeReplaceableTarget(targetPath); err != nil {
			return 0, 0, err
		}
		mode, err := tarEntryMode(header.Mode)
		if err != nil {
			return 0, 0, err
		}
		file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode) // #nosec G304 -- targetPath is constrained beneath the materialized rootfs and rejects symlink traversal.
		if err != nil {
			return 0, 0, err
		}
		defer func() { _ = file.Close() }()
		written, err := io.Copy(file, io.LimitReader(reader, header.Size+1))
		if err != nil {
			return 0, written, err
		}
		if written > header.Size {
			return 0, written, fmt.Errorf("tar entry %s exceeds declared size %d", header.Name, header.Size)
		}
		return 1, written, nil
	case tar.TypeSymlink:
		if err := removeReplaceableTarget(targetPath); err != nil {
			return 0, 0, err
		}
		return 0, 0, os.Symlink(header.Linkname, targetPath)
	case tar.TypeLink:
		linkTarget, err := safePathNoFollow(rootfsPath, sanitizeTarPath(header.Linkname), false)
		if err != nil {
			return 0, 0, err
		}
		if err := removeReplaceableTarget(targetPath); err != nil {
			return 0, 0, err
		}
		return 0, 0, os.Link(linkTarget, targetPath)
	default:
		return 0, 0, nil
	}
}

func (m *LocalMaterializer) validateRegularFileLimits(name string, size, existingFileCount, fileCount, existingByteSize, byteSize int64) error {
	if m == nil {
		return fmt.Errorf("local materializer is nil")
	}
	if m.maxFileCount > 0 && existingFileCount+fileCount+1 > m.maxFileCount {
		return fmt.Errorf("materialized file count exceeds max of %d", m.maxFileCount)
	}
	if m.maxFileBytes > 0 && size > m.maxFileBytes {
		return fmt.Errorf("tar entry %s exceeds max size of %d bytes", name, m.maxFileBytes)
	}
	if m.maxTotalBytes > 0 {
		exceeds, err := exceedsMaterializedSizeLimit(existingByteSize, byteSize, size, m.maxTotalBytes)
		if err != nil {
			return err
		}
		if exceeds {
			return fmt.Errorf("materialized filesystem exceeds max size of %d bytes", m.maxTotalBytes)
		}
	}
	return nil
}

func exceedsMaterializedSizeLimit(existingByteSize, byteSize, entryByteSize, maxTotalBytes int64) (bool, error) {
	existingU64, err := int64ToUint64(existingByteSize)
	if err != nil {
		return false, err
	}
	currentU64, err := int64ToUint64(byteSize)
	if err != nil {
		return false, err
	}
	entryU64, err := int64ToUint64(entryByteSize)
	if err != nil {
		return false, err
	}
	maxU64, err := int64ToUint64(maxTotalBytes)
	if err != nil {
		return false, err
	}
	if existingU64 > maxU64 || currentU64 > maxU64 {
		return true, nil
	}
	if currentU64 > maxU64-existingU64 {
		return true, nil
	}
	used := existingU64 + currentU64
	return entryU64 > maxU64-used, nil
}

func int64ToUint64(value int64) (uint64, error) {
	if value < 0 {
		return 0, fmt.Errorf("negative size %d is not supported", value)
	}
	return uint64(value), nil
}

func applyWhiteout(rootfsPath, dir, base string) error {
	dirPath, err := safePathNoFollow(rootfsPath, dir, false)
	if err != nil {
		return err
	}
	if base == ".wh..wh..opq" {
		entries, err := os.ReadDir(dirPath)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		for _, entry := range entries {
			if err := os.RemoveAll(filepath.Join(dirPath, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	targetName := strings.TrimPrefix(base, ".wh.")
	targetPath, err := safePathNoFollow(rootfsPath, filepath.Join(dir, targetName), true)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(targetPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (m *LocalMaterializer) rootfsPath(runID string) (string, error) {
	basePath, err := filepath.Abs(m.basePath)
	if err != nil {
		return "", fmt.Errorf("resolve rootfs base path %s: %w", m.basePath, err)
	}
	rootfsPath := filepath.Join(basePath, sanitizePathComponent(runID))
	return m.validateExistingPath(rootfsPath)
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

func sanitizeTarPath(raw string) string {
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
	relPath = sanitizeTarPath(relPath)
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

func removeReplaceableTarget(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return os.Remove(path)
	}
	return os.RemoveAll(path)
}

func tarEntryMode(raw int64) (os.FileMode, error) {
	if raw < 0 || raw > 0o7777 {
		return 0, fmt.Errorf("tar entry mode %d is out of range", raw)
	}
	return os.FileMode(raw), nil
}

func sanitizePathComponent(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "..", "-")
	return replacer.Replace(raw)
}
