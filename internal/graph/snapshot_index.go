package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	graphSnapshotManifestAPIVersion = "cerebro.graph_snapshot_manifest/v1"
	graphSnapshotIndexAPIVersion    = "cerebro.graph_snapshot_index/v1"
	graphSnapshotManifestKind       = "GraphSnapshotManifest"
	graphSnapshotRetentionLocal     = "local_retained"
	graphSnapshotStorageLocalStore  = "local_snapshot_store"
)

// GraphSnapshotManifest is the durable manifest associated with one stored graph snapshot artifact.
type GraphSnapshotManifest struct {
	APIVersion       string              `json:"api_version"`
	Kind             string              `json:"kind"`
	SnapshotID       string              `json:"snapshot_id"`
	ParentSnapshotID string              `json:"parent_snapshot_id,omitempty"`
	ArtifactPath     string              `json:"artifact_path"`
	IntegrityHash    string              `json:"integrity_hash,omitempty"`
	RetentionClass   string              `json:"retention_class,omitempty"`
	ExpiresAt        *time.Time          `json:"expires_at,omitempty"`
	Record           GraphSnapshotRecord `json:"record"`
}

type graphSnapshotIndex struct {
	APIVersion  string                  `json:"api_version"`
	GeneratedAt time.Time               `json:"generated_at"`
	Snapshots   []GraphSnapshotManifest `json:"snapshots"`
}

type graphSnapshotIndexedArtifact struct {
	info         SnapshotInfo
	snapshot     *Snapshot
	record       *GraphSnapshotRecord
	relativePath string
}

func (s *SnapshotStore) snapshotIndexPath() string {
	return filepath.Join(s.basePath, "index.json")
}

func (s *SnapshotStore) snapshotManifestDir() string {
	return filepath.Join(s.basePath, "manifests")
}

func (s *SnapshotStore) snapshotManifestPath(snapshotID string) string {
	return filepath.Join(s.snapshotManifestDir(), sanitizeReportFileName(snapshotID)+".json")
}

func (s *SnapshotStore) loadSnapshotIndex() (*graphSnapshotIndex, error) {
	file, err := os.Open(s.snapshotIndexPath()) // #nosec G304 -- snapshot index is owned by the local snapshot store.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var index graphSnapshotIndex
	if err := json.NewDecoder(file).Decode(&index); err != nil {
		return nil, fmt.Errorf("decode snapshot index: %w", err)
	}
	if version := strings.TrimSpace(index.APIVersion); version != "" && version != graphSnapshotIndexAPIVersion {
		return nil, fmt.Errorf("unsupported snapshot index version %q", version)
	}
	return &index, nil
}

func (s *SnapshotStore) loadOrRebuildSnapshotIndex() (*graphSnapshotIndex, error) {
	infos, err := s.List()
	if err != nil {
		return nil, err
	}
	index, err := s.loadSnapshotIndex()
	switch {
	case err == nil && !snapshotIndexNeedsRefresh(index, infos):
		return index, nil
	case err == nil:
		return s.rebuildSnapshotIndex(infos)
	case os.IsNotExist(err):
		return s.rebuildSnapshotIndex(infos)
	default:
		return s.rebuildSnapshotIndex(infos)
	}
}

func snapshotIndexNeedsRefresh(index *graphSnapshotIndex, infos []SnapshotInfo) bool {
	if index == nil {
		return true
	}
	if strings.TrimSpace(index.APIVersion) != "" && strings.TrimSpace(index.APIVersion) != graphSnapshotIndexAPIVersion {
		return true
	}
	if len(index.Snapshots) != len(infos) {
		return true
	}
	seen := make(map[string]struct{}, len(index.Snapshots))
	for _, manifest := range index.Snapshots {
		artifactPath := strings.TrimSpace(manifest.ArtifactPath)
		if artifactPath == "" {
			return true
		}
		seen[artifactPath] = struct{}{}
	}
	for _, info := range infos {
		if _, ok := seen[filepath.Base(info.Path)]; !ok {
			return true
		}
	}
	return false
}

func (s *SnapshotStore) rebuildSnapshotIndex(infos []SnapshotInfo) (*graphSnapshotIndex, error) {
	if infos == nil {
		var err error
		infos, err = s.List()
		if err != nil {
			return nil, err
		}
	}
	artifacts := make([]graphSnapshotIndexedArtifact, 0, len(infos))
	for _, info := range infos {
		snapshot, err := LoadSnapshotFromFile(info.Path)
		if err != nil {
			continue
		}
		record := buildGraphSnapshotRecordFromSnapshot(snapshot, info)
		if record == nil {
			continue
		}
		hash, err := sha256File(info.Path)
		if err == nil {
			record.IntegrityHash = hash
		}
		if strings.TrimSpace(record.RetentionClass) == "" {
			record.RetentionClass = graphSnapshotRetentionLocal
		}
		artifacts = append(artifacts, graphSnapshotIndexedArtifact{
			info:         info,
			snapshot:     snapshot,
			record:       record,
			relativePath: filepath.Base(info.Path),
		})
	}
	sort.Slice(artifacts, func(i, j int) bool {
		left := graphSnapshotSortTime(*artifacts[i].record)
		right := graphSnapshotSortTime(*artifacts[j].record)
		if !left.Equal(right) {
			return left.Before(right)
		}
		return artifacts[i].record.ID < artifacts[j].record.ID
	})

	manifests := make([]GraphSnapshotManifest, 0, len(artifacts))
	parentSnapshotID := ""
	for i := range artifacts {
		record := *artifacts[i].record
		record.ParentSnapshotID = strings.TrimSpace(parentSnapshotID)
		if strings.TrimSpace(record.RetentionClass) == "" {
			record.RetentionClass = graphSnapshotRetentionLocal
		}
		manifests = append(manifests, GraphSnapshotManifest{
			APIVersion:       graphSnapshotManifestAPIVersion,
			Kind:             graphSnapshotManifestKind,
			SnapshotID:       record.ID,
			ParentSnapshotID: record.ParentSnapshotID,
			ArtifactPath:     artifacts[i].relativePath,
			IntegrityHash:    record.IntegrityHash,
			RetentionClass:   record.RetentionClass,
			ExpiresAt:        cloneTimePtr(record.ExpiresAt),
			Record:           record,
		})
		parentSnapshotID = record.ID
	}

	if err := os.RemoveAll(s.snapshotManifestDir()); err != nil {
		return nil, fmt.Errorf("reset snapshot manifests: %w", err)
	}
	if len(manifests) > 0 {
		if err := os.MkdirAll(s.snapshotManifestDir(), 0o750); err != nil {
			return nil, fmt.Errorf("create snapshot manifest dir: %w", err)
		}
	}
	for i := range manifests {
		if err := writeJSONAtomic(s.snapshotManifestPath(manifests[i].SnapshotID), manifests[i]); err != nil {
			return nil, fmt.Errorf("write snapshot manifest: %w", err)
		}
	}
	index := &graphSnapshotIndex{
		APIVersion:  graphSnapshotIndexAPIVersion,
		GeneratedAt: time.Now().UTC(),
		Snapshots:   manifests,
	}
	if err := writeJSONAtomic(s.snapshotIndexPath(), index); err != nil {
		return nil, fmt.Errorf("write snapshot index: %w", err)
	}
	return index, nil
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path) // #nosec G304 -- snapshot artifact path comes from the local snapshot store.
	if err != nil {
		return "", fmt.Errorf("open snapshot artifact: %w", err)
	}
	defer func() { _ = file.Close() }()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash snapshot artifact: %w", err)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
