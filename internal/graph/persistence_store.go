package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gcs "cloud.google.com/go/storage"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"google.golang.org/api/iterator"
)

const (
	graphRecoverySourceLocal   = "local"
	graphRecoverySourceReplica = "replica"
)

type GraphPersistenceOptions struct {
	LocalPath    string
	MaxSnapshots int
	ReplicaURI   string
}

type GraphPersistenceStatus struct {
	Configured             bool       `json:"configured"`
	LocalPath              string     `json:"local_path,omitempty"`
	ReplicaConfigured      bool       `json:"replica_configured,omitempty"`
	ReplicaURI             string     `json:"replica_uri,omitempty"`
	LastPersistedSnapshot  string     `json:"last_persisted_snapshot_id,omitempty"`
	LastPersistedAt        *time.Time `json:"last_persisted_at,omitempty"`
	LastReplicatedSnapshot string     `json:"last_replicated_snapshot_id,omitempty"`
	LastReplicatedAt       *time.Time `json:"last_replicated_at,omitempty"`
	LastReplicationError   string     `json:"last_replication_error,omitempty"`
	LastRecoverySource     string     `json:"last_recovery_source,omitempty"`
	LastRecoveredSnapshot  string     `json:"last_recovered_snapshot_id,omitempty"`
	LastRecoveredAt        *time.Time `json:"last_recovered_at,omitempty"`
	LastRecoveryError      string     `json:"last_recovery_error,omitempty"`
}

type GraphPersistenceStore struct {
	local   *SnapshotStore
	replica graphSnapshotReplica

	statusMu sync.RWMutex
	status   GraphPersistenceStatus
}

type graphSnapshotReplica interface {
	URI() string
	PutFile(ctx context.Context, key, localPath, contentType string) error
	PutBytes(ctx context.Context, key string, payload []byte, contentType string) error
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	ListKeys(ctx context.Context, prefix string) ([]string, error)
	DeleteKeys(ctx context.Context, keys ...string) error
}

func NewGraphPersistenceStore(opts GraphPersistenceOptions) (*GraphPersistenceStore, error) {
	localPath := strings.TrimSpace(opts.LocalPath)
	if localPath == "" {
		return nil, fmt.Errorf("graph persistence local path required")
	}
	local := NewSnapshotStore(localPath, opts.MaxSnapshots)
	store := &GraphPersistenceStore{
		local: local,
		status: GraphPersistenceStatus{
			Configured: true,
			LocalPath:  local.BasePath(),
		},
	}
	replicaURI := strings.TrimSpace(opts.ReplicaURI)
	if replicaURI == "" {
		return store, nil
	}
	replica, err := newGraphSnapshotReplica(replicaURI)
	if err != nil {
		return nil, err
	}
	store.replica = replica
	store.status.ReplicaConfigured = true
	store.status.ReplicaURI = replica.URI()
	return store, nil
}

func (s *GraphPersistenceStore) LocalStore() *SnapshotStore {
	if s == nil {
		return nil
	}
	return s.local
}

func (s *GraphPersistenceStore) Status() GraphPersistenceStatus {
	if s == nil {
		return GraphPersistenceStatus{}
	}
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	status := s.status
	status.LastPersistedAt = cloneTimePtr(status.LastPersistedAt)
	status.LastReplicatedAt = cloneTimePtr(status.LastReplicatedAt)
	status.LastRecoveredAt = cloneTimePtr(status.LastRecoveredAt)
	return status
}

func (s *GraphPersistenceStore) Save(g *Graph) error {
	_, err := s.SaveGraph(g)
	return err
}

func (s *GraphPersistenceStore) SaveGraph(g *Graph) (*GraphSnapshotRecord, error) {
	if s == nil || s.local == nil {
		return nil, fmt.Errorf("graph persistence store not configured")
	}
	record, _, err := s.local.SaveGraph(g)
	if err != nil {
		return nil, err
	}
	s.recordPersisted(record)
	if s.replica == nil {
		return record, nil
	}
	if err := s.syncReplica(context.Background()); err != nil {
		s.recordReplicationError(err)
		return record, err
	}
	s.recordReplicated(record)
	return record, nil
}

func (s *GraphPersistenceStore) LoadLatest() (*Graph, error) {
	snapshot, _, _, err := s.LoadLatestSnapshot()
	if err != nil {
		return nil, err
	}
	return RestoreFromSnapshot(snapshot), nil
}

func (s *GraphPersistenceStore) PeekLatestSnapshot() (*Snapshot, *GraphSnapshotRecord, string, error) {
	if s == nil {
		return nil, nil, "", fmt.Errorf("graph persistence store not configured")
	}
	if s.local != nil {
		snapshot, record, err := s.local.LoadLatestSnapshot()
		if err == nil {
			return snapshot, record, graphRecoverySourceLocal, nil
		}
		if s.replica == nil {
			return nil, nil, "", err
		}
	}
	if s.replica == nil {
		return nil, nil, "", fmt.Errorf("graph persistence replica not configured")
	}
	snapshot, record, err := s.loadLatestSnapshotFromReplica(context.Background())
	if err != nil {
		return nil, nil, "", err
	}
	return snapshot, record, graphRecoverySourceReplica, nil
}

func (s *GraphPersistenceStore) LoadLatestSnapshot() (*Snapshot, *GraphSnapshotRecord, string, error) {
	if s == nil {
		return nil, nil, "", fmt.Errorf("graph persistence store not configured")
	}
	if s.local != nil {
		snapshot, record, err := s.local.LoadLatestSnapshot()
		if err == nil {
			s.recordRecovered(record, graphRecoverySourceLocal, nil)
			return snapshot, record, graphRecoverySourceLocal, nil
		}
		if s.replica == nil {
			s.recordRecovered(nil, graphRecoverySourceLocal, err)
			return nil, nil, "", err
		}
	}
	if s.replica == nil {
		return nil, nil, "", fmt.Errorf("graph persistence replica not configured")
	}
	snapshot, record, err := s.loadLatestSnapshotFromReplica(context.Background())
	if err != nil {
		s.recordRecovered(nil, graphRecoverySourceReplica, err)
		return nil, nil, "", err
	}
	s.recordRecovered(record, graphRecoverySourceReplica, nil)
	return snapshot, record, graphRecoverySourceReplica, nil
}

func (s *GraphPersistenceStore) ListGraphSnapshotRecords() ([]GraphSnapshotRecord, error) {
	if s == nil {
		return nil, fmt.Errorf("graph persistence store not configured")
	}
	if s.local != nil {
		records, err := s.local.ListGraphSnapshotRecords()
		if err == nil && len(records) > 0 {
			return records, nil
		}
		if err == nil && s.replica == nil {
			return records, nil
		}
	}
	if s.replica == nil {
		return nil, fmt.Errorf("graph persistence replica not configured")
	}
	index, err := s.loadReplicaIndex(context.Background())
	if err != nil {
		return nil, err
	}
	records := make([]GraphSnapshotRecord, 0, len(index.Snapshots))
	for _, manifest := range index.Snapshots {
		records = append(records, manifest.Record)
	}
	return records, nil
}

func (s *GraphPersistenceStore) LoadSnapshotsByRecordIDs(snapshotIDs ...string) (map[string]*Snapshot, map[string]*GraphSnapshotRecord, error) {
	if s == nil {
		return nil, nil, fmt.Errorf("graph persistence store not configured")
	}
	if s.local != nil {
		snapshots, records, err := s.local.LoadSnapshotsByRecordIDs(snapshotIDs...)
		if err == nil {
			return snapshots, records, nil
		}
		if s.replica == nil {
			return nil, nil, err
		}
	}
	if s.replica == nil {
		return nil, nil, fmt.Errorf("graph persistence replica not configured")
	}
	return s.loadSnapshotsByRecordIDsFromReplica(context.Background(), snapshotIDs...)
}

func (s *GraphPersistenceStore) DiffByTime(t1, t2 time.Time) (*GraphDiff, error) {
	if s == nil {
		return nil, fmt.Errorf("graph persistence store not configured")
	}
	if s.local != nil {
		diff, err := s.local.DiffByTime(t1, t2)
		if err == nil {
			return diff, nil
		}
		if s.replica == nil {
			return nil, err
		}
	}
	if s.replica == nil {
		return nil, fmt.Errorf("graph persistence replica not configured")
	}
	before, err := s.loadClosestSnapshotAtReplica(context.Background(), t1)
	if err != nil {
		return nil, err
	}
	after, err := s.loadClosestSnapshotAtReplica(context.Background(), t2)
	if err != nil {
		return nil, err
	}
	return DiffSnapshots(before, after), nil
}

func (s *GraphPersistenceStore) syncReplica(ctx context.Context) error {
	index, err := s.local.loadOrRebuildSnapshotIndex()
	if err != nil {
		return err
	}
	previousIndex, err := s.loadReplicaIndexIfPresent(ctx)
	if err != nil {
		return err
	}
	keep := map[string]struct{}{
		"index.json": {},
	}
	localBase := s.local.BasePath()
	for _, manifest := range index.Snapshots {
		artifactKey, err := normalizeReplicaKey(manifest.ArtifactPath)
		if err != nil {
			return fmt.Errorf("invalid snapshot artifact path for %s: %w", manifest.SnapshotID, err)
		}
		localArtifactPath, err := resolveReplicaLocalPath(localBase, artifactKey)
		if err != nil {
			return fmt.Errorf("resolve local snapshot artifact %s: %w", manifest.SnapshotID, err)
		}
		manifest.ArtifactPath = artifactKey
		manifestKey := path.Join("manifests", sanitizeReportFileName(manifest.SnapshotID)+".json")
		keep[manifestKey] = struct{}{}
		keep[artifactKey] = struct{}{}

		if err := s.replica.PutFile(ctx, artifactKey, localArtifactPath, "application/gzip"); err != nil {
			return fmt.Errorf("replicate snapshot artifact %s: %w", manifest.SnapshotID, err)
		}
		payload, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal snapshot manifest %s: %w", manifest.SnapshotID, err)
		}
		if err := s.replica.PutBytes(ctx, manifestKey, append(payload, '\n'), "application/json"); err != nil {
			return fmt.Errorf("replicate snapshot manifest %s: %w", manifest.SnapshotID, err)
		}
	}
	indexPayload, err := os.ReadFile(filepath.Join(localBase, "index.json")) // #nosec G304 -- local graph snapshot index path is store-owned.
	if err != nil {
		return fmt.Errorf("read local snapshot index: %w", err)
	}
	if err := s.replica.PutBytes(ctx, "index.json", indexPayload, "application/json"); err != nil {
		return fmt.Errorf("replicate snapshot index: %w", err)
	}
	stale := make([]string, 0)
	if previousIndex != nil {
		for _, key := range replicaTrackedKeysFromIndex(*previousIndex) {
			if _, ok := keep[key]; !ok {
				stale = append(stale, key)
			}
		}
	}
	if len(stale) > 0 {
		if err := s.replica.DeleteKeys(ctx, stale...); err != nil {
			return fmt.Errorf("delete stale replica artifacts: %w", err)
		}
	}
	return nil
}

func (s *GraphPersistenceStore) loadLatestSnapshotFromReplica(ctx context.Context) (*Snapshot, *GraphSnapshotRecord, error) {
	index, err := s.loadReplicaIndex(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(index.Snapshots) == 0 {
		return nil, nil, fmt.Errorf("no replica snapshots found")
	}
	manifest := index.Snapshots[len(index.Snapshots)-1]
	return s.loadSnapshotFromReplicaManifest(ctx, manifest)
}

func (s *GraphPersistenceStore) loadSnapshotsByRecordIDsFromReplica(ctx context.Context, snapshotIDs ...string) (map[string]*Snapshot, map[string]*GraphSnapshotRecord, error) {
	requested := make(map[string]struct{}, len(snapshotIDs))
	for _, snapshotID := range snapshotIDs {
		snapshotID = strings.TrimSpace(snapshotID)
		if snapshotID != "" {
			requested[snapshotID] = struct{}{}
		}
	}
	if len(requested) == 0 {
		return nil, nil, fmt.Errorf("at least one snapshot id required")
	}
	index, err := s.loadReplicaIndex(ctx)
	if err != nil {
		return nil, nil, err
	}
	snapshots := make(map[string]*Snapshot, len(requested))
	records := make(map[string]*GraphSnapshotRecord, len(requested))
	for _, manifest := range index.Snapshots {
		if len(snapshots) == len(requested) {
			break
		}
		id := strings.TrimSpace(manifest.Record.ID)
		if _, ok := requested[id]; !ok {
			continue
		}
		snapshot, record, err := s.loadSnapshotFromReplicaManifest(ctx, manifest)
		if err != nil {
			return nil, nil, err
		}
		snapshots[id] = snapshot
		records[id] = record
	}
	for snapshotID := range requested {
		if _, ok := snapshots[snapshotID]; !ok {
			return nil, nil, fmt.Errorf("snapshot %q not found", snapshotID)
		}
	}
	return snapshots, records, nil
}

func (s *GraphPersistenceStore) loadClosestSnapshotAtReplica(ctx context.Context, ts time.Time) (*Snapshot, error) {
	if ts.IsZero() {
		return nil, fmt.Errorf("timestamp required")
	}
	index, err := s.loadReplicaIndex(ctx)
	if err != nil {
		return nil, err
	}
	if len(index.Snapshots) == 0 {
		return nil, fmt.Errorf("no replica snapshots found")
	}
	var (
		closestBefore *GraphSnapshotManifest
		closestAfter  *GraphSnapshotManifest
	)
	for i := range index.Snapshots {
		manifest := index.Snapshots[i]
		recordTime := graphSnapshotManifestSortTime(manifest)
		if recordTime.IsZero() {
			continue
		}
		switch {
		case !recordTime.After(ts):
			if closestBefore == nil || recordTime.After(graphSnapshotManifestSortTime(*closestBefore)) {
				manifestCopy := manifest
				closestBefore = &manifestCopy
			}
		default:
			if closestAfter == nil || recordTime.Before(graphSnapshotManifestSortTime(*closestAfter)) {
				manifestCopy := manifest
				closestAfter = &manifestCopy
			}
		}
	}
	if closestBefore != nil {
		snapshot, _, err := s.loadSnapshotFromReplicaManifest(ctx, *closestBefore)
		return snapshot, err
	}
	if closestAfter != nil {
		snapshot, _, err := s.loadSnapshotFromReplicaManifest(ctx, *closestAfter)
		return snapshot, err
	}
	return nil, fmt.Errorf("no readable replica snapshots found")
}

func (s *GraphPersistenceStore) loadSnapshotFromReplicaManifest(ctx context.Context, manifest GraphSnapshotManifest) (*Snapshot, *GraphSnapshotRecord, error) {
	artifactKey, err := normalizeReplicaKey(manifest.ArtifactPath)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid replica snapshot artifact path for %s: %w", manifest.SnapshotID, err)
	}
	reader, err := s.replica.Open(ctx, artifactKey)
	if err != nil {
		return nil, nil, fmt.Errorf("open replica snapshot artifact %s: %w", manifest.SnapshotID, err)
	}
	defer func() { _ = reader.Close() }()
	snapshot, err := loadSnapshotFromCompressedReader(reader)
	if err != nil {
		return nil, nil, err
	}
	record := manifest.Record
	return snapshot, &record, nil
}

func (s *GraphPersistenceStore) loadReplicaIndex(ctx context.Context) (*graphSnapshotIndex, error) {
	reader, err := s.replica.Open(ctx, "index.json")
	if err != nil {
		return nil, fmt.Errorf("open replica snapshot index: %w", err)
	}
	defer func() { _ = reader.Close() }()
	var index graphSnapshotIndex
	if err := json.NewDecoder(reader).Decode(&index); err != nil {
		return nil, fmt.Errorf("decode replica snapshot index: %w", err)
	}
	if version := strings.TrimSpace(index.APIVersion); version != "" && version != graphSnapshotIndexAPIVersion {
		return nil, fmt.Errorf("unsupported replica snapshot index version %q", version)
	}
	for i := range index.Snapshots {
		artifactKey, err := normalizeReplicaKey(index.Snapshots[i].ArtifactPath)
		if err != nil {
			return nil, fmt.Errorf("invalid replica snapshot artifact path for %s: %w", index.Snapshots[i].SnapshotID, err)
		}
		index.Snapshots[i].ArtifactPath = artifactKey
	}
	return &index, nil
}

func (s *GraphPersistenceStore) loadReplicaIndexIfPresent(ctx context.Context) (*graphSnapshotIndex, error) {
	keys, err := s.replica.ListKeys(ctx, "index.json")
	if err != nil {
		return nil, fmt.Errorf("list replica snapshot index: %w", err)
	}
	for _, key := range keys {
		normalized, err := normalizeReplicaKey(key)
		if err != nil {
			continue
		}
		if normalized == "index.json" {
			return s.loadReplicaIndex(ctx)
		}
	}
	return nil, nil
}

func replicaTrackedKeysFromIndex(index graphSnapshotIndex) []string {
	tracked := map[string]struct{}{
		"index.json": {},
	}
	for _, manifest := range index.Snapshots {
		artifactKey, err := normalizeReplicaKey(manifest.ArtifactPath)
		if err != nil {
			continue
		}
		tracked[artifactKey] = struct{}{}
		tracked[path.Join("manifests", sanitizeReportFileName(manifest.SnapshotID)+".json")] = struct{}{}
	}
	keys := make([]string, 0, len(tracked))
	for key := range tracked {
		keys = append(keys, key)
	}
	return keys
}

func (s *GraphPersistenceStore) recordPersisted(record *GraphSnapshotRecord) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.Configured = true
	if record != nil {
		now := time.Now().UTC()
		s.status.LastPersistedSnapshot = strings.TrimSpace(record.ID)
		s.status.LastPersistedAt = &now
	}
}

func (s *GraphPersistenceStore) recordReplicated(record *GraphSnapshotRecord) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	now := time.Now().UTC()
	s.status.LastReplicationError = ""
	if record != nil {
		s.status.LastReplicatedSnapshot = strings.TrimSpace(record.ID)
	}
	s.status.LastReplicatedAt = &now
}

func (s *GraphPersistenceStore) recordReplicationError(err error) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if err == nil {
		s.status.LastReplicationError = ""
		return
	}
	s.status.LastReplicationError = strings.TrimSpace(err.Error())
}

func (s *GraphPersistenceStore) recordRecovered(record *GraphSnapshotRecord, source string, err error) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.LastRecoverySource = strings.TrimSpace(source)
	if err != nil {
		s.status.LastRecoveryError = strings.TrimSpace(err.Error())
		return
	}
	now := time.Now().UTC()
	s.status.LastRecoveryError = ""
	s.status.LastRecoveredAt = &now
	if record != nil {
		s.status.LastRecoveredSnapshot = strings.TrimSpace(record.ID)
	}
}

func newGraphSnapshotReplica(raw string) (graphSnapshotReplica, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		return nil, fmt.Errorf("replica uri required")
	case strings.HasPrefix(raw, "s3://"):
		return newS3GraphSnapshotReplica(raw)
	case strings.HasPrefix(raw, "gs://"):
		return newGCSGraphSnapshotReplica(raw)
	case strings.HasPrefix(raw, "file://"):
		return newFileGraphSnapshotReplica(strings.TrimPrefix(raw, "file://")), nil
	default:
		return newFileGraphSnapshotReplica(raw), nil
	}
}

type fileGraphSnapshotReplica struct {
	basePath string
}

func newFileGraphSnapshotReplica(basePath string) *fileGraphSnapshotReplica {
	return &fileGraphSnapshotReplica{basePath: filepath.Clean(strings.TrimSpace(basePath))}
}

func (r *fileGraphSnapshotReplica) URI() string { return "file://" + r.basePath }

func (r *fileGraphSnapshotReplica) PutFile(_ context.Context, key, localPath, _ string) error {
	keyPath, err := r.keyPath(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o750); err != nil {
		return err
	}
	src, err := os.Open(localPath) // #nosec G304 -- local snapshot artifact path is store-owned.
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	tmp := keyPath + ".tmp"
	dst, err := os.Create(tmp) // #nosec G304 -- replica temp file path is resolved under the configured replica root.
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, keyPath)
}

func (r *fileGraphSnapshotReplica) PutBytes(_ context.Context, key string, payload []byte, _ string) error {
	keyPath, err := r.keyPath(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o750); err != nil { // #nosec G301,G304,G703 -- replica path is validated and contained under the configured replica root.
		return err
	}
	tmp := keyPath + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil { // #nosec G304,G703 -- validated replica temp path stays within the configured replica root.
		return err
	}
	return os.Rename(tmp, keyPath) // #nosec G304,G703 -- validated replica destination path stays within the configured replica root.
}

func (r *fileGraphSnapshotReplica) Open(_ context.Context, key string) (io.ReadCloser, error) {
	keyPath, err := r.keyPath(key)
	if err != nil {
		return nil, err
	}
	return os.Open(keyPath) // #nosec G304 -- replica key is resolved under the configured replica root.
}

func (r *fileGraphSnapshotReplica) ListKeys(_ context.Context, prefix string) ([]string, error) {
	keys := make([]string, 0)
	err := filepath.WalkDir(r.basePath, func(current string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(r.basePath, current)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if prefix == "" || strings.HasPrefix(rel, prefix) {
			keys = append(keys, rel)
		}
		return nil
	})
	if os.IsNotExist(err) {
		return nil, nil
	}
	return keys, err
}

func (r *fileGraphSnapshotReplica) DeleteKeys(_ context.Context, keys ...string) error {
	for _, key := range keys {
		keyPath, err := r.keyPath(key)
		if err != nil {
			return err
		}
		if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (r *fileGraphSnapshotReplica) keyPath(key string) (string, error) {
	return resolveReplicaLocalPath(r.basePath, key)
}

type s3GraphSnapshotReplica struct {
	uri    string
	bucket string
	prefix string
	client *s3.Client
}

func newS3GraphSnapshotReplica(raw string) (*s3GraphSnapshotReplica, error) {
	bucket, prefix, err := parseBucketURI(raw, "s3://")
	if err != nil {
		return nil, err
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("load aws config for graph snapshot replica: %w", err)
	}
	return &s3GraphSnapshotReplica{
		uri:    raw,
		bucket: bucket,
		prefix: prefix,
		client: s3.NewFromConfig(cfg),
	}, nil
}

func (r *s3GraphSnapshotReplica) URI() string { return r.uri }

func (r *s3GraphSnapshotReplica) PutFile(ctx context.Context, key, localPath, contentType string) error {
	objectKey, err := r.objectKey(key)
	if err != nil {
		return err
	}
	file, err := os.Open(localPath) // #nosec G304 -- local snapshot artifact path is store-owned.
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	_, err = r.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &r.bucket,
		Key:         strPtr(objectKey),
		Body:        file,
		ContentType: strPtr(contentType),
	})
	return err
}

func (r *s3GraphSnapshotReplica) PutBytes(ctx context.Context, key string, payload []byte, contentType string) error {
	objectKey, err := r.objectKey(key)
	if err != nil {
		return err
	}
	_, err = r.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &r.bucket,
		Key:         strPtr(objectKey),
		Body:        bytes.NewReader(payload),
		ContentType: strPtr(contentType),
	})
	return err
}

func (r *s3GraphSnapshotReplica) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	objectKey, err := r.objectKey(key)
	if err != nil {
		return nil, err
	}
	out, err := r.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &r.bucket,
		Key:    strPtr(objectKey),
	})
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}

func (r *s3GraphSnapshotReplica) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	objectPrefix, err := r.objectKey(prefix)
	if err != nil {
		return nil, err
	}
	input := &s3.ListObjectsV2Input{
		Bucket: &r.bucket,
		Prefix: strPtr(objectPrefix),
	}
	paginator := s3.NewListObjectsV2Paginator(r.client, input)
	keys := make([]string, 0)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, object := range page.Contents {
			if object.Key == nil {
				continue
			}
			keys = append(keys, strings.TrimPrefix(strings.TrimPrefix(*object.Key, r.prefix), "/"))
		}
	}
	return keys, nil
}

func (r *s3GraphSnapshotReplica) DeleteKeys(ctx context.Context, keys ...string) error {
	for _, key := range keys {
		objectKey, err := r.objectKey(key)
		if err != nil {
			return err
		}
		_, err = r.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &r.bucket,
			Key:    strPtr(objectKey),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *s3GraphSnapshotReplica) objectKey(key string) (string, error) {
	if strings.TrimSpace(key) == "" {
		return r.prefix, nil
	}
	key, err := normalizeReplicaKey(key)
	if err != nil {
		return "", err
	}
	if r.prefix == "" {
		return key, nil
	}
	return path.Join(r.prefix, key), nil
}

type gcsGraphSnapshotReplica struct {
	uri    string
	bucket string
	prefix string
	client *gcs.Client
}

func newGCSGraphSnapshotReplica(raw string) (*gcsGraphSnapshotReplica, error) {
	bucket, prefix, err := parseBucketURI(raw, "gs://")
	if err != nil {
		return nil, err
	}
	client, err := gcs.NewClient(context.Background())
	if err != nil {
		return nil, fmt.Errorf("load gcs client for graph snapshot replica: %w", err)
	}
	return &gcsGraphSnapshotReplica{
		uri:    raw,
		bucket: bucket,
		prefix: prefix,
		client: client,
	}, nil
}

func (r *gcsGraphSnapshotReplica) URI() string { return r.uri }

func (r *gcsGraphSnapshotReplica) PutFile(ctx context.Context, key, localPath, contentType string) error {
	objectKey, err := r.objectKey(key)
	if err != nil {
		return err
	}
	file, err := os.Open(localPath) // #nosec G304 -- local snapshot artifact path is store-owned.
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	writer := r.client.Bucket(r.bucket).Object(objectKey).NewWriter(ctx)
	writer.ContentType = contentType
	if _, err := io.Copy(writer, file); err != nil {
		_ = writer.Close()
		return err
	}
	return writer.Close()
}

func (r *gcsGraphSnapshotReplica) PutBytes(ctx context.Context, key string, payload []byte, contentType string) error {
	objectKey, err := r.objectKey(key)
	if err != nil {
		return err
	}
	writer := r.client.Bucket(r.bucket).Object(objectKey).NewWriter(ctx)
	writer.ContentType = contentType
	if _, err := writer.Write(payload); err != nil {
		_ = writer.Close()
		return err
	}
	return writer.Close()
}

func (r *gcsGraphSnapshotReplica) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	objectKey, err := r.objectKey(key)
	if err != nil {
		return nil, err
	}
	return r.client.Bucket(r.bucket).Object(objectKey).NewReader(ctx)
}

func (r *gcsGraphSnapshotReplica) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	objectPrefix, err := r.objectKey(prefix)
	if err != nil {
		return nil, err
	}
	query := &gcs.Query{Prefix: objectPrefix}
	it := r.client.Bucket(r.bucket).Objects(ctx, query)
	keys := make([]string, 0)
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return keys, nil
		}
		if err != nil {
			return nil, err
		}
		keys = append(keys, strings.TrimPrefix(strings.TrimPrefix(attrs.Name, r.prefix), "/"))
	}
}

func (r *gcsGraphSnapshotReplica) DeleteKeys(ctx context.Context, keys ...string) error {
	for _, key := range keys {
		objectKey, err := r.objectKey(key)
		if err != nil {
			return err
		}
		if err := r.client.Bucket(r.bucket).Object(objectKey).Delete(ctx); err != nil && !errors.Is(err, gcs.ErrObjectNotExist) {
			return err
		}
	}
	return nil
}

func (r *gcsGraphSnapshotReplica) objectKey(key string) (string, error) {
	if strings.TrimSpace(key) == "" {
		return r.prefix, nil
	}
	key, err := normalizeReplicaKey(key)
	if err != nil {
		return "", err
	}
	if r.prefix == "" {
		return key, nil
	}
	return path.Join(r.prefix, key), nil
}

func parseBucketURI(raw, prefix string) (string, string, error) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(raw, prefix))
	parts := strings.SplitN(trimmed, "/", 2)
	bucket := strings.TrimSpace(parts[0])
	if bucket == "" {
		return "", "", fmt.Errorf("invalid replica uri %q: missing bucket", raw)
	}
	objectPrefix := ""
	if len(parts) == 2 {
		objectPrefix = strings.Trim(strings.TrimSpace(parts[1]), "/")
		if objectPrefix != "" {
			var err error
			objectPrefix, err = normalizeReplicaKey(objectPrefix)
			if err != nil {
				return "", "", fmt.Errorf("invalid replica prefix %q: %w", raw, err)
			}
		}
	}
	return bucket, objectPrefix, nil
}

func normalizeReplicaKey(key string) (string, error) {
	key = filepath.ToSlash(strings.TrimSpace(key))
	if key == "" {
		return "", fmt.Errorf("replica key required")
	}
	if strings.ContainsRune(key, 0) {
		return "", fmt.Errorf("replica key contains NUL byte")
	}
	if strings.HasPrefix(key, "/") || path.IsAbs(key) {
		return "", fmt.Errorf("replica key must be relative")
	}
	clean := path.Clean(key)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("replica key escapes configured prefix")
	}
	if strings.Contains(clean, ":") {
		return "", fmt.Errorf("replica key contains invalid drive separator")
	}
	return clean, nil
}

func resolveReplicaLocalPath(basePath, key string) (string, error) {
	normalized, err := normalizeReplicaKey(key)
	if err != nil {
		return "", err
	}
	baseAbs, err := filepath.Abs(strings.TrimSpace(basePath))
	if err != nil {
		return "", err
	}
	full := filepath.Join(baseAbs, filepath.FromSlash(normalized))
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	if fullAbs != baseAbs && !strings.HasPrefix(fullAbs, baseAbs+string(os.PathSeparator)) {
		return "", fmt.Errorf("replica key escapes configured base path")
	}
	return fullAbs, nil
}

func strPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func graphSnapshotManifestSortTime(manifest GraphSnapshotManifest) time.Time {
	recordTime := graphSnapshotSortTime(manifest.Record)
	if recordTime.IsZero() && manifest.Record.CapturedAt != nil {
		return manifest.Record.CapturedAt.UTC()
	}
	return recordTime
}
