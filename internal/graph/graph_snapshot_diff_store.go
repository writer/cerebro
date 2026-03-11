package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const graphSnapshotDiffStorageClass = "local_diff_store"

const maxGraphSnapshotDiffByteSizeIterations = 16

// GraphSnapshotDiffStore persists materialized graph snapshot diff artifacts.
type GraphSnapshotDiffStore struct {
	basePath string
}

func NewGraphSnapshotDiffStore(basePath string) *GraphSnapshotDiffStore {
	return &GraphSnapshotDiffStore{basePath: strings.TrimSpace(basePath)}
}

func (s *GraphSnapshotDiffStore) Save(record *GraphSnapshotDiffRecord) (*GraphSnapshotDiffRecord, error) {
	if s == nil || strings.TrimSpace(s.basePath) == "" {
		return nil, fmt.Errorf("graph snapshot diff store not configured")
	}
	if record == nil || strings.TrimSpace(record.ID) == "" {
		return nil, fmt.Errorf("graph snapshot diff record is required")
	}
	stored := *record
	now := time.Now().UTC()
	stored.StoredAt = &now
	stored.Materialized = true
	stored.StorageClass = graphSnapshotDiffStorageClass
	stored.JobID = strings.TrimSpace(record.JobID)

	payloadForHash := stored
	payloadForHash.IntegrityHash = ""
	payloadForHash.ByteSize = 0
	hashPayload, err := json.Marshal(payloadForHash)
	if err != nil {
		return nil, fmt.Errorf("marshal graph snapshot diff: %w", err)
	}
	sum := sha256.Sum256(hashPayload)
	stored.IntegrityHash = "sha256:" + hex.EncodeToString(sum[:])
	if err := stabilizeGraphSnapshotDiffByteSize(&stored); err != nil {
		return nil, err
	}
	if err := writeJSONAtomic(s.pathForDiffID(stored.ID), stored); err != nil {
		return nil, err
	}
	return &stored, nil
}

func (s *GraphSnapshotDiffStore) Load(diffID string) (*GraphSnapshotDiffRecord, error) {
	if s == nil || strings.TrimSpace(s.basePath) == "" {
		return nil, fmt.Errorf("graph snapshot diff store not configured")
	}
	diffID = strings.TrimSpace(diffID)
	if diffID == "" {
		return nil, fmt.Errorf("graph snapshot diff id required")
	}
	file, err := os.Open(s.pathForDiffID(diffID)) // #nosec G304 -- diff artifact path is owned by the local diff store.
	if err != nil {
		return nil, fmt.Errorf("open graph snapshot diff: %w", err)
	}
	defer func() { _ = file.Close() }()

	var record GraphSnapshotDiffRecord
	if err := json.NewDecoder(file).Decode(&record); err != nil {
		return nil, fmt.Errorf("decode graph snapshot diff: %w", err)
	}
	return &record, nil
}

func (s *GraphSnapshotDiffStore) pathForDiffID(diffID string) string {
	return filepath.Join(s.basePath, sanitizeReportFileName(diffID)+".json")
}

func stabilizeGraphSnapshotDiffByteSize(record *GraphSnapshotDiffRecord) error {
	if record == nil {
		return fmt.Errorf("graph snapshot diff record is required")
	}
	for i := 0; i < maxGraphSnapshotDiffByteSizeIterations; i++ {
		payload, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("marshal materialized graph snapshot diff: %w", err)
		}
		size := int64(len(payload))
		if record.ByteSize == size {
			return nil
		}
		record.ByteSize = size
	}
	return fmt.Errorf("compute stable graph snapshot diff byte size")
}
