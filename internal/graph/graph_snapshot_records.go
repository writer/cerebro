package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// GraphSnapshotRecord is the typed graph-state resource referenced by report lineage.
type GraphSnapshotRecord struct {
	ID                       string     `json:"id"`
	ParentSnapshotID         string     `json:"parent_snapshot_id,omitempty"`
	BuiltAt                  *time.Time `json:"built_at,omitempty"`
	CapturedAt               *time.Time `json:"captured_at,omitempty"`
	Current                  bool       `json:"current,omitempty"`
	Materialized             bool       `json:"materialized,omitempty"`
	Diffable                 bool       `json:"diffable,omitempty"`
	StorageClass             string     `json:"storage_class,omitempty"`
	RetentionClass           string     `json:"retention_class,omitempty"`
	IntegrityHash            string     `json:"integrity_hash,omitempty"`
	ExpiresAt                *time.Time `json:"expires_at,omitempty"`
	ByteSize                 int64      `json:"byte_size,omitempty"`
	NodeCount                int        `json:"node_count,omitempty"`
	EdgeCount                int        `json:"edge_count,omitempty"`
	Providers                []string   `json:"providers,omitempty"`
	Accounts                 []string   `json:"accounts,omitempty"`
	BuildDurationMS          int64      `json:"build_duration_ms,omitempty"`
	GraphSchemaVersion       int64      `json:"graph_schema_version,omitempty"`
	OntologyContractVersion  string     `json:"ontology_contract_version,omitempty"`
	ObservedRunCount         int        `json:"observed_run_count,omitempty"`
	ObservedMaterializations int        `json:"observed_materializations,omitempty"`
	ObservedReportIDs        []string   `json:"observed_report_ids,omitempty"`
	FirstObservedAt          *time.Time `json:"first_observed_at,omitempty"`
	LastObservedAt           *time.Time `json:"last_observed_at,omitempty"`
}

// GraphSnapshotCollection is the list payload for graph snapshot resources.
type GraphSnapshotCollection struct {
	GeneratedAt time.Time             `json:"generated_at"`
	Count       int                   `json:"count"`
	Snapshots   []GraphSnapshotRecord `json:"snapshots"`
}

// GraphSnapshotCollectionFromRecords normalizes a graph snapshot record map into a stable collection payload.
func GraphSnapshotCollectionFromRecords(records map[string]*GraphSnapshotRecord, now time.Time) GraphSnapshotCollection {
	snapshots := make([]GraphSnapshotRecord, 0, len(records))
	for _, record := range records {
		if record == nil || strings.TrimSpace(record.ID) == "" {
			continue
		}
		record.ID = strings.TrimSpace(record.ID)
		record.ParentSnapshotID = strings.TrimSpace(record.ParentSnapshotID)
		record.Providers = append([]string(nil), record.Providers...)
		record.Accounts = append([]string(nil), record.Accounts...)
		record.ObservedReportIDs = append([]string(nil), record.ObservedReportIDs...)
		sort.Strings(record.Providers)
		sort.Strings(record.Accounts)
		sort.Strings(record.ObservedReportIDs)
		snapshots = append(snapshots, *record)
	}
	sort.Slice(snapshots, func(i, j int) bool {
		left := snapshots[i]
		right := snapshots[j]
		if left.Current != right.Current {
			return left.Current
		}
		leftSortTime := graphSnapshotSortTime(left)
		rightSortTime := graphSnapshotSortTime(right)
		if !leftSortTime.Equal(rightSortTime) {
			return leftSortTime.After(rightSortTime)
		}
		return left.ID < right.ID
	})
	return GraphSnapshotCollection{
		GeneratedAt: now.UTC(),
		Count:       len(snapshots),
		Snapshots:   snapshots,
	}
}

// CurrentGraphSnapshotRecord builds the current graph snapshot resource from graph metadata.
func CurrentGraphSnapshotRecord(g *Graph) *GraphSnapshotRecord {
	if g == nil {
		return nil
	}
	return CurrentGraphSnapshotRecordFromMetadata(g.Metadata())
}

// CurrentGraphSnapshotRecordFromMetadata builds the current graph snapshot
// resource from already-resolved graph metadata.
func CurrentGraphSnapshotRecordFromMetadata(meta Metadata) *GraphSnapshotRecord {
	snapshotID := buildReportGraphSnapshotID(meta)
	if snapshotID == "" {
		return nil
	}
	record := &GraphSnapshotRecord{
		ID:                      snapshotID,
		Current:                 true,
		NodeCount:               meta.NodeCount,
		EdgeCount:               meta.EdgeCount,
		Providers:               append([]string(nil), meta.Providers...),
		Accounts:                append([]string(nil), meta.Accounts...),
		BuildDurationMS:         meta.BuildDuration.Milliseconds(),
		GraphSchemaVersion:      SchemaVersion(),
		OntologyContractVersion: GraphOntologyContractVersion,
	}
	if !meta.BuiltAt.IsZero() {
		builtAt := meta.BuiltAt.UTC()
		record.BuiltAt = &builtAt
	}
	return record
}

func graphSnapshotSortTime(record GraphSnapshotRecord) time.Time {
	switch {
	case record.BuiltAt != nil && !record.BuiltAt.IsZero():
		return record.BuiltAt.UTC()
	case record.CapturedAt != nil && !record.CapturedAt.IsZero():
		return record.CapturedAt.UTC()
	case record.LastObservedAt != nil && !record.LastObservedAt.IsZero():
		return record.LastObservedAt.UTC()
	case record.FirstObservedAt != nil && !record.FirstObservedAt.IsZero():
		return record.FirstObservedAt.UTC()
	default:
		return time.Time{}
	}
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func buildReportGraphSnapshotID(meta Metadata) string {
	if meta.BuiltAt.IsZero() {
		return ""
	}
	providers := append([]string(nil), meta.Providers...)
	accounts := append([]string(nil), meta.Accounts...)
	sort.Strings(providers)
	sort.Strings(accounts)
	payload := fmt.Sprintf("%s|%d|%d|%s|%s",
		meta.BuiltAt.UTC().Format(time.RFC3339Nano),
		meta.NodeCount,
		meta.EdgeCount,
		strings.Join(providers, ","),
		strings.Join(accounts, ","),
	)
	sum := sha256.Sum256([]byte(payload))
	return "graph_snapshot:" + hex.EncodeToString(sum[:12])
}
