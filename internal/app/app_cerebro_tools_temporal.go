package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	entities "github.com/evalops/cerebro/internal/graph/entities"
)

type cerebroGraphChangelogRequest struct {
	DiffID   string `json:"diff_id"`
	Since    string `json:"since"`
	Until    string `json:"until"`
	Last     string `json:"last"`
	Kind     string `json:"kind"`
	Provider string `json:"provider"`
	Account  string `json:"account"`
	Limit    int    `json:"limit"`
}

type cerebroEntityHistoryRequest struct {
	EntityID   string `json:"entity_id"`
	Timestamp  string `json:"timestamp"`
	From       string `json:"from"`
	To         string `json:"to"`
	RecordedAt string `json:"recorded_at"`
}

func (a *App) toolCerebroGraphChangelog(_ context.Context, args json.RawMessage) (string, error) {
	var req cerebroGraphChangelogRequest
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	filter := graph.GraphDiffFilter{
		Kind:     graph.NodeKind(strings.ToLower(strings.TrimSpace(req.Kind))),
		Provider: strings.ToLower(strings.TrimSpace(req.Provider)),
		Account:  strings.TrimSpace(req.Account),
	}

	if diffID := strings.TrimSpace(req.DiffID); diffID != "" {
		details, err := a.platformGraphDiffDetailsForTool(diffID, filter)
		if err != nil {
			return "", err
		}
		return marshalToolResponse(details)
	}

	now := time.Now().UTC()
	since, until, err := parseToolChangelogWindow(req.Since, req.Until, req.Last, now)
	if err != nil {
		return "", err
	}
	changelog, err := a.platformGraphChangelogForTool(now, since, until, clampInt(req.Limit, 20, 1, 200), filter)
	if err != nil {
		return "", err
	}
	return marshalToolResponse(changelog)
}

func (a *App) toolCerebroEntityHistory(_ context.Context, args json.RawMessage) (string, error) {
	var req cerebroEntityHistoryRequest
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	g, err := a.requireReadableSecurityGraph()
	if err != nil {
		return "", err
	}

	entityID := strings.TrimSpace(req.EntityID)
	if entityID == "" {
		return "", fmt.Errorf("entity_id is required")
	}
	recordedAt, err := parseToolOptionalRFC3339(req.RecordedAt)
	if err != nil {
		return "", fmt.Errorf("recorded_at must be RFC3339")
	}

	if timestamp := strings.TrimSpace(req.Timestamp); timestamp != "" {
		asOf, err := parseToolRequiredRFC3339(timestamp, "timestamp")
		if err != nil {
			return "", err
		}
		record, ok := entities.GetEntityRecordAtTime(g, entityID, asOf, recordedAt)
		if !ok {
			return "", fmt.Errorf("entity not found: %s", entityID)
		}
		return marshalToolResponse(record)
	}

	fromRaw := strings.TrimSpace(req.From)
	toRaw := strings.TrimSpace(req.To)
	if fromRaw == "" || toRaw == "" {
		return "", fmt.Errorf("timestamp or both from and to are required")
	}
	from, err := parseToolRequiredRFC3339(fromRaw, "from")
	if err != nil {
		return "", err
	}
	to, err := parseToolRequiredRFC3339(toRaw, "to")
	if err != nil {
		return "", err
	}

	record, ok := entities.GetEntityTimeDiff(g, entityID, from, to, recordedAt)
	if !ok {
		return "", fmt.Errorf("entity not found: %s", entityID)
	}
	return marshalToolResponse(record)
}

func (a *App) platformGraphChangelogForTool(now, since, until time.Time, limit int, filter graph.GraphDiffFilter) (graph.GraphChangelog, error) {
	changelog := graph.GraphChangelog{
		GeneratedAt: now.UTC(),
		Filter:      filter,
	}
	if !since.IsZero() {
		copy := since.UTC()
		changelog.Since = &copy
	}
	if !until.IsZero() {
		copy := until.UTC()
		changelog.Until = &copy
	}

	records := a.platformGraphSnapshotRecordsForTool(now)
	if len(records) == 0 {
		return changelog, nil
	}
	sort.Slice(records, func(i, j int) bool {
		left := toolGraphSnapshotSortTime(records[i])
		right := toolGraphSnapshotSortTime(records[j])
		if !left.Equal(right) {
			return left.Before(right)
		}
		return records[i].ID < records[j].ID
	})

	store := a.platformGraphSnapshotStoreForTool()
	if store == nil {
		return changelog, nil
	}
	diffStore := a.platformGraphDiffStoreForTool()
	entries := make([]graph.GraphChangelogEntry, 0, limit)
	for i := len(records) - 2; i >= 0; i-- {
		fromRecord := records[i]
		toRecord := records[i+1]
		changeTime := toolGraphSnapshotSortTime(toRecord)
		if !since.IsZero() && changeTime.Before(since) {
			continue
		}
		if !until.IsZero() && changeTime.After(until) {
			continue
		}
		if !fromRecord.Diffable || !toRecord.Diffable {
			continue
		}
		snapshots, _, err := store.LoadSnapshotsByRecordIDs(fromRecord.ID, toRecord.ID)
		if err != nil {
			continue
		}
		diff := graph.DiffSnapshots(snapshots[fromRecord.ID], snapshots[toRecord.ID])
		record := graph.BuildGraphSnapshotDiffRecord(fromRecord, toRecord, diff, changeTime)
		if record == nil {
			continue
		}
		diffURL := "/api/v1/platform/graph/snapshots/" + fromRecord.ID + "/diffs/" + toRecord.ID
		if diffStore != nil {
			if stored, err := diffStore.Load(record.ID); err == nil && stored != nil {
				record = stored
				diffURL = "/api/v1/platform/graph/diffs/" + record.ID
			}
		}
		details := graph.BuildGraphSnapshotDiffDetails(record, snapshots[fromRecord.ID], snapshots[toRecord.ID], filter)
		if details == nil {
			continue
		}
		if details.Summary.NodesAdded == 0 &&
			details.Summary.NodesRemoved == 0 &&
			details.Summary.NodesModified == 0 &&
			details.Summary.EdgesAdded == 0 &&
			details.Summary.EdgesRemoved == 0 {
			continue
		}
		entries = append(entries, graph.GraphChangelogEntry{
			DiffID:       record.ID,
			DiffURL:      diffURL,
			GeneratedAt:  record.GeneratedAt,
			StoredAt:     record.StoredAt,
			Materialized: record.Materialized,
			From:         record.From,
			To:           record.To,
			Summary:      details.Summary,
			Attribution:  details.Attribution,
		})
		if len(entries) == limit {
			break
		}
	}

	changelog.Entries = entries
	changelog.Count = len(entries)
	return changelog, nil
}

func (a *App) platformGraphDiffDetailsForTool(diffID string, filter graph.GraphDiffFilter) (*graph.GraphSnapshotDiffDetails, error) {
	diffID = strings.TrimSpace(diffID)
	if diffID == "" {
		return nil, fmt.Errorf("diff_id is required")
	}
	record, snapshots, err := a.platformGraphDiffForReadForTool(diffID)
	if err != nil {
		return nil, err
	}
	details := graph.BuildGraphSnapshotDiffDetails(record, snapshots[record.From.ID], snapshots[record.To.ID], filter)
	if details == nil {
		return nil, fmt.Errorf("failed to build graph snapshot diff details")
	}
	return details, nil
}

func (a *App) platformGraphDiffForReadForTool(diffID string) (*graph.GraphSnapshotDiffRecord, map[string]*graph.Snapshot, error) {
	diffStore := a.platformGraphDiffStoreForTool()
	if diffStore == nil {
		return nil, nil, fmt.Errorf("graph snapshot diff store not configured")
	}
	if record, err := diffStore.Load(diffID); err == nil && record != nil {
		snapshots, err := a.platformGraphSnapshotsForDiffRecordForTool(record)
		if err != nil {
			return nil, nil, err
		}
		return record, snapshots, nil
	}
	return a.platformGraphSnapshotDiffByIDForTool(diffID)
}

func (a *App) platformGraphSnapshotsForDiffRecordForTool(record *graph.GraphSnapshotDiffRecord) (map[string]*graph.Snapshot, error) {
	snapshotStore := a.platformGraphSnapshotStoreForTool()
	if snapshotStore == nil {
		return nil, fmt.Errorf("graph snapshot store not configured")
	}
	if record == nil {
		return nil, fmt.Errorf("graph snapshot diff not found")
	}
	if strings.TrimSpace(record.From.ID) == "" || strings.TrimSpace(record.To.ID) == "" {
		return nil, fmt.Errorf("graph snapshot diff missing snapshot references")
	}
	snapshots, _, err := snapshotStore.LoadSnapshotsByRecordIDs(record.From.ID, record.To.ID)
	if err != nil {
		return nil, err
	}
	return snapshots, nil
}

func (a *App) platformGraphSnapshotDiffByIDForTool(diffID string) (*graph.GraphSnapshotDiffRecord, map[string]*graph.Snapshot, error) {
	records := a.platformGraphSnapshotRecordsForTool(time.Now().UTC())
	if len(records) < 2 {
		return nil, nil, fmt.Errorf("graph snapshot diff not found: %s", diffID)
	}
	sort.Slice(records, func(i, j int) bool {
		left := toolGraphSnapshotSortTime(records[i])
		right := toolGraphSnapshotSortTime(records[j])
		if !left.Equal(right) {
			return left.Before(right)
		}
		return records[i].ID < records[j].ID
	})
	snapshotStore := a.platformGraphSnapshotStoreForTool()
	if snapshotStore == nil {
		return nil, nil, fmt.Errorf("graph snapshot store not configured")
	}
	for i := 0; i+1 < len(records); i++ {
		if !records[i].Diffable || !records[i+1].Diffable {
			continue
		}
		candidate := graph.BuildGraphSnapshotDiffRecord(records[i], records[i+1], &graph.GraphDiff{}, time.Time{})
		if candidate == nil || candidate.ID != diffID {
			continue
		}
		snapshots, _, err := snapshotStore.LoadSnapshotsByRecordIDs(records[i].ID, records[i+1].ID)
		if err != nil {
			return nil, nil, err
		}
		changeTime := toolGraphSnapshotSortTime(records[i+1])
		record := graph.BuildGraphSnapshotDiffRecord(records[i], records[i+1], graph.DiffSnapshots(snapshots[records[i].ID], snapshots[records[i+1].ID]), changeTime)
		if record == nil {
			return nil, nil, fmt.Errorf("graph snapshot diff not found: %s", diffID)
		}
		return record, snapshots, nil
	}
	return nil, nil, fmt.Errorf("graph snapshot diff not found: %s", diffID)
}

func (a *App) platformGraphSnapshotRecordsForTool(now time.Time) []graph.GraphSnapshotRecord {
	records := map[string]*graph.GraphSnapshotRecord{}
	if g := a.CurrentSecurityGraph(); g != nil {
		if current := graph.CurrentGraphSnapshotRecord(g); current != nil {
			records[current.ID] = current
		}
	}

	store := a.platformGraphSnapshotStoreForTool()
	if store != nil {
		persisted, err := store.ListGraphSnapshotRecords()
		if err == nil {
			for i := range persisted {
				record := persisted[i]
				existing, ok := records[record.ID]
				if !ok {
					copy := record
					records[record.ID] = &copy
					continue
				}
				mergeToolGraphSnapshotRecord(existing, record)
			}
		}
	}

	collection := graph.GraphSnapshotCollectionFromRecords(records, now)
	return append([]graph.GraphSnapshotRecord(nil), collection.Snapshots...)
}

func (a *App) platformGraphSnapshotStoreForTool() *graph.GraphPersistenceStore {
	if a != nil && a.GraphSnapshots != nil {
		return a.GraphSnapshots
	}
	snapshotPath := strings.TrimSpace(os.Getenv("GRAPH_SNAPSHOT_PATH"))
	maxSnapshots := 10
	if a != nil && a.Config != nil {
		if configured := strings.TrimSpace(a.Config.GraphSnapshotPath); configured != "" {
			snapshotPath = configured
		}
		if a.Config.GraphSnapshotMaxRetained > 0 {
			maxSnapshots = a.Config.GraphSnapshotMaxRetained
		}
	}
	if snapshotPath == "" {
		snapshotPath = filepath.Join(".cerebro", "graph-snapshots")
	}
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    snapshotPath,
		MaxSnapshots: maxSnapshots,
	})
	if err != nil {
		return nil
	}
	return store
}

func (a *App) platformGraphDiffStoreForTool() *graph.GraphSnapshotDiffStore {
	snapshotPath := strings.TrimSpace(os.Getenv("GRAPH_SNAPSHOT_PATH"))
	if a != nil && a.Config != nil && strings.TrimSpace(a.Config.GraphSnapshotPath) != "" {
		snapshotPath = strings.TrimSpace(a.Config.GraphSnapshotPath)
	}
	if snapshotPath == "" {
		snapshotPath = filepath.Join(".cerebro", "graph-snapshots")
	}
	return graph.NewGraphSnapshotDiffStore(filepath.Join(snapshotPath, "diffs"))
}

func parseToolChangelogWindow(sinceRaw, untilRaw, lastRaw string, now time.Time) (time.Time, time.Time, error) {
	since, err := parseToolOptionalRFC3339(sinceRaw)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("since must be RFC3339")
	}
	until, err := parseToolOptionalRFC3339(untilRaw)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("until must be RFC3339")
	}
	lastRaw = strings.TrimSpace(lastRaw)
	if lastRaw != "" {
		window, err := parseFlexibleDuration(lastRaw)
		if err != nil || window <= 0 {
			return time.Time{}, time.Time{}, fmt.Errorf("last must be a positive duration")
		}
		until = now.UTC()
		since = until.Add(-window)
	}
	if !since.IsZero() && !until.IsZero() && until.Before(since) {
		return time.Time{}, time.Time{}, fmt.Errorf("until must be greater than or equal to since")
	}
	return since, until, nil
}

func parseToolOptionalRFC3339(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func parseToolRequiredRFC3339(raw, key string) (time.Time, error) {
	parsed, err := parseToolOptionalRFC3339(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339", key)
	}
	if parsed.IsZero() {
		return time.Time{}, fmt.Errorf("%s must be RFC3339", key)
	}
	return parsed, nil
}

func parseFlexibleDuration(raw string) (time.Duration, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return 0, fmt.Errorf("duration required")
	}
	if strings.HasSuffix(raw, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(raw, "d"), 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(raw)
}

func toolGraphSnapshotSortTime(record graph.GraphSnapshotRecord) time.Time {
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

func mergeToolGraphSnapshotRecord(dst *graph.GraphSnapshotRecord, src graph.GraphSnapshotRecord) {
	if dst == nil {
		return
	}
	if dst.BuiltAt == nil && src.BuiltAt != nil {
		copy := src.BuiltAt.UTC()
		dst.BuiltAt = &copy
	}
	if dst.CapturedAt == nil && src.CapturedAt != nil {
		copy := src.CapturedAt.UTC()
		dst.CapturedAt = &copy
	}
	if src.Current {
		dst.Current = true
	}
	if src.Materialized {
		dst.Materialized = true
	}
	if src.Diffable {
		dst.Diffable = true
	}
	if dst.ParentSnapshotID == "" {
		dst.ParentSnapshotID = strings.TrimSpace(src.ParentSnapshotID)
	}
	if dst.StorageClass == "" {
		dst.StorageClass = strings.TrimSpace(src.StorageClass)
	}
	if dst.RetentionClass == "" {
		dst.RetentionClass = strings.TrimSpace(src.RetentionClass)
	}
	if dst.IntegrityHash == "" {
		dst.IntegrityHash = strings.TrimSpace(src.IntegrityHash)
	}
	if dst.ExpiresAt == nil && src.ExpiresAt != nil {
		copy := src.ExpiresAt.UTC()
		dst.ExpiresAt = &copy
	}
	if dst.ByteSize == 0 {
		dst.ByteSize = src.ByteSize
	}
	if dst.NodeCount == 0 {
		dst.NodeCount = src.NodeCount
	}
	if dst.EdgeCount == 0 {
		dst.EdgeCount = src.EdgeCount
	}
	if dst.BuildDurationMS == 0 {
		dst.BuildDurationMS = src.BuildDurationMS
	}
	if dst.GraphSchemaVersion == 0 {
		dst.GraphSchemaVersion = src.GraphSchemaVersion
	}
	if dst.OntologyContractVersion == "" {
		dst.OntologyContractVersion = strings.TrimSpace(src.OntologyContractVersion)
	}
	if len(dst.Providers) == 0 {
		dst.Providers = append([]string(nil), src.Providers...)
	}
	if len(dst.Accounts) == 0 {
		dst.Accounts = append([]string(nil), src.Accounts...)
	}
}
