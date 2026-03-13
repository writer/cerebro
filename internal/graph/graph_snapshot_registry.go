package graph

import (
	"strings"
	"time"
)

// GraphSnapshotCollectionSnapshot builds a durable graph snapshot catalog from the current graph and persisted report lineage.
func GraphSnapshotCollectionSnapshot(g *Graph, runs map[string]*ReportRun, now time.Time) GraphSnapshotCollection {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	records := map[string]*GraphSnapshotRecord{}
	if current := CurrentGraphSnapshotRecord(g); current != nil {
		records[current.ID] = current
	}
	for _, run := range runs {
		if run == nil {
			continue
		}
		accumulateGraphSnapshotRecord(records, run.Lineage, run.ReportID, run.SubmittedAt, false)
		if run.Snapshot != nil {
			accumulateGraphSnapshotRecord(records, run.Snapshot.Lineage, run.ReportID, run.Snapshot.GeneratedAt, true)
		}
	}
	return GraphSnapshotCollectionFromRecords(records, now)
}

func accumulateGraphSnapshotRecord(records map[string]*GraphSnapshotRecord, lineage ReportLineage, reportID string, observedAt time.Time, materialized bool) {
	snapshotID := strings.TrimSpace(lineage.GraphSnapshotID)
	if snapshotID == "" {
		return
	}
	record, ok := records[snapshotID]
	if !ok {
		record = &GraphSnapshotRecord{
			ID:                      snapshotID,
			GraphSchemaVersion:      lineage.GraphSchemaVersion,
			OntologyContractVersion: strings.TrimSpace(lineage.OntologyContractVersion),
		}
		if lineage.GraphBuiltAt != nil {
			record.BuiltAt = cloneTimePtr(lineage.GraphBuiltAt)
		}
		records[snapshotID] = record
	}
	if record.GraphSchemaVersion == 0 {
		record.GraphSchemaVersion = lineage.GraphSchemaVersion
	}
	if record.OntologyContractVersion == "" {
		record.OntologyContractVersion = strings.TrimSpace(lineage.OntologyContractVersion)
	}
	if record.BuiltAt == nil && lineage.GraphBuiltAt != nil {
		record.BuiltAt = cloneTimePtr(lineage.GraphBuiltAt)
	}
	if strings.TrimSpace(reportID) != "" && !containsGraphSnapshotString(record.ObservedReportIDs, reportID) {
		record.ObservedReportIDs = append(record.ObservedReportIDs, strings.TrimSpace(reportID))
	}
	record.ObservedRunCount++
	if materialized {
		record.ObservedMaterializations++
	}
	if !observedAt.IsZero() {
		at := observedAt.UTC()
		if record.FirstObservedAt == nil || at.Before(record.FirstObservedAt.UTC()) {
			copy := at
			record.FirstObservedAt = &copy
		}
		if record.LastObservedAt == nil || at.After(record.LastObservedAt.UTC()) {
			copy := at
			record.LastObservedAt = &copy
		}
	}
}

func containsGraphSnapshotString(values []string, needle string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(needle) {
			return true
		}
	}
	return false
}
