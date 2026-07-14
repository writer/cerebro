package ports

import (
	"context"
	"errors"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// ErrInputSnapshotChanged indicates that a paged input no longer has the total
// observed on its first page. Callers must discard the partial snapshot and retry.
var ErrInputSnapshotChanged = errors.New("input snapshot changed during scan")

// InputSnapshotRequest scopes one complete, cutoff-bounded keyset scan.
// ExpectedTotal and ExpectedWatermark are supplied after the first page to
// detect inserts, deletes, or mutable rows during later pages.
type InputSnapshotRequest struct {
	TenantID          string
	RuntimeIDs        []string
	Cutoff            time.Time
	AfterID           string
	Limit             uint32
	ExpectedTotal     *uint64
	ExpectedWatermark *time.Time
}

// InputSnapshotPage contains proof needed to assemble a complete input manifest.
type InputSnapshotPage[T any] struct {
	Records    []T
	Total      uint64
	NextCursor string
	Complete   bool
	Cutoff     time.Time
	Watermark  time.Time
}

// ComplianceInputSnapshotStore exposes assessment-only scans that are not bound
// by UI list limits. Each page is read in a repeatable-read transaction and is
// stable by tenant, cutoff, and primary-key cursor.
type ComplianceInputSnapshotStore interface {
	ScanFindingSnapshot(context.Context, InputSnapshotRequest) (InputSnapshotPage[*FindingRecord], error)
	ScanFindingEvidenceSnapshot(context.Context, InputSnapshotRequest) (InputSnapshotPage[*cerebrov1.FindingEvidence], error)
	ScanSourceRuntimeSnapshot(context.Context, InputSnapshotRequest) (InputSnapshotPage[*cerebrov1.SourceRuntime], error)
}
