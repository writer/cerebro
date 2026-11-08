package cloudidentity

import "time"

// CollectionCoverage is the durable, bounded coverage record a collection
// source projects alongside (but separate from) the full per-principal
// Evidence it originates from: scope, completeness and a possibly
// truncated, deduplicated set of Gaps, without the per-principal Evidence
// array itself. It lives in this package, rather than the source adapter
// package that emits it, because internal/sourceprojection must decode the
// exact wire shape to report accurate gap_count/gaps_truncated and cannot
// import an internal/ source package.
type CollectionCoverage struct {
	Schema            string            `json:"schema"`
	Scope             string            `json:"scope"`
	CollectedAt       time.Time         `json:"collected_at"`
	InventoryComplete bool              `json:"inventory_complete"`
	PrincipalCount    int               `json:"principal_count"`
	GapCount          int               `json:"gap_count"`
	Gaps              []Gap             `json:"gaps,omitempty"`
	GapsTruncated     bool              `json:"gaps_truncated,omitempty"`
	Handoff           CollectionHandoff `json:"handoff,omitempty"`
}

// CollectionHandoff records the outcome of publishing this collection
// pass's evidence bundle to the VulnView-owned S3 intake bucket. Status is
// "published", "failed", or "disabled" (no evidence_handoff_bucket
// configured). ErrorCode is a short, stable failure classification and
// never contains secret-bearing text (no raw AWS SDK error strings, no
// credential material).
type CollectionHandoff struct {
	Status    string `json:"status"`
	Bucket    string `json:"bucket,omitempty"`
	Key       string `json:"key,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	Stream    string `json:"stream,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}
