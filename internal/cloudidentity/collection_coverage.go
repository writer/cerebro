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
	Schema            string    `json:"schema"`
	Scope             string    `json:"scope"`
	CollectedAt       time.Time `json:"collected_at"`
	InventoryComplete bool      `json:"inventory_complete"`
	PrincipalCount    int       `json:"principal_count"`
	GapCount          int       `json:"gap_count"`
	Gaps              []Gap     `json:"gaps,omitempty"`
	GapsTruncated     bool      `json:"gaps_truncated,omitempty"`
}
