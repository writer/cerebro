package ports

import "context"

// ExposureCoverageProfile declares the closed source and entity-kind filters
// for one bounded comparison. Relation semantics remain server-owned.
type ExposureCoverageProfile struct {
	PrimarySourceID              string
	PrimaryEntityKindPrefix      string
	CorroboratingSourceID        string
	CorroboratingEntityKind      string
	IndicatorKinds               []string
	AccountKind                  string
	CorroboratingObservationKind string
}

// ExposureCoverageRequest scopes one comparison to a tenant and hard result bound.
type ExposureCoverageRequest struct {
	TenantID  string
	Profile   ExposureCoverageProfile
	AccountID string
	Region    string
	Query     string
	Limit     int
}

// ExposureCoverageEntity is the stable product identity returned by the typed read.
type ExposureCoverageEntity struct {
	URN        string
	EntityType string
	Label      string
}

// ExposureCoverageCounts reports the complete aggregate comparison.
type ExposureCoverageCounts struct {
	PrimaryEntities                  uint64
	Indicators                       uint64
	HostIndicators                   uint64
	IPIndicators                     uint64
	OverlappingPrimaryEntities       uint64
	OverlappingIndicators            uint64
	OverlappingCorroboratingEntities uint64
}

// ExposureCoverageKindCount reports one primary entity-kind count.
type ExposureCoverageKindCount struct {
	EntityKind string
	Count      uint64
}

// ExposureCoverageOverlap is one observation present in both sources.
type ExposureCoverageOverlap struct {
	Primary       ExposureCoverageEntity
	Indicator     ExposureCoverageEntity
	Corroborating ExposureCoverageEntity
}

// ExposureCoveragePair is one primary observation without corroboration.
type ExposureCoveragePair struct {
	Primary   ExposureCoverageEntity
	Indicator ExposureCoverageEntity
}

// ExposureCoverageCorroboratingOnly is one corroborating observation missing from the primary source.
type ExposureCoverageCorroboratingOnly struct {
	Corroborating ExposureCoverageEntity
	Indicator     ExposureCoverageEntity
}

// ExposureCoverageAccount reports source coverage for one account.
type ExposureCoverageAccount struct {
	Account                   ExposureCoverageEntity
	PrimaryEntities           uint64
	CorroboratingObservations uint64
}

// ExposureCoverageCompleteness reports whether any returned collection hit its server bound.
type ExposureCoverageCompleteness struct {
	TypeCountsTruncated        bool
	OverlapsTruncated          bool
	PrimaryOnlyTruncated       bool
	CorroboratingOnlyTruncated bool
	AccountsTruncated          bool
}

// ExposureCoverageResult binds all values to one tenant graph revision.
type ExposureCoverageResult struct {
	TenantID          string
	GraphRevision     uint64
	Counts            ExposureCoverageCounts
	TypeCounts        []ExposureCoverageKindCount
	Overlaps          []ExposureCoverageOverlap
	PrimaryOnly       []ExposureCoveragePair
	CorroboratingOnly []ExposureCoverageCorroboratingOnly
	Accounts          []ExposureCoverageAccount
	Completeness      ExposureCoverageCompleteness
}

// ExposureCoverageStore serves one typed, bounded exposure comparison.
type ExposureCoverageStore interface {
	CompareExposureCoverage(context.Context, ExposureCoverageRequest) (*ExposureCoverageResult, error)
}
