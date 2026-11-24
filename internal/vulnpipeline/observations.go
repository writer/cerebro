package vulnpipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultObservationLimit = 50
	maxObservationLimit     = 200
	maxFilterValues         = 20
)

// ObservationView is the API representation of a normalized observation.
type ObservationView struct {
	ID             string `json:"id"`
	ProfileID      string `json:"profile_id"`
	SourceID       string `json:"source_id"`
	Scanner        string `json:"scanner,omitempty"`
	SourceRecordID string `json:"source_record_id"`
	CorrelationKey string `json:"correlation_key"`
	Format         string `json:"format"`
	MappingVersion int    `json:"mapping_version,omitempty"`
	BatchID        string `json:"batch_id,omitempty"`
	ObservationDetailsView
	Asset      AssetView         `json:"asset"`
	Package    *PackageView      `json:"package,omitempty"`
	Location   string            `json:"location,omitempty"`
	References []string          `json:"references,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	ObservationLifecycleView
}

// ObservationDetailsView describes the reported weakness. Its fields are
// flattened into the observation JSON object.
type ObservationDetailsView struct {
	Title                  string   `json:"title"`
	Description            string   `json:"description,omitempty"`
	Class                  string   `json:"class"`
	PrimaryVulnerabilityID string   `json:"primary_vulnerability_id,omitempty"`
	VulnerabilityIDs       []string `json:"vulnerability_ids,omitempty"`
	CWEs                   []string `json:"cwes,omitempty"`
	Severity               string   `json:"severity"`
	SourceSeverity         string   `json:"source_severity,omitempty"`
	CVSSScore              *float64 `json:"cvss_score,omitempty"`
	CVSSVector             string   `json:"cvss_vector,omitempty"`
	Status                 string   `json:"status"`
	SourceStatus           string   `json:"source_status,omitempty"`
}

// ObservationLifecycleView records when an observation was seen and
// resolved. Its fields are flattened into the observation JSON object.
type ObservationLifecycleView struct {
	FirstSeenAt *time.Time `json:"first_seen_at,omitempty"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	ObservedAt  time.Time  `json:"observed_at"`
	IngestedAt  time.Time  `json:"ingested_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
	Resolution  string     `json:"resolution,omitempty"`
}

// AssetView identifies the affected asset.
type AssetView struct {
	Type        string `json:"type,omitempty"`
	Identifier  string `json:"identifier,omitempty"`
	Name        string `json:"name,omitempty"`
	ImageDigest string `json:"image_digest,omitempty"`
}

// PackageView identifies the affected package.
type PackageView struct {
	Ecosystem    string `json:"ecosystem,omitempty"`
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	FixedVersion string `json:"fixed_version,omitempty"`
	PURL         string `json:"purl,omitempty"`
}

// ObservationPageView is one page of observations.
type ObservationPageView struct {
	Observations []ObservationView `json:"observations"`
	NextCursor   string            `json:"next_cursor,omitempty"`
}

// ViewObservation converts a stored observation to its API view.
func ViewObservation(observation *ports.VulnerabilityObservation) ObservationView {
	details := observation.VulnerabilityDetails
	lifecycle := observation.VulnerabilityLifecycle
	view := ObservationView{
		ID: observation.ID, ProfileID: observation.ProfileID, SourceID: observation.SourceID, Scanner: observation.Scanner,
		SourceRecordID: observation.SourceRecordID, CorrelationKey: observation.CorrelationKey, Format: observation.Format,
		MappingVersion: observation.MappingVersion, BatchID: observation.BatchID,
		ObservationDetailsView: ObservationDetailsView(details),
		Asset:                  AssetView{Type: observation.AssetType, Identifier: observation.AssetIdentifier, Name: observation.AssetName, ImageDigest: observation.ImageDigest},
		Location:               observation.Location, References: observation.References, Attributes: observation.Attributes,
		ObservationLifecycleView: ObservationLifecycleView(lifecycle),
	}
	if observation.PackageName != "" || observation.PackageURL != "" {
		view.Package = &PackageView{
			Ecosystem: observation.PackageEcosystem, Name: observation.PackageName, Version: observation.PackageVersion,
			FixedVersion: observation.FixedVersion, PURL: observation.PackageURL,
		}
	}
	return view
}

// ListObservations returns one filtered page of observations.
func (s *Service) ListObservations(ctx context.Context, filter ports.VulnerabilityObservationFilter) (*ObservationPageView, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	filter.TenantID = strings.TrimSpace(filter.TenantID)
	if filter.TenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	var err error
	if filter.Severities, err = filterValues("severity", filter.Severities, validSeverity); err != nil {
		return nil, err
	}
	if filter.Statuses, err = filterValues("status", filter.Statuses, validStatus); err != nil {
		return nil, err
	}
	if filter.Classes, err = filterValues("class", filter.Classes, validClass); err != nil {
		return nil, err
	}
	if filter.SourceIDs, err = filterValues("source_id", filter.SourceIDs, identifierPattern.MatchString); err != nil {
		return nil, err
	}
	filter.ProfileID = strings.TrimSpace(filter.ProfileID)
	filter.VulnerabilityID = strings.ToUpper(clean(filter.VulnerabilityID, 128))
	filter.AssetIdentifier = clean(filter.AssetIdentifier, 1024)
	filter.CorrelationKey = clean(filter.CorrelationKey, 128)
	filter.Search = clean(filter.Search, 200)
	filter.Cursor = clean(filter.Cursor, 512)
	filter.Limit = boundedLimit(filter.Limit, defaultObservationLimit, maxObservationLimit)
	page, err := s.store.ListVulnerabilityObservations(ctx, filter)
	if err != nil {
		return nil, err
	}
	view := &ObservationPageView{Observations: make([]ObservationView, 0, len(page.Observations)), NextCursor: page.NextCursor}
	for _, observation := range page.Observations {
		view.Observations = append(view.Observations, ViewObservation(observation))
	}
	return view, nil
}

func filterValues(name string, values []string, valid func(string) bool) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, raw := range values {
		for _, part := range strings.Split(raw, ",") {
			value := strings.ToLower(strings.TrimSpace(part))
			if value == "" || seen[value] {
				continue
			}
			if !valid(value) {
				return nil, fmt.Errorf("%w: unknown %s %q", ErrInvalidRequest, name, value)
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	if len(out) > maxFilterValues {
		return nil, fmt.Errorf("%w: too many %s values", ErrInvalidRequest, name)
	}
	return out, nil
}

// GetObservation returns one observation.
func (s *Service) GetObservation(ctx context.Context, tenantID string, observationID string) (*ObservationView, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	observation, err := s.store.GetVulnerabilityObservation(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(observationID))
	if err != nil {
		if errors.Is(err, ports.ErrVulnerabilityObservationNotFound) {
			return nil, fmt.Errorf("%w: observation %q", ErrNotFound, observationID)
		}
		return nil, err
	}
	view := ViewObservation(observation)
	return &view, nil
}

// SummaryView aggregates a tenant's observations for the dashboard.
type SummaryView struct {
	Total                    int                 `json:"total"`
	Open                     int                 `json:"open"`
	DistinctOpenVulns        int                 `json:"distinct_open_vulnerabilities"`
	MultiSourceOpen          int                 `json:"multi_source_open"`
	OldestOpenSeenAt         *time.Time          `json:"oldest_open_seen_at,omitempty"`
	BySeverity               map[string]int      `json:"by_severity"`
	ByClass                  map[string]int      `json:"by_class"`
	ByStatus                 map[string]int      `json:"by_status"`
	BySource                 []SourceSummaryView `json:"by_source"`
	Profiles                 int                 `json:"profiles"`
	ProfilesNeedingAttention int                 `json:"profiles_needing_attention"`
}

// SourceSummaryView aggregates one source tag.
type SourceSummaryView struct {
	SourceID     string         `json:"source_id"`
	Total        int            `json:"total"`
	Open         int            `json:"open"`
	BySeverity   map[string]int `json:"by_severity"`
	LastIngestAt *time.Time     `json:"last_ingest_at,omitempty"`
}

// Summary aggregates a tenant's observations and profile health.
func (s *Service) Summary(ctx context.Context, tenantID string) (*SummaryView, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	summary, err := s.store.SummarizeVulnerabilityObservations(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	profiles, err := s.store.ListVulnerabilityProfiles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	view := &SummaryView{
		Total: summary.Total, Open: summary.Open, DistinctOpenVulns: summary.DistinctOpenVulns, MultiSourceOpen: summary.MultiSourceOpen,
		OldestOpenSeenAt: summary.OldestOpenSeenAt, BySeverity: zeroFilled(summary.BySeverity, Severities()),
		ByClass: nonNil(summary.ByClass), ByStatus: zeroFilled(summary.ByStatus, Statuses()),
		BySource: make([]SourceSummaryView, 0, len(summary.BySource)), Profiles: len(profiles),
	}
	for _, source := range summary.BySource {
		view.BySource = append(view.BySource, SourceSummaryView{
			SourceID: source.SourceID, Total: source.Total, Open: source.Open,
			BySeverity: zeroFilled(source.BySeverity, Severities()), LastIngestAt: source.LastIngestAt,
		})
	}
	for _, profile := range profiles {
		if profile.Enabled && profile.LastStatus != "" && profile.LastStatus != ProfileStatusHealthy {
			view.ProfilesNeedingAttention++
		}
	}
	return view, nil
}

func zeroFilled(values map[string]int, keys []string) map[string]int {
	out := make(map[string]int, len(keys))
	for _, key := range keys {
		out[key] = values[key]
	}
	for key, value := range values {
		out[key] = value
	}
	return out
}

func nonNil(values map[string]int) map[string]int {
	if values == nil {
		return map[string]int{}
	}
	return values
}
