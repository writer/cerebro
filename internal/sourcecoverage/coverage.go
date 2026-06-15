package sourcecoverage

import (
	"fmt"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	StateHealthy      = "healthy"
	StatePartial      = "partial"
	StateUnsupported  = "unsupported"
	StateUnconfigured = "unconfigured"
	StateStale        = "stale"
	StateFailed       = "failed"
	StateUnknown      = "unknown"
)

type Options struct {
	TenantID string
	SourceID string
}

type RuntimeObservation struct {
	RuntimeID           string
	SourceID            string
	TenantID            string
	Family              string
	Status              string
	LastFailureCategory string
	LastSyncedAt        string
}

type Record struct {
	SourceID                 string   `json:"source_id"`
	TenantID                 string   `json:"tenant_id,omitempty"`
	DimensionID              string   `json:"dimension_id"`
	DimensionType            string   `json:"dimension_type"`
	Title                    string   `json:"title"`
	State                    string   `json:"state"`
	SupportLevel             string   `json:"support_level"`
	RuntimeID                string   `json:"runtime_id,omitempty"`
	Family                   string   `json:"family,omitempty"`
	LastSyncedAt             string   `json:"last_synced_at,omitempty"`
	OwnerDomain              string   `json:"owner_domain,omitempty"`
	AuthorityDomain          string   `json:"authority_domain,omitempty"`
	HighValue                bool     `json:"high_value,omitempty"`
	BlindSpot                bool     `json:"blind_spot"`
	Warning                  string   `json:"warning,omitempty"`
	KnownUnsupportedFields   []string `json:"known_unsupported_fields,omitempty"`
	Notes                    []string `json:"notes,omitempty"`
	SupportedRuntimeFamilies []string `json:"supported_runtime_families,omitempty"`
}

type Summary struct {
	SourceID     string `json:"source_id"`
	Total        int    `json:"total"`
	Healthy      int    `json:"healthy"`
	Partial      int    `json:"partial"`
	Unsupported  int    `json:"unsupported"`
	Unconfigured int    `json:"unconfigured"`
	Stale        int    `json:"stale"`
	Failed       int    `json:"failed"`
	Unknown      int    `json:"unknown"`
	BlindSpots   int    `json:"blind_spots"`
}

func ContractsFromRegistry(registry *sourcecdk.Registry) []sourcecdk.CoverageContract {
	if registry == nil {
		return nil
	}
	return registry.CoverageContracts()
}

func ObservationsFromRuntimes(runtimes []*cerebrov1.SourceRuntime, status func(*cerebrov1.SourceRuntime) string) []RuntimeObservation {
	observations := make([]RuntimeObservation, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		lastSyncedAt := ""
		if ts := timestampValue(runtime.GetLastSyncedAt()); !ts.IsZero() {
			lastSyncedAt = ts.UTC().Format(time.RFC3339Nano)
		}
		observations = append(observations, RuntimeObservation{
			RuntimeID:           strings.TrimSpace(runtime.GetId()),
			SourceID:            strings.TrimSpace(runtime.GetSourceId()),
			TenantID:            strings.TrimSpace(runtime.GetTenantId()),
			Family:              strings.TrimSpace(runtime.GetConfig()["family"]),
			Status:              strings.TrimSpace(status(runtime)),
			LastFailureCategory: strings.TrimSpace(runtime.GetConfig()["__cerebro_runtime_last_failure_category"]),
			LastSyncedAt:        lastSyncedAt,
		})
	}
	return observations
}

func Evaluate(contracts []sourcecdk.CoverageContract, observations []RuntimeObservation, options Options) []Record {
	options.TenantID = strings.TrimSpace(options.TenantID)
	options.SourceID = strings.TrimSpace(options.SourceID)
	bySource := observationsBySource(observations)
	records := make([]Record, 0)
	for _, contract := range contracts {
		contract.SourceID = strings.TrimSpace(contract.SourceID)
		if contract.SourceID == "" || (options.SourceID != "" && contract.SourceID != options.SourceID) {
			continue
		}
		for _, dimension := range contract.Dimensions {
			record := coverageRecord(contract, dimension, bySource[contract.SourceID], options)
			if record.DimensionID != "" {
				records = append(records, record)
			}
		}
	}
	sort.Slice(records, func(i int, j int) bool {
		if records[i].SourceID != records[j].SourceID {
			return records[i].SourceID < records[j].SourceID
		}
		if records[i].BlindSpot != records[j].BlindSpot {
			return records[i].BlindSpot
		}
		if stateRank(records[i].State) != stateRank(records[j].State) {
			return stateRank(records[i].State) < stateRank(records[j].State)
		}
		return records[i].DimensionID < records[j].DimensionID
	})
	return records
}

func BlindSpots(records []Record) []Record {
	out := make([]Record, 0)
	for _, record := range records {
		if record.BlindSpot {
			out = append(out, record)
		}
	}
	return out
}

func Summaries(records []Record) []Summary {
	bySource := map[string]*Summary{}
	for _, record := range records {
		sourceID := strings.TrimSpace(record.SourceID)
		if sourceID == "" {
			sourceID = "unknown"
		}
		summary := bySource[sourceID]
		if summary == nil {
			summary = &Summary{SourceID: sourceID}
			bySource[sourceID] = summary
		}
		summary.Total++
		switch record.State {
		case StateHealthy:
			summary.Healthy++
		case StatePartial:
			summary.Partial++
		case StateUnsupported:
			summary.Unsupported++
		case StateUnconfigured:
			summary.Unconfigured++
		case StateStale:
			summary.Stale++
		case StateFailed:
			summary.Failed++
		default:
			summary.Unknown++
		}
		if record.BlindSpot {
			summary.BlindSpots++
		}
	}
	summaries := make([]Summary, 0, len(bySource))
	for _, summary := range bySource {
		summaries = append(summaries, *summary)
	}
	sort.Slice(summaries, func(i int, j int) bool {
		if summaries[i].BlindSpots != summaries[j].BlindSpots {
			return summaries[i].BlindSpots > summaries[j].BlindSpots
		}
		if summaries[i].Total != summaries[j].Total {
			return summaries[i].Total > summaries[j].Total
		}
		return summaries[i].SourceID < summaries[j].SourceID
	})
	return summaries
}

func coverageRecord(contract sourcecdk.CoverageContract, dimension sourcecdk.CoverageDimension, observations []RuntimeObservation, options Options) Record {
	dimension.ID = strings.TrimSpace(dimension.ID)
	dimension.Type = strings.TrimSpace(dimension.Type)
	dimension.Title = strings.TrimSpace(dimension.Title)
	dimension.Support = strings.ToLower(strings.TrimSpace(dimension.Support))
	if dimension.ID == "" || dimension.Type == "" || dimension.Title == "" {
		return Record{}
	}
	record := Record{
		SourceID:                 contract.SourceID,
		TenantID:                 options.TenantID,
		DimensionID:              dimension.ID,
		DimensionType:            dimension.Type,
		Title:                    dimension.Title,
		SupportLevel:             dimension.Support,
		OwnerDomain:              strings.TrimSpace(contract.OwnerDomain),
		AuthorityDomain:          strings.TrimSpace(contract.AuthorityDomain),
		HighValue:                dimension.HighValue,
		KnownUnsupportedFields:   append([]string(nil), dimension.KnownUnsupportedFields...),
		Notes:                    append([]string(nil), dimension.Notes...),
		SupportedRuntimeFamilies: append([]string(nil), dimension.Families...),
	}
	if dimension.Support == sourcecdk.CoverageSupportUnsupported || dimension.Support == sourcecdk.CoverageSupportPlanned {
		record.State = StateUnsupported
		return withBlindSpot(record)
	}
	matches := matchingObservations(observations, dimension.Families, options.TenantID)
	if len(matches) == 0 {
		record.State = StateUnconfigured
		return withBlindSpot(record)
	}
	best := mostConcerningObservation(matches)
	record.RuntimeID = best.RuntimeID
	record.Family = best.Family
	record.LastSyncedAt = best.LastSyncedAt
	record.State = observationState(best)
	if record.State == StateHealthy && dimension.Support == sourcecdk.CoverageSupportPartial {
		record.State = StatePartial
	}
	return withBlindSpot(record)
}

func withBlindSpot(record Record) Record {
	record.BlindSpot = record.HighValue && record.State != StateHealthy
	if record.BlindSpot {
		record.Warning = coverageWarning(record)
	}
	return record
}

func coverageWarning(record Record) string {
	subject := strings.TrimSpace(record.Title)
	if subject == "" {
		subject = record.DimensionID
	}
	sourceID := strings.TrimSpace(record.SourceID)
	switch record.State {
	case StateUnsupported:
		return fmt.Sprintf("%s coverage is unsupported by %s", subject, sourceID)
	case StateUnconfigured:
		if record.TenantID != "" {
			return fmt.Sprintf("%s coverage is unconfigured for tenant %s", subject, record.TenantID)
		}
		return fmt.Sprintf("%s coverage is unconfigured", subject)
	case StateStale:
		return fmt.Sprintf("%s coverage is stale for %s", subject, sourceID)
	case StateFailed:
		return fmt.Sprintf("%s coverage is failing for %s", subject, sourceID)
	case StatePartial:
		return fmt.Sprintf("%s coverage is partial for %s", subject, sourceID)
	default:
		return fmt.Sprintf("%s coverage state is %s for %s", subject, record.State, sourceID)
	}
}

func observationsBySource(observations []RuntimeObservation) map[string][]RuntimeObservation {
	bySource := map[string][]RuntimeObservation{}
	for _, observation := range observations {
		sourceID := strings.TrimSpace(observation.SourceID)
		if sourceID == "" {
			continue
		}
		bySource[sourceID] = append(bySource[sourceID], observation)
	}
	return bySource
}

func matchingObservations(observations []RuntimeObservation, families []string, tenantID string) []RuntimeObservation {
	familySet := map[string]struct{}{}
	for _, family := range families {
		family = strings.TrimSpace(family)
		if family != "" {
			familySet[family] = struct{}{}
		}
	}
	matches := make([]RuntimeObservation, 0, len(observations))
	for _, observation := range observations {
		if tenantID != "" && strings.TrimSpace(observation.TenantID) != tenantID {
			continue
		}
		if len(familySet) != 0 {
			if _, ok := familySet[strings.TrimSpace(observation.Family)]; !ok {
				continue
			}
		}
		matches = append(matches, observation)
	}
	return matches
}

func mostConcerningObservation(observations []RuntimeObservation) RuntimeObservation {
	best := observations[0]
	for _, observation := range observations[1:] {
		if stateRank(observationState(observation)) < stateRank(observationState(best)) {
			best = observation
		}
	}
	return best
}

func observationState(observation RuntimeObservation) string {
	if strings.TrimSpace(observation.LastFailureCategory) != "" {
		return StateFailed
	}
	switch strings.ToLower(strings.TrimSpace(observation.Status)) {
	case "failing", "failed":
		return StateFailed
	case "stale":
		return StateStale
	case "healthy", "current":
		return StateHealthy
	case "partial":
		return StatePartial
	default:
		return StateUnknown
	}
}

func stateRank(state string) int {
	switch state {
	case StateFailed:
		return 0
	case StateStale:
		return 1
	case StateUnconfigured:
		return 2
	case StateUnsupported:
		return 3
	case StatePartial:
		return 4
	case StateUnknown:
		return 5
	case StateHealthy:
		return 6
	default:
		return 7
	}
}

func timestampValue(ts *timestamppb.Timestamp) time.Time {
	if ts == nil || !ts.IsValid() {
		return time.Time{}
	}
	return ts.AsTime()
}
