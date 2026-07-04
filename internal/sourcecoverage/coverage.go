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
	SourceID                 string                         `json:"source_id"`
	TenantID                 string                         `json:"tenant_id,omitempty"`
	DimensionID              string                         `json:"dimension_id"`
	DimensionType            string                         `json:"dimension_type"`
	Title                    string                         `json:"title"`
	State                    string                         `json:"state"`
	SupportLevel             string                         `json:"support_level"`
	RuntimeID                string                         `json:"runtime_id,omitempty"`
	Family                   string                         `json:"family,omitempty"`
	LastSyncedAt             string                         `json:"last_synced_at,omitempty"`
	OwnerDomain              string                         `json:"owner_domain,omitempty"`
	AuthorityDomain          string                         `json:"authority_domain,omitempty"`
	HighValue                bool                           `json:"high_value,omitempty"`
	BlindSpot                bool                           `json:"blind_spot"`
	Warning                  string                         `json:"warning,omitempty"`
	KnownUnsupportedFields   []string                       `json:"known_unsupported_fields,omitempty"`
	Notes                    []string                       `json:"notes,omitempty"`
	EvidenceTypes            []string                       `json:"evidence_types,omitempty"`
	ControlDomains           []string                       `json:"control_domains,omitempty"`
	ControlRefs              []sourcecdk.CoverageControlRef `json:"control_refs,omitempty"`
	SupportedRuntimeFamilies []string                       `json:"supported_runtime_families,omitempty"`
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

type Report struct {
	Version            string    `json:"version"`
	GeneratedAt        string    `json:"generated_at,omitempty"`
	TenantID           string    `json:"tenant_id,omitempty"`
	SourceID           string    `json:"source_id,omitempty"`
	Totals             Totals    `json:"totals"`
	Gate               Gate      `json:"gate"`
	Records            []Record  `json:"records"`
	BlindSpots         []Record  `json:"blind_spots"`
	Summaries          []Summary `json:"summaries"`
	BlindSpotSummaries []Summary `json:"blind_spot_summaries"`
}

type Totals struct {
	Dimensions          int `json:"dimensions"`
	HighValueDimensions int `json:"high_value_dimensions"`
	Healthy             int `json:"healthy"`
	Partial             int `json:"partial"`
	Unsupported         int `json:"unsupported"`
	Unconfigured        int `json:"unconfigured"`
	Stale               int `json:"stale"`
	Failed              int `json:"failed"`
	Unknown             int `json:"unknown"`
	BlindSpots          int `json:"blind_spots"`
}

type Gate struct {
	Status         string `json:"status"`
	BlockingReason string `json:"blocking_reason"`
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

func FirstTenantID(records []Record) string {
	for _, record := range records {
		if tenantID := strings.TrimSpace(record.TenantID); tenantID != "" {
			return tenantID
		}
	}
	return ""
}

func BuildReport(records []Record, options Options, generatedAt time.Time) Report {
	options.TenantID = strings.TrimSpace(options.TenantID)
	options.SourceID = strings.TrimSpace(options.SourceID)
	clonedRecords := cloneRecords(records)
	blindSpots := BlindSpots(clonedRecords)
	totals := TotalsFor(clonedRecords)
	return Report{
		Version:            "source-coverage/v1",
		GeneratedAt:        generatedAt.UTC().Format(time.RFC3339Nano),
		TenantID:           options.TenantID,
		SourceID:           options.SourceID,
		Totals:             totals,
		Gate:               GateForTotals(totals),
		Records:            clonedRecords,
		BlindSpots:         blindSpots,
		Summaries:          Summaries(clonedRecords),
		BlindSpotSummaries: Summaries(blindSpots),
	}
}

func BuildScopedReport(records []Record, tenantID string, sourceID string, generatedAt string) Report {
	reportTime := time.Now().UTC()
	if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(generatedAt)); err == nil {
		reportTime = parsed
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = FirstTenantID(records)
	}
	return BuildReport(records, Options{TenantID: tenantID, SourceID: strings.TrimSpace(sourceID)}, reportTime)
}

func TotalsFor(records []Record) Totals {
	var totals Totals
	for _, record := range records {
		totals.Dimensions++
		if record.HighValue {
			totals.HighValueDimensions++
		}
		switch record.State {
		case StateHealthy:
			totals.Healthy++
		case StatePartial:
			totals.Partial++
		case StateUnsupported:
			totals.Unsupported++
		case StateUnconfigured:
			totals.Unconfigured++
		case StateStale:
			totals.Stale++
		case StateFailed:
			totals.Failed++
		default:
			totals.Unknown++
		}
		if record.BlindSpot {
			totals.BlindSpots++
		}
	}
	return totals
}

func GateForTotals(totals Totals) Gate {
	switch {
	case totals.Failed > 0:
		return Gate{Status: "fail", BlockingReason: "failed"}
	case totals.BlindSpots > 0:
		return Gate{Status: "fail", BlockingReason: "blind_spot"}
	case totals.Stale > 0:
		return Gate{Status: "warn", BlockingReason: "stale"}
	case totals.Unconfigured > 0:
		return Gate{Status: "warn", BlockingReason: "unconfigured"}
	case totals.Unsupported > 0:
		return Gate{Status: "warn", BlockingReason: "unsupported"}
	case totals.Partial > 0:
		return Gate{Status: "warn", BlockingReason: "partial"}
	case totals.Unknown > 0:
		return Gate{Status: "warn", BlockingReason: "unknown"}
	default:
		return Gate{Status: "pass", BlockingReason: "none"}
	}
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

func cloneRecords(records []Record) []Record {
	cloned := make([]Record, len(records))
	for i, record := range records {
		cloned[i] = record
		cloned[i].KnownUnsupportedFields = append([]string(nil), record.KnownUnsupportedFields...)
		cloned[i].Notes = append([]string(nil), record.Notes...)
		cloned[i].EvidenceTypes = append([]string(nil), record.EvidenceTypes...)
		cloned[i].ControlDomains = append([]string(nil), record.ControlDomains...)
		cloned[i].ControlRefs = append([]sourcecdk.CoverageControlRef(nil), record.ControlRefs...)
		cloned[i].SupportedRuntimeFamilies = append([]string(nil), record.SupportedRuntimeFamilies...)
	}
	return cloned
}

func coverageRecord(contract sourcecdk.CoverageContract, dimension sourcecdk.CoverageDimension, observations []RuntimeObservation, options Options) Record {
	dimension.ID = strings.TrimSpace(dimension.ID)
	dimension.Type = strings.TrimSpace(dimension.Type)
	dimension.Title = strings.TrimSpace(dimension.Title)
	dimension.Support = strings.ToLower(strings.TrimSpace(dimension.Support))
	if dimension.ID == "" || dimension.Type == "" || dimension.Title == "" {
		return Record{}
	}
	runtimeFamilies := coverageRuntimeFamilies(dimension)
	supportedRuntimeFamilies := coverageSupportedRuntimeFamilies(dimension)
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
		EvidenceTypes:            append([]string(nil), dimension.EvidenceTypes...),
		ControlDomains:           append([]string(nil), dimension.ControlDomains...),
		ControlRefs:              append([]sourcecdk.CoverageControlRef(nil), dimension.ControlRefs...),
		SupportedRuntimeFamilies: supportedRuntimeFamilies,
	}
	if dimension.Support == sourcecdk.CoverageSupportUnsupported || dimension.Support == sourcecdk.CoverageSupportPlanned {
		record.State = StateUnsupported
		return withBlindSpot(record)
	}
	matches := matchingObservations(observations, runtimeFamilies, options.TenantID)
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

func coverageRuntimeFamilies(dimension sourcecdk.CoverageDimension) []string {
	if runtimeFamilies := uniqueNonEmptyStrings(dimension.RuntimeFamilies); len(runtimeFamilies) != 0 {
		return runtimeFamilies
	}
	return uniqueNonEmptyStrings(dimension.Families)
}

func coverageSupportedRuntimeFamilies(dimension sourcecdk.CoverageDimension) []string {
	return uniqueNonEmptyStrings(dimension.Families, dimension.RuntimeFamilies)
}

func uniqueNonEmptyStrings(groups ...[]string) []string {
	seen := map[string]struct{}{}
	var result []string
	for _, values := range groups {
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
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
