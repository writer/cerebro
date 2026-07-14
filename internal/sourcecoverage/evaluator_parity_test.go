package sourcecoverage

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestRustEvaluatorMatchesGoOracle(t *testing.T) {
	contracts := []sourcecdk.CoverageContract{
		{
			SourceID: " zeta ", OwnerDomain: " platform ", AuthorityDomain: " provider ",
			Dimensions: []sourcecdk.CoverageDimension{
				{ID: "", Type: "entity_family", Title: "Invalid", Support: sourcecdk.CoverageSupportSupported},
				{ID: " users ", Type: " entity_family ", Title: " Users ", Families: []string{" user ", "user"}, RuntimeFamilies: []string{" users ", "users"}, Support: " supported ", HighValue: true, KnownUnsupportedFields: []string{"legacy"}, Notes: []string{"owner review"}, EvidenceTypes: []string{"identity"}, ControlDomains: []string{"access"}, ControlRefs: []sourcecdk.CoverageControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}}},
				{ID: "apps", Type: "entity_family", Title: "Applications", Families: []string{"application"}, Support: sourcecdk.CoverageSupportSupported, HighValue: true},
				{ID: "remediation", Type: "remediation_state", Title: "Remediation", Support: sourcecdk.CoverageSupportPlanned, HighValue: true},
			},
		},
		{
			SourceID: "alpha",
			Dimensions: []sourcecdk.CoverageDimension{
				{ID: "audit", Type: "audit_event", Title: "Audit", Families: []string{"audit"}, Support: sourcecdk.CoverageSupportPartial, HighValue: true},
				{ID: "devices", Type: "entity_family", Title: "Devices", Families: []string{"device"}, Support: sourcecdk.CoverageSupportSupported},
			},
		},
	}
	observations := []RuntimeObservation{
		{RuntimeID: "wrong-family-failed", SourceID: "zeta", TenantID: "tenant-a", Family: "user", Status: "failed"},
		{RuntimeID: "first-users-failed", SourceID: " zeta ", TenantID: "tenant-a", Family: "users", Status: "healthy", LastFailureCategory: "schema", LastSyncedAt: "2026-07-14T10:00:00Z"},
		{RuntimeID: "second-users-failed", SourceID: "zeta", TenantID: "tenant-a", Family: "users", Status: "failed"},
		{RuntimeID: "wrong-tenant", SourceID: "zeta", TenantID: "tenant-b", Family: "application", Status: "healthy"},
		{RuntimeID: "alpha-audit", SourceID: "alpha", TenantID: "tenant-a", Family: "audit", Status: "current"},
		{RuntimeID: "alpha-device", SourceID: "alpha", TenantID: "tenant-a", Family: "device", Status: "mystery"},
		{RuntimeID: "ignored", SourceID: " ", TenantID: "tenant-a", Family: "audit", Status: "failed"},
	}

	for _, options := range []Options{
		{TenantID: " tenant-a "},
		{TenantID: "tenant-a", SourceID: " zeta "},
	} {
		got, err := Evaluate(context.Background(), contracts, observations, options)
		if err != nil {
			t.Fatalf("Evaluate(%+v) error = %v", options, err)
		}
		want := evaluateCoverageGoOracle(contracts, observations, options)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Evaluate(%+v) parity mismatch\ngot:  %#v\nwant: %#v", options, got, want)
		}
	}
}

func TestCoverageEvaluatorRejectsMalformedAndOversizedInput(t *testing.T) {
	if _, err := runCoverageEvaluator(context.Background(), []byte("{")); !errors.Is(err, ErrEvaluatorUnavailable) {
		t.Fatalf("runCoverageEvaluator(malformed) error = %v, want ErrEvaluatorUnavailable", err)
	}
	oversized := make([]byte, coverageEvaluatorMaxInput+1)
	if _, err := runCoverageEvaluator(context.Background(), oversized); !errors.Is(err, ErrEvaluatorUnavailable) {
		t.Fatalf("runCoverageEvaluator(oversized) error = %v, want ErrEvaluatorUnavailable", err)
	}
}

func evaluateCoverageGoOracle(contracts []sourcecdk.CoverageContract, observations []RuntimeObservation, options Options) []Record {
	options.TenantID = strings.TrimSpace(options.TenantID)
	options.SourceID = strings.TrimSpace(options.SourceID)
	bySource := oracleObservationsBySource(observations)
	records := make([]Record, 0)
	for _, contract := range contracts {
		contract.SourceID = strings.TrimSpace(contract.SourceID)
		if contract.SourceID == "" || (options.SourceID != "" && contract.SourceID != options.SourceID) {
			continue
		}
		for _, dimension := range contract.Dimensions {
			record := oracleCoverageRecord(contract, dimension, bySource[contract.SourceID], options)
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
		if oracleStateRank(records[i].State) != oracleStateRank(records[j].State) {
			return oracleStateRank(records[i].State) < oracleStateRank(records[j].State)
		}
		return records[i].DimensionID < records[j].DimensionID
	})
	return records
}

func oracleCoverageRecord(contract sourcecdk.CoverageContract, dimension sourcecdk.CoverageDimension, observations []RuntimeObservation, options Options) Record {
	dimension.ID = strings.TrimSpace(dimension.ID)
	dimension.Type = strings.TrimSpace(dimension.Type)
	dimension.Title = strings.TrimSpace(dimension.Title)
	dimension.Support = strings.ToLower(strings.TrimSpace(dimension.Support))
	if dimension.ID == "" || dimension.Type == "" || dimension.Title == "" {
		return Record{}
	}
	runtimeFamilies := oracleCoverageRuntimeFamilies(dimension)
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
		SupportedRuntimeFamilies: oracleUniqueNonEmptyStrings(dimension.Families, dimension.RuntimeFamilies),
	}
	if dimension.Support == sourcecdk.CoverageSupportUnsupported || dimension.Support == sourcecdk.CoverageSupportPlanned {
		record.State = StateUnsupported
		return oracleWithBlindSpot(record)
	}
	matches := oracleMatchingObservations(observations, runtimeFamilies, options.TenantID)
	if len(matches) == 0 {
		record.State = StateUnconfigured
		return oracleWithBlindSpot(record)
	}
	best := oracleMostConcerningObservation(matches)
	record.RuntimeID = best.RuntimeID
	record.Family = best.Family
	record.LastSyncedAt = best.LastSyncedAt
	record.State = oracleObservationState(best)
	if record.State == StateHealthy && dimension.Support == sourcecdk.CoverageSupportPartial {
		record.State = StatePartial
	}
	return oracleWithBlindSpot(record)
}

func oracleCoverageRuntimeFamilies(dimension sourcecdk.CoverageDimension) []string {
	if families := oracleUniqueNonEmptyStrings(dimension.RuntimeFamilies); len(families) != 0 {
		return families
	}
	return oracleUniqueNonEmptyStrings(dimension.Families)
}

func oracleUniqueNonEmptyStrings(groups ...[]string) []string {
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

func oracleObservationsBySource(observations []RuntimeObservation) map[string][]RuntimeObservation {
	bySource := map[string][]RuntimeObservation{}
	for _, observation := range observations {
		sourceID := strings.TrimSpace(observation.SourceID)
		if sourceID != "" {
			bySource[sourceID] = append(bySource[sourceID], observation)
		}
	}
	return bySource
}

func oracleMatchingObservations(observations []RuntimeObservation, families []string, tenantID string) []RuntimeObservation {
	familySet := map[string]struct{}{}
	for _, family := range families {
		if family = strings.TrimSpace(family); family != "" {
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

func oracleMostConcerningObservation(observations []RuntimeObservation) RuntimeObservation {
	best := observations[0]
	for _, observation := range observations[1:] {
		if oracleStateRank(oracleObservationState(observation)) < oracleStateRank(oracleObservationState(best)) {
			best = observation
		}
	}
	return best
}

func oracleObservationState(observation RuntimeObservation) string {
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

func oracleWithBlindSpot(record Record) Record {
	record.BlindSpot = record.HighValue && record.State != StateHealthy
	if record.BlindSpot {
		record.Warning = oracleCoverageWarning(record)
	}
	return record
}

func oracleCoverageWarning(record Record) string {
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

func oracleStateRank(state string) int {
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
