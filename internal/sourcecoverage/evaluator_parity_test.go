package sourcecoverage

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/wasmjson/wasmjsontest"
)

const coverageEvaluatorFuzzMaxInput = 64 << 10

//go:embed testdata/wasmjson/*.json
var coverageEvaluatorCorpus embed.FS

func TestCoverageEvaluatorCorpus(t *testing.T) {
	t.Parallel()
	inputs := wasmjsontest.LoadInputs[coverageEvaluationRequest](t, coverageEvaluatorCorpus, "testdata/wasmjson/*.json", coverageEvaluatorFuzzMaxInput)
	wasmjsontest.RunCorpus(t, context.Background(), inputs, coverageEvaluatorDifferential())
}

func FuzzCoverageEvaluatorParity(f *testing.F) {
	inputs := wasmjsontest.LoadInputs[coverageEvaluationRequest](f, coverageEvaluatorCorpus, "testdata/wasmjson/*.json", coverageEvaluatorFuzzMaxInput)
	wasmjsontest.AddSeeds(f, inputs)
	differential := coverageEvaluatorDifferential()
	f.Fuzz(func(t *testing.T, raw []byte) {
		wasmjsontest.CheckFuzzInput(t, context.Background(), raw, differential)
	})
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

func TestCoverageEvaluatorSupportsConcurrentCalls(t *testing.T) {
	t.Parallel()
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "source-a",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID: "users", Type: "entity_family", Title: "Users", Families: []string{"user"}, Support: sourcecdk.CoverageSupportSupported,
		}},
	}}
	observations := []RuntimeObservation{{RuntimeID: "runtime-a", SourceID: "source-a", Family: "user", Status: "healthy"}}

	var wait sync.WaitGroup
	errors := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			records, err := Evaluate(context.Background(), contracts, observations, Options{})
			if err != nil {
				errors <- err
				return
			}
			if len(records) != 1 || records[0].State != StateHealthy {
				errors <- fmt.Errorf("records = %#v; want one healthy record", records)
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Errorf("concurrent Evaluate() error = %v", err)
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

func coverageEvaluatorDifferential() wasmjsontest.Differential[coverageEvaluationRequest, []Record] {
	return wasmjsontest.Differential[coverageEvaluationRequest, []Record]{
		MaxInputBytes: coverageEvaluatorFuzzMaxInput,
		Oracle: func(request coverageEvaluationRequest) []Record {
			contracts, observations, options := coverageEvaluationArguments(request)
			return evaluateCoverageGoOracle(contracts, observations, options)
		},
		Candidate: func(ctx context.Context, input wasmjsontest.Input[coverageEvaluationRequest]) ([]Record, error) {
			contracts, observations, options := coverageEvaluationArguments(input.Value)
			return Evaluate(ctx, contracts, observations, options)
		},
	}
}

func coverageEvaluationArguments(request coverageEvaluationRequest) ([]sourcecdk.CoverageContract, []RuntimeObservation, Options) {
	observations := make([]RuntimeObservation, 0, len(request.Observations))
	for _, observation := range request.Observations {
		observations = append(observations, RuntimeObservation(observation))
	}
	return request.Contracts, observations, Options(request.Options)
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
