package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestAssessmentSamplingSchemaPreservesImmutableInputsAndSelections(t *testing.T) {
	t.Parallel()
	joined := strings.Join(ensureAssessmentSamplingStatements, "\n")
	for _, fragment := range []string{
		"compliance_assessment_activities", "compliance_assessment_activity_revisions",
		"PRIMARY KEY (tenant_id, activity_id, aggregate_version)",
		"compliance_assessment_populations", "compliance_assessment_population_subjects",
		"compliance_assessment_samples", "algorithm TEXT NOT NULL", "seed TEXT NOT NULL",
		"population_digest TEXT NOT NULL", "selection_digest TEXT NOT NULL",
		"compliance_assessment_sample_subjects", "UNIQUE (tenant_id, sample_id, ordinal)",
		"compliance_sampling_event_application_receipts", "PRIMARY KEY (tenant_id, event_id)",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("assessment sampling schema missing %q", fragment)
		}
	}
	if strings.Contains(joined, "control_outcome") || strings.Contains(joined, "control_result") {
		t.Fatal("activity execution state was persisted as a control outcome")
	}
}

func TestAssessmentSamplingSchemaIncludesReceiptUpgradeAndTenantIndexes(t *testing.T) {
	t.Parallel()
	joined := strings.Join(ensureAssessmentSamplingStatements, "\n")
	for _, fragment := range []string{
		"ALTER TABLE compliance_sampling_event_application_receipts ADD COLUMN IF NOT EXISTS event_digest",
		"compliance_assessment_activities_run_state_idx", "compliance_assessment_populations_run_objective_idx",
		"compliance_assessment_samples_population_idx",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("assessment sampling schema upgrade missing %q", fragment)
		}
	}
}

func TestAssessmentSamplingReceiptAndVersionDecisions(t *testing.T) {
	t.Parallel()
	if apply, err := assessmentSamplingReceiptDecision("", false, "digest-a"); err != nil || !apply {
		t.Fatalf("new receipt decision = (%v, %v), want apply", apply, err)
	}
	if apply, err := assessmentSamplingReceiptDecision("digest-a", true, "digest-a"); err != nil || apply {
		t.Fatalf("duplicate receipt decision = (%v, %v), want no-op", apply, err)
	}
	if _, err := assessmentSamplingReceiptDecision("digest-a", true, "digest-b"); !errors.Is(err, complianceassessment.ErrSamplingProjectionConflict) {
		t.Fatalf("conflicting receipt error = %v", err)
	}
	for _, test := range []struct {
		exists   bool
		current  uint64
		incoming uint64
		want     error
	}{{incoming: 1}, {exists: true, current: 1, incoming: 2}, {incoming: 2, want: complianceassessment.ErrSamplingProjectionGap},
		{exists: true, current: 2, incoming: 4, want: complianceassessment.ErrSamplingProjectionGap},
		{exists: true, current: 2, incoming: 2, want: complianceassessment.ErrSamplingProjectionConflict}} {
		if err := validateSamplingAdvance(test.exists, test.current, test.incoming); !errors.Is(err, test.want) {
			t.Fatalf("validateSamplingAdvance(%v, %d, %d) error = %v, want %v", test.exists, test.current, test.incoming, err, test.want)
		}
	}
}

func TestAssessmentActivityTransitionsRemainExecutionOnly(t *testing.T) {
	t.Parallel()
	if !activityTransitionAllowed("", complianceassessment.ActivityQueued, false) ||
		!activityTransitionAllowed(complianceassessment.ActivityQueued, complianceassessment.ActivityRunning, true) ||
		!activityTransitionAllowed(complianceassessment.ActivityRunning, complianceassessment.ActivityCompleted, true) {
		t.Fatal("valid execution transition was rejected")
	}
	if activityTransitionAllowed(complianceassessment.ActivityCompleted, complianceassessment.ActivityRunning, true) {
		t.Fatal("terminal activity execution state transitioned back to running")
	}
}

func TestCompletePopulationValidationChecksCountsAndDigest(t *testing.T) {
	t.Parallel()
	events := testAssessmentSamplingEvents(t, "tenant-population")
	populationEvent, err := decodeAssessmentSamplingEvent(events[3])
	if err != nil {
		t.Fatalf("decode population event: %v", err)
	}
	population := testPopulationPayload(t)
	if _, err := validateCompleteAssessmentPopulation(populationEvent, population); err != nil {
		t.Fatalf("valid complete population error = %v", err)
	}
	population.Snapshot.ObservedCount++
	if _, err := validateCompleteAssessmentPopulation(populationEvent, population); !errors.Is(err, complianceassessment.ErrInvalidPopulation) {
		t.Fatalf("count mismatch error = %v", err)
	}
	population = testPopulationPayload(t)
	population.Snapshot.ContentDigest = testSamplingDigest("9")
	if _, err := validateCompleteAssessmentPopulation(populationEvent, population); !errors.Is(err, complianceassessment.ErrInvalidPopulation) {
		t.Fatalf("digest mismatch error = %v", err)
	}
	population = testPopulationPayload(t)
	population.Snapshot.Complete = false
	if _, err := validateCompleteAssessmentPopulation(populationEvent, population); !errors.Is(err, complianceassessment.ErrInvalidPopulation) {
		t.Fatalf("incomplete population error = %v", err)
	}
}

func TestDeterministicSelectionValidationRejectsChangedSeedOrSubjects(t *testing.T) {
	t.Parallel()
	population := testPopulationPayload(t)
	sample := testSampleSelection(t, population)
	if err := validateDeterministicAssessmentSample(sample, population); err != nil {
		t.Fatalf("valid deterministic sample error = %v", err)
	}
	changedSeed := sample
	changedSeed.Seed = "seed-2"
	if err := validateDeterministicAssessmentSample(changedSeed, population); !errors.Is(err, complianceassessment.ErrInvalidSample) {
		t.Fatalf("changed seed error = %v", err)
	}
	changedSubjects := sample
	changedSubjects.Subjects = append([]complianceassessment.PopulationSubject(nil), sample.Subjects...)
	changedSubjects.Subjects[0] = complianceassessment.PopulationSubject{ID: "different", Type: "asset"}
	if err := validateDeterministicAssessmentSample(changedSubjects, population); !errors.Is(err, complianceassessment.ErrInvalidSample) {
		t.Fatalf("changed subjects error = %v", err)
	}
}

func TestAssessmentSamplingReplayIsDeterministicAndRejectsConflictingDuplicate(t *testing.T) {
	t.Parallel()
	events := testAssessmentSamplingEvents(t, "tenant-replay")
	first := newSamplingReplayState()
	second := newSamplingReplayState()
	for _, event := range events {
		if err := first.apply(event); err != nil {
			t.Fatalf("first replay apply: %v", err)
		}
		if err := second.apply(event); err != nil {
			t.Fatalf("second replay apply: %v", err)
		}
		if err := second.apply(event); err != nil {
			t.Fatalf("duplicate replay apply: %v", err)
		}
	}
	if !reflect.DeepEqual(first.snapshot(), second.snapshot()) {
		t.Fatalf("sampling replay snapshots differ:\nfirst = %#v\nsecond = %#v", first.snapshot(), second.snapshot())
	}
	queued := testActivity(complianceassessment.ActivityQueued)
	queued.Procedure = "changed procedure"
	conflict := testSamplingEvent(t, complianceassessment.AggregateTypeAssessmentActivity, queued.ID, 1, queued)
	original, err := decodeAssessmentSamplingEvent(events[0])
	if err != nil {
		t.Fatalf("decode original: %v", err)
	}
	changed, err := decodeAssessmentSamplingEvent(conflict)
	if err != nil {
		t.Fatalf("decode conflict: %v", err)
	}
	if events[0].GetId() != conflict.GetId() || original.eventDigest == changed.eventDigest {
		t.Fatal("conflicting duplicate did not retain id and change digest")
	}
	if _, err := assessmentSamplingReceiptDecision(original.eventDigest, true, changed.eventDigest); !errors.Is(err, complianceassessment.ErrSamplingProjectionConflict) {
		t.Fatalf("conflicting duplicate error = %v", err)
	}
}

func TestAssessmentSamplingRejectsEnvelopeTenantMismatch(t *testing.T) {
	t.Parallel()
	event := testAssessmentSamplingEvents(t, "tenant-one")[0]
	foreignEnvelope := proto.Clone(event).(*cerebrov1.EventEnvelope)
	foreignEnvelope.TenantId = "tenant-two"
	if _, err := decodeAssessmentSamplingEvent(foreignEnvelope); !errors.Is(err, complianceassessment.ErrSamplingProjectionConflict) {
		t.Fatalf("tenant-mismatched envelope error = %v, want projection conflict", err)
	}
}

func TestAssessmentSamplingPostgresTenantIsolation(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run assessment sampling integration test")
	}
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	ctx := context.Background()
	if err := store.ensureAssessmentSamplingTables(ctx); err != nil {
		t.Fatalf("ensure assessment sampling tables: %v", err)
	}
	tenantID := fmt.Sprintf("assessment-sampling-%d", time.Now().UnixNano())
	cleanupAssessmentSamplingTenant(t, ctx, store, tenantID)
	t.Cleanup(func() {
		cleanupAssessmentSamplingTenant(t, context.Background(), store, tenantID)
		_ = store.Close()
	})
	events := testAssessmentSamplingEvents(t, tenantID)
	for _, event := range events {
		applied, applyErr := store.ApplyAssessmentSamplingEvent(ctx, event)
		if applyErr != nil || !applied {
			t.Fatalf("ApplyAssessmentSamplingEvent() = (%v, %v)", applied, applyErr)
		}
	}
	if applied, applyErr := store.ApplyAssessmentSamplingEvent(ctx, events[0]); applyErr != nil || applied {
		t.Fatalf("duplicate ApplyAssessmentSamplingEvent() = (%v, %v), want no-op", applied, applyErr)
	}
	if _, err := store.GetAssessmentActivity(ctx, tenantID, "activity-one"); err != nil {
		t.Fatalf("GetAssessmentActivity() error = %v", err)
	}
	if _, err := store.GetAssessmentPopulation(ctx, tenantID, "population-one"); err != nil {
		t.Fatalf("GetAssessmentPopulation() error = %v", err)
	}
	if _, err := store.GetAssessmentSample(ctx, tenantID, "sample-one"); err != nil {
		t.Fatalf("GetAssessmentSample() error = %v", err)
	}
	if _, err := store.GetAssessmentActivity(ctx, tenantID+"-foreign", "activity-one"); !errors.Is(err, complianceassessment.ErrActivityNotFound) {
		t.Fatalf("foreign tenant activity error = %v, want opaque not found", err)
	}
}

type samplingReplayState struct {
	receipts map[string]string
	versions map[string]uint64
	payloads map[string]string
}

func newSamplingReplayState() *samplingReplayState {
	return &samplingReplayState{receipts: map[string]string{}, versions: map[string]uint64{}, payloads: map[string]string{}}
}

func (state *samplingReplayState) apply(envelope *cerebrov1.EventEnvelope) error {
	event, err := decodeAssessmentSamplingEvent(envelope)
	if err != nil {
		return err
	}
	existing, exists := state.receipts[event.eventID]
	apply, err := assessmentSamplingReceiptDecision(existing, exists, event.eventDigest)
	if err != nil || !apply {
		return err
	}
	key := event.aggregateType + "\x00" + event.aggregateID
	current, aggregateExists := state.versions[key]
	if err := validateSamplingAdvance(aggregateExists, current, event.aggregateVersion); err != nil {
		return err
	}
	state.receipts[event.eventID] = event.eventDigest
	state.versions[key] = event.aggregateVersion
	state.payloads[key] = event.payloadJSON
	return nil
}

func (state *samplingReplayState) snapshot() []string {
	keys := make([]string, 0, len(state.payloads))
	for key := range state.payloads {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, fmt.Sprintf("%s|%d|%s", key, state.versions[key], state.payloads[key]))
	}
	return result
}

func testAssessmentSamplingEvents(t *testing.T, tenantID string) []*cerebrov1.EventEnvelope {
	t.Helper()
	population := testPopulationPayload(t)
	sample := testSampleSelection(t, population)
	return []*cerebrov1.EventEnvelope{
		testSamplingEventForTenant(t, tenantID, complianceassessment.AggregateTypeAssessmentActivity, "activity-one", 1, testActivity(complianceassessment.ActivityQueued)),
		testSamplingEventForTenant(t, tenantID, complianceassessment.AggregateTypeAssessmentActivity, "activity-one", 2, testActivity(complianceassessment.ActivityRunning)),
		testSamplingEventForTenant(t, tenantID, complianceassessment.AggregateTypeAssessmentActivity, "activity-one", 3, testActivity(complianceassessment.ActivityCompleted)),
		testSamplingEventForTenant(t, tenantID, complianceassessment.AggregateTypeAssessmentPopulation, population.Snapshot.ID, 1, population),
		testSamplingEventForTenant(t, tenantID, complianceassessment.AggregateTypeAssessmentSample, sample.ID, 1, sample),
	}
}

func testSamplingEvent(t *testing.T, aggregateType string, aggregateID string, version uint64, payload any) *cerebrov1.EventEnvelope {
	return testSamplingEventForTenant(t, "tenant-replay", aggregateType, aggregateID, version, payload)
}

func testSamplingEventForTenant(t *testing.T, tenantID string, aggregateType string, aggregateID string, version uint64, payload any) *cerebrov1.EventEnvelope {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal sampling payload: %v", err)
	}
	digest := assessmentSamplingDigest(encoded)
	if population, ok := payload.(complianceassessment.PopulationRecordedPayload); ok {
		digest = population.Snapshot.ContentDigest
	}
	if sample, ok := payload.(complianceassessment.SampleSelection); ok {
		digest = sample.SelectionDigest
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: samplingTestEventKind(aggregateType), TenantID: tenantID, AggregateType: aggregateType,
		AggregateID: aggregateID, AggregateVersion: int64(version), // #nosec G115 -- test versions are small.
		Operation: "recorded", ContentDigest: digest, PayloadJSON: string(encoded),
		ActorID: "operator-one", RecordedAt: testSamplingTime().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("NewComplianceAggregateEvent() error = %v", err)
	}
	return event
}

func samplingTestEventKind(aggregateType string) string {
	switch aggregateType {
	case complianceassessment.AggregateTypeAssessmentActivity:
		return workflowevents.EventKindComplianceActivityRecorded
	case complianceassessment.AggregateTypeAssessmentPopulation:
		return workflowevents.EventKindCompliancePopulationRecorded
	case complianceassessment.AggregateTypeAssessmentSample:
		return workflowevents.EventKindComplianceSampleRecorded
	default:
		return ""
	}
}

func testActivity(state complianceassessment.ActivityExecutionState) complianceassessment.AssessmentActivity {
	activity := complianceassessment.AssessmentActivity{
		ID: "activity-one", RunID: "run-one", ObjectiveID: "objective-one", PlanTaskID: "task-one",
		Method: complianceassessment.ActivityTest, Procedure: "Inspect the selected records.",
		ExpectedResult: "Required fields are present.", ExecutionState: state, SubjectCount: 2,
	}
	if state == complianceassessment.ActivityRunning || state == complianceassessment.ActivityCompleted {
		activity.StartedAt = testSamplingTime()
	}
	if state == complianceassessment.ActivityCompleted {
		activity.FinishedAt = testSamplingTime().Add(time.Minute)
	}
	return activity
}

func testPopulationPayload(t *testing.T) complianceassessment.PopulationRecordedPayload {
	t.Helper()
	subjects := []complianceassessment.PopulationSubject{
		{ID: "a", Type: "asset"}, {ID: "b", Type: "asset"},
		{ID: "c", Type: "asset"}, {ID: "d", Type: "asset"},
	}
	normalized, err := complianceassessment.NormalizePopulation(subjects)
	if err != nil {
		t.Fatalf("NormalizePopulation() error = %v", err)
	}
	digest, err := complianceassessment.PopulationDigest(normalized)
	if err != nil {
		t.Fatalf("PopulationDigest() error = %v", err)
	}
	return complianceassessment.PopulationRecordedPayload{
		Snapshot: complianceassessment.PopulationSnapshot{
			ID: "population-one", RunID: "run-one", ObjectiveID: "objective-one",
			QueryDigest: testSamplingDigest("1"), SourceWatermark: testSamplingTime(),
			ExpectedCount: uint64(len(normalized)), ObservedCount: uint64(len(normalized)),
			Complete: true, ContentDigest: digest,
		}, Subjects: normalized,
	}
}

func testSampleSelection(t *testing.T, population complianceassessment.PopulationRecordedPayload) complianceassessment.SampleSelection {
	t.Helper()
	sample, err := complianceassessment.SelectDeterministicSample(population.Snapshot.ID, "seed-1", 2, population.Subjects)
	if err != nil {
		t.Fatalf("SelectDeterministicSample() error = %v", err)
	}
	sample.ID = "sample-one"
	return sample
}

func cleanupAssessmentSamplingTenant(t *testing.T, ctx context.Context, store *Store, tenantID string) {
	t.Helper()
	for _, statement := range []string{
		`DELETE FROM compliance_sampling_event_application_receipts WHERE tenant_id = $1`,
		`DELETE FROM compliance_assessment_sample_subjects WHERE tenant_id = $1`,
		`DELETE FROM compliance_assessment_samples WHERE tenant_id = $1`,
		`DELETE FROM compliance_assessment_population_subjects WHERE tenant_id = $1`,
		`DELETE FROM compliance_assessment_populations WHERE tenant_id = $1`,
		`DELETE FROM compliance_assessment_activity_revisions WHERE tenant_id = $1`,
		`DELETE FROM compliance_assessment_activities WHERE tenant_id = $1`,
	} {
		if _, err := store.db.ExecContext(ctx, statement, tenantID); err != nil {
			t.Fatalf("clean assessment sampling tenant: %v", err)
		}
	}
}

func testSamplingDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func testSamplingTime() time.Time {
	return time.Date(2026, time.July, 12, 2, 0, 0, 0, time.UTC)
}
