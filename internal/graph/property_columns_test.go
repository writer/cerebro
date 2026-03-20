package graph

import (
	"testing"
	"time"
)

func TestPropertyColumnsObservationRoundTrip(t *testing.T) {
	columns := NewPropertyColumns()
	ordinal := NodeOrdinal(7)
	observedAt := time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC)
	validTo := observedAt.Add(time.Hour)

	columns.SetObservationProperties(ordinal, ObservationProperties{
		ObservationType: "runtime_signal",
		SubjectID:       "service:payments",
		Detail:          "error rate increased",
		SourceSystem:    "agent",
		SourceEventID:   "evt-7",
		Confidence:      0.92,
		ObservedAt:      observedAt,
		ValidFrom:       observedAt,
		ValidTo:         &validTo,
		RecordedAt:      observedAt.Add(time.Minute),
		TransactionFrom: observedAt.Add(time.Minute),
		present: observationPropertyObservationType |
			observationPropertySubjectID |
			observationPropertyDetail |
			observationPropertySourceSystem |
			observationPropertySourceEventID |
			observationPropertyConfidence |
			observationPropertyObservedAt |
			observationPropertyValidFrom |
			observationPropertyValidTo |
			observationPropertyRecordedAt |
			observationPropertyTransactionFrom,
	})

	props, ok := columns.ObservationProperties(ordinal)
	if !ok {
		t.Fatal("expected stored observation properties")
	}
	if props.ObservationType != "runtime_signal" || props.SubjectID != "service:payments" {
		t.Fatalf("unexpected observation properties: %+v", props)
	}
	if props.ValidTo == nil || !props.ValidTo.Equal(validTo) {
		t.Fatalf("ValidTo = %v, want %v", props.ValidTo, validTo)
	}

	columns.ClearObservationProperties(ordinal)
	if _, ok := columns.ObservationProperties(ordinal); ok {
		t.Fatal("expected observation properties to clear")
	}
}

func TestPropertyColumnsAttackSequenceCloneIsIndependent(t *testing.T) {
	columns := NewPropertyColumns()
	ordinal := NodeOrdinal(9)
	columns.SetAttackSequenceProperties(ordinal, AttackSequenceProperties{
		SequenceType:          "runtime_window",
		WorkloadRef:           "deployment:prod/api",
		ObservationCount:      3,
		ObservationTypes:      []string{"process_exec", "dns_query"},
		OrderedObservationIDs: []string{"observation:1", "observation:2"},
		present: attackSequencePropertySequenceType |
			attackSequencePropertyWorkloadRef |
			attackSequencePropertyObservationCount |
			attackSequencePropertyObservationTypes |
			attackSequencePropertyOrderedObservationIDs,
	})

	cloned := columns.Clone()
	cloned.SetAttackSequenceProperties(ordinal, AttackSequenceProperties{
		SequenceType:     "runtime_window",
		WorkloadRef:      "deployment:prod/api",
		ObservationCount: 5,
		present: attackSequencePropertySequenceType |
			attackSequencePropertyWorkloadRef |
			attackSequencePropertyObservationCount,
	})

	originalProps, ok := columns.AttackSequenceProperties(ordinal)
	if !ok {
		t.Fatal("expected original attack sequence properties")
	}
	clonedProps, ok := cloned.AttackSequenceProperties(ordinal)
	if !ok {
		t.Fatal("expected cloned attack sequence properties")
	}
	if originalProps.ObservationCount != 3 {
		t.Fatalf("original ObservationCount = %d, want 3", originalProps.ObservationCount)
	}
	if clonedProps.ObservationCount != 5 {
		t.Fatalf("cloned ObservationCount = %d, want 5", clonedProps.ObservationCount)
	}
}

func TestPropertyColumnsZeroTimesRoundTrip(t *testing.T) {
	columns := NewPropertyColumns()

	observationOrdinal := NodeOrdinal(11)
	columns.SetObservationProperties(observationOrdinal, ObservationProperties{
		ObservedAt: time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC),
		present:    observationPropertyObservedAt,
	})
	columns.SetObservationProperties(observationOrdinal, ObservationProperties{
		ObservedAt: time.Time{},
		present:    observationPropertyObservedAt,
	})

	observationProps, ok := columns.ObservationProperties(observationOrdinal)
	if !ok {
		t.Fatal("expected zero-valued observation time to remain present")
	}
	if !observationProps.ObservedAt.IsZero() {
		t.Fatalf("ObservedAt = %s, want zero time", observationProps.ObservedAt)
	}

	attackSequenceOrdinal := NodeOrdinal(12)
	columns.SetAttackSequenceProperties(attackSequenceOrdinal, AttackSequenceProperties{
		SequenceStart: time.Date(2026, 3, 20, 11, 0, 0, 0, time.UTC),
		present:       attackSequencePropertySequenceStart,
	})
	columns.SetAttackSequenceProperties(attackSequenceOrdinal, AttackSequenceProperties{
		SequenceStart: time.Time{},
		present:       attackSequencePropertySequenceStart,
	})

	attackSequenceProps, ok := columns.AttackSequenceProperties(attackSequenceOrdinal)
	if !ok {
		t.Fatal("expected zero-valued attack sequence time to remain present")
	}
	if !attackSequenceProps.SequenceStart.IsZero() {
		t.Fatalf("SequenceStart = %s, want zero time", attackSequenceProps.SequenceStart)
	}
}
