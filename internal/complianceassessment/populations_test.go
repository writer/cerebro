package complianceassessment

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
)

func TestDeterministicSampleSurvivesShuffleDuplicatesAndLargePopulation(t *testing.T) {
	t.Parallel()
	subjects := make([]PopulationSubject, 0, 1205)
	for index := 0; index < 1205; index++ {
		subjects = append(subjects, PopulationSubject{Type: "asset", ID: fmt.Sprintf("asset-%04d", index)})
	}
	want, err := SelectDeterministicSample("population-1", "seed-1", 75, subjects)
	if err != nil {
		t.Fatalf("SelectDeterministicSample() error = %v", err)
	}
	shuffled := append([]PopulationSubject(nil), subjects...)
	rand.New(rand.NewSource(42)).Shuffle(len(shuffled), func(i, j int) { //nolint:gosec // deterministic test shuffle only.
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	shuffled = append(shuffled, subjects[0], subjects[100])
	got, err := SelectDeterministicSample("population-1", "seed-1", 75, shuffled)
	if err != nil {
		t.Fatalf("SelectDeterministicSample(shuffled) error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sample changed after shuffle or duplicates\ngot=%#v\nwant=%#v", got, want)
	}
}

func TestDeterministicSampleChangesWithSeed(t *testing.T) {
	t.Parallel()
	subjects := []PopulationSubject{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	left, err := SelectDeterministicSample("population-1", "seed-1", 2, subjects)
	if err != nil {
		t.Fatal(err)
	}
	right, err := SelectDeterministicSample("population-1", "seed-2", 2, subjects)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(left.Subjects, right.Subjects) {
		t.Fatalf("different seeds returned identical subjects: %#v", left.Subjects)
	}
}

func TestDeterministicSampleRejectsInvalidSizeAndIdentity(t *testing.T) {
	t.Parallel()
	if _, err := SelectDeterministicSample("population-1", "seed", 2, []PopulationSubject{{ID: "only"}}); err == nil {
		t.Fatal("oversized sample unexpectedly accepted")
	}
	if _, err := PopulationDigest([]PopulationSubject{{ID: " "}}); err == nil {
		t.Fatal("empty subject id unexpectedly accepted")
	}
}

func TestActivityExecutionFailureIsNotAControlOutcome(t *testing.T) {
	t.Parallel()
	activity := AssessmentActivity{ExecutionState: ActivityFailed, FailureCode: "source_unavailable"}
	if activity.ExecutionState == ActivityCompleted {
		t.Fatal("failed activity reported as completed")
	}
	// AssessmentActivity intentionally has no result or control-status field.
	type resultCarrier interface{ ControlOutcome() string }
	if _, ok := any(activity).(resultCarrier); ok {
		t.Fatal("activity execution unexpectedly exposes a control outcome")
	}
}
