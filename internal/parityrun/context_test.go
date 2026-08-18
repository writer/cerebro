package parityrun

import (
	"context"
	"errors"
	"testing"
)

func TestWithIDPreservesValidValue(t *testing.T) {
	const runID = "cutover.run-2026:08_13"
	const observationID = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	ctx, err := WithIDs(context.Background(), runID, observationID)
	if err != nil {
		t.Fatalf("WithID() error = %v", err)
	}
	if got := FromContext(ctx); got != (Values{RunID: runID, ObservationID: observationID}) {
		t.Fatalf("FromContext() = %#v", got)
	}
}

func TestWithIDAllowsAbsentValue(t *testing.T) {
	ctx, err := WithIDs(context.Background(), "", "")
	if err != nil {
		t.Fatalf("WithID() error = %v", err)
	}
	if got := FromContext(ctx); got != (Values{}) {
		t.Fatalf("FromContext() = %#v, want empty", got)
	}
}

func TestWithIDRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{
		"short",
		" leading-space",
		"trailing-space ",
		"contains/slash",
		"contains,boundary",
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-x",
	} {
		t.Run(value, func(t *testing.T) {
			ctx, err := WithIDs(context.Background(), value, "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
			if !errors.Is(err, ErrInvalidRunID) {
				t.Fatalf("WithID() error = %v, want ErrInvalidRunID", err)
			}
			if ctx != nil {
				t.Fatal("WithID() returned a context for an invalid value")
			}
		})
	}
}

func TestWithIDsRejectsMissingOrInvalidObservationID(t *testing.T) {
	for _, value := range []string{"", "sha256:ABCDEF", "sha256:0123"} {
		if _, err := WithIDs(context.Background(), "cutover-run-2026", value); !errors.Is(err, ErrInvalidObservationID) {
			t.Fatalf("WithIDs(%q) error = %v", value, err)
		}
	}
}
