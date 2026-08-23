package grcprogram

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunReadinessEnrichmentsIgnoresOptionalFailure(t *testing.T) {
	optionalErr := errors.New("optional enrichment unavailable")
	required, optional, err := RunReadinessEnrichments(t.Context(), time.Second, func(context.Context) (string, error) { return "required", nil }, func(context.Context) (string, error) { return "partial", optionalErr })
	if err != nil {
		t.Fatalf("RunReadinessEnrichments() error = %v, want nil", err)
	}
	if required != "required" || optional != "" {
		t.Fatalf("RunReadinessEnrichments() = %q, %q, want required result and omitted optional result", required, optional)
	}
}

func TestRunReadinessEnrichmentsReturnsRequiredFailure(t *testing.T) {
	requiredErr := errors.New("required enrichment unavailable")
	_, _, err := RunReadinessEnrichments(t.Context(), time.Second, func(context.Context) (string, error) { return "", requiredErr }, func(context.Context) (string, error) { return "optional", nil })
	if !errors.Is(err, requiredErr) {
		t.Fatalf("RunReadinessEnrichments() error = %v, want %v", err, requiredErr)
	}
}

func TestRunReadinessEnrichmentsBoundsOptionalWork(t *testing.T) {
	startedAt := time.Now()
	_, _, err := RunReadinessEnrichments(t.Context(), time.Millisecond, func(context.Context) (string, error) { return "required", nil }, func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	})
	if err != nil {
		t.Fatalf("RunReadinessEnrichments() error = %v, want nil", err)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("RunReadinessEnrichments() elapsed = %s, want bounded optional work", elapsed)
	}
}
