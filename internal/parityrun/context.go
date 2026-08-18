// Package parityrun carries a bounded cutover correlation identifier through a
// request without exposing request payloads or authorization data.
package parityrun

import (
	"context"
	"errors"
	"regexp"
)

const HeaderName = "X-Cerebro-Parity-Run-ID"
const ObservationHeaderName = "X-Cerebro-Parity-Observation-ID"

var (
	ErrInvalidRunID         = errors.New("parity run id is invalid")
	ErrInvalidObservationID = errors.New("parity observation id is invalid")
	runIDPattern            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`)
	observationIDPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type contextKey struct{}

type Values struct {
	RunID         string
	ObservationID string
}

// WithIDs validates and attaches one complete parity correlation pair. Both
// empty values mean the request is not part of a cutover parity exercise.
func WithIDs(ctx context.Context, runID, observationID string) (context.Context, error) {
	if runID == "" && observationID == "" {
		return ctx, nil
	}
	if !runIDPattern.MatchString(runID) {
		return nil, ErrInvalidRunID
	}
	if !observationIDPattern.MatchString(observationID) {
		return nil, ErrInvalidObservationID
	}
	return context.WithValue(ctx, contextKey{}, Values{RunID: runID, ObservationID: observationID}), nil
}

// FromContext returns the validated cutover correlation identifiers.
func FromContext(ctx context.Context) Values {
	value, _ := ctx.Value(contextKey{}).(Values)
	return value
}
