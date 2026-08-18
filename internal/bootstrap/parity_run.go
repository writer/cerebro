package bootstrap

import (
	"fmt"
	"net/http"

	"github.com/writer/cerebro/internal/parityrun"
)

func withParityCorrelation(r *http.Request) (*http.Request, error) {
	runValues := r.Header.Values(parityrun.HeaderName)
	observationValues := r.Header.Values(parityrun.ObservationHeaderName)
	if len(runValues) > 1 || len(observationValues) > 1 {
		return nil, fmt.Errorf("%w: parity correlation headers must be supplied at most once", errInvalidHTTPRequest)
	}
	runID, observationID := "", ""
	if len(runValues) == 1 {
		runID = runValues[0]
	}
	if len(observationValues) == 1 {
		observationID = observationValues[0]
	}
	ctx, err := parityrun.WithIDs(r.Context(), runID, observationID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidHTTPRequest, err)
	}
	return r.WithContext(ctx), nil
}
