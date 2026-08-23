package grcprogram

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"
)

// RunReadinessEnrichments runs required enrichment alongside bounded optional
// enrichment. Optional failure degrades the response; required failure stops it.
func RunReadinessEnrichments[Required, Optional any](ctx context.Context, optionalTimeout time.Duration, required func(context.Context) (Required, error), optional func(context.Context) (Optional, error)) (Required, Optional, error) {
	var requiredResult Required
	var optionalResult Optional
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		var err error
		requiredResult, err = required(groupCtx)
		return err
	})
	group.Go(func() error {
		optionalCtx, cancel := context.WithTimeout(groupCtx, optionalTimeout)
		defer cancel()
		var err error
		optionalResult, err = optional(optionalCtx)
		if err != nil {
			var zero Optional
			optionalResult = zero
		}
		return nil
	})
	return requiredResult, optionalResult, group.Wait()
}
