package sync

import (
	"context"

	"google.golang.org/api/option"
)

type gcpClientOptionsContextKey struct{}

func WithGCPClientOptions(ctx context.Context, opts ...option.ClientOption) context.Context {
	if len(opts) == 0 {
		return ctx
	}

	filtered := make([]option.ClientOption, 0, len(opts))
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		filtered = append(filtered, opt)
	}
	if len(filtered) == 0 {
		return ctx
	}

	return context.WithValue(ctx, gcpClientOptionsContextKey{}, filtered)
}

func gcpClientOptionsFromContext(ctx context.Context) []option.ClientOption {
	if ctx == nil {
		return nil
	}

	raw := ctx.Value(gcpClientOptionsContextKey{})
	if raw == nil {
		return nil
	}

	opts, ok := raw.([]option.ClientOption)
	if !ok || len(opts) == 0 {
		return nil
	}

	copyOpts := make([]option.ClientOption, len(opts))
	copy(copyOpts, opts)
	return copyOpts
}
