package operationtelemetry

import (
	"context"

	"github.com/writer/cerebro/internal/telemetry"
)

type Work func(context.Context) (telemetry.Attributes, error)

func Run(ctx context.Context, name string, start telemetry.Attributes, work Work) error {
	spanCtx, span := telemetry.Start(ctx, name, start)
	attrs, err := work(spanCtx)
	attrs = start.With(attrs)
	status := "completed"
	if err != nil {
		status = "failed"
	}
	telemetry.End(span, status, attrs)
	return err
}

func RunMainPhase(ctx context.Context, name string, start telemetry.Attributes, work Work) error {
	return Run(ctx, name, start, func(spanCtx context.Context) (telemetry.Attributes, error) {
		attrs, err := work(spanCtx)
		status := "completed"
		if err != nil {
			status = "failed"
		}
		telemetry.AnnotateMainPhase(spanCtx, name, status, attrs)
		return attrs, err
	})
}
