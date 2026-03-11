package app

import (
	"context"

	"github.com/writer/cerebro/internal/telemetry"
)

func (a *App) initTelemetry(ctx context.Context) error {
	if a.Config == nil || !a.Config.TracingEnabled {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	shutdown, err := telemetry.Init(ctx, telemetry.Config{
		Enabled:       true,
		ServiceName:   a.Config.TracingServiceName,
		OTLPEndpoint:  a.Config.TracingOTLPEndpoint,
		OTLPInsecure:  a.Config.TracingOTLPInsecure,
		OTLPHeaders:   a.Config.TracingOTLPHeaders,
		SampleRatio:   a.Config.TracingSampleRatio,
		ExportTimeout: a.Config.TracingExportTimeout,
	})
	if err != nil {
		return err
	}

	a.traceShutdown = shutdown
	if a.Logger != nil {
		a.Logger.Info("opentelemetry tracing enabled",
			"service", a.Config.TracingServiceName,
			"endpoint", a.Config.TracingOTLPEndpoint,
			"sample_ratio", a.Config.TracingSampleRatio,
		)
	}

	return nil
}
