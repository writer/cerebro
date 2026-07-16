package endpointtelemetry

import (
	"context"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// Persistence returns the durable commit step for a normalized telemetry
// request. Append precedes graph projection so accepted responses always refer
// to events present in the configured append log.
func Persistence(events []*cerebrov1.EventEnvelope, appendLog ports.AppendLog, projector ports.SourceProjector) func(context.Context) error {
	return func(ctx context.Context) error {
		if batcher, ok := appendLog.(ports.AppendLogBatcher); ok {
			if err := batcher.AppendBatch(ctx, events); err != nil {
				return err
			}
		} else {
			for _, event := range events {
				if err := appendLog.Append(ctx, event); err != nil {
					return err
				}
			}
		}
		for _, event := range events {
			if _, err := projector.Project(ctx, event); err != nil {
				return err
			}
		}
		return nil
	}
}
