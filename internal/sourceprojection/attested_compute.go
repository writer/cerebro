package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/attestedcompute"
	"github.com/writer/cerebro/internal/ports"
)

func attestedComputeGraphDeltaProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return attestedcompute.ProjectEvent(event)
}
