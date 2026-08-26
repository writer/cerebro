package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errGoogleVertexAiRustProjectionRequired = errors.New("google_vertex_ai projection requires Rust authority")

func googleVertexAiModelsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errGoogleVertexAiRustProjectionRequired
}

func googleVertexAiEndpointsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errGoogleVertexAiRustProjectionRequired
}

func googleVertexAiCustomJobsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errGoogleVertexAiRustProjectionRequired
}

func googleVertexAiBatchPredictionJobsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errGoogleVertexAiRustProjectionRequired
}

func googleVertexAiIndexesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errGoogleVertexAiRustProjectionRequired
}

func googleVertexAiReasoningEnginesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errGoogleVertexAiRustProjectionRequired
}
