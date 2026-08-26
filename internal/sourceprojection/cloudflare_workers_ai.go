package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errCloudflareWorkersAiRustProjectionRequired = errors.New("cloudflare_workers_ai projection requires Rust authority")

func cloudflareWorkersAiModelCatalogProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareWorkersAiRustProjectionRequired
}

func cloudflareWorkersAiAiGatewaysProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareWorkersAiRustProjectionRequired
}

func cloudflareWorkersAiGatewayProviderConfigsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareWorkersAiRustProjectionRequired
}

func cloudflareWorkersAiGatewayEvaluationsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareWorkersAiRustProjectionRequired
}

func cloudflareWorkersAiGatewayLogsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareWorkersAiRustProjectionRequired
}

func cloudflareWorkersAiVectorizeIndexesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareWorkersAiRustProjectionRequired
}
