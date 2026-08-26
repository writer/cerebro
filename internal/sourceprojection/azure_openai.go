package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errAzureOpenaiRustProjectionRequired = errors.New("azure_openai projection requires Rust authority")

func azureOpenaiDeploymentsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAzureOpenaiRustProjectionRequired
}

func azureOpenaiModelCatalogProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAzureOpenaiRustProjectionRequired
}

func azureOpenaiRaiPoliciesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAzureOpenaiRustProjectionRequired
}

func azureOpenaiRaiBlocklistsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAzureOpenaiRustProjectionRequired
}

func azureOpenaiPrivateEndpointConnectionsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAzureOpenaiRustProjectionRequired
}
