package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errAwsBedrockRustProjectionRequired = errors.New("aws_bedrock projection requires Rust authority")

func awsBedrockFoundationModelsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAwsBedrockRustProjectionRequired
}

func awsBedrockCustomModelsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAwsBedrockRustProjectionRequired
}

func awsBedrockProvisionedModelThroughputsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAwsBedrockRustProjectionRequired
}

func awsBedrockModelCustomizationJobsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAwsBedrockRustProjectionRequired
}

func awsBedrockGuardrailsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAwsBedrockRustProjectionRequired
}
