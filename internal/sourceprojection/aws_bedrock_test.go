package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAwsBedrockGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"aws_bedrock.custom_models",
		"aws_bedrock.foundation_models",
		"aws_bedrock.guardrails",
		"aws_bedrock.model_customization_jobs",
		"aws_bedrock.provisioned_model_throughputs",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "aws_bedrock",
				Kind:     kind,
			})
			if !errors.Is(err, errAwsBedrockRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
