package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
)

func (e *SyncEngine) bedrockCustomModelTable() TableSpec {
	return TableSpec{
		Name: "aws_bedrock_custom_models",
		Columns: []string{
			"arn", "model_arn", "model_name", "region", "account_id",
			"base_model_arn", "creation_time", "job_arn", "customization_type",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := bedrock.NewFromConfig(cfg)
			var results []map[string]interface{}
			var nextToken *string

			for {
				listOut, err := client.ListCustomModels(ctx, &bedrock.ListCustomModelsInput{
					NextToken: nextToken,
				})
				if err != nil {
					// Bedrock may not be available in all regions
					return results, nil
				}

				for _, model := range listOut.ModelSummaries {
					arn := ptrToStr(model.ModelArn)

					row := map[string]interface{}{
						"_cq_id":             arn,
						"arn":                arn,
						"model_arn":          arn,
						"model_name":         ptrToStr(model.ModelName),
						"region":             region,
						"account_id":         e.accountID,
						"base_model_arn":     ptrToStr(model.BaseModelArn),
						"creation_time":      model.CreationTime,
						"customization_type": string(model.CustomizationType),
					}

					results = append(results, row)
				}

				if listOut.NextToken == nil {
					break
				}
				nextToken = listOut.NextToken
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) bedrockProvisionedThroughputTable() TableSpec {
	return TableSpec{
		Name: "aws_bedrock_provisioned_model_throughputs",
		Columns: []string{
			"arn", "provisioned_model_arn", "provisioned_model_name",
			"region", "account_id", "model_arn", "desired_model_arn",
			"foundation_model_arn", "model_units", "desired_model_units",
			"status", "commitment_duration", "commitment_expiration_time",
			"creation_time", "last_modified_time",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := bedrock.NewFromConfig(cfg)
			var results []map[string]interface{}
			var nextToken *string

			for {
				listOut, err := client.ListProvisionedModelThroughputs(ctx, &bedrock.ListProvisionedModelThroughputsInput{
					NextToken: nextToken,
				})
				if err != nil {
					// Bedrock may not be available in all regions
					return results, nil
				}

				for _, pmt := range listOut.ProvisionedModelSummaries {
					arn := ptrToStr(pmt.ProvisionedModelArn)

					row := map[string]interface{}{
						"_cq_id":                     arn,
						"arn":                        arn,
						"provisioned_model_arn":      arn,
						"provisioned_model_name":     ptrToStr(pmt.ProvisionedModelName),
						"region":                     region,
						"account_id":                 e.accountID,
						"model_arn":                  ptrToStr(pmt.ModelArn),
						"desired_model_arn":          ptrToStr(pmt.DesiredModelArn),
						"foundation_model_arn":       ptrToStr(pmt.FoundationModelArn),
						"model_units":                pmt.ModelUnits,
						"desired_model_units":        pmt.DesiredModelUnits,
						"status":                     string(pmt.Status),
						"commitment_duration":        string(pmt.CommitmentDuration),
						"commitment_expiration_time": pmt.CommitmentExpirationTime,
						"creation_time":              pmt.CreationTime,
						"last_modified_time":         pmt.LastModifiedTime,
					}

					results = append(results, row)
				}

				if listOut.NextToken == nil {
					break
				}
				nextToken = listOut.NextToken
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) bedrockGuardrailTable() TableSpec {
	return TableSpec{
		Name: "aws_bedrock_guardrails",
		Columns: []string{
			"arn", "guardrail_id", "name", "region", "account_id",
			"version", "status", "description", "created_at", "updated_at",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := bedrock.NewFromConfig(cfg)
			var results []map[string]interface{}
			var nextToken *string

			for {
				listOut, err := client.ListGuardrails(ctx, &bedrock.ListGuardrailsInput{
					NextToken: nextToken,
				})
				if err != nil {
					return results, nil
				}

				for _, gr := range listOut.Guardrails {
					arn := ptrToStr(gr.Arn)

					row := map[string]interface{}{
						"_cq_id":       arn,
						"arn":          arn,
						"guardrail_id": ptrToStr(gr.Id),
						"name":         ptrToStr(gr.Name),
						"region":       region,
						"account_id":   e.accountID,
						"version":      ptrToStr(gr.Version),
						"status":       string(gr.Status),
						"description":  ptrToStr(gr.Description),
						"created_at":   gr.CreatedAt,
						"updated_at":   gr.UpdatedAt,
					}

					results = append(results, row)
				}

				if listOut.NextToken == nil {
					break
				}
				nextToken = listOut.NextToken
			}

			return results, nil
		},
	}
}
