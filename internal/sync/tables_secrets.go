package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func (e *SyncEngine) secretsManagerSecretTable() TableSpec {
	return TableSpec{
		Name:    "aws_secretsmanager_secrets",
		Columns: []string{"arn", "account_id", "region", "name", "description", "kms_key_id", "rotation_enabled", "rotation_lambda_arn", "last_changed_date", "last_accessed_date", "deleted_date", "tags"},
		Fetch:   e.fetchSecretsManagerSecrets,
	}
}

func (e *SyncEngine) fetchSecretsManagerSecrets(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := secretsmanager.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, secret := range page.SecretList {
			rows = append(rows, map[string]interface{}{
				"_cq_id":              aws.ToString(secret.ARN),
				"arn":                 aws.ToString(secret.ARN),
				"account_id":          accountID,
				"region":              region,
				"name":                aws.ToString(secret.Name),
				"description":         aws.ToString(secret.Description),
				"kms_key_id":          aws.ToString(secret.KmsKeyId),
				"rotation_enabled":    aws.ToBool(secret.RotationEnabled),
				"rotation_lambda_arn": aws.ToString(secret.RotationLambdaARN),
				"last_changed_date":   secret.LastChangedDate,
				"last_accessed_date":  secret.LastAccessedDate,
				"deleted_date":        secret.DeletedDate,
				"tags":                secret.Tags,
			})
		}
	}
	return rows, nil
}
