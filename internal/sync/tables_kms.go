package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func (e *SyncEngine) kmsKeyTable() TableSpec {
	return TableSpec{
		Name:    "aws_kms_keys",
		Columns: []string{"arn", "account_id", "region", "key_id", "description", "key_state", "key_usage", "creation_date", "enabled", "key_manager", "origin"},
		Fetch:   e.fetchKMSKeys,
	}
}

func (e *SyncEngine) fetchKMSKeys(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := kms.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, key := range page.Keys {
			descOut, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyId})
			if err != nil {
				continue
			}

			km := descOut.KeyMetadata
			rows = append(rows, map[string]interface{}{
				"_cq_id":        aws.ToString(km.Arn),
				"arn":           aws.ToString(km.Arn),
				"account_id":    accountID,
				"region":        region,
				"key_id":        aws.ToString(km.KeyId),
				"description":   aws.ToString(km.Description),
				"key_state":     string(km.KeyState),
				"key_usage":     string(km.KeyUsage),
				"creation_date": km.CreationDate,
				"enabled":       km.Enabled,
				"key_manager":   string(km.KeyManager),
				"origin":        string(km.Origin),
			})
		}
	}
	return rows, nil
}
