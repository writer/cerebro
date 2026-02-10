package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func (e *SyncEngine) ec2RegionalConfigTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_regional_configs",
		Columns: []string{
			"account_id",
			"region",
			"ebs_encryption_enabled",
			"default_kms_key_id",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ec2.NewFromConfig(cfg)
			accountID := e.getAccountIDFromConfig(ctx, cfg)

			encOut, err := client.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
			if err != nil {
				return nil, fmt.Errorf("get ebs encryption by default: %w", err)
			}

			row := map[string]interface{}{
				"_cq_id":                 fmt.Sprintf("%s:%s", accountID, region),
				"account_id":             accountID,
				"region":                 region,
				"ebs_encryption_enabled": aws.ToBool(encOut.EbsEncryptionByDefault),
			}

			if kmsOut, err := client.GetEbsDefaultKmsKeyId(ctx, &ec2.GetEbsDefaultKmsKeyIdInput{}); err == nil {
				row["default_kms_key_id"] = aws.ToString(kmsOut.KmsKeyId)
			}

			return []map[string]interface{}{row}, nil
		},
	}
}
