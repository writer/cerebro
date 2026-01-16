package jobs

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

func LoadAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	if region != "" {
		return config.LoadDefaultConfig(ctx, config.WithRegion(region))
	}
	return config.LoadDefaultConfig(ctx)
}
