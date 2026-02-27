package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func (e *SyncEngine) ec2InstanceTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_instances",
		Columns: []string{"arn", "account_id", "region", "instance_id", "instance_type", "state_name", "public_ip_address", "private_ip_address", "vpc_id", "subnet_id", "security_groups", "iam_instance_profile", "metadata_options_http_tokens", "metadata_options_http_endpoint", "metadata_options_http_put_response_hop_limit", "metadata_options_instance_metadata_tags", "tags", "launch_time", "image_id", "platform"},
		Fetch:   e.fetchEC2Instances,
	}
}

// Note: ec2SecurityGroupTable and ec2VpcTable are defined in tables_vpc.go with more complete implementations

func (e *SyncEngine) fetchEC2Instances(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, err
	}

	instanceCount := 0
	for _, res := range out.Reservations {
		instanceCount += len(res.Instances)
	}

	rows := make([]map[string]interface{}, 0, instanceCount)
	for _, res := range out.Reservations {
		for _, inst := range res.Instances {
			instanceID := aws.ToString(inst.InstanceId)
			arn := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, accountID, instanceID)

			var iamProfile interface{}
			if inst.IamInstanceProfile != nil {
				iamProfile = map[string]string{
					"arn": aws.ToString(inst.IamInstanceProfile.Arn),
					"id":  aws.ToString(inst.IamInstanceProfile.Id),
				}
			}

			metadataHTTPTokens := ""
			metadataHTTPEndpoint := ""
			metadataHTTPPutHopLimit := int32(0)
			metadataInstanceTags := ""
			if inst.MetadataOptions != nil {
				metadataHTTPTokens = string(inst.MetadataOptions.HttpTokens)
				metadataHTTPEndpoint = string(inst.MetadataOptions.HttpEndpoint)
				metadataHTTPPutHopLimit = aws.ToInt32(inst.MetadataOptions.HttpPutResponseHopLimit)
				metadataInstanceTags = string(inst.MetadataOptions.InstanceMetadataTags)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                         arn,
				"arn":                            arn,
				"account_id":                     accountID,
				"region":                         region,
				"instance_id":                    instanceID,
				"instance_type":                  string(inst.InstanceType),
				"state_name":                     string(inst.State.Name),
				"public_ip_address":              aws.ToString(inst.PublicIpAddress),
				"private_ip_address":             aws.ToString(inst.PrivateIpAddress),
				"vpc_id":                         aws.ToString(inst.VpcId),
				"subnet_id":                      aws.ToString(inst.SubnetId),
				"security_groups":                inst.SecurityGroups,
				"iam_instance_profile":           iamProfile,
				"metadata_options_http_tokens":   metadataHTTPTokens,
				"metadata_options_http_endpoint": metadataHTTPEndpoint,
				"metadata_options_http_put_response_hop_limit": metadataHTTPPutHopLimit,
				"metadata_options_instance_metadata_tags":      metadataInstanceTags,
				"tags":        inst.Tags,
				"launch_time": inst.LaunchTime,
				"image_id":    aws.ToString(inst.ImageId),
				"platform":    string(inst.Platform),
			})
		}
	}
	return rows, nil
}
