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
		Columns: []string{"arn", "account_id", "region", "instance_id", "instance_type", "state_name", "public_ip_address", "private_ip_address", "vpc_id", "subnet_id", "security_groups", "iam_instance_profile", "tags", "launch_time", "image_id", "platform"},
		Fetch:   e.fetchEC2Instances,
	}
}

func (e *SyncEngine) ec2SecurityGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_security_groups",
		Columns: []string{"arn", "account_id", "region", "group_id", "group_name", "description", "vpc_id", "owner_id", "ip_permissions", "ip_permissions_egress", "tags"},
		Fetch:   e.fetchSecurityGroups,
	}
}

func (e *SyncEngine) ec2VPCTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_vpcs",
		Columns: []string{"arn", "account_id", "region", "vpc_id", "cidr_block", "state", "is_default", "owner_id", "dhcp_options_id", "instance_tenancy", "tags"},
		Fetch:   e.fetchVPCs,
	}
}

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

			rows = append(rows, map[string]interface{}{
				"_cq_id":               arn,
				"arn":                  arn,
				"account_id":           accountID,
				"region":               region,
				"instance_id":          instanceID,
				"instance_type":        string(inst.InstanceType),
				"state_name":           string(inst.State.Name),
				"public_ip_address":    aws.ToString(inst.PublicIpAddress),
				"private_ip_address":   aws.ToString(inst.PrivateIpAddress),
				"vpc_id":               aws.ToString(inst.VpcId),
				"subnet_id":            aws.ToString(inst.SubnetId),
				"security_groups":      inst.SecurityGroups,
				"iam_instance_profile": iamProfile,
				"tags":                 inst.Tags,
				"launch_time":          inst.LaunchTime,
				"image_id":             aws.ToString(inst.ImageId),
				"platform":             string(inst.Platform),
			})
		}
	}
	return rows, nil
}

func (e *SyncEngine) fetchSecurityGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.SecurityGroups))
	for _, sg := range out.SecurityGroups {
		groupID := aws.ToString(sg.GroupId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", region, accountID, groupID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":                arn,
			"arn":                   arn,
			"account_id":            accountID,
			"region":                region,
			"group_id":              groupID,
			"group_name":            aws.ToString(sg.GroupName),
			"description":           aws.ToString(sg.Description),
			"vpc_id":                aws.ToString(sg.VpcId),
			"owner_id":              aws.ToString(sg.OwnerId),
			"ip_permissions":        sg.IpPermissions,
			"ip_permissions_egress": sg.IpPermissionsEgress,
			"tags":                  sg.Tags,
		})
	}
	return rows, nil
}

func (e *SyncEngine) fetchVPCs(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.Vpcs))
	for _, vpc := range out.Vpcs {
		vpcID := aws.ToString(vpc.VpcId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", region, accountID, vpcID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":           arn,
			"arn":              arn,
			"account_id":       accountID,
			"region":           region,
			"vpc_id":           vpcID,
			"cidr_block":       aws.ToString(vpc.CidrBlock),
			"state":            string(vpc.State),
			"is_default":       aws.ToBool(vpc.IsDefault),
			"owner_id":         aws.ToString(vpc.OwnerId),
			"dhcp_options_id":  aws.ToString(vpc.DhcpOptionsId),
			"instance_tenancy": string(vpc.InstanceTenancy),
			"tags":             vpc.Tags,
		})
	}
	return rows, nil
}
