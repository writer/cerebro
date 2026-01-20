package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

func (s *AWSSyncer) syncECSClusters(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := ecs.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_ecs_clusters", []string{
		"arn", "account_id", "region", "name", "status", "settings", "tags",
	}); err != nil {
		return nil, err
	}

	listOut, err := client.ListClusters(ctx, &ecs.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("list clusters: %w", err)
	}

	if len(listOut.ClusterArns) == 0 {
		return &SyncResult{Table: "aws_ecs_clusters", Duration: time.Since(start)}, nil
	}

	descOut, err := client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
		Clusters: listOut.ClusterArns,
		Include:  []ecstypes.ClusterField{ecstypes.ClusterFieldSettings, ecstypes.ClusterFieldTags},
	})
	if err != nil {
		return nil, fmt.Errorf("describe clusters: %w", err)
	}

	var rows []map[string]interface{}
	for _, c := range descOut.Clusters {
		rows = append(rows, map[string]interface{}{
			"_cq_id":     aws.ToString(c.ClusterArn),
			"arn":        aws.ToString(c.ClusterArn),
			"account_id": accountID,
			"region":     s.region,
			"name":       aws.ToString(c.ClusterName),
			"status":     aws.ToString(c.Status),
			"settings":   c.Settings,
			"tags":       c.Tags,
		})
	}

	changes, err := s.upsertRows(ctx, "aws_ecs_clusters", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_ecs_clusters", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}

func (s *AWSSyncer) syncECSServices(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := ecs.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_ecs_services", []string{
		"arn", "account_id", "region", "name", "cluster_arn", "status", "task_definition",
		"desired_count", "running_count", "launch_type", "network_configuration",
	}); err != nil {
		return nil, err
	}

	listClusters, err := client.ListClusters(ctx, &ecs.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("list clusters: %w", err)
	}

	var rows []map[string]interface{}
	for _, clusterArn := range listClusters.ClusterArns {
		listOut, err := client.ListServices(ctx, &ecs.ListServicesInput{Cluster: aws.String(clusterArn)})
		if err != nil || len(listOut.ServiceArns) == 0 {
			continue
		}

		descOut, err := client.DescribeServices(ctx, &ecs.DescribeServicesInput{
			Cluster:  aws.String(clusterArn),
			Services: listOut.ServiceArns,
		})
		if err != nil {
			continue
		}

		for _, svc := range descOut.Services {
			rows = append(rows, map[string]interface{}{
				"_cq_id":                aws.ToString(svc.ServiceArn),
				"arn":                   aws.ToString(svc.ServiceArn),
				"account_id":            accountID,
				"region":                s.region,
				"name":                  aws.ToString(svc.ServiceName),
				"cluster_arn":           aws.ToString(svc.ClusterArn),
				"status":                aws.ToString(svc.Status),
				"task_definition":       aws.ToString(svc.TaskDefinition),
				"desired_count":         svc.DesiredCount,
				"running_count":         svc.RunningCount,
				"launch_type":           string(svc.LaunchType),
				"network_configuration": svc.NetworkConfiguration,
			})
		}
	}

	changes, err := s.upsertRows(ctx, "aws_ecs_services", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_ecs_services", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}

func (s *AWSSyncer) syncECSTaskDefinitions(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := ecs.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_ecs_task_definitions", []string{
		"arn", "account_id", "region", "family", "revision", "status", "network_mode",
		"container_definitions", "task_role_arn", "execution_role_arn",
		"cpu", "memory", "requires_compatibilities",
	}); err != nil {
		return nil, err
	}

	listOut, err := client.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{
		Status: ecstypes.TaskDefinitionStatusActive,
	})
	if err != nil {
		return nil, fmt.Errorf("list task definitions: %w", err)
	}

	var rows []map[string]interface{}
	for _, arn := range listOut.TaskDefinitionArns {
		descOut, err := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: aws.String(arn),
		})
		if err != nil {
			continue
		}

		td := descOut.TaskDefinition
		rows = append(rows, map[string]interface{}{
			"_cq_id":                   aws.ToString(td.TaskDefinitionArn),
			"arn":                      aws.ToString(td.TaskDefinitionArn),
			"account_id":               accountID,
			"region":                   s.region,
			"family":                   aws.ToString(td.Family),
			"revision":                 td.Revision,
			"status":                   string(td.Status),
			"network_mode":             string(td.NetworkMode),
			"container_definitions":    td.ContainerDefinitions,
			"task_role_arn":            aws.ToString(td.TaskRoleArn),
			"execution_role_arn":       aws.ToString(td.ExecutionRoleArn),
			"cpu":                      aws.ToString(td.Cpu),
			"memory":                   aws.ToString(td.Memory),
			"requires_compatibilities": td.RequiresCompatibilities,
		})
	}

	changes, err := s.upsertRows(ctx, "aws_ecs_task_definitions", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_ecs_task_definitions", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}

func (s *AWSSyncer) syncEC2Instances(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := ec2.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_ec2_instances", []string{
		"arn", "account_id", "region", "instance_id", "instance_type",
		"state_name", "public_ip_address", "private_ip_address",
		"vpc_id", "subnet_id", "security_groups", "iam_instance_profile",
		"tags", "launch_time", "image_id", "platform",
	}); err != nil {
		return nil, err
	}

	out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("describe instances: %w", err)
	}

	var rows []map[string]interface{}
	for _, res := range out.Reservations {
		for _, inst := range res.Instances {
			instanceID := aws.ToString(inst.InstanceId)
			arn := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", s.region, accountID, instanceID)

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
				"region":               s.region,
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

	changes, err := s.upsertRows(ctx, "aws_ec2_instances", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_ec2_instances", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}

func (s *AWSSyncer) syncSecurityGroups(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := ec2.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_ec2_security_groups", []string{
		"arn", "account_id", "region", "group_id", "group_name", "description", "vpc_id", "owner_id",
		"ip_permissions", "ip_permissions_egress", "tags",
	}); err != nil {
		return nil, err
	}

	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe security groups: %w", err)
	}

	var rows []map[string]interface{}
	for _, sg := range out.SecurityGroups {
		groupID := aws.ToString(sg.GroupId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", s.region, accountID, groupID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":                arn,
			"arn":                   arn,
			"account_id":            accountID,
			"region":                s.region,
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

	changes, err := s.upsertRows(ctx, "aws_ec2_security_groups", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_ec2_security_groups", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}

func (s *AWSSyncer) syncVPCs(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := ec2.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_ec2_vpcs", []string{
		"arn", "account_id", "region", "vpc_id", "cidr_block", "state", "is_default", "owner_id",
		"dhcp_options_id", "instance_tenancy", "tags",
	}); err != nil {
		return nil, err
	}

	out, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe vpcs: %w", err)
	}

	var rows []map[string]interface{}
	for _, vpc := range out.Vpcs {
		vpcID := aws.ToString(vpc.VpcId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", s.region, accountID, vpcID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":           arn,
			"arn":              arn,
			"account_id":       accountID,
			"region":           s.region,
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

	changes, err := s.upsertRows(ctx, "aws_ec2_vpcs", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_ec2_vpcs", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}

func (s *AWSSyncer) syncLambdaFunctions(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := lambda.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_lambda_functions", []string{
		"arn", "account_id", "region", "function_name", "name", "runtime", "role", "handler",
		"code_size", "timeout", "memory_size", "environment", "description",
		"vpc_config", "last_modified",
	}); err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list functions: %w", err)
		}

		for _, fn := range page.Functions {
			var env interface{}
			if fn.Environment != nil {
				env = fn.Environment.Variables
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":        aws.ToString(fn.FunctionArn),
				"arn":           aws.ToString(fn.FunctionArn),
				"account_id":    accountID,
				"region":        s.region,
				"function_name": aws.ToString(fn.FunctionName),
				"name":          aws.ToString(fn.FunctionName),
				"runtime":       string(fn.Runtime),
				"role":          aws.ToString(fn.Role),
				"handler":       aws.ToString(fn.Handler),
				"code_size":     fn.CodeSize,
				"timeout":       fn.Timeout,
				"memory_size":   fn.MemorySize,
				"environment":   env,
				"description":   aws.ToString(fn.Description),
				"vpc_config":    fn.VpcConfig,
				"last_modified": aws.ToString(fn.LastModified),
			})
		}
	}

	changes, err := s.upsertRows(ctx, "aws_lambda_functions", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_lambda_functions", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}
