package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

type AWSSyncer struct {
	sf     *snowflake.Client
	logger *slog.Logger
	region string
}

func NewAWSSyncer(sf *snowflake.Client, logger *slog.Logger) *AWSSyncer {
	return &AWSSyncer{
		sf:     sf,
		logger: logger,
		region: "us-east-1",
	}
}

type SyncResult struct {
	Table     string
	Synced    int
	Errors    int
	Duration  time.Duration
}

func (s *AWSSyncer) SyncAll(ctx context.Context) ([]SyncResult, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(s.region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	var results []SyncResult

	// Sync each resource type
	syncFuncs := []struct {
		name string
		fn   func(context.Context, aws.Config) (*SyncResult, error)
	}{
		{"aws_ecs_clusters", s.syncECSClusters},
		{"aws_ecs_services", s.syncECSServices},
		{"aws_ecs_task_definitions", s.syncECSTaskDefinitions},
		{"aws_ec2_instances", s.syncEC2Instances},
		{"aws_ec2_security_groups", s.syncSecurityGroups},
		{"aws_iam_roles", s.syncIAMRoles},
		{"aws_iam_users", s.syncIAMUsers},
		{"aws_s3_buckets", s.syncS3Buckets},
		{"aws_lambda_functions", s.syncLambdaFunctions},
	}

	for _, sf := range syncFuncs {
		s.logger.Info("syncing", "table", sf.name)
		result, err := sf.fn(ctx, cfg)
		if err != nil {
			s.logger.Error("sync failed", "table", sf.name, "error", err)
			results = append(results, SyncResult{Table: sf.name, Errors: 1})
			continue
		}
		results = append(results, *result)
		s.logger.Info("synced", "table", sf.name, "count", result.Synced)
	}

	return results, nil
}

func (s *AWSSyncer) ensureTable(ctx context.Context, table string, columns []string) error {
	colDefs := make([]string, len(columns))
	for i, col := range columns {
		colDefs[i] = fmt.Sprintf("%s VARIANT", strings.ToUpper(col))
	}
	
	query := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		_CQ_ID VARCHAR PRIMARY KEY,
		_CQ_SYNC_TIME TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
		%s
	)`, table, strings.Join(colDefs, ", "))
	
	_, err := s.sf.Exec(ctx, query)
	return err
}

func (s *AWSSyncer) upsertRows(ctx context.Context, table string, rows []map[string]interface{}) error {
	if len(rows) == 0 {
		return nil
	}

	// Delete existing and insert new (simple overwrite)
	if _, err := s.sf.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
		// Table might not exist yet, that's ok
		s.logger.Debug("delete failed (table may not exist)", "error", err)
	}

	for _, row := range rows {
		id := row["_cq_id"].(string)
		delete(row, "_cq_id")
		
		cols := []string{"_CQ_ID"}
		selects := []string{fmt.Sprintf("'%s'", strings.ReplaceAll(id, "'", "''"))}
		
		for k, v := range row {
			cols = append(cols, strings.ToUpper(k))
			jsonVal, _ := json.Marshal(v)
			escaped := strings.ReplaceAll(string(jsonVal), "'", "''")
			selects = append(selects, fmt.Sprintf("PARSE_JSON('%s')", escaped))
		}
		
		// Use INSERT INTO ... SELECT instead of INSERT INTO ... VALUES for PARSE_JSON
		query := fmt.Sprintf("INSERT INTO %s (%s) SELECT %s",
			table, strings.Join(cols, ", "), strings.Join(selects, ", "))
		
		if _, err := s.sf.Exec(ctx, query); err != nil {
			return fmt.Errorf("insert row: %w", err)
		}
	}
	
	return nil
}

func (s *AWSSyncer) syncECSClusters(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := ecs.NewFromConfig(cfg)
	
	// Ensure table exists
	if err := s.ensureTable(ctx, "aws_ecs_clusters", []string{"arn", "name", "status", "settings", "tags"}); err != nil {
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
			"_cq_id":   aws.ToString(c.ClusterArn),
			"arn":      aws.ToString(c.ClusterArn),
			"name":     aws.ToString(c.ClusterName),
			"status":   aws.ToString(c.Status),
			"settings": c.Settings,
			"tags":     c.Tags,
		})
	}
	
	if err := s.upsertRows(ctx, "aws_ecs_clusters", rows); err != nil {
		return nil, err
	}
	
	return &SyncResult{Table: "aws_ecs_clusters", Synced: len(rows), Duration: time.Since(start)}, nil
}

func (s *AWSSyncer) syncECSServices(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := ecs.NewFromConfig(cfg)
	
	if err := s.ensureTable(ctx, "aws_ecs_services", []string{
		"arn", "name", "cluster_arn", "status", "task_definition", 
		"desired_count", "running_count", "launch_type", "network_configuration",
	}); err != nil {
		return nil, err
	}
	
	// List clusters first
	listClusters, err := client.ListClusters(ctx, &ecs.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("list clusters: %w", err)
	}
	
	var rows []map[string]interface{}
	for _, clusterArn := range listClusters.ClusterArns {
		listOut, err := client.ListServices(ctx, &ecs.ListServicesInput{
			Cluster: aws.String(clusterArn),
		})
		if err != nil {
			continue
		}
		
		if len(listOut.ServiceArns) == 0 {
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
	
	if err := s.upsertRows(ctx, "aws_ecs_services", rows); err != nil {
		return nil, err
	}
	
	return &SyncResult{Table: "aws_ecs_services", Synced: len(rows), Duration: time.Since(start)}, nil
}

func (s *AWSSyncer) syncECSTaskDefinitions(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := ecs.NewFromConfig(cfg)
	
	if err := s.ensureTable(ctx, "aws_ecs_task_definitions", []string{
		"arn", "family", "revision", "status", "network_mode",
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
			"_cq_id":                  aws.ToString(td.TaskDefinitionArn),
			"arn":                     aws.ToString(td.TaskDefinitionArn),
			"family":                  aws.ToString(td.Family),
			"revision":                td.Revision,
			"status":                  string(td.Status),
			"network_mode":            string(td.NetworkMode),
			"container_definitions":   td.ContainerDefinitions,
			"task_role_arn":           aws.ToString(td.TaskRoleArn),
			"execution_role_arn":      aws.ToString(td.ExecutionRoleArn),
			"cpu":                     aws.ToString(td.Cpu),
			"memory":                  aws.ToString(td.Memory),
			"requires_compatibilities": td.RequiresCompatibilities,
		})
	}
	
	if err := s.upsertRows(ctx, "aws_ecs_task_definitions", rows); err != nil {
		return nil, err
	}
	
	return &SyncResult{Table: "aws_ecs_task_definitions", Synced: len(rows), Duration: time.Since(start)}, nil
}

func (s *AWSSyncer) syncEC2Instances(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := ec2.NewFromConfig(cfg)
	
	if err := s.ensureTable(ctx, "aws_ec2_instances", []string{
		"instance_id", "instance_type", "state", "public_ip", "private_ip",
		"vpc_id", "subnet_id", "security_groups", "iam_instance_profile",
		"tags", "launch_time",
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
			var iamProfile interface{}
			if inst.IamInstanceProfile != nil {
				iamProfile = map[string]string{
					"arn": aws.ToString(inst.IamInstanceProfile.Arn),
					"id":  aws.ToString(inst.IamInstanceProfile.Id),
				}
			}
			
			rows = append(rows, map[string]interface{}{
				"_cq_id":               aws.ToString(inst.InstanceId),
				"instance_id":          aws.ToString(inst.InstanceId),
				"instance_type":        string(inst.InstanceType),
				"state":                string(inst.State.Name),
				"public_ip":            aws.ToString(inst.PublicIpAddress),
				"private_ip":           aws.ToString(inst.PrivateIpAddress),
				"vpc_id":               aws.ToString(inst.VpcId),
				"subnet_id":            aws.ToString(inst.SubnetId),
				"security_groups":      inst.SecurityGroups,
				"iam_instance_profile": iamProfile,
				"tags":                 inst.Tags,
				"launch_time":          inst.LaunchTime,
			})
		}
	}
	
	if err := s.upsertRows(ctx, "aws_ec2_instances", rows); err != nil {
		return nil, err
	}
	
	return &SyncResult{Table: "aws_ec2_instances", Synced: len(rows), Duration: time.Since(start)}, nil
}

func (s *AWSSyncer) syncSecurityGroups(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := ec2.NewFromConfig(cfg)
	
	if err := s.ensureTable(ctx, "aws_ec2_security_groups", []string{
		"group_id", "group_name", "description", "vpc_id",
		"ingress_rules", "egress_rules", "tags",
	}); err != nil {
		return nil, err
	}
	
	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe security groups: %w", err)
	}
	
	var rows []map[string]interface{}
	for _, sg := range out.SecurityGroups {
		rows = append(rows, map[string]interface{}{
			"_cq_id":        aws.ToString(sg.GroupId),
			"group_id":      aws.ToString(sg.GroupId),
			"group_name":    aws.ToString(sg.GroupName),
			"description":   aws.ToString(sg.Description),
			"vpc_id":        aws.ToString(sg.VpcId),
			"ingress_rules": sg.IpPermissions,
			"egress_rules":  sg.IpPermissionsEgress,
			"tags":          sg.Tags,
		})
	}
	
	if err := s.upsertRows(ctx, "aws_ec2_security_groups", rows); err != nil {
		return nil, err
	}
	
	return &SyncResult{Table: "aws_ec2_security_groups", Synced: len(rows), Duration: time.Since(start)}, nil
}

func (s *AWSSyncer) syncIAMRoles(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := iam.NewFromConfig(cfg)
	
	if err := s.ensureTable(ctx, "aws_iam_roles", []string{
		"arn", "role_name", "role_id", "path", "assume_role_policy_document",
		"create_date", "max_session_duration", "permissions_boundary", "tags",
	}); err != nil {
		return nil, err
	}
	
	var rows []map[string]interface{}
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list roles: %w", err)
		}
		
		for _, role := range page.Roles {
			rows = append(rows, map[string]interface{}{
				"_cq_id":                      aws.ToString(role.Arn),
				"arn":                         aws.ToString(role.Arn),
				"role_name":                   aws.ToString(role.RoleName),
				"role_id":                     aws.ToString(role.RoleId),
				"path":                        aws.ToString(role.Path),
				"assume_role_policy_document": aws.ToString(role.AssumeRolePolicyDocument),
				"create_date":                 role.CreateDate,
				"max_session_duration":        role.MaxSessionDuration,
				"permissions_boundary":        role.PermissionsBoundary,
				"tags":                        role.Tags,
			})
		}
	}
	
	if err := s.upsertRows(ctx, "aws_iam_roles", rows); err != nil {
		return nil, err
	}
	
	return &SyncResult{Table: "aws_iam_roles", Synced: len(rows), Duration: time.Since(start)}, nil
}

func (s *AWSSyncer) syncIAMUsers(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := iam.NewFromConfig(cfg)
	
	if err := s.ensureTable(ctx, "aws_iam_users", []string{
		"arn", "user_name", "user_id", "path", "create_date",
		"password_last_used", "permissions_boundary", "tags",
	}); err != nil {
		return nil, err
	}
	
	var rows []map[string]interface{}
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list users: %w", err)
		}
		
		for _, user := range page.Users {
			rows = append(rows, map[string]interface{}{
				"_cq_id":               aws.ToString(user.Arn),
				"arn":                  aws.ToString(user.Arn),
				"user_name":            aws.ToString(user.UserName),
				"user_id":              aws.ToString(user.UserId),
				"path":                 aws.ToString(user.Path),
				"create_date":          user.CreateDate,
				"password_last_used":   user.PasswordLastUsed,
				"permissions_boundary": user.PermissionsBoundary,
				"tags":                 user.Tags,
			})
		}
	}
	
	if err := s.upsertRows(ctx, "aws_iam_users", rows); err != nil {
		return nil, err
	}
	
	return &SyncResult{Table: "aws_iam_users", Synced: len(rows), Duration: time.Since(start)}, nil
}

func (s *AWSSyncer) syncS3Buckets(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := s3.NewFromConfig(cfg)
	
	if err := s.ensureTable(ctx, "aws_s3_buckets", []string{
		"name", "creation_date", "region", "public_access_block",
		"versioning", "encryption", "logging", "tags",
	}); err != nil {
		return nil, err
	}
	
	listOut, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}
	
	var rows []map[string]interface{}
	for _, bucket := range listOut.Buckets {
		name := aws.ToString(bucket.Name)
		
		row := map[string]interface{}{
			"_cq_id":        name,
			"name":          name,
			"creation_date": bucket.CreationDate,
		}
		
		// Get public access block
		pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &name})
		if err == nil && pab.PublicAccessBlockConfiguration != nil {
			row["public_access_block"] = map[string]bool{
				"block_public_acls":       aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicAcls),
				"block_public_policy":     aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicPolicy),
				"ignore_public_acls":      aws.ToBool(pab.PublicAccessBlockConfiguration.IgnorePublicAcls),
				"restrict_public_buckets": aws.ToBool(pab.PublicAccessBlockConfiguration.RestrictPublicBuckets),
			}
		}
		
		rows = append(rows, row)
	}
	
	if err := s.upsertRows(ctx, "aws_s3_buckets", rows); err != nil {
		return nil, err
	}
	
	return &SyncResult{Table: "aws_s3_buckets", Synced: len(rows), Duration: time.Since(start)}, nil
}

func (s *AWSSyncer) syncLambdaFunctions(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := lambda.NewFromConfig(cfg)
	
	if err := s.ensureTable(ctx, "aws_lambda_functions", []string{
		"arn", "function_name", "runtime", "role", "handler",
		"code_size", "timeout", "memory_size", "environment",
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
				"function_name": aws.ToString(fn.FunctionName),
				"runtime":       string(fn.Runtime),
				"role":          aws.ToString(fn.Role),
				"handler":       aws.ToString(fn.Handler),
				"code_size":     fn.CodeSize,
				"timeout":       fn.Timeout,
				"memory_size":   fn.MemorySize,
				"environment":   env,
				"vpc_config":    fn.VpcConfig,
				"last_modified": aws.ToString(fn.LastModified),
			})
		}
	}
	
	if err := s.upsertRows(ctx, "aws_lambda_functions", rows); err != nil {
		return nil, err
	}
	
	return &SyncResult{Table: "aws_lambda_functions", Synced: len(rows), Duration: time.Since(start)}, nil
}
