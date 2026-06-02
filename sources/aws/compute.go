package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/writer/cerebro/internal/primitives"
)

type ecsServicePageCursor struct {
	ClusterIndex int    `json:"cluster_index,omitempty"`
	ServiceToken string `json:"service_token,omitempty"`
}

func listEC2Instances(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsEC2Instance, string, error) {
	output, err := clients.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 5, 1000))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsEC2Instance, 0)
	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			record := awsEC2Instance{Instance: instance}
			if profileName := instanceProfileName(ec2InstanceProfileARN(instance)); profileName != "" {
				profile, err := clients.iam.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: awssdk.String(profileName)})
				if err != nil {
					return nil, "", fmt.Errorf("get instance profile %q: %w", profileName, err)
				}
				if profile != nil && profile.InstanceProfile != nil && len(profile.InstanceProfile.Roles) != 0 {
					record.Role = profile.InstanceProfile.Roles[0]
				}
			}
			records = append(records, record)
		}
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listLambdaFunctions(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]lambdatypes.FunctionConfiguration, string, error) {
	output, err := clients.lambda.ListFunctions(ctx, &lambda.ListFunctionsInput{
		Marker:   stringPtr(cursor),
		MaxItems: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 50))),
	})
	if err != nil {
		return nil, "", err
	}
	return output.Functions, awssdk.ToString(output.NextMarker), nil
}

func listECSServices(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsECSService, string, error) {
	clusters, err := listAllECSClusters(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	if len(clusters) == 0 {
		return nil, "", nil
	}
	state, err := decodeECSServiceCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if state.ClusterIndex < 0 || state.ClusterIndex >= len(clusters) {
		state.ClusterIndex = 0
		state.ServiceToken = ""
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsECSService, 0, remaining)
	for state.ClusterIndex < len(clusters) && len(records) < remaining {
		clusterARN := clusters[state.ClusterIndex]
		output, err := clients.ecs.ListServices(ctx, &ecs.ListServicesInput{
			Cluster:    awssdk.String(clusterARN),
			MaxResults: awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 100))),
			NextToken:  stringPtr(state.ServiceToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list services for cluster %q: %w", clusterARN, err)
		}
		services, err := describeECSServices(ctx, clients, clusterARN, output.ServiceArns)
		if err != nil {
			return nil, "", err
		}
		for _, service := range services {
			records = append(records, awsECSService{ClusterARN: clusterARN, Service: service})
		}
		if awssdk.ToString(output.NextToken) != "" {
			state.ServiceToken = awssdk.ToString(output.NextToken)
			return records, encodeECSServiceCursor(state), nil
		}
		state.ClusterIndex++
		state.ServiceToken = ""
	}
	if state.ClusterIndex < len(clusters) {
		return records, encodeECSServiceCursor(state), nil
	}
	return records, "", nil
}

func listECSTaskDefinitions(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ecstypes.TaskDefinition, string, error) {
	output, err := clients.ecs.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]ecstypes.TaskDefinition, 0, len(output.TaskDefinitionArns))
	for _, arn := range output.TaskDefinitionArns {
		describe, err := clients.ecs.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: awssdk.String(arn)})
		if err != nil {
			return nil, "", fmt.Errorf("describe task definition %q: %w", arn, err)
		}
		if describe.TaskDefinition != nil {
			records = append(records, *describe.TaskDefinition)
		}
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func ec2InstanceEvent(settings settings, record awsEC2Instance) (*primitives.Event, error) {
	instance := record.Instance
	instanceID := awssdk.ToString(instance.InstanceId)
	roleARN := firstNonEmpty(awssdk.ToString(record.Role.Arn), instanceProfileRoleARN(record.Role))
	roleName := firstNonEmpty(awssdk.ToString(record.Role.RoleName), roleNameFromARN(roleARN))
	attributes := map[string]string{
		"arn":                   ec2InstanceARN(settings, instanceID),
		"availability_zone":     ec2AvailabilityZone(instance),
		"domain":                settings.accountID,
		"family":                familyEC2Instance,
		"image_id":              awssdk.ToString(instance.ImageId),
		"instance_id":           instanceID,
		"instance_profile_arn":  ec2InstanceProfileARN(instance),
		"instance_profile_id":   ec2InstanceProfileID(instance),
		"instance_type":         string(instance.InstanceType),
		"network_interface_ids": strings.Join(ec2InstanceNetworkInterfaceIDs(instance), ","),
		"private_dns_name":      awssdk.ToString(instance.PrivateDnsName),
		"private_ip":            awssdk.ToString(instance.PrivateIpAddress),
		"public_dns_name":       awssdk.ToString(instance.PublicDnsName),
		"public_ip":             awssdk.ToString(instance.PublicIpAddress),
		"region":                settings.region,
		"relationship":          "runs_as",
		"resource_id":           instanceID,
		"resource_name":         firstNonEmpty(ec2NameTag(instance.Tags), instanceID),
		"resource_provider":     "aws",
		"resource_type":         "ec2_instance",
		"role_arn":              roleARN,
		"role_id":               firstNonEmpty(awssdk.ToString(record.Role.RoleId), roleARN),
		"role_name":             roleName,
		"security_group_ids":    strings.Join(ec2InstanceSecurityGroupIDs(instance), ","),
		"state":                 ec2InstanceState(instance),
		"subnet_id":             awssdk.ToString(instance.SubnetId),
		"tags":                  encodeAWSTags(ec2Tags(instance.Tags)),
		"vpc_id":                awssdk.ToString(instance.VpcId),
	}
	addTimeAttribute(attributes, "launched_at", instance.LaunchTime)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "instance": instance, "role": record.Role})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ec2-instance-"+instanceID, "aws.ec2_instance", "aws/ec2_instance/v1", payload, attributes, firstTime(instance.LaunchTime))
}

func lambdaFunctionEvent(settings settings, fn lambdatypes.FunctionConfiguration) (*primitives.Event, error) {
	functionARN := awssdk.ToString(fn.FunctionArn)
	functionName := firstNonEmpty(awssdk.ToString(fn.FunctionName), functionARN)
	roleARN := awssdk.ToString(fn.Role)
	attributes := map[string]string{
		"architectures":      strings.Join(lambdaArchitectures(fn.Architectures), ","),
		"domain":             settings.accountID,
		"family":             familyLambdaFunction,
		"function_arn":       functionARN,
		"function_name":      functionName,
		"handler":            awssdk.ToString(fn.Handler),
		"package_type":       string(fn.PackageType),
		"region":             settings.region,
		"relationship":       "runs_as",
		"resource_id":        firstNonEmpty(functionARN, functionName),
		"resource_name":      functionName,
		"resource_provider":  "aws",
		"resource_type":      "lambda_function",
		"role_arn":           roleARN,
		"role_name":          roleNameFromARN(roleARN),
		"runtime":            string(fn.Runtime),
		"security_group_ids": strings.Join(lambdaSecurityGroupIDs(fn), ","),
		"state":              string(fn.State),
		"subnet_ids":         strings.Join(lambdaSubnetIDs(fn), ","),
		"tracing_mode":       lambdaTracingMode(fn),
		"version":            awssdk.ToString(fn.Version),
		"vpc_id":             lambdaVPCID(fn),
	}
	if parsed := parseAWSStringTime(awssdk.ToString(fn.LastModified)); !parsed.IsZero() {
		attributes["last_modified_at"] = parsed.UTC().Format(time.RFC3339Nano)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "function": fn})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-lambda-function-"+firstNonEmpty(functionARN, functionName), "aws.lambda_function", "aws/lambda_function/v1", payload, attributes, parseAWSStringTime(awssdk.ToString(fn.LastModified)))
}

func ecsServiceEvent(settings settings, record awsECSService) (*primitives.Event, error) {
	service := record.Service
	serviceARN := awssdk.ToString(service.ServiceArn)
	serviceName := firstNonEmpty(awssdk.ToString(service.ServiceName), serviceARN)
	taskDefinitionARN := awssdk.ToString(service.TaskDefinition)
	roleARN := awssdk.ToString(service.RoleArn)
	attributes := map[string]string{
		"cluster_arn":                record.ClusterARN,
		"cluster_name":               path.Base(record.ClusterARN),
		"desired_count":              strconv.FormatInt(int64(service.DesiredCount), 10),
		"domain":                     settings.accountID,
		"family":                     familyECSService,
		"launch_type":                string(service.LaunchType),
		"network_security_group_ids": strings.Join(ecsServiceSecurityGroupIDs(service), ","),
		"network_subnet_ids":         strings.Join(ecsServiceSubnetIDs(service), ","),
		"pending_count":              strconv.FormatInt(int64(service.PendingCount), 10),
		"platform_version":           awssdk.ToString(service.PlatformVersion),
		"region":                     settings.region,
		"resource_id":                serviceARN,
		"resource_name":              serviceName,
		"resource_provider":          "aws",
		"resource_type":              "ecs_service",
		"role_arn":                   roleARN,
		"role_name":                  roleNameFromARN(roleARN),
		"running_count":              strconv.FormatInt(int64(service.RunningCount), 10),
		"scheduling_strategy":        string(service.SchedulingStrategy),
		"service_arn":                serviceARN,
		"service_name":               serviceName,
		"status":                     awssdk.ToString(service.Status),
		"task_definition_arn":        taskDefinitionARN,
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster_arn": record.ClusterARN, "service": service})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ecs-service-"+serviceARN, "aws.ecs_service", "aws/ecs_service/v1", payload, attributes, time.Now().UTC())
}

func ecsTaskDefinitionEvent(settings settings, task ecstypes.TaskDefinition) (*primitives.Event, error) {
	taskARN := awssdk.ToString(task.TaskDefinitionArn)
	taskRoleARN := awssdk.ToString(task.TaskRoleArn)
	executionRoleARN := awssdk.ToString(task.ExecutionRoleArn)
	attributes := map[string]string{
		"container_images":         strings.Join(ecsContainerImages(task.ContainerDefinitions), ","),
		"container_names":          strings.Join(ecsContainerNames(task.ContainerDefinitions), ","),
		"cpu":                      awssdk.ToString(task.Cpu),
		"domain":                   settings.accountID,
		"execution_role_arn":       executionRoleARN,
		"execution_role_name":      roleNameFromARN(executionRoleARN),
		"family":                   familyECSTaskDefinition,
		"memory":                   awssdk.ToString(task.Memory),
		"network_mode":             string(task.NetworkMode),
		"region":                   settings.region,
		"relationship":             "runs_as",
		"requires_compatibilities": strings.Join(ecsCompatibilities(task.RequiresCompatibilities), ","),
		"resource_id":              taskARN,
		"resource_name":            firstNonEmpty(awssdk.ToString(task.Family), taskARN),
		"resource_provider":        "aws",
		"resource_type":            "ecs_task_definition",
		"revision":                 strconv.FormatInt(int64(task.Revision), 10),
		"status":                   string(task.Status),
		"task_definition_arn":      taskARN,
		"task_family":              awssdk.ToString(task.Family),
		"task_role_arn":            taskRoleARN,
		"task_role_name":           roleNameFromARN(taskRoleARN),
	}
	addTimeAttribute(attributes, "registered_at", task.RegisteredAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "task_definition": task})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ecs-task-definition-"+taskARN, "aws.ecs_task_definition", "aws/ecs_task_definition/v1", payload, attributes, firstTime(task.RegisteredAt))
}

func listAllECSClusters(ctx context.Context, clients awsClients) ([]string, error) {
	var clusters []string
	var next *string
	for {
		output, err := clients.ecs.ListClusters(ctx, &ecs.ListClustersInput{MaxResults: awssdk.Int32(100), NextToken: next})
		if err != nil {
			return nil, err
		}
		clusters = append(clusters, output.ClusterArns...)
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	sort.Strings(clusters)
	return clusters, nil
}

func describeECSServices(ctx context.Context, clients awsClients, clusterARN string, serviceARNs []string) ([]ecstypes.Service, error) {
	var services []ecstypes.Service
	for _, batch := range stringBatches(serviceARNs, 10) {
		output, err := clients.ecs.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: awssdk.String(clusterARN), Services: batch})
		if err != nil {
			return nil, fmt.Errorf("describe services for cluster %q: %w", clusterARN, err)
		}
		services = append(services, output.Services...)
	}
	return services, nil
}

func boundedAWSPageSize(limit int, min int, max int) int {
	if limit <= 0 {
		limit = defaultPageSize
	}
	if limit < min {
		return min
	}
	if limit > max {
		return max
	}
	return limit
}

func instanceProfileName(arn string) string {
	_, resource, ok := strings.Cut(strings.TrimSpace(arn), ":instance-profile/")
	if !ok {
		return ""
	}
	return strings.Trim(resource, "/")
}

func roleNameFromARN(arn string) string {
	_, resource, ok := strings.Cut(strings.TrimSpace(arn), ":role/")
	if !ok {
		return ""
	}
	return strings.Trim(resource, "/")
}

func instanceProfileRoleARN(role iamtypes.Role) string {
	return awssdk.ToString(role.Arn)
}

func ec2InstanceARN(settings settings, instanceID string) string {
	if strings.TrimSpace(instanceID) == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", settings.region, settings.accountID, instanceID)
}

func ec2InstanceProfileARN(instance ec2types.Instance) string {
	if instance.IamInstanceProfile == nil {
		return ""
	}
	return awssdk.ToString(instance.IamInstanceProfile.Arn)
}

func ec2InstanceProfileID(instance ec2types.Instance) string {
	if instance.IamInstanceProfile == nil {
		return ""
	}
	return awssdk.ToString(instance.IamInstanceProfile.Id)
}

func ec2AvailabilityZone(instance ec2types.Instance) string {
	if instance.Placement == nil {
		return ""
	}
	return awssdk.ToString(instance.Placement.AvailabilityZone)
}

func ec2InstanceState(instance ec2types.Instance) string {
	if instance.State == nil {
		return ""
	}
	return string(instance.State.Name)
}

func ec2NameTag(tags []ec2types.Tag) string {
	return ec2Tags(tags)["Name"]
}

func ec2Tags(tags []ec2types.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := strings.TrimSpace(awssdk.ToString(tag.Key))
		if key == "" {
			continue
		}
		out[key] = awssdk.ToString(tag.Value)
	}
	return out
}

func encodeAWSTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, key+"="+tags[key])
	}
	return strings.Join(pairs, ",")
}

func ec2InstanceNetworkInterfaceIDs(instance ec2types.Instance) []string {
	ids := make([]string, 0, len(instance.NetworkInterfaces))
	for _, iface := range instance.NetworkInterfaces {
		if id := awssdk.ToString(iface.NetworkInterfaceId); id != "" {
			ids = append(ids, id)
		}
	}
	return cleanStrings(ids)
}

func ec2InstanceSecurityGroupIDs(instance ec2types.Instance) []string {
	var ids []string
	for _, group := range instance.SecurityGroups {
		if id := awssdk.ToString(group.GroupId); id != "" {
			ids = append(ids, id)
		}
	}
	for _, iface := range instance.NetworkInterfaces {
		for _, group := range iface.Groups {
			if id := awssdk.ToString(group.GroupId); id != "" {
				ids = append(ids, id)
			}
		}
	}
	return cleanStrings(ids)
}

func lambdaArchitectures(values []lambdatypes.Architecture) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return cleanStrings(out)
}

func lambdaSecurityGroupIDs(fn lambdatypes.FunctionConfiguration) []string {
	if fn.VpcConfig == nil {
		return nil
	}
	return cleanStrings(fn.VpcConfig.SecurityGroupIds)
}

func lambdaSubnetIDs(fn lambdatypes.FunctionConfiguration) []string {
	if fn.VpcConfig == nil {
		return nil
	}
	return cleanStrings(fn.VpcConfig.SubnetIds)
}

func lambdaVPCID(fn lambdatypes.FunctionConfiguration) string {
	if fn.VpcConfig == nil {
		return ""
	}
	return awssdk.ToString(fn.VpcConfig.VpcId)
}

func lambdaTracingMode(fn lambdatypes.FunctionConfiguration) string {
	if fn.TracingConfig == nil {
		return ""
	}
	return string(fn.TracingConfig.Mode)
}

func ecsServiceSecurityGroupIDs(service ecstypes.Service) []string {
	if service.NetworkConfiguration == nil || service.NetworkConfiguration.AwsvpcConfiguration == nil {
		return nil
	}
	return cleanStrings(service.NetworkConfiguration.AwsvpcConfiguration.SecurityGroups)
}

func ecsServiceSubnetIDs(service ecstypes.Service) []string {
	if service.NetworkConfiguration == nil || service.NetworkConfiguration.AwsvpcConfiguration == nil {
		return nil
	}
	return cleanStrings(service.NetworkConfiguration.AwsvpcConfiguration.Subnets)
}

func ecsContainerNames(definitions []ecstypes.ContainerDefinition) []string {
	names := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		if name := awssdk.ToString(definition.Name); name != "" {
			names = append(names, name)
		}
	}
	return cleanStrings(names)
}

func ecsContainerImages(definitions []ecstypes.ContainerDefinition) []string {
	images := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		if image := awssdk.ToString(definition.Image); image != "" {
			images = append(images, image)
		}
	}
	return cleanStrings(images)
}

func ecsCompatibilities(values []ecstypes.Compatibility) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return cleanStrings(out)
}

func stringBatches(values []string, size int) [][]string {
	if size <= 0 || len(values) == 0 {
		return nil
	}
	batches := make([][]string, 0, (len(values)+size-1)/size)
	for start := 0; start < len(values); start += size {
		end := start + size
		if end > len(values) {
			end = len(values)
		}
		batches = append(batches, values[start:end])
	}
	return batches
}

func parseAWSStringTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000-0700", "2006-01-02T15:04:05.000-07:00"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func decodeECSServiceCursor(raw string) (ecsServicePageCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ecsServicePageCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return ecsServicePageCursor{}, fmt.Errorf("decode ecs service cursor: %w", err)
	}
	var cursor ecsServicePageCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return ecsServicePageCursor{}, fmt.Errorf("parse ecs service cursor: %w", err)
	}
	return cursor, nil
}

func encodeECSServiceCursor(cursor ecsServicePageCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}
