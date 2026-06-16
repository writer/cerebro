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
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
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

type ecsTaskPageCursor struct {
	ClusterIndex int    `json:"cluster_index,omitempty"`
	TaskToken    string `json:"task_token,omitempty"`
}

type eksChildPageCursor struct {
	ClusterIndex int    `json:"cluster_index,omitempty"`
	NextToken    string `json:"next_token,omitempty"`
}

type awsECSTask struct {
	ClusterARN        string
	Task              ecstypes.Task
	NetworkInterfaces []ec2types.NetworkInterface
}

type awsEKSNodegroup struct {
	ClusterName string
	Nodegroup   ekstypes.Nodegroup
}

type awsEKSFargateProfile struct {
	ClusterName string
	Profile     ekstypes.FargateProfile
}

func listEC2Instances(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsEC2Instance, string, error) {
	output, err := clients.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 1000)),
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

func listEC2AMIs(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ec2types.Image, string, error) {
	output, err := clients.ec2.DescribeImages(ctx, &ec2.DescribeImagesInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 1000)),
		NextToken:  stringPtr(cursor),
		Owners:     []string{"self"},
	})
	if err != nil {
		return nil, "", err
	}
	return output.Images, awssdk.ToString(output.NextToken), nil
}

func listLambdaFunctions(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]lambdatypes.FunctionConfiguration, string, error) {
	output, err := clients.lambda.ListFunctions(ctx, &lambda.ListFunctionsInput{
		Marker:   stringPtr(cursor),
		MaxItems: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 50)),
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
			MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(remaining-len(records), 1, 100)),
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

func listECSTasks(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsECSTask, string, error) {
	clusters, err := listAllECSClusters(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	if len(clusters) == 0 {
		return nil, "", nil
	}
	state, err := decodeECSTaskCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if state.ClusterIndex < 0 || state.ClusterIndex >= len(clusters) {
		state.ClusterIndex = 0
		state.TaskToken = ""
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsECSTask, 0, remaining)
	for state.ClusterIndex < len(clusters) && len(records) < remaining {
		clusterARN := clusters[state.ClusterIndex]
		output, err := clients.ecs.ListTasks(ctx, &ecs.ListTasksInput{
			Cluster:       awssdk.String(clusterARN),
			DesiredStatus: ecstypes.DesiredStatusRunning,
			MaxResults:    awssdk.Int32(boundedAWSPageSizeInt32(remaining-len(records), 1, 100)),
			NextToken:     stringPtr(state.TaskToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list tasks for cluster %q: %w", clusterARN, err)
		}
		tasks, err := describeECSTasks(ctx, clients, clusterARN, output.TaskArns)
		if err != nil {
			return nil, "", err
		}
		tasks, err = enrichECSTaskNetworkInterfaces(ctx, clients, tasks)
		if err != nil {
			return nil, "", err
		}
		records = append(records, tasks...)
		if awssdk.ToString(output.NextToken) != "" {
			state.TaskToken = awssdk.ToString(output.NextToken)
			return records, encodeECSTaskCursor(state), nil
		}
		state.ClusterIndex++
		state.TaskToken = ""
	}
	if state.ClusterIndex < len(clusters) {
		return records, encodeECSTaskCursor(state), nil
	}
	return records, "", nil
}

func listECSTaskDefinitions(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ecstypes.TaskDefinition, string, error) {
	output, err := clients.ecs.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
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

func listEKSClusters(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ekstypes.Cluster, string, error) {
	output, err := clients.eks.ListClusters(ctx, &eks.ListClustersInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]ekstypes.Cluster, 0, len(output.Clusters))
	for _, name := range output.Clusters {
		describe, err := clients.eks.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("describe eks cluster %q: %w", name, err)
		}
		if describe.Cluster != nil {
			records = append(records, *describe.Cluster)
		}
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listEKSNodegroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsEKSNodegroup, string, error) {
	clusters, err := listAllEKSClusters(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	if len(clusters) == 0 {
		return nil, "", nil
	}
	state, err := decodeEKSChildCursor(cursor, "eks nodegroup")
	if err != nil {
		return nil, "", err
	}
	if state.ClusterIndex < 0 || state.ClusterIndex >= len(clusters) {
		state.ClusterIndex = 0
		state.NextToken = ""
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsEKSNodegroup, 0, remaining)
	for state.ClusterIndex < len(clusters) && len(records) < remaining {
		clusterName := clusters[state.ClusterIndex]
		output, err := clients.eks.ListNodegroups(ctx, &eks.ListNodegroupsInput{
			ClusterName: awssdk.String(clusterName),
			MaxResults:  awssdk.Int32(boundedAWSPageSizeInt32(remaining-len(records), 1, 100)),
			NextToken:   stringPtr(state.NextToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list eks nodegroups for cluster %q: %w", clusterName, err)
		}
		for _, name := range output.Nodegroups {
			describe, err := clients.eks.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{ClusterName: awssdk.String(clusterName), NodegroupName: awssdk.String(name)})
			if err != nil {
				return nil, "", fmt.Errorf("describe eks nodegroup %q/%q: %w", clusterName, name, err)
			}
			if describe.Nodegroup != nil {
				records = append(records, awsEKSNodegroup{ClusterName: clusterName, Nodegroup: *describe.Nodegroup})
			}
		}
		if awssdk.ToString(output.NextToken) != "" {
			state.NextToken = awssdk.ToString(output.NextToken)
			return records, encodeEKSChildCursor(state), nil
		}
		state.ClusterIndex++
		state.NextToken = ""
	}
	if state.ClusterIndex < len(clusters) {
		return records, encodeEKSChildCursor(state), nil
	}
	return records, "", nil
}

func listEKSFargateProfiles(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsEKSFargateProfile, string, error) {
	clusters, err := listAllEKSClusters(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	if len(clusters) == 0 {
		return nil, "", nil
	}
	state, err := decodeEKSChildCursor(cursor, "eks fargate profile")
	if err != nil {
		return nil, "", err
	}
	if state.ClusterIndex < 0 || state.ClusterIndex >= len(clusters) {
		state.ClusterIndex = 0
		state.NextToken = ""
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsEKSFargateProfile, 0, remaining)
	for state.ClusterIndex < len(clusters) && len(records) < remaining {
		clusterName := clusters[state.ClusterIndex]
		output, err := clients.eks.ListFargateProfiles(ctx, &eks.ListFargateProfilesInput{
			ClusterName: awssdk.String(clusterName),
			MaxResults:  awssdk.Int32(boundedAWSPageSizeInt32(remaining-len(records), 1, 100)),
			NextToken:   stringPtr(state.NextToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list eks fargate profiles for cluster %q: %w", clusterName, err)
		}
		for _, name := range output.FargateProfileNames {
			describe, err := clients.eks.DescribeFargateProfile(ctx, &eks.DescribeFargateProfileInput{ClusterName: awssdk.String(clusterName), FargateProfileName: awssdk.String(name)})
			if err != nil {
				return nil, "", fmt.Errorf("describe eks fargate profile %q/%q: %w", clusterName, name, err)
			}
			if describe.FargateProfile != nil {
				records = append(records, awsEKSFargateProfile{ClusterName: clusterName, Profile: *describe.FargateProfile})
			}
		}
		if awssdk.ToString(output.NextToken) != "" {
			state.NextToken = awssdk.ToString(output.NextToken)
			return records, encodeEKSChildCursor(state), nil
		}
		state.ClusterIndex++
		state.NextToken = ""
	}
	if state.ClusterIndex < len(clusters) {
		return records, encodeEKSChildCursor(state), nil
	}
	return records, "", nil
}

func listEKSPodIdentityAssociations(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ekstypes.PodIdentityAssociation, string, error) {
	clusters, err := listAllEKSClusters(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	if len(clusters) == 0 {
		return nil, "", nil
	}
	state, err := decodeEKSChildCursor(cursor, "eks pod identity association")
	if err != nil {
		return nil, "", err
	}
	if state.ClusterIndex < 0 || state.ClusterIndex >= len(clusters) {
		state.ClusterIndex = 0
		state.NextToken = ""
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]ekstypes.PodIdentityAssociation, 0, remaining)
	for state.ClusterIndex < len(clusters) && len(records) < remaining {
		clusterName := clusters[state.ClusterIndex]
		output, err := clients.eks.ListPodIdentityAssociations(ctx, &eks.ListPodIdentityAssociationsInput{
			ClusterName: awssdk.String(clusterName),
			MaxResults:  awssdk.Int32(boundedAWSPageSizeInt32(remaining-len(records), 1, 100)),
			NextToken:   stringPtr(state.NextToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list eks pod identity associations for cluster %q: %w", clusterName, err)
		}
		for _, summary := range output.Associations {
			associationID := awssdk.ToString(summary.AssociationId)
			if associationID == "" {
				continue
			}
			describe, err := clients.eks.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{ClusterName: awssdk.String(firstNonEmpty(awssdk.ToString(summary.ClusterName), clusterName)), AssociationId: awssdk.String(associationID)})
			if err != nil {
				return nil, "", fmt.Errorf("describe eks pod identity association %q/%q: %w", clusterName, associationID, err)
			}
			if describe.Association != nil {
				records = append(records, *describe.Association)
			}
		}
		if awssdk.ToString(output.NextToken) != "" {
			state.NextToken = awssdk.ToString(output.NextToken)
			return records, encodeEKSChildCursor(state), nil
		}
		state.ClusterIndex++
		state.NextToken = ""
	}
	if state.ClusterIndex < len(clusters) {
		return records, encodeEKSChildCursor(state), nil
	}
	return records, "", nil
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

func ec2AMIEvent(settings settings, image ec2types.Image) (*primitives.Event, error) {
	imageID := awssdk.ToString(image.ImageId)
	tags := ec2Tags(image.Tags)
	name := firstNonEmpty(awssdk.ToString(image.Name), ec2NameTag(image.Tags), imageID)
	public := awssdk.ToBool(image.Public)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEC2AMI, imageID, name, "ec2_ami", tags)
	attributes["architecture"] = string(image.Architecture)
	attributes["arn"] = ec2ImageARN(settings, imageID)
	attributes["boot_mode"] = string(image.BootMode)
	attributes["creation_date"] = awssdk.ToString(image.CreationDate)
	attributes["deprecation_time"] = awssdk.ToString(image.DeprecationTime)
	attributes["description"] = awssdk.ToString(image.Description)
	attributes["ena_support"] = boolString(awssdk.ToBool(image.EnaSupport))
	attributes["image_allowed"] = boolString(awssdk.ToBool(image.ImageAllowed))
	attributes["image_id"] = imageID
	attributes["image_location"] = awssdk.ToString(image.ImageLocation)
	attributes["image_owner_alias"] = awssdk.ToString(image.ImageOwnerAlias)
	attributes["image_type"] = string(image.ImageType)
	attributes["imds_support"] = string(image.ImdsSupport)
	attributes["internet_exposed"] = boolString(public)
	attributes["is_public"] = boolString(public)
	attributes["last_launched_time"] = awssdk.ToString(image.LastLaunchedTime)
	attributes["owner_id"] = awssdk.ToString(image.OwnerId)
	attributes["platform"] = string(image.Platform)
	attributes["platform_details"] = awssdk.ToString(image.PlatformDetails)
	attributes["public"] = boolString(public)
	attributes["root_device_name"] = awssdk.ToString(image.RootDeviceName)
	attributes["root_device_type"] = string(image.RootDeviceType)
	attributes["source_image_id"] = awssdk.ToString(image.SourceImageId)
	attributes["source_image_region"] = awssdk.ToString(image.SourceImageRegion)
	attributes["source_instance_id"] = awssdk.ToString(image.SourceInstanceId)
	attributes["state"] = string(image.State)
	attributes["virtualization_type"] = string(image.VirtualizationType)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "image": image, "public": public})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ec2-ami-"+imageID, "aws.ec2_ami", "aws/ec2_ami/v1", payload, attributes, parseAWSStringTime(awssdk.ToString(image.CreationDate)))
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

func ecsTaskEvent(settings settings, record awsECSTask) (*primitives.Event, error) {
	task := record.Task
	taskARN := awssdk.ToString(task.TaskArn)
	taskDefinitionARN := awssdk.ToString(task.TaskDefinitionArn)
	serviceName := ecsTaskServiceName(task)
	serviceARN := ecsServiceARN(settings, record.ClusterARN, serviceName)
	attributes := map[string]string{
		"cluster_arn":            record.ClusterARN,
		"cluster_name":           path.Base(record.ClusterARN),
		"cpu":                    awssdk.ToString(task.Cpu),
		"desired_status":         awssdk.ToString(task.DesiredStatus),
		"domain":                 settings.accountID,
		"enable_execute_command": strconv.FormatBool(task.EnableExecuteCommand),
		"family":                 familyECSTask,
		"group":                  awssdk.ToString(task.Group),
		"health_status":          string(task.HealthStatus),
		"last_status":            awssdk.ToString(task.LastStatus),
		"launch_type":            string(task.LaunchType),
		"memory":                 awssdk.ToString(task.Memory),
		"network_interface_ids":  strings.Join(ecsTaskNetworkInterfaceIDs(record), ","),
		"platform_family":        awssdk.ToString(task.PlatformFamily),
		"platform_version":       awssdk.ToString(task.PlatformVersion),
		"private_ips":            strings.Join(ecsTaskPrivateIPs(record), ","),
		"region":                 settings.region,
		"resource_id":            taskARN,
		"resource_name":          firstNonEmpty(path.Base(taskARN), taskARN),
		"resource_provider":      "aws",
		"resource_type":          "ecs_task",
		"security_group_ids":     strings.Join(ecsTaskSecurityGroupIDs(record), ","),
		"service_arn":            serviceARN,
		"service_name":           serviceName,
		"subnet_ids":             strings.Join(ecsTaskSubnetIDs(record), ","),
		"task_arn":               taskARN,
		"task_definition_arn":    taskDefinitionARN,
		"vpc_id":                 ecsTaskVPCID(record),
	}
	addTimeAttribute(attributes, "created_at", task.CreatedAt)
	addTimeAttribute(attributes, "started_at", task.StartedAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster_arn": record.ClusterARN, "task": task, "network_interfaces": record.NetworkInterfaces})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ecs-task-"+taskARN, "aws.ecs_task", "aws/ecs_task/v1", payload, attributes, firstTime(task.StartedAt, task.CreatedAt))
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

func eksClusterEvent(settings settings, cluster ekstypes.Cluster) (*primitives.Event, error) {
	clusterName := awssdk.ToString(cluster.Name)
	clusterARN := firstNonEmpty(awssdk.ToString(cluster.Arn), eksClusterARN(settings, clusterName))
	roleARN := awssdk.ToString(cluster.RoleArn)
	attributes := map[string]string{
		"arn":                     clusterARN,
		"cluster_arn":             clusterARN,
		"cluster_name":            clusterName,
		"domain":                  settings.accountID,
		"endpoint":                awssdk.ToString(cluster.Endpoint),
		"endpoint_private_access": strconv.FormatBool(eksEndpointPrivateAccess(cluster)),
		"endpoint_public_access":  strconv.FormatBool(eksEndpointPublicAccess(cluster)),
		"family":                  familyEKSCluster,
		"platform_version":        awssdk.ToString(cluster.PlatformVersion),
		"public_access_cidrs":     strings.Join(eksPublicAccessCIDRs(cluster), ","),
		"region":                  settings.region,
		"relationship":            "runs_as",
		"resource_id":             clusterARN,
		"resource_name":           clusterName,
		"resource_provider":       "aws",
		"resource_type":           "eks_cluster",
		"role_arn":                roleARN,
		"role_name":               roleNameFromARN(roleARN),
		"security_group_ids":      strings.Join(eksClusterSecurityGroupIDs(cluster), ","),
		"state":                   string(cluster.Status),
		"subnet_ids":              strings.Join(eksClusterSubnetIDs(cluster), ","),
		"tags":                    encodeAWSTags(cluster.Tags),
		"version":                 awssdk.ToString(cluster.Version),
		"vpc_id":                  eksClusterVPCID(cluster),
	}
	addTimeAttribute(attributes, "created_at", cluster.CreatedAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster": cluster})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-eks-cluster-"+clusterARN, "aws.eks_cluster", "aws/eks_cluster/v1", payload, attributes, time.Now().UTC())
}

func eksNodegroupEvent(settings settings, record awsEKSNodegroup) (*primitives.Event, error) {
	nodegroup := record.Nodegroup
	clusterName := firstNonEmpty(awssdk.ToString(nodegroup.ClusterName), record.ClusterName)
	clusterARN := eksClusterARN(settings, clusterName)
	nodegroupARN := awssdk.ToString(nodegroup.NodegroupArn)
	roleARN := awssdk.ToString(nodegroup.NodeRole)
	attributes := map[string]string{
		"ami_type":           string(nodegroup.AmiType),
		"capacity_type":      string(nodegroup.CapacityType),
		"cluster_arn":        clusterARN,
		"cluster_name":       clusterName,
		"domain":             settings.accountID,
		"family":             familyEKSNodegroup,
		"instance_types":     strings.Join(cleanStrings(nodegroup.InstanceTypes), ","),
		"node_role_arn":      roleARN,
		"node_role_name":     roleNameFromARN(roleARN),
		"nodegroup_arn":      nodegroupARN,
		"nodegroup_name":     awssdk.ToString(nodegroup.NodegroupName),
		"region":             settings.region,
		"relationship":       "runs_as",
		"resource_id":        nodegroupARN,
		"resource_name":      awssdk.ToString(nodegroup.NodegroupName),
		"resource_provider":  "aws",
		"resource_type":      "eks_nodegroup",
		"role_arn":           roleARN,
		"role_name":          roleNameFromARN(roleARN),
		"security_group_ids": strings.Join(eksNodegroupSecurityGroupIDs(nodegroup), ","),
		"state":              string(nodegroup.Status),
		"subnet_ids":         strings.Join(cleanStrings(nodegroup.Subnets), ","),
		"tags":               encodeAWSTags(nodegroup.Tags),
		"version":            awssdk.ToString(nodegroup.Version),
	}
	addTimeAttribute(attributes, "created_at", nodegroup.CreatedAt)
	addTimeAttribute(attributes, "modified_at", nodegroup.ModifiedAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster_name": clusterName, "nodegroup": nodegroup})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-eks-nodegroup-"+firstNonEmpty(nodegroupARN, clusterName+"/"+awssdk.ToString(nodegroup.NodegroupName)), "aws.eks_nodegroup", "aws/eks_nodegroup/v1", payload, attributes, firstTime(nodegroup.ModifiedAt, nodegroup.CreatedAt))
}

func eksFargateProfileEvent(settings settings, record awsEKSFargateProfile) (*primitives.Event, error) {
	profile := record.Profile
	clusterName := firstNonEmpty(awssdk.ToString(profile.ClusterName), record.ClusterName)
	clusterARN := eksClusterARN(settings, clusterName)
	profileARN := awssdk.ToString(profile.FargateProfileArn)
	roleARN := awssdk.ToString(profile.PodExecutionRoleArn)
	attributes := map[string]string{
		"cluster_arn":             clusterARN,
		"cluster_name":            clusterName,
		"domain":                  settings.accountID,
		"family":                  familyEKSFargateProfile,
		"fargate_profile_arn":     profileARN,
		"fargate_profile_name":    awssdk.ToString(profile.FargateProfileName),
		"pod_execution_role_arn":  roleARN,
		"pod_execution_role_name": roleNameFromARN(roleARN),
		"region":                  settings.region,
		"relationship":            "runs_as",
		"resource_id":             profileARN,
		"resource_name":           awssdk.ToString(profile.FargateProfileName),
		"resource_provider":       "aws",
		"resource_type":           "eks_fargate_profile",
		"role_arn":                roleARN,
		"role_name":               roleNameFromARN(roleARN),
		"selector_namespaces":     strings.Join(eksFargateSelectorNamespaces(profile.Selectors), ","),
		"selectors":               encodeEKSFargateSelectors(profile.Selectors),
		"state":                   string(profile.Status),
		"subnet_ids":              strings.Join(cleanStrings(profile.Subnets), ","),
		"tags":                    encodeAWSTags(profile.Tags),
	}
	addTimeAttribute(attributes, "created_at", profile.CreatedAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster_name": clusterName, "fargate_profile": profile})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-eks-fargate-profile-"+firstNonEmpty(profileARN, clusterName+"/"+awssdk.ToString(profile.FargateProfileName)), "aws.eks_fargate_profile", "aws/eks_fargate_profile/v1", payload, attributes, firstTime(profile.CreatedAt))
}

func eksPodIdentityAssociationEvent(settings settings, association ekstypes.PodIdentityAssociation) (*primitives.Event, error) {
	clusterName := awssdk.ToString(association.ClusterName)
	clusterARN := eksClusterARN(settings, clusterName)
	roleARN := firstNonEmpty(awssdk.ToString(association.RoleArn), awssdk.ToString(association.TargetRoleArn))
	associationID := firstNonEmpty(awssdk.ToString(association.AssociationArn), awssdk.ToString(association.AssociationId))
	attributes := map[string]string{
		"association_arn":      awssdk.ToString(association.AssociationArn),
		"association_id":       awssdk.ToString(association.AssociationId),
		"cluster_arn":          clusterARN,
		"cluster_name":         clusterName,
		"disable_session_tags": strconv.FormatBool(awssdk.ToBool(association.DisableSessionTags)),
		"domain":               settings.accountID,
		"external_id":          awssdk.ToString(association.ExternalId),
		"family":               familyEKSPodIdentity,
		"namespace":            awssdk.ToString(association.Namespace),
		"owner_arn":            awssdk.ToString(association.OwnerArn),
		"region":               settings.region,
		"relationship":         "can_assume",
		"resource_id":          associationID,
		"resource_name":        firstNonEmpty(awssdk.ToString(association.ServiceAccount), awssdk.ToString(association.AssociationId)),
		"resource_provider":    "aws",
		"resource_type":        "eks_pod_identity_association",
		"role_arn":             roleARN,
		"role_name":            roleNameFromARN(roleARN),
		"service_account":      awssdk.ToString(association.ServiceAccount),
		"tags":                 encodeAWSTags(association.Tags),
		"target_role_arn":      awssdk.ToString(association.TargetRoleArn),
		"target_role_name":     roleNameFromARN(awssdk.ToString(association.TargetRoleArn)),
	}
	addTimeAttribute(attributes, "created_at", association.CreatedAt)
	addTimeAttribute(attributes, "modified_at", association.ModifiedAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "association": association})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-eks-pod-identity-association-"+associationID, "aws.eks_pod_identity_association", "aws/eks_pod_identity_association/v1", payload, attributes, firstTime(association.ModifiedAt, association.CreatedAt))
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

func describeECSTasks(ctx context.Context, clients awsClients, clusterARN string, taskARNs []string) ([]awsECSTask, error) {
	var tasks []awsECSTask
	for _, batch := range stringBatches(taskARNs, 100) {
		output, err := clients.ecs.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: awssdk.String(clusterARN), Tasks: batch})
		if err != nil {
			return nil, fmt.Errorf("describe tasks for cluster %q: %w", clusterARN, err)
		}
		for _, task := range output.Tasks {
			tasks = append(tasks, awsECSTask{ClusterARN: clusterARN, Task: task})
		}
	}
	return tasks, nil
}

func enrichECSTaskNetworkInterfaces(ctx context.Context, clients awsClients, tasks []awsECSTask) ([]awsECSTask, error) {
	ids := make([]string, 0)
	for _, task := range tasks {
		ids = append(ids, ecsTaskAttachmentNetworkInterfaceIDs(task.Task)...)
	}
	ids = cleanStrings(ids)
	if len(ids) == 0 {
		return tasks, nil
	}
	interfaces := map[string]ec2types.NetworkInterface{}
	for _, batch := range stringBatches(ids, 100) {
		output, err := clients.ec2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: batch})
		if err != nil {
			return nil, fmt.Errorf("describe ecs task network interfaces: %w", err)
		}
		for _, iface := range output.NetworkInterfaces {
			if id := awssdk.ToString(iface.NetworkInterfaceId); id != "" {
				interfaces[id] = iface
			}
		}
	}
	for index := range tasks {
		for _, id := range ecsTaskAttachmentNetworkInterfaceIDs(tasks[index].Task) {
			if iface, ok := interfaces[id]; ok {
				tasks[index].NetworkInterfaces = append(tasks[index].NetworkInterfaces, iface)
			}
		}
	}
	return tasks, nil
}

func listAllEKSClusters(ctx context.Context, clients awsClients) ([]string, error) {
	var clusters []string
	var next *string
	for {
		output, err := clients.eks.ListClusters(ctx, &eks.ListClustersInput{MaxResults: awssdk.Int32(100), NextToken: next})
		if err != nil {
			return nil, err
		}
		clusters = append(clusters, output.Clusters...)
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	sort.Strings(clusters)
	return clusters, nil
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

func boundedAWSPageSizeInt32(limit int, min int, max int) int32 {
	return int32(boundedAWSPageSize(limit, min, max)) // #nosec G115 -- boundedAWSPageSize clamps to AWS API page-size ranges.
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

func ec2ImageARN(settings settings, imageID string) string {
	if strings.TrimSpace(imageID) == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:ec2:%s::image/%s", settings.region, imageID)
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

func ecsTaskAttachmentNetworkInterfaceIDs(task ecstypes.Task) []string {
	return ecsTaskAttachmentValues(task, "networkInterfaceId")
}

func ecsTaskNetworkInterfaceIDs(record awsECSTask) []string {
	ids := ecsTaskAttachmentNetworkInterfaceIDs(record.Task)
	for _, iface := range record.NetworkInterfaces {
		if id := awssdk.ToString(iface.NetworkInterfaceId); id != "" {
			ids = append(ids, id)
		}
	}
	return cleanStrings(ids)
}

func ecsTaskSubnetIDs(record awsECSTask) []string {
	ids := ecsTaskAttachmentValues(record.Task, "subnetId")
	for _, iface := range record.NetworkInterfaces {
		if id := awssdk.ToString(iface.SubnetId); id != "" {
			ids = append(ids, id)
		}
	}
	return cleanStrings(ids)
}

func ecsTaskPrivateIPs(record awsECSTask) []string {
	ids := ecsTaskAttachmentValues(record.Task, "privateIPv4Address")
	for _, iface := range record.NetworkInterfaces {
		if id := awssdk.ToString(iface.PrivateIpAddress); id != "" {
			ids = append(ids, id)
		}
	}
	return cleanStrings(ids)
}

func ecsTaskSecurityGroupIDs(record awsECSTask) []string {
	var ids []string
	for _, iface := range record.NetworkInterfaces {
		for _, group := range iface.Groups {
			if id := awssdk.ToString(group.GroupId); id != "" {
				ids = append(ids, id)
			}
		}
	}
	return cleanStrings(ids)
}

func ecsTaskVPCID(record awsECSTask) string {
	for _, iface := range record.NetworkInterfaces {
		if id := awssdk.ToString(iface.VpcId); id != "" {
			return id
		}
	}
	return ""
}

func ecsTaskAttachmentValues(task ecstypes.Task, key string) []string {
	var values []string
	for _, attachment := range task.Attachments {
		for _, detail := range attachment.Details {
			if awssdk.ToString(detail.Name) == key {
				values = append(values, awssdk.ToString(detail.Value))
			}
		}
	}
	return cleanStrings(values)
}

func ecsTaskServiceName(task ecstypes.Task) string {
	group := awssdk.ToString(task.Group)
	if strings.HasPrefix(group, "service:") {
		return strings.TrimSpace(strings.TrimPrefix(group, "service:"))
	}
	return ""
}

func ecsServiceARN(settings settings, clusterARN string, serviceName string) string {
	serviceName = strings.TrimSpace(serviceName)
	if clusterARN == "" || serviceName == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:ecs:%s:%s:service/%s/%s", settings.region, settings.accountID, path.Base(clusterARN), serviceName)
}

func eksClusterARN(settings settings, clusterName string) string {
	clusterName = strings.TrimSpace(clusterName)
	if clusterName == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:eks:%s:%s:cluster/%s", settings.region, settings.accountID, clusterName)
}

func eksEndpointPublicAccess(cluster ekstypes.Cluster) bool {
	return cluster.ResourcesVpcConfig != nil && cluster.ResourcesVpcConfig.EndpointPublicAccess
}

func eksEndpointPrivateAccess(cluster ekstypes.Cluster) bool {
	return cluster.ResourcesVpcConfig != nil && cluster.ResourcesVpcConfig.EndpointPrivateAccess
}

func eksPublicAccessCIDRs(cluster ekstypes.Cluster) []string {
	if cluster.ResourcesVpcConfig == nil {
		return nil
	}
	return cleanStrings(cluster.ResourcesVpcConfig.PublicAccessCidrs)
}

func eksClusterSubnetIDs(cluster ekstypes.Cluster) []string {
	if cluster.ResourcesVpcConfig == nil {
		return nil
	}
	return cleanStrings(cluster.ResourcesVpcConfig.SubnetIds)
}

func eksClusterSecurityGroupIDs(cluster ekstypes.Cluster) []string {
	if cluster.ResourcesVpcConfig == nil {
		return nil
	}
	ids := append([]string{}, cluster.ResourcesVpcConfig.SecurityGroupIds...)
	if id := awssdk.ToString(cluster.ResourcesVpcConfig.ClusterSecurityGroupId); id != "" {
		ids = append(ids, id)
	}
	return cleanStrings(ids)
}

func eksClusterVPCID(cluster ekstypes.Cluster) string {
	if cluster.ResourcesVpcConfig == nil {
		return ""
	}
	return awssdk.ToString(cluster.ResourcesVpcConfig.VpcId)
}

func eksNodegroupSecurityGroupIDs(nodegroup ekstypes.Nodegroup) []string {
	var ids []string
	if nodegroup.RemoteAccess != nil {
		ids = append(ids, nodegroup.RemoteAccess.SourceSecurityGroups...)
	}
	if nodegroup.Resources != nil {
		if id := awssdk.ToString(nodegroup.Resources.RemoteAccessSecurityGroup); id != "" {
			ids = append(ids, id)
		}
	}
	return cleanStrings(ids)
}

func eksFargateSelectorNamespaces(selectors []ekstypes.FargateProfileSelector) []string {
	namespaces := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		namespaces = append(namespaces, awssdk.ToString(selector.Namespace))
	}
	return cleanStrings(namespaces)
}

func encodeEKSFargateSelectors(selectors []ekstypes.FargateProfileSelector) string {
	if len(selectors) == 0 {
		return ""
	}
	type selector struct {
		Namespace string            `json:"namespace,omitempty"`
		Labels    map[string]string `json:"labels,omitempty"`
	}
	values := make([]selector, 0, len(selectors))
	for _, item := range selectors {
		values = append(values, selector{Namespace: awssdk.ToString(item.Namespace), Labels: item.Labels})
	}
	payload, err := json.Marshal(values)
	if err != nil {
		return ""
	}
	return string(payload)
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

func decodeECSTaskCursor(raw string) (ecsTaskPageCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ecsTaskPageCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return ecsTaskPageCursor{}, fmt.Errorf("decode ecs task cursor: %w", err)
	}
	var cursor ecsTaskPageCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return ecsTaskPageCursor{}, fmt.Errorf("parse ecs task cursor: %w", err)
	}
	return cursor, nil
}

func encodeECSTaskCursor(cursor ecsTaskPageCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeEKSChildCursor(raw string, label string) (eksChildPageCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return eksChildPageCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return eksChildPageCursor{}, fmt.Errorf("decode %s cursor: %w", label, err)
	}
	var cursor eksChildPageCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return eksChildPageCursor{}, fmt.Errorf("parse %s cursor: %w", label, err)
	}
	return cursor, nil
}

func encodeEKSChildCursor(cursor eksChildPageCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}
