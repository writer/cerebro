package aws

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	batchtypes "github.com/aws/aws-sdk-go-v2/service/batch/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsBatchComputeEnvironment = batchtypes.ComputeEnvironmentDetail
type awsBatchJobQueue = batchtypes.JobQueueDetail

type awsBatchAPI interface {
	DescribeComputeEnvironments(context.Context, *batch.DescribeComputeEnvironmentsInput, ...func(*batch.Options)) (*batch.DescribeComputeEnvironmentsOutput, error)
	DescribeJobQueues(context.Context, *batch.DescribeJobQueuesInput, ...func(*batch.Options)) (*batch.DescribeJobQueuesOutput, error)
}

func listBatchComputeEnvironments(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsBatchComputeEnvironment, string, error) {
	output, err := clients.batch.DescribeComputeEnvironments(ctx, &batch.DescribeComputeEnvironmentsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return output.ComputeEnvironments, awssdk.ToString(output.NextToken), nil
}

func listBatchJobQueues(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsBatchJobQueue, string, error) {
	output, err := clients.batch.DescribeJobQueues(ctx, &batch.DescribeJobQueuesInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return output.JobQueues, awssdk.ToString(output.NextToken), nil
}

func batchComputeEnvironmentEvent(settings settings, environment awsBatchComputeEnvironment) (*primitives.Event, error) {
	arn := awssdk.ToString(environment.ComputeEnvironmentArn)
	name := firstNonEmpty(awssdk.ToString(environment.ComputeEnvironmentName), awsResourceName(arn))
	resourceID := firstNonEmpty(arn, name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyBatchComputeEnv, resourceID, name, "batch_compute_environment", environment.Tags)
	attributes["arn"] = arn
	attributes["compute_environment_arn"] = arn
	attributes["compute_environment_name"] = name
	attributes["compute_environment_type"] = string(environment.Type)
	attributes["container_orchestration_type"] = string(environment.ContainerOrchestrationType)
	attributes["ecs_cluster_arn"] = awssdk.ToString(environment.EcsClusterArn)
	attributes["role_arn"] = awssdk.ToString(environment.ServiceRole)
	attributes["role_name"] = roleNameFromARN(attributes["role_arn"])
	attributes["service_role_arn"] = attributes["role_arn"]
	attributes["service_role_name"] = attributes["role_name"]
	attributes["state"] = string(environment.State)
	attributes["status"] = string(environment.Status)
	attributes["status_reason"] = awssdk.ToString(environment.StatusReason)
	attributes["unmanaged_vcpus"] = int32AttrString(environment.UnmanagedvCpus)
	attributes["uuid"] = awssdk.ToString(environment.Uuid)
	if environment.EksConfiguration != nil {
		attributes["eks_cluster_arn"] = awssdk.ToString(environment.EksConfiguration.EksClusterArn)
		attributes["kubernetes_namespace"] = awssdk.ToString(environment.EksConfiguration.KubernetesNamespace)
	}
	if resources := environment.ComputeResources; resources != nil {
		attributes["allocation_strategy"] = string(resources.AllocationStrategy)
		attributes["compute_resource_type"] = string(resources.Type)
		attributes["desired_vcpus"] = int32AttrString(resources.DesiredvCpus)
		attributes["instance_role"] = awssdk.ToString(resources.InstanceRole)
		attributes["instance_types"] = strings.Join(cleanStrings(resources.InstanceTypes), ",")
		attributes["max_vcpus"] = int32AttrString(resources.MaxvCpus)
		attributes["min_vcpus"] = int32AttrString(resources.MinvCpus)
		attributes["security_group_ids"] = strings.Join(cleanStrings(resources.SecurityGroupIds), ",")
		attributes["spot_iam_fleet_role"] = awssdk.ToString(resources.SpotIamFleetRole)
		attributes["subnet_ids"] = strings.Join(cleanStrings(resources.Subnets), ",")
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "compute_environment": environment})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-batch-compute-environment-"+resourceID, "aws.batch_compute_environment", "aws/batch_compute_environment/v1", payload, attributes, time.Now().UTC())
}

func batchJobQueueEvent(settings settings, queue awsBatchJobQueue) (*primitives.Event, error) {
	arn := awssdk.ToString(queue.JobQueueArn)
	name := firstNonEmpty(awssdk.ToString(queue.JobQueueName), awsResourceName(arn))
	resourceID := firstNonEmpty(arn, name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyBatchJobQueue, resourceID, name, "batch_job_queue", queue.Tags)
	attributes["arn"] = arn
	attributes["compute_environment_arns"] = strings.Join(batchJobQueueComputeEnvironments(queue.ComputeEnvironmentOrder), ",")
	attributes["compute_environment_names"] = strings.Join(batchJobQueueComputeEnvironmentNames(queue.ComputeEnvironmentOrder), ",")
	attributes["job_queue_arn"] = arn
	attributes["job_queue_name"] = name
	attributes["job_queue_type"] = string(queue.JobQueueType)
	attributes["priority"] = int32AttrString(queue.Priority)
	attributes["scheduling_policy_arn"] = awssdk.ToString(queue.SchedulingPolicyArn)
	attributes["state"] = string(queue.State)
	attributes["status"] = string(queue.Status)
	attributes["status_reason"] = awssdk.ToString(queue.StatusReason)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "job_queue": queue})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-batch-job-queue-"+resourceID, "aws.batch_job_queue", "aws/batch_job_queue/v1", payload, attributes, time.Now().UTC())
}

func batchJobQueueComputeEnvironments(order []batchtypes.ComputeEnvironmentOrder) []string {
	values := make([]string, 0, len(order))
	for _, item := range order {
		values = append(values, awssdk.ToString(item.ComputeEnvironment))
	}
	return cleanStrings(values)
}

func batchJobQueueComputeEnvironmentNames(order []batchtypes.ComputeEnvironmentOrder) []string {
	values := make([]string, 0, len(order))
	for _, arn := range batchJobQueueComputeEnvironments(order) {
		values = append(values, awsResourceName(arn))
	}
	return cleanStrings(values)
}
