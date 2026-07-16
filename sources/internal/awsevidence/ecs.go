package awsevidence

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

type taskDefinitionClient interface {
	ListTaskDefinitions(context.Context, *ecs.ListTaskDefinitionsInput, ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error)
	DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}

// ListTaskDefinitions enumerates both ACTIVE and INACTIVE revisions so
// deregistration is projected as current state instead of leaving stale ACTIVE
// graph evidence behind.
func ListTaskDefinitions(ctx context.Context, client taskDefinitionClient, cursor string, limit int) ([]ecstypes.TaskDefinition, string, error) {
	status, nextToken := ecstypes.TaskDefinitionStatusActive, strings.TrimSpace(cursor)
	if strings.HasPrefix(nextToken, "active:") {
		nextToken = strings.TrimPrefix(nextToken, "active:")
	} else if strings.HasPrefix(nextToken, "inactive:") {
		status, nextToken = ecstypes.TaskDefinitionStatusInactive, strings.TrimPrefix(nextToken, "inactive:")
	}
	if limit < 1 {
		limit = 1
	} else if limit > 100 {
		limit = 100
	}
	input := &ecs.ListTaskDefinitionsInput{MaxResults: awssdk.Int32(int32(limit)), Status: status}
	if nextToken != "" {
		input.NextToken = awssdk.String(nextToken)
	}
	output, err := client.ListTaskDefinitions(ctx, input)
	if err != nil {
		return nil, "", err
	}
	records := make([]ecstypes.TaskDefinition, 0, len(output.TaskDefinitionArns))
	for _, arn := range output.TaskDefinitionArns {
		describe, err := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: awssdk.String(arn)})
		if err != nil {
			return nil, "", fmt.Errorf("describe task definition %q: %w", arn, err)
		}
		if describe.TaskDefinition != nil {
			records = append(records, *describe.TaskDefinition)
		}
	}
	if nextToken = awssdk.ToString(output.NextToken); nextToken != "" {
		return records, strings.ToLower(string(status)) + ":" + nextToken, nil
	}
	if status == ecstypes.TaskDefinitionStatusActive {
		return records, "inactive:", nil
	}
	return records, "", nil
}

type CloudTrailDetail struct {
	EventName         string                  `json:"eventName"`
	EventTime         string                  `json:"eventTime"`
	SourceIPAddress   string                  `json:"sourceIPAddress"`
	UserIdentity      CloudTrailUserIdentity  `json:"userIdentity"`
	Resources         []CloudTrailResourceRef `json:"resources"`
	RequestParameters ecsRequest              `json:"requestParameters"`
	ResponseElements  ecsResponse             `json:"responseElements"`
}

type CloudTrailUserIdentity struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	Arn         string `json:"arn"`
	UserName    string `json:"userName"`
}

type CloudTrailResourceRef struct {
	ARN      string `json:"ARN"`
	ARNLower string `json:"arn"`
	Name     string `json:"resourceName"`
	Type     string `json:"resourceType"`
}

type ecsRequest struct {
	Cluster              string                   `json:"cluster"`
	Family               string                   `json:"family"`
	StartedBy            string                   `json:"startedBy"`
	TaskDefinition       string                   `json:"taskDefinition"`
	TaskRoleARN          string                   `json:"taskRoleArn"`
	ExecutionRoleARN     string                   `json:"executionRoleArn"`
	ContainerDefinitions []ecsContainerDefinition `json:"containerDefinitions"`
}

type ecsResponse struct {
	TaskDefinition ecsTaskDefinition `json:"taskDefinition"`
	Tasks          []ecsTask         `json:"tasks"`
}

type ecsTaskDefinition struct {
	TaskDefinitionARN    string                   `json:"taskDefinitionArn"`
	Family               string                   `json:"family"`
	TaskRoleARN          string                   `json:"taskRoleArn"`
	ExecutionRoleARN     string                   `json:"executionRoleArn"`
	ContainerDefinitions []ecsContainerDefinition `json:"containerDefinitions"`
}

type ecsTask struct {
	TaskARN           string `json:"taskArn"`
	TaskDefinitionARN string `json:"taskDefinitionArn"`
	ClusterARN        string `json:"clusterArn"`
	StartedBy         string `json:"startedBy"`
	LastStatus        string `json:"lastStatus"`
}

type ecsContainerDefinition struct {
	Name    string         `json:"name"`
	Image   string         `json:"image"`
	Secrets []ecsSecretRef `json:"secrets"`
}

type ecsSecretRef struct {
	Name string `json:"name"`
}

func AddCloudTrailECSAttributes(attributes map[string]string, raw string) {
	detail := CloudTrailDetail{}
	if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &detail) != nil {
		return
	}
	switch strings.TrimSpace(first(detail.EventName, attributes["event_type"])) {
	case "RegisterTaskDefinition":
		definition := detail.ResponseElements.TaskDefinition
		containers := definition.ContainerDefinitions
		if len(containers) == 0 {
			containers = detail.RequestParameters.ContainerDefinitions
		}
		taskDefinitionARN := strings.TrimSpace(definition.TaskDefinitionARN)
		if taskDefinitionARN == "" {
			return
		}
		taskRoleARN := first(definition.TaskRoleARN, detail.RequestParameters.TaskRoleARN)
		executionRoleARN := first(definition.ExecutionRoleARN, detail.RequestParameters.ExecutionRoleARN)
		attributes["resource_id"] = taskDefinitionARN
		attributes["resource_name"] = first(definition.Family, detail.RequestParameters.Family, taskDefinitionARN)
		attributes["resource_type"] = "ecs_task_definition"
		attributes["task_definition_arn"] = taskDefinitionARN
		attributes["task_family"] = first(definition.Family, detail.RequestParameters.Family)
		attributes["task_role_arn"], attributes["task_role_name"] = taskRoleARN, roleName(taskRoleARN)
		attributes["execution_role_arn"], attributes["execution_role_name"] = executionRoleARN, roleName(executionRoleARN)
		attributes["container_names"] = strings.Join(containerValues(containers, func(container ecsContainerDefinition) string { return container.Name }), ",")
		attributes["container_images"] = strings.Join(containerValues(containers, func(container ecsContainerDefinition) string { return container.Image }), ",")
		attributes["container_count"] = strconv.Itoa(len(containers))
		secretCount := 0
		for _, container := range containers {
			secretCount += len(container.Secrets)
		}
		attributes["secret_binding_count"] = strconv.Itoa(secretCount)
		attributes["has_secret_bindings"] = strconv.FormatBool(secretCount > 0)
		attributes["has_candidate_marker"] = strconv.FormatBool(hasCandidateMarker(attributes["task_family"], attributes["container_names"], attributes["container_images"]))
	case "RunTask":
		if len(detail.ResponseElements.Tasks) == 0 {
			return
		}
		task := detail.ResponseElements.Tasks[0]
		if strings.TrimSpace(task.TaskARN) == "" {
			return
		}
		attributes["resource_id"], attributes["resource_name"], attributes["resource_type"] = task.TaskARN, path.Base(task.TaskARN), "ecs_task"
		attributes["task_arn"] = task.TaskARN
		attributes["task_definition_arn"] = first(task.TaskDefinitionARN, detail.RequestParameters.TaskDefinition)
		attributes["cluster_arn"] = first(task.ClusterARN, detail.RequestParameters.Cluster)
		attributes["cluster_name"] = path.Base(attributes["cluster_arn"])
		attributes["started_by"] = first(task.StartedBy, detail.RequestParameters.StartedBy)
		attributes["observed_last_status"] = task.LastStatus
	}
}

func AddTaskDefinitionRiskAttributes(attributes map[string]string, task ecstypes.TaskDefinition) {
	secretCount := 0
	names, images := make([]string, 0, len(task.ContainerDefinitions)), make([]string, 0, len(task.ContainerDefinitions))
	for _, container := range task.ContainerDefinitions {
		secretCount += len(container.Secrets)
		names, images = append(names, awssdk.ToString(container.Name)), append(images, awssdk.ToString(container.Image))
	}
	attributes["secret_binding_count"] = strconv.Itoa(secretCount)
	attributes["has_secret_bindings"] = strconv.FormatBool(secretCount > 0)
	attributes["has_candidate_marker"] = strconv.FormatBool(hasCandidateMarker(awssdk.ToString(task.Family), strings.Join(names, ","), strings.Join(images, ",")))
}

func containerValues(containers []ecsContainerDefinition, value func(ecsContainerDefinition) string) []string {
	values, seen := make([]string, 0, len(containers)), map[string]struct{}{}
	for _, container := range containers {
		candidate := strings.TrimSpace(value(container))
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		values = append(values, candidate)
	}
	return values
}

func hasCandidateMarker(values ...string) bool {
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), "candidate") {
			return true
		}
	}
	return false
}

func first(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func roleName(arn string) string {
	if marker := strings.LastIndex(arn, ":role/"); marker >= 0 {
		return path.Base(arn[marker+len(":role/"):])
	}
	return path.Base(arn)
}
