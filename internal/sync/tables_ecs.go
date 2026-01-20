package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func (e *SyncEngine) ecsClusterTable() TableSpec {
	return TableSpec{
		Name:    "aws_ecs_clusters",
		Columns: []string{"arn", "account_id", "region", "name", "status", "settings", "tags"},
		Fetch:   e.fetchECSClusters,
	}
}

func (e *SyncEngine) ecsServiceTable() TableSpec {
	return TableSpec{
		Name:    "aws_ecs_services",
		Columns: []string{"arn", "account_id", "region", "name", "cluster_arn", "status", "task_definition", "desired_count", "running_count", "launch_type", "network_configuration"},
		Fetch:   e.fetchECSServices,
	}
}

func (e *SyncEngine) ecsTaskDefinitionTable() TableSpec {
	return TableSpec{
		Name:    "aws_ecs_task_definitions",
		Columns: []string{"arn", "account_id", "region", "family", "revision", "status", "network_mode", "container_definitions", "task_role_arn", "execution_role_arn", "cpu", "memory", "requires_compatibilities"},
		Fetch:   e.fetchECSTaskDefinitions,
	}
}

func (e *SyncEngine) fetchECSClusters(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ecs.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	listOut, err := client.ListClusters(ctx, &ecs.ListClustersInput{})
	if err != nil {
		return nil, err
	}
	if len(listOut.ClusterArns) == 0 {
		return nil, nil
	}

	descOut, err := client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
		Clusters: listOut.ClusterArns,
		Include:  []ecstypes.ClusterField{ecstypes.ClusterFieldSettings, ecstypes.ClusterFieldTags},
	})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(descOut.Clusters))
	for _, c := range descOut.Clusters {
		rows = append(rows, map[string]interface{}{
			"_cq_id":     aws.ToString(c.ClusterArn),
			"arn":        aws.ToString(c.ClusterArn),
			"account_id": accountID,
			"region":     region,
			"name":       aws.ToString(c.ClusterName),
			"status":     aws.ToString(c.Status),
			"settings":   c.Settings,
			"tags":       c.Tags,
		})
	}
	return rows, nil
}

func (e *SyncEngine) fetchECSServices(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ecs.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	listClusters, err := client.ListClusters(ctx, &ecs.ListClustersInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(listClusters.ClusterArns))
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
				"region":                region,
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
	return rows, nil
}

func (e *SyncEngine) fetchECSTaskDefinitions(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ecs.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	listOut, err := client.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{
		Status: ecstypes.TaskDefinitionStatusActive,
	})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(listOut.TaskDefinitionArns))
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
			"region":                   region,
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
	return rows, nil
}
