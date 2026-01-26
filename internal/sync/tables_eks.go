package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

func (e *SyncEngine) eksClusterTable() TableSpec {
	return TableSpec{
		Name: "aws_eks_clusters",
		Columns: []string{
			"arn", "name", "region", "account_id", "version", "status",
			"platform_version", "endpoint", "role_arn", "certificate_authority",
			"vpc_config", "kubernetes_network_config", "logging", "identity",
			"encryption_config", "connector_config", "created_at", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := eks.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := eks.NewListClustersPaginator(client, &eks.ListClustersInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list clusters: %w", err)
				}

				for _, clusterName := range page.Clusters {
					cluster, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{
						Name: aws.String(clusterName),
					})
					if err != nil {
						continue
					}

					c := cluster.Cluster
					arn := ptrToStr(c.Arn)

					var certAuth string
					if c.CertificateAuthority != nil {
						certAuth = ptrToStr(c.CertificateAuthority.Data)
					}

					row := map[string]interface{}{
						"_cq_id":                    arn,
						"arn":                       arn,
						"name":                      ptrToStr(c.Name),
						"region":                    region,
						"account_id":                e.accountID,
						"version":                   ptrToStr(c.Version),
						"status":                    string(c.Status),
						"platform_version":          ptrToStr(c.PlatformVersion),
						"endpoint":                  ptrToStr(c.Endpoint),
						"role_arn":                  ptrToStr(c.RoleArn),
						"certificate_authority":     certAuth,
						"vpc_config":                c.ResourcesVpcConfig,
						"kubernetes_network_config": c.KubernetesNetworkConfig,
						"logging":                   c.Logging,
						"identity":                  c.Identity,
						"encryption_config":         c.EncryptionConfig,
						"connector_config":          c.ConnectorConfig,
						"created_at":                c.CreatedAt,
						"tags":                      c.Tags,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) eksNodegroupTable() TableSpec {
	return TableSpec{
		Name: "aws_eks_node_groups",
		Columns: []string{
			"arn", "nodegroup_name", "cluster_name", "region", "account_id",
			"version", "status", "capacity_type", "scaling_config",
			"instance_types", "subnets", "ami_type", "node_role",
			"disk_size", "health", "launch_template", "created_at", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := eks.NewFromConfig(cfg)
			var results []map[string]interface{}

			// List clusters first
			clusterPager := eks.NewListClustersPaginator(client, &eks.ListClustersInput{})

			for clusterPager.HasMorePages() {
				clusterPage, err := clusterPager.NextPage(ctx)
				if err != nil {
					continue
				}

				for _, clusterName := range clusterPage.Clusters {
					// List node groups for this cluster
					ngPager := eks.NewListNodegroupsPaginator(client, &eks.ListNodegroupsInput{
						ClusterName: aws.String(clusterName),
					})

					for ngPager.HasMorePages() {
						ngPage, err := ngPager.NextPage(ctx)
						if err != nil {
							continue
						}

						for _, ngName := range ngPage.Nodegroups {
							ng, err := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
								ClusterName:   aws.String(clusterName),
								NodegroupName: aws.String(ngName),
							})
							if err != nil {
								continue
							}

							n := ng.Nodegroup
							arn := ptrToStr(n.NodegroupArn)

							row := map[string]interface{}{
								"_cq_id":          arn,
								"arn":             arn,
								"nodegroup_name":  ptrToStr(n.NodegroupName),
								"cluster_name":    ptrToStr(n.ClusterName),
								"region":          region,
								"account_id":      e.accountID,
								"version":         ptrToStr(n.Version),
								"status":          string(n.Status),
								"capacity_type":   string(n.CapacityType),
								"scaling_config":  n.ScalingConfig,
								"instance_types":  n.InstanceTypes,
								"subnets":         n.Subnets,
								"ami_type":        string(n.AmiType),
								"node_role":       ptrToStr(n.NodeRole),
								"disk_size":       n.DiskSize,
								"health":          n.Health,
								"launch_template": n.LaunchTemplate,
								"created_at":      n.CreatedAt,
								"tags":            n.Tags,
							}

							results = append(results, row)
						}
					}
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) eksFargateProfileTable() TableSpec {
	return TableSpec{
		Name: "aws_eks_fargate_profiles",
		Columns: []string{
			"arn", "fargate_profile_name", "cluster_name", "region", "account_id",
			"status", "pod_execution_role_arn", "subnets", "selectors",
			"created_at", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := eks.NewFromConfig(cfg)
			var results []map[string]interface{}

			clusterPager := eks.NewListClustersPaginator(client, &eks.ListClustersInput{})

			for clusterPager.HasMorePages() {
				clusterPage, err := clusterPager.NextPage(ctx)
				if err != nil {
					continue
				}

				for _, clusterName := range clusterPage.Clusters {
					fpPager := eks.NewListFargateProfilesPaginator(client, &eks.ListFargateProfilesInput{
						ClusterName: aws.String(clusterName),
					})

					for fpPager.HasMorePages() {
						fpPage, err := fpPager.NextPage(ctx)
						if err != nil {
							continue
						}

						for _, fpName := range fpPage.FargateProfileNames {
							fp, err := client.DescribeFargateProfile(ctx, &eks.DescribeFargateProfileInput{
								ClusterName:        aws.String(clusterName),
								FargateProfileName: aws.String(fpName),
							})
							if err != nil {
								continue
							}

							f := fp.FargateProfile
							arn := ptrToStr(f.FargateProfileArn)

							row := map[string]interface{}{
								"_cq_id":                 arn,
								"arn":                    arn,
								"fargate_profile_name":   ptrToStr(f.FargateProfileName),
								"cluster_name":           ptrToStr(f.ClusterName),
								"region":                 region,
								"account_id":             e.accountID,
								"status":                 string(f.Status),
								"pod_execution_role_arn": ptrToStr(f.PodExecutionRoleArn),
								"subnets":                f.Subnets,
								"selectors":              f.Selectors,
								"created_at":             f.CreatedAt,
								"tags":                   f.Tags,
							}

							results = append(results, row)
						}
					}
				}
			}

			return results, nil
		},
	}
}
