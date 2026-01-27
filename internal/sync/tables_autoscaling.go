package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
)

// Auto Scaling Groups table
func (e *SyncEngine) autoscalingGroupTable() TableSpec {
	return TableSpec{
		Name: "aws_autoscaling_groups",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"availability_zones", "created_time", "default_cooldown",
			"desired_capacity", "enabled_metrics", "health_check_grace_period",
			"health_check_type", "instances", "launch_configuration_name",
			"launch_template", "load_balancer_names", "max_instance_lifetime",
			"max_size", "min_size", "mixed_instances_policy", "new_instances_protected_from_scale_in",
			"placement_group", "predicted_capacity", "service_linked_role_arn",
			"status", "suspended_processes", "tags", "target_group_arns",
			"termination_policies", "vpc_zone_identifier", "warm_pool_configuration",
			"warm_pool_size",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := autoscaling.NewFromConfig(cfg, func(o *autoscaling.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := autoscaling.NewDescribeAutoScalingGroupsPaginator(client, &autoscaling.DescribeAutoScalingGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, asg := range page.AutoScalingGroups {
					azJSON, _ := json.Marshal(asg.AvailabilityZones)
					metricsJSON, _ := json.Marshal(asg.EnabledMetrics)
					instancesJSON, _ := json.Marshal(asg.Instances)
					launchTemplateJSON, _ := json.Marshal(asg.LaunchTemplate)
					lbNamesJSON, _ := json.Marshal(asg.LoadBalancerNames)
					mixedPolicyJSON, _ := json.Marshal(asg.MixedInstancesPolicy)
					suspendedJSON, _ := json.Marshal(asg.SuspendedProcesses)
					targetGroupsJSON, _ := json.Marshal(asg.TargetGroupARNs)
					termPoliciesJSON, _ := json.Marshal(asg.TerminationPolicies)
					warmPoolJSON, _ := json.Marshal(asg.WarmPoolConfiguration)

					tags := map[string]string{}
					for _, t := range asg.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}
					tagsJSON, _ := json.Marshal(tags)

					row := map[string]interface{}{
						"arn":                                   aws.ToString(asg.AutoScalingGroupARN),
						"name":                                  aws.ToString(asg.AutoScalingGroupName),
						"account_id":                            accountID,
						"region":                                region,
						"availability_zones":                    string(azJSON),
						"created_time":                          timeToString(asg.CreatedTime),
						"default_cooldown":                      asg.DefaultCooldown,
						"desired_capacity":                      asg.DesiredCapacity,
						"enabled_metrics":                       string(metricsJSON),
						"health_check_grace_period":             asg.HealthCheckGracePeriod,
						"health_check_type":                     aws.ToString(asg.HealthCheckType),
						"instances":                             string(instancesJSON),
						"launch_configuration_name":             aws.ToString(asg.LaunchConfigurationName),
						"launch_template":                       string(launchTemplateJSON),
						"load_balancer_names":                   string(lbNamesJSON),
						"max_instance_lifetime":                 asg.MaxInstanceLifetime,
						"max_size":                              asg.MaxSize,
						"min_size":                              asg.MinSize,
						"mixed_instances_policy":                string(mixedPolicyJSON),
						"new_instances_protected_from_scale_in": asg.NewInstancesProtectedFromScaleIn,
						"placement_group":                       aws.ToString(asg.PlacementGroup),
						"predicted_capacity":                    asg.PredictedCapacity,
						"service_linked_role_arn":               aws.ToString(asg.ServiceLinkedRoleARN),
						"status":                                aws.ToString(asg.Status),
						"suspended_processes":                   string(suspendedJSON),
						"tags":                                  string(tagsJSON),
						"target_group_arns":                     string(targetGroupsJSON),
						"termination_policies":                  string(termPoliciesJSON),
						"vpc_zone_identifier":                   aws.ToString(asg.VPCZoneIdentifier),
						"warm_pool_configuration":               string(warmPoolJSON),
						"warm_pool_size":                        asg.WarmPoolSize,
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Auto Scaling Launch Configurations table
func (e *SyncEngine) autoscalingLaunchConfigTable() TableSpec {
	return TableSpec{
		Name: "aws_autoscaling_launch_configurations",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"associate_public_ip_address", "block_device_mappings",
			"classic_link_vpc_id", "classic_link_vpc_security_groups",
			"created_time", "ebs_optimized", "iam_instance_profile",
			"image_id", "instance_monitoring", "instance_type",
			"kernel_id", "key_name", "metadata_options", "placement_tenancy",
			"ramdisk_id", "security_groups", "spot_price", "user_data",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := autoscaling.NewFromConfig(cfg, func(o *autoscaling.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := autoscaling.NewDescribeLaunchConfigurationsPaginator(client, &autoscaling.DescribeLaunchConfigurationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, lc := range page.LaunchConfigurations {
					blockDevicesJSON, _ := json.Marshal(lc.BlockDeviceMappings)
					classicSGJSON, _ := json.Marshal(lc.ClassicLinkVPCSecurityGroups)
					monitoringJSON, _ := json.Marshal(lc.InstanceMonitoring)
					metadataJSON, _ := json.Marshal(lc.MetadataOptions)
					sgJSON, _ := json.Marshal(lc.SecurityGroups)

					row := map[string]interface{}{
						"arn":                              aws.ToString(lc.LaunchConfigurationARN),
						"name":                             aws.ToString(lc.LaunchConfigurationName),
						"account_id":                       accountID,
						"region":                           region,
						"associate_public_ip_address":      lc.AssociatePublicIpAddress,
						"block_device_mappings":            string(blockDevicesJSON),
						"classic_link_vpc_id":              aws.ToString(lc.ClassicLinkVPCId),
						"classic_link_vpc_security_groups": string(classicSGJSON),
						"created_time":                     timeToString(lc.CreatedTime),
						"ebs_optimized":                    lc.EbsOptimized,
						"iam_instance_profile":             aws.ToString(lc.IamInstanceProfile),
						"image_id":                         aws.ToString(lc.ImageId),
						"instance_monitoring":              string(monitoringJSON),
						"instance_type":                    aws.ToString(lc.InstanceType),
						"kernel_id":                        aws.ToString(lc.KernelId),
						"key_name":                         aws.ToString(lc.KeyName),
						"metadata_options":                 string(metadataJSON),
						"placement_tenancy":                aws.ToString(lc.PlacementTenancy),
						"ramdisk_id":                       aws.ToString(lc.RamdiskId),
						"security_groups":                  string(sgJSON),
						"spot_price":                       aws.ToString(lc.SpotPrice),
						"user_data":                        aws.ToString(lc.UserData),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Auto Scaling Policies table
func (e *SyncEngine) autoscalingPolicyTable() TableSpec {
	return TableSpec{
		Name: "aws_autoscaling_policies",
		Columns: []string{
			"_cq_hash", "arn", "policy_name", "account_id", "region",
			"auto_scaling_group_name", "adjustment_type", "alarms",
			"cooldown", "enabled", "estimated_instance_warmup",
			"metric_aggregation_type", "min_adjustment_magnitude",
			"min_adjustment_step", "policy_type", "predictive_scaling_configuration",
			"scaling_adjustment", "step_adjustments", "target_tracking_configuration",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := autoscaling.NewFromConfig(cfg, func(o *autoscaling.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := autoscaling.NewDescribePoliciesPaginator(client, &autoscaling.DescribePoliciesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, policy := range page.ScalingPolicies {
					alarmsJSON, _ := json.Marshal(policy.Alarms)
					predictiveJSON, _ := json.Marshal(policy.PredictiveScalingConfiguration)
					stepAdjJSON, _ := json.Marshal(policy.StepAdjustments)
					targetTrackingJSON, _ := json.Marshal(policy.TargetTrackingConfiguration)

					row := map[string]interface{}{
						"arn":                              aws.ToString(policy.PolicyARN),
						"policy_name":                      aws.ToString(policy.PolicyName),
						"account_id":                       accountID,
						"region":                           region,
						"auto_scaling_group_name":          aws.ToString(policy.AutoScalingGroupName),
						"adjustment_type":                  aws.ToString(policy.AdjustmentType),
						"alarms":                           string(alarmsJSON),
						"cooldown":                         policy.Cooldown,
						"enabled":                          policy.Enabled,
						"estimated_instance_warmup":        policy.EstimatedInstanceWarmup,
						"metric_aggregation_type":          aws.ToString(policy.MetricAggregationType),
						"min_adjustment_magnitude":         policy.MinAdjustmentMagnitude,
						"min_adjustment_step":              0, // Deprecated
						"policy_type":                      aws.ToString(policy.PolicyType),
						"predictive_scaling_configuration": string(predictiveJSON),
						"scaling_adjustment":               policy.ScalingAdjustment,
						"step_adjustments":                 string(stepAdjJSON),
						"target_tracking_configuration":    string(targetTrackingJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Auto Scaling Scheduled Actions table
func (e *SyncEngine) autoscalingScheduledActionTable() TableSpec {
	return TableSpec{
		Name: "aws_autoscaling_scheduled_actions",
		Columns: []string{
			"_cq_hash", "arn", "scheduled_action_name", "account_id", "region",
			"auto_scaling_group_name", "desired_capacity", "end_time",
			"max_size", "min_size", "recurrence", "start_time", "time", "time_zone",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := autoscaling.NewFromConfig(cfg, func(o *autoscaling.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := autoscaling.NewDescribeScheduledActionsPaginator(client, &autoscaling.DescribeScheduledActionsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, action := range page.ScheduledUpdateGroupActions {
					row := map[string]interface{}{
						"arn":                     aws.ToString(action.ScheduledActionARN),
						"scheduled_action_name":   aws.ToString(action.ScheduledActionName),
						"account_id":              accountID,
						"region":                  region,
						"auto_scaling_group_name": aws.ToString(action.AutoScalingGroupName),
						"desired_capacity":        action.DesiredCapacity,
						"end_time":                timeToString(action.EndTime),
						"max_size":                action.MaxSize,
						"min_size":                action.MinSize,
						"recurrence":              aws.ToString(action.Recurrence),
						"start_time":              timeToString(action.StartTime),
						"time":                    timeToString(action.Time),
						"time_zone":               aws.ToString(action.TimeZone),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Auto Scaling Lifecycle Hooks table
func (e *SyncEngine) autoscalingLifecycleHookTable() TableSpec {
	return TableSpec{
		Name: "aws_autoscaling_lifecycle_hooks",
		Columns: []string{
			"_cq_hash", "lifecycle_hook_name", "account_id", "region",
			"auto_scaling_group_name", "default_result", "global_timeout",
			"heartbeat_timeout", "lifecycle_transition", "notification_metadata",
			"notification_target_arn", "role_arn",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := autoscaling.NewFromConfig(cfg, func(o *autoscaling.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			// First get all ASGs
			asgPaginator := autoscaling.NewDescribeAutoScalingGroupsPaginator(client, &autoscaling.DescribeAutoScalingGroupsInput{})
			for asgPaginator.HasMorePages() {
				asgPage, err := asgPaginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, asg := range asgPage.AutoScalingGroups {
					asgName := aws.ToString(asg.AutoScalingGroupName)

					// Get lifecycle hooks for this ASG
					hooksOut, err := client.DescribeLifecycleHooks(ctx, &autoscaling.DescribeLifecycleHooksInput{
						AutoScalingGroupName: aws.String(asgName),
					})
					if err != nil {
						continue
					}

					for _, hook := range hooksOut.LifecycleHooks {
						row := map[string]interface{}{
							"lifecycle_hook_name":     aws.ToString(hook.LifecycleHookName),
							"account_id":              accountID,
							"region":                  region,
							"auto_scaling_group_name": asgName,
							"default_result":          aws.ToString(hook.DefaultResult),
							"global_timeout":          hook.GlobalTimeout,
							"heartbeat_timeout":       hook.HeartbeatTimeout,
							"lifecycle_transition":    aws.ToString(hook.LifecycleTransition),
							"notification_metadata":   aws.ToString(hook.NotificationMetadata),
							"notification_target_arn": aws.ToString(hook.NotificationTargetARN),
							"role_arn":                aws.ToString(hook.RoleARN),
						}
						results = append(results, row)
					}
				}
			}
			return results, nil
		},
	}
}
