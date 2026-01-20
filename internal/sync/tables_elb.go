package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

func (e *SyncEngine) elbv2LoadBalancerTable() TableSpec {
	return TableSpec{
		Name:    "aws_elbv2_load_balancers",
		Columns: []string{"arn", "account_id", "region", "load_balancer_name", "name", "dns_name", "canonical_hosted_zone_id", "created_time", "scheme", "vpc_id", "state", "type", "availability_zones", "security_groups", "ip_address_type", "customer_owned_ipv4_pool", "tags"},
		Fetch:   e.fetchELBv2LoadBalancers,
	}
}

func (e *SyncEngine) elbv2TargetGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_elbv2_target_groups",
		Columns: []string{"arn", "account_id", "region", "target_group_name", "name", "protocol", "port", "vpc_id", "health_check_protocol", "health_check_port", "health_check_enabled", "health_check_interval_seconds", "health_check_timeout_seconds", "healthy_threshold_count", "unhealthy_threshold_count", "health_check_path", "target_type", "protocol_version", "load_balancer_arns", "tags"},
		Fetch:   e.fetchELBv2TargetGroups,
	}
}

func (e *SyncEngine) fetchELBv2LoadBalancers(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := elbv2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := elbv2.NewDescribeLoadBalancersPaginator(client, &elbv2.DescribeLoadBalancersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, lb := range page.LoadBalancers {
			arn := aws.ToString(lb.LoadBalancerArn)

			row := map[string]interface{}{
				"_cq_id":                   arn,
				"arn":                      arn,
				"account_id":               accountID,
				"region":                   region,
				"load_balancer_name":       aws.ToString(lb.LoadBalancerName),
				"name":                     aws.ToString(lb.LoadBalancerName),
				"dns_name":                 aws.ToString(lb.DNSName),
				"canonical_hosted_zone_id": aws.ToString(lb.CanonicalHostedZoneId),
				"created_time":             lb.CreatedTime,
				"scheme":                   string(lb.Scheme),
				"vpc_id":                   aws.ToString(lb.VpcId),
				"type":                     string(lb.Type),
				"availability_zones":       lb.AvailabilityZones,
				"security_groups":          lb.SecurityGroups,
				"ip_address_type":          string(lb.IpAddressType),
				"customer_owned_ipv4_pool": aws.ToString(lb.CustomerOwnedIpv4Pool),
			}

			if lb.State != nil {
				row["state"] = string(lb.State.Code)
			}

			// Get tags
			tagsOut, err := client.DescribeTags(ctx, &elbv2.DescribeTagsInput{
				ResourceArns: []string{arn},
			})
			if err == nil && len(tagsOut.TagDescriptions) > 0 {
				row["tags"] = tagsOut.TagDescriptions[0].Tags
			}

			rows = append(rows, row)
		}
	}
	return rows, nil
}

func (e *SyncEngine) fetchELBv2TargetGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := elbv2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := elbv2.NewDescribeTargetGroupsPaginator(client, &elbv2.DescribeTargetGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, tg := range page.TargetGroups {
			arn := aws.ToString(tg.TargetGroupArn)

			row := map[string]interface{}{
				"_cq_id":                        arn,
				"arn":                           arn,
				"account_id":                    accountID,
				"region":                        region,
				"target_group_name":             aws.ToString(tg.TargetGroupName),
				"name":                          aws.ToString(tg.TargetGroupName),
				"protocol":                      string(tg.Protocol),
				"port":                          tg.Port,
				"vpc_id":                        aws.ToString(tg.VpcId),
				"health_check_protocol":         string(tg.HealthCheckProtocol),
				"health_check_port":             aws.ToString(tg.HealthCheckPort),
				"health_check_enabled":          aws.ToBool(tg.HealthCheckEnabled),
				"health_check_interval_seconds": tg.HealthCheckIntervalSeconds,
				"health_check_timeout_seconds":  tg.HealthCheckTimeoutSeconds,
				"healthy_threshold_count":       tg.HealthyThresholdCount,
				"unhealthy_threshold_count":     tg.UnhealthyThresholdCount,
				"health_check_path":             aws.ToString(tg.HealthCheckPath),
				"target_type":                   string(tg.TargetType),
				"protocol_version":              aws.ToString(tg.ProtocolVersion),
				"load_balancer_arns":            tg.LoadBalancerArns,
			}

			// Get tags
			tagsOut, err := client.DescribeTags(ctx, &elbv2.DescribeTagsInput{
				ResourceArns: []string{arn},
			})
			if err == nil && len(tagsOut.TagDescriptions) > 0 {
				row["tags"] = tagsOut.TagDescriptions[0].Tags
			}

			rows = append(rows, row)
		}
	}
	return rows, nil
}
