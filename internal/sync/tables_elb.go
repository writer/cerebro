package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
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

func (e *SyncEngine) elbv2ListenerTable() TableSpec {
	return TableSpec{
		Name:    "aws_lb_listeners",
		Columns: []string{"arn", "account_id", "region", "listener_arn", "load_balancer_arn", "port", "protocol", "ssl_policy", "certificates", "alpn_policy", "default_actions"},
		Fetch:   e.fetchELBv2Listeners,
	}
}

func (e *SyncEngine) elbv2ListenerActionTable() TableSpec {
	return TableSpec{
		Name:    "default_actions",
		Columns: []string{"listener_arn", "action_order", "type", "target_group_arn", "redirect_config", "fixed_response_config", "authenticate_oidc_config", "authenticate_cognito_config", "account_id", "region"},
		Fetch:   e.fetchELBv2ListenerActions,
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

func (e *SyncEngine) listELBv2Listeners(ctx context.Context, client *elbv2.Client) ([]elbv2types.Listener, error) {
	lbPager := elbv2.NewDescribeLoadBalancersPaginator(client, &elbv2.DescribeLoadBalancersInput{})
	var listeners []elbv2types.Listener

	for lbPager.HasMorePages() {
		lbPage, err := lbPager.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, lb := range lbPage.LoadBalancers {
			lbArn := aws.ToString(lb.LoadBalancerArn)
			if lbArn == "" {
				continue
			}

			listenerPager := elbv2.NewDescribeListenersPaginator(client, &elbv2.DescribeListenersInput{
				LoadBalancerArn: aws.String(lbArn),
			})
			for listenerPager.HasMorePages() {
				listenerPage, err := listenerPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				listeners = append(listeners, listenerPage.Listeners...)
			}
		}
	}

	return listeners, nil
}

func (e *SyncEngine) fetchELBv2Listeners(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := elbv2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	listeners, err := e.listELBv2Listeners(ctx, client)
	if err != nil {
		return nil, err
	}

	for _, listener := range listeners {
		arn := aws.ToString(listener.ListenerArn)
		row := map[string]interface{}{
			"_cq_id":            arn,
			"arn":               arn,
			"account_id":        accountID,
			"region":            region,
			"listener_arn":      arn,
			"load_balancer_arn": aws.ToString(listener.LoadBalancerArn),
			"port":              listener.Port,
			"protocol":          string(listener.Protocol),
			"ssl_policy":        aws.ToString(listener.SslPolicy),
			"certificates":      listener.Certificates,
			"alpn_policy":       listener.AlpnPolicy,
			"default_actions":   listener.DefaultActions,
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (e *SyncEngine) fetchELBv2ListenerActions(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := elbv2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	listeners, err := e.listELBv2Listeners(ctx, client)
	if err != nil {
		return nil, err
	}

	for _, listener := range listeners {
		listenerArn := aws.ToString(listener.ListenerArn)
		for i, action := range listener.DefaultActions {
			row := map[string]interface{}{
				"_cq_id":           fmt.Sprintf("%s/%d", listenerArn, i),
				"listener_arn":     listenerArn,
				"action_order":     action.Order,
				"type":             string(action.Type),
				"target_group_arn": selectActionTargetGroup(action),
			}

			if action.RedirectConfig != nil {
				row["redirect_config"] = map[string]interface{}{
					"protocol":    aws.ToString(action.RedirectConfig.Protocol),
					"port":        aws.ToString(action.RedirectConfig.Port),
					"host":        aws.ToString(action.RedirectConfig.Host),
					"path":        aws.ToString(action.RedirectConfig.Path),
					"query":       aws.ToString(action.RedirectConfig.Query),
					"status_code": string(action.RedirectConfig.StatusCode),
				}
			}

			if action.FixedResponseConfig != nil {
				row["fixed_response_config"] = map[string]interface{}{
					"content_type": aws.ToString(action.FixedResponseConfig.ContentType),
					"message_body": aws.ToString(action.FixedResponseConfig.MessageBody),
					"status_code":  aws.ToString(action.FixedResponseConfig.StatusCode),
				}
			}

			if action.AuthenticateOidcConfig != nil {
				row["authenticate_oidc_config"] = map[string]interface{}{
					"authorization_endpoint": aws.ToString(action.AuthenticateOidcConfig.AuthorizationEndpoint),
					"issuer":                 aws.ToString(action.AuthenticateOidcConfig.Issuer),
					"token_endpoint":         aws.ToString(action.AuthenticateOidcConfig.TokenEndpoint),
					"user_info_endpoint":     aws.ToString(action.AuthenticateOidcConfig.UserInfoEndpoint),
					"scope":                  aws.ToString(action.AuthenticateOidcConfig.Scope),
				}
			}

			if action.AuthenticateCognitoConfig != nil {
				row["authenticate_cognito_config"] = map[string]interface{}{
					"user_pool_arn":       aws.ToString(action.AuthenticateCognitoConfig.UserPoolArn),
					"user_pool_client_id": aws.ToString(action.AuthenticateCognitoConfig.UserPoolClientId),
					"user_pool_domain":    aws.ToString(action.AuthenticateCognitoConfig.UserPoolDomain),
					"scope":               aws.ToString(action.AuthenticateCognitoConfig.Scope),
				}
			}

			row["account_id"] = accountID
			row["region"] = region

			rows = append(rows, row)
		}
	}

	return rows, nil
}

func selectActionTargetGroup(action elbv2types.Action) string {
	if action.TargetGroupArn != nil {
		return aws.ToString(action.TargetGroupArn)
	}
	if action.ForwardConfig != nil && len(action.ForwardConfig.TargetGroups) > 0 {
		return aws.ToString(action.ForwardConfig.TargetGroups[0].TargetGroupArn)
	}
	return ""
}
