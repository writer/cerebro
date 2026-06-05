package aws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigatewaytypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsAPIGatewayStage struct {
	Version string
	RestAPI apigatewaytypes.RestApi
	Stage   apigatewaytypes.Stage
	API     apigatewayv2types.Api
	StageV2 apigatewayv2types.Stage
}

type awsAPIGatewayRoute struct {
	Version    string
	RestAPI    apigatewaytypes.RestApi
	Resource   apigatewaytypes.Resource
	HTTPMethod string
	Method     apigatewaytypes.Method
	API        apigatewayv2types.Api
	Route      apigatewayv2types.Route
}

type awsAPIGatewayIntegration struct {
	Version       string
	RestAPI       apigatewaytypes.RestApi
	Resource      apigatewaytypes.Resource
	HTTPMethod    string
	Method        apigatewaytypes.Method
	Integration   apigatewaytypes.Integration
	API           apigatewayv2types.Api
	IntegrationV2 apigatewayv2types.Integration
}

func listELBListeners(ctx context.Context, clients awsClients, _ settings, _ string, limit int) ([]elbv2types.Listener, string, error) {
	loadBalancers, err := listAllELBLoadBalancers(ctx, clients, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]elbv2types.Listener, 0)
	for _, loadBalancer := range loadBalancers {
		var marker *string
		for {
			output, err := clients.elbv2.DescribeListeners(ctx, &elbv2.DescribeListenersInput{
				LoadBalancerArn: loadBalancer.LoadBalancerArn,
				Marker:          marker,
				PageSize:        awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 400))),
			})
			if err != nil {
				return nil, "", fmt.Errorf("describe listeners for load balancer %q: %w", awssdk.ToString(loadBalancer.LoadBalancerArn), err)
			}
			records = append(records, output.Listeners...)
			if awssdk.ToString(output.NextMarker) == "" {
				break
			}
			marker = output.NextMarker
		}
	}
	return records, "", nil
}

func listELBTargetGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]elbv2types.TargetGroup, string, error) {
	output, err := clients.elbv2.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
		Marker:   stringPtr(cursor),
		PageSize: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 400))),
	})
	if err != nil {
		return nil, "", err
	}
	return output.TargetGroups, awssdk.ToString(output.NextMarker), nil
}

func listAPIGatewayStages(ctx context.Context, clients awsClients, _ settings, _ string, limit int) ([]awsAPIGatewayStage, string, error) {
	restAPIs, err := listAllAPIGatewayRestAPIs(ctx, clients, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]awsAPIGatewayStage, 0)
	for _, api := range restAPIs {
		output, err := clients.apiGateway.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: api.Id})
		if err != nil {
			return nil, "", fmt.Errorf("get api gateway stages for rest api %q: %w", awssdk.ToString(api.Id), err)
		}
		for _, stage := range output.Item {
			records = append(records, awsAPIGatewayStage{Version: "rest", RestAPI: api, Stage: stage})
		}
	}
	v2APIs, err := listAllAPIGatewayV2APIs(ctx, clients, limit)
	if err != nil {
		return nil, "", err
	}
	for _, api := range v2APIs {
		var token *string
		for {
			output, err := clients.apiGatewayV2.GetStages(ctx, &apigatewayv2.GetStagesInput{
				ApiId:      api.ApiId,
				MaxResults: stringPtr(strconv.Itoa(boundedAWSPageSize(limit, 1, 100))),
				NextToken:  token,
			})
			if err != nil {
				return nil, "", fmt.Errorf("get api gateway v2 stages for api %q: %w", awssdk.ToString(api.ApiId), err)
			}
			for _, stage := range output.Items {
				records = append(records, awsAPIGatewayStage{Version: "v2", API: api, StageV2: stage})
			}
			if awssdk.ToString(output.NextToken) == "" {
				break
			}
			token = output.NextToken
		}
	}
	return records, "", nil
}

func listAPIGatewayRoutes(ctx context.Context, clients awsClients, _ settings, _ string, limit int) ([]awsAPIGatewayRoute, string, error) {
	restAPIs, err := listAllAPIGatewayRestAPIs(ctx, clients, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]awsAPIGatewayRoute, 0)
	for _, api := range restAPIs {
		resources, err := listAllAPIGatewayResources(ctx, clients, api, limit)
		if err != nil {
			return nil, "", err
		}
		for _, resource := range resources {
			for methodName, method := range resource.ResourceMethods {
				records = append(records, awsAPIGatewayRoute{Version: "rest", RestAPI: api, Resource: resource, HTTPMethod: methodName, Method: method})
			}
		}
	}
	v2APIs, err := listAllAPIGatewayV2APIs(ctx, clients, limit)
	if err != nil {
		return nil, "", err
	}
	for _, api := range v2APIs {
		var token *string
		for {
			output, err := clients.apiGatewayV2.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{
				ApiId:      api.ApiId,
				MaxResults: stringPtr(strconv.Itoa(boundedAWSPageSize(limit, 1, 100))),
				NextToken:  token,
			})
			if err != nil {
				return nil, "", fmt.Errorf("get api gateway v2 routes for api %q: %w", awssdk.ToString(api.ApiId), err)
			}
			for _, route := range output.Items {
				records = append(records, awsAPIGatewayRoute{Version: "v2", API: api, Route: route})
			}
			if awssdk.ToString(output.NextToken) == "" {
				break
			}
			token = output.NextToken
		}
	}
	return records, "", nil
}

func listAPIGatewayIntegrations(ctx context.Context, clients awsClients, _ settings, _ string, limit int) ([]awsAPIGatewayIntegration, string, error) {
	restAPIs, err := listAllAPIGatewayRestAPIs(ctx, clients, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]awsAPIGatewayIntegration, 0)
	for _, api := range restAPIs {
		resources, err := listAllAPIGatewayResources(ctx, clients, api, limit)
		if err != nil {
			return nil, "", err
		}
		for _, resource := range resources {
			for methodName, method := range resource.ResourceMethods {
				if method.MethodIntegration != nil {
					records = append(records, awsAPIGatewayIntegration{Version: "rest", RestAPI: api, Resource: resource, HTTPMethod: methodName, Method: method, Integration: *method.MethodIntegration})
				}
			}
		}
	}
	v2APIs, err := listAllAPIGatewayV2APIs(ctx, clients, limit)
	if err != nil {
		return nil, "", err
	}
	for _, api := range v2APIs {
		var token *string
		for {
			output, err := clients.apiGatewayV2.GetIntegrations(ctx, &apigatewayv2.GetIntegrationsInput{
				ApiId:      api.ApiId,
				MaxResults: stringPtr(strconv.Itoa(boundedAWSPageSize(limit, 1, 100))),
				NextToken:  token,
			})
			if err != nil {
				return nil, "", fmt.Errorf("get api gateway v2 integrations for api %q: %w", awssdk.ToString(api.ApiId), err)
			}
			for _, integration := range output.Items {
				records = append(records, awsAPIGatewayIntegration{Version: "v2", API: api, IntegrationV2: integration})
			}
			if awssdk.ToString(output.NextToken) == "" {
				break
			}
			token = output.NextToken
		}
	}
	return records, "", nil
}

func listCloudFrontOriginAccessControls(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]cloudfronttypes.OriginAccessControlSummary, string, error) {
	output, err := clients.cloudFront.ListOriginAccessControls(ctx, &cloudfront.ListOriginAccessControlsInput{
		Marker:   stringPtr(cursor),
		MaxItems: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	if output.OriginAccessControlList == nil {
		return nil, "", nil
	}
	return output.OriginAccessControlList.Items, awssdk.ToString(output.OriginAccessControlList.NextMarker), nil
}

func listCloudFrontKeyGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]cloudfronttypes.KeyGroupSummary, string, error) {
	output, err := clients.cloudFront.ListKeyGroups(ctx, &cloudfront.ListKeyGroupsInput{
		Marker:   stringPtr(cursor),
		MaxItems: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	if output.KeyGroupList == nil {
		return nil, "", nil
	}
	return output.KeyGroupList.Items, awssdk.ToString(output.KeyGroupList.NextMarker), nil
}

func listCloudFrontPublicKeys(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]cloudfronttypes.PublicKeySummary, string, error) {
	output, err := clients.cloudFront.ListPublicKeys(ctx, &cloudfront.ListPublicKeysInput{
		Marker:   stringPtr(cursor),
		MaxItems: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	if output.PublicKeyList == nil {
		return nil, "", nil
	}
	return output.PublicKeyList.Items, awssdk.ToString(output.PublicKeyList.NextMarker), nil
}

func listCloudFrontResponseHeadersPolicies(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]cloudfronttypes.ResponseHeadersPolicySummary, string, error) {
	output, err := clients.cloudFront.ListResponseHeadersPolicies(ctx, &cloudfront.ListResponseHeadersPoliciesInput{
		Marker:   stringPtr(cursor),
		MaxItems: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	if output.ResponseHeadersPolicyList == nil {
		return nil, "", nil
	}
	return output.ResponseHeadersPolicyList.Items, awssdk.ToString(output.ResponseHeadersPolicyList.NextMarker), nil
}

func elbListenerEvent(settings settings, listener elbv2types.Listener) (*primitives.Event, error) {
	listenerARN := awssdk.ToString(listener.ListenerArn)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyELBListener, listenerARN, firstNonEmpty(listenerARN, awssdk.ToString(listener.LoadBalancerArn)), "elb_listener", nil)
	attributes["arn"] = listenerARN
	attributes["listener_arn"] = listenerARN
	attributes["load_balancer_arn"] = awssdk.ToString(listener.LoadBalancerArn)
	attributes["port"] = int32AttrString(listener.Port)
	attributes["protocol"] = string(listener.Protocol)
	attributes["ssl_policy"] = awssdk.ToString(listener.SslPolicy)
	attributes["certificate_arns"] = strings.Join(elbCertificateARNs(listener.Certificates), ",")
	attributes["default_action_types"] = strings.Join(elbActionTypes(listener.DefaultActions), ",")
	attributes["target_group_arns"] = strings.Join(elbActionTargetGroupARNs(listener.DefaultActions), ",")
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "listener": listener})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-elb-listener-"+listenerARN, "aws.elb_listener", "aws/elb_listener/v1", payload, attributes, time.Now().UTC())
}

func elbTargetGroupEvent(settings settings, group elbv2types.TargetGroup) (*primitives.Event, error) {
	groupARN := awssdk.ToString(group.TargetGroupArn)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyELBTargetGroup, groupARN, awssdk.ToString(group.TargetGroupName), "elb_target_group", nil)
	attributes["arn"] = groupARN
	attributes["target_group_arn"] = groupARN
	attributes["target_group_name"] = awssdk.ToString(group.TargetGroupName)
	attributes["target_type"] = string(group.TargetType)
	attributes["protocol"] = string(group.Protocol)
	attributes["protocol_version"] = awssdk.ToString(group.ProtocolVersion)
	attributes["port"] = int32AttrString(group.Port)
	attributes["vpc_id"] = awssdk.ToString(group.VpcId)
	attributes["load_balancer_arns"] = strings.Join(cleanStrings(group.LoadBalancerArns), ",")
	attributes["health_check_enabled"] = boolPtrString(group.HealthCheckEnabled)
	attributes["health_check_protocol"] = string(group.HealthCheckProtocol)
	attributes["health_check_path"] = awssdk.ToString(group.HealthCheckPath)
	attributes["health_check_port"] = awssdk.ToString(group.HealthCheckPort)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "target_group": group})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-elb-target-group-"+groupARN, "aws.elb_target_group", "aws/elb_target_group/v1", payload, attributes, time.Now().UTC())
}

func apiGatewayStageEvent(settings settings, stage awsAPIGatewayStage) (*primitives.Event, error) {
	id := apiGatewayStageID(stage)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAPIGatewayStage, id, apiGatewayStageName(stage), "api_gateway_stage", apiGatewayStageTags(stage))
	attributes["api_gateway_version"] = stage.Version
	attributes["api_id"] = apiGatewayStageAPIID(stage)
	attributes["api_name"] = apiGatewayStageAPIName(stage)
	attributes["api_endpoint"] = apiGatewayStageAPIEndpoint(stage)
	attributes["stage_name"] = apiGatewayStageName(stage)
	attributes["deployment_id"] = apiGatewayStageDeploymentID(stage)
	attributes["auto_deploy"] = apiGatewayStageAutoDeploy(stage)
	attributes["tracing_enabled"] = apiGatewayStageTracingEnabled(stage)
	attributes["public"] = boolString(apiGatewayStagePublic(stage))
	attributes["internet_exposed"] = attributes["public"]
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "stage": stage})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-api-gateway-stage-"+id, "aws.api_gateway_stage", "aws/api_gateway_stage/v1", payload, attributes, apiGatewayStageTime(stage))
}

func apiGatewayRouteEvent(settings settings, route awsAPIGatewayRoute) (*primitives.Event, error) {
	id := apiGatewayRouteID(route)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAPIGatewayRoute, id, apiGatewayRouteName(route), "api_gateway_route", nil)
	attributes["api_gateway_version"] = route.Version
	attributes["api_id"] = apiGatewayRouteAPIID(route)
	attributes["api_name"] = apiGatewayRouteAPIName(route)
	attributes["api_endpoint"] = apiGatewayRouteAPIEndpoint(route)
	attributes["route_id"] = apiGatewayRouteNativeID(route)
	attributes["route_key"] = apiGatewayRouteKey(route)
	attributes["resource_path"] = awssdk.ToString(route.Resource.Path)
	attributes["http_method"] = apiGatewayRouteHTTPMethod(route)
	attributes["authorization_type"] = apiGatewayRouteAuthorizationType(route)
	attributes["api_key_required"] = apiGatewayRouteAPIKeyRequired(route)
	attributes["integration_target"] = apiGatewayRouteIntegrationTarget(route)
	attributes["public"] = boolString(apiGatewayRoutePublic(route))
	attributes["internet_exposed"] = attributes["public"]
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "route": route})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-api-gateway-route-"+id, "aws.api_gateway_route", "aws/api_gateway_route/v1", payload, attributes, time.Now().UTC())
}

func apiGatewayIntegrationEvent(settings settings, integration awsAPIGatewayIntegration) (*primitives.Event, error) {
	id := apiGatewayIntegrationID(integration)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAPIGatewayIntegrate, id, apiGatewayIntegrationName(integration), "api_gateway_integration", nil)
	attributes["api_gateway_version"] = integration.Version
	attributes["api_id"] = apiGatewayIntegrationAPIID(integration)
	attributes["api_name"] = apiGatewayIntegrationAPIName(integration)
	attributes["api_endpoint"] = apiGatewayIntegrationAPIEndpoint(integration)
	attributes["integration_id"] = apiGatewayIntegrationNativeID(integration)
	attributes["integration_type"] = apiGatewayIntegrationType(integration)
	attributes["integration_uri"] = apiGatewayIntegrationURI(integration)
	attributes["integration_method"] = apiGatewayIntegrationMethod(integration)
	attributes["connection_type"] = apiGatewayIntegrationConnectionType(integration)
	attributes["connection_id"] = apiGatewayIntegrationConnectionID(integration)
	attributes["credentials_arn"] = apiGatewayIntegrationCredentials(integration)
	attributes["timeout_millis"] = apiGatewayIntegrationTimeout(integration)
	attributes["public"] = boolString(apiGatewayIntegrationPublic(integration))
	attributes["internet_exposed"] = attributes["public"]
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "integration": integration})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-api-gateway-integration-"+id, "aws.api_gateway_integration", "aws/api_gateway_integration/v1", payload, attributes, time.Now().UTC())
}

func cloudFrontOriginAccessControlEvent(settings settings, control cloudfronttypes.OriginAccessControlSummary) (*primitives.Event, error) {
	id := awssdk.ToString(control.Id)
	attributes := commonCloudAssetAttributes(settings, "global", familyCloudFrontOAC, id, awssdk.ToString(control.Name), "cloudfront_origin_access_control", nil)
	attributes["origin_access_control_id"] = id
	attributes["name"] = awssdk.ToString(control.Name)
	attributes["description"] = awssdk.ToString(control.Description)
	attributes["origin_type"] = string(control.OriginAccessControlOriginType)
	attributes["signing_behavior"] = string(control.SigningBehavior)
	attributes["signing_protocol"] = string(control.SigningProtocol)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": "global", "origin_access_control": control})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudfront-origin-access-control-"+id, "aws.cloudfront_origin_access_control", "aws/cloudfront_origin_access_control/v1", payload, attributes, time.Now().UTC())
}

func cloudFrontKeyGroupEvent(settings settings, group cloudfronttypes.KeyGroupSummary) (*primitives.Event, error) {
	id := cloudFrontKeyGroupID(group)
	name := cloudFrontKeyGroupName(group)
	attributes := commonCloudAssetAttributes(settings, "global", familyCloudFrontKeyGroup, id, name, "cloudfront_key_group", nil)
	attributes["key_group_id"] = id
	attributes["name"] = name
	attributes["comment"] = cloudFrontKeyGroupComment(group)
	attributes["public_key_ids"] = strings.Join(cloudFrontKeyGroupPublicKeyIDs(group), ",")
	addTimeAttribute(attributes, "last_modified_at", cloudFrontKeyGroupLastModified(group))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": "global", "key_group": group})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudfront-key-group-"+id, "aws.cloudfront_key_group", "aws/cloudfront_key_group/v1", payload, attributes, firstTime(cloudFrontKeyGroupLastModified(group)))
}

func cloudFrontPublicKeyEvent(settings settings, key cloudfronttypes.PublicKeySummary) (*primitives.Event, error) {
	id := awssdk.ToString(key.Id)
	attributes := commonCloudAssetAttributes(settings, "global", familyCloudFrontPublicKey, id, awssdk.ToString(key.Name), "cloudfront_public_key", nil)
	attributes["public_key_id"] = id
	attributes["name"] = awssdk.ToString(key.Name)
	attributes["comment"] = awssdk.ToString(key.Comment)
	attributes["encoded_key_sha256"] = awsSHA256Hex(awssdk.ToString(key.EncodedKey))
	addTimeAttribute(attributes, "created_at", key.CreatedTime)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": "global", "public_key": key})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudfront-public-key-"+id, "aws.cloudfront_public_key", "aws/cloudfront_public_key/v1", payload, attributes, firstTime(key.CreatedTime))
}

func cloudFrontResponseHeadersPolicyEvent(settings settings, policy cloudfronttypes.ResponseHeadersPolicySummary) (*primitives.Event, error) {
	id := cloudFrontResponseHeadersPolicyID(policy)
	name := cloudFrontResponseHeadersPolicyName(policy)
	attributes := commonCloudAssetAttributes(settings, "global", familyCloudFrontRHP, id, name, "cloudfront_response_headers_policy", nil)
	attributes["response_headers_policy_id"] = id
	attributes["name"] = name
	attributes["policy_type"] = string(policy.Type)
	attributes["comment"] = cloudFrontResponseHeadersPolicyComment(policy)
	attributes["has_cors_config"] = boolString(cloudFrontResponseHeadersPolicyHasCORS(policy))
	attributes["has_security_headers_config"] = boolString(cloudFrontResponseHeadersPolicyHasSecurityHeaders(policy))
	attributes["has_custom_headers_config"] = boolString(cloudFrontResponseHeadersPolicyHasCustomHeaders(policy))
	addTimeAttribute(attributes, "last_modified_at", cloudFrontResponseHeadersPolicyLastModified(policy))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": "global", "response_headers_policy": policy})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudfront-response-headers-policy-"+id, "aws.cloudfront_response_headers_policy", "aws/cloudfront_response_headers_policy/v1", payload, attributes, firstTime(cloudFrontResponseHeadersPolicyLastModified(policy)))
}

func listAllELBLoadBalancers(ctx context.Context, clients awsClients, limit int) ([]elbv2types.LoadBalancer, error) {
	var records []elbv2types.LoadBalancer
	var marker *string
	for {
		output, err := clients.elbv2.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{
			Marker:   marker,
			PageSize: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 400))),
		})
		if err != nil {
			return nil, err
		}
		records = append(records, output.LoadBalancers...)
		if awssdk.ToString(output.NextMarker) == "" {
			return records, nil
		}
		marker = output.NextMarker
	}
}

func listAllAPIGatewayRestAPIs(ctx context.Context, clients awsClients, limit int) ([]apigatewaytypes.RestApi, error) {
	var records []apigatewaytypes.RestApi
	var position *string
	for {
		output, err := clients.apiGateway.GetRestApis(ctx, &apigateway.GetRestApisInput{
			Limit:    awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 500))),
			Position: position,
		})
		if err != nil {
			return nil, err
		}
		records = append(records, output.Items...)
		if awssdk.ToString(output.Position) == "" {
			return records, nil
		}
		position = output.Position
	}
}

func listAllAPIGatewayV2APIs(ctx context.Context, clients awsClients, limit int) ([]apigatewayv2types.Api, error) {
	var records []apigatewayv2types.Api
	var token *string
	for {
		output, err := clients.apiGatewayV2.GetApis(ctx, &apigatewayv2.GetApisInput{
			MaxResults: stringPtr(strconv.Itoa(boundedAWSPageSize(limit, 1, 100))),
			NextToken:  token,
		})
		if err != nil {
			return nil, err
		}
		records = append(records, output.Items...)
		if awssdk.ToString(output.NextToken) == "" {
			return records, nil
		}
		token = output.NextToken
	}
}

func listAllAPIGatewayResources(ctx context.Context, clients awsClients, api apigatewaytypes.RestApi, limit int) ([]apigatewaytypes.Resource, error) {
	var resources []apigatewaytypes.Resource
	var position *string
	for {
		output, err := clients.apiGateway.GetResources(ctx, &apigateway.GetResourcesInput{
			RestApiId: api.Id,
			Embed:     []string{"methods"},
			Limit:     awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 500))),
			Position:  position,
		})
		if err != nil {
			return nil, fmt.Errorf("get resources for rest api %q: %w", awssdk.ToString(api.Id), err)
		}
		resources = append(resources, output.Items...)
		if awssdk.ToString(output.Position) == "" {
			return resources, nil
		}
		position = output.Position
	}
}

func apiGatewayStageID(stage awsAPIGatewayStage) string {
	return strings.Join(cleanStrings([]string{stage.Version, apiGatewayStageAPIID(stage), apiGatewayStageName(stage)}), ":")
}

func apiGatewayStageAPIID(stage awsAPIGatewayStage) string {
	if stage.Version == "v2" {
		return awssdk.ToString(stage.API.ApiId)
	}
	return awssdk.ToString(stage.RestAPI.Id)
}

func apiGatewayStageAPIName(stage awsAPIGatewayStage) string {
	if stage.Version == "v2" {
		return awssdk.ToString(stage.API.Name)
	}
	return awssdk.ToString(stage.RestAPI.Name)
}

func apiGatewayStageAPIEndpoint(stage awsAPIGatewayStage) string {
	if stage.Version == "v2" {
		return awssdk.ToString(stage.API.ApiEndpoint)
	}
	return ""
}

func apiGatewayStageName(stage awsAPIGatewayStage) string {
	if stage.Version == "v2" {
		return awssdk.ToString(stage.StageV2.StageName)
	}
	return awssdk.ToString(stage.Stage.StageName)
}

func apiGatewayStageDeploymentID(stage awsAPIGatewayStage) string {
	if stage.Version == "v2" {
		return awssdk.ToString(stage.StageV2.DeploymentId)
	}
	return awssdk.ToString(stage.Stage.DeploymentId)
}

func apiGatewayStageTags(stage awsAPIGatewayStage) map[string]string {
	if stage.Version == "v2" {
		return stage.StageV2.Tags
	}
	return stage.Stage.Tags
}

func apiGatewayStageAutoDeploy(stage awsAPIGatewayStage) string {
	if stage.Version == "v2" {
		return boolPtrString(stage.StageV2.AutoDeploy)
	}
	return ""
}

func apiGatewayStageTracingEnabled(stage awsAPIGatewayStage) string {
	if stage.Version == "v2" {
		return ""
	}
	return boolString(stage.Stage.TracingEnabled)
}

func apiGatewayStagePublic(stage awsAPIGatewayStage) bool {
	if stage.Version == "v2" {
		return awssdk.ToString(stage.API.ApiEndpoint) != "" && !awssdk.ToBool(stage.API.DisableExecuteApiEndpoint)
	}
	return true
}

func apiGatewayStageTime(stage awsAPIGatewayStage) time.Time {
	if stage.Version == "v2" {
		return firstTime(stage.StageV2.LastUpdatedDate, stage.StageV2.CreatedDate)
	}
	return firstTime(stage.Stage.LastUpdatedDate, stage.Stage.CreatedDate)
}

func apiGatewayRouteID(route awsAPIGatewayRoute) string {
	return strings.Join(cleanStrings([]string{route.Version, apiGatewayRouteAPIID(route), firstNonEmpty(apiGatewayRouteNativeID(route), apiGatewayRouteKey(route))}), ":")
}

func apiGatewayRouteAPIID(route awsAPIGatewayRoute) string {
	if route.Version == "v2" {
		return awssdk.ToString(route.API.ApiId)
	}
	return awssdk.ToString(route.RestAPI.Id)
}

func apiGatewayRouteAPIName(route awsAPIGatewayRoute) string {
	if route.Version == "v2" {
		return awssdk.ToString(route.API.Name)
	}
	return awssdk.ToString(route.RestAPI.Name)
}

func apiGatewayRouteAPIEndpoint(route awsAPIGatewayRoute) string {
	if route.Version == "v2" {
		return awssdk.ToString(route.API.ApiEndpoint)
	}
	return ""
}

func apiGatewayRouteNativeID(route awsAPIGatewayRoute) string {
	if route.Version == "v2" {
		return awssdk.ToString(route.Route.RouteId)
	}
	return awssdk.ToString(route.Resource.Id) + ":" + apiGatewayRouteHTTPMethod(route)
}

func apiGatewayRouteKey(route awsAPIGatewayRoute) string {
	if route.Version == "v2" {
		return awssdk.ToString(route.Route.RouteKey)
	}
	return strings.TrimSpace(route.HTTPMethod + " " + awssdk.ToString(route.Resource.Path))
}

func apiGatewayRouteName(route awsAPIGatewayRoute) string {
	return firstNonEmpty(apiGatewayRouteKey(route), apiGatewayRouteNativeID(route))
}

func apiGatewayRouteHTTPMethod(route awsAPIGatewayRoute) string {
	if route.Version == "v2" {
		method, _, ok := strings.Cut(awssdk.ToString(route.Route.RouteKey), " ")
		if ok {
			return method
		}
		return awssdk.ToString(route.Route.RouteKey)
	}
	return firstNonEmpty(awssdk.ToString(route.Method.HttpMethod), route.HTTPMethod)
}

func apiGatewayRouteAuthorizationType(route awsAPIGatewayRoute) string {
	if route.Version == "v2" {
		return string(route.Route.AuthorizationType)
	}
	return awssdk.ToString(route.Method.AuthorizationType)
}

func apiGatewayRouteAPIKeyRequired(route awsAPIGatewayRoute) string {
	if route.Version == "v2" {
		return boolPtrString(route.Route.ApiKeyRequired)
	}
	return boolPtrString(route.Method.ApiKeyRequired)
}

func apiGatewayRouteIntegrationTarget(route awsAPIGatewayRoute) string {
	if route.Version == "v2" {
		return awssdk.ToString(route.Route.Target)
	}
	if route.Method.MethodIntegration == nil {
		return ""
	}
	return awssdk.ToString(route.Method.MethodIntegration.Uri)
}

func apiGatewayRoutePublic(route awsAPIGatewayRoute) bool {
	if route.Version == "v2" {
		return !awssdk.ToBool(route.API.DisableExecuteApiEndpoint)
	}
	return true
}

func apiGatewayIntegrationID(integration awsAPIGatewayIntegration) string {
	return strings.Join(cleanStrings([]string{integration.Version, apiGatewayIntegrationAPIID(integration), firstNonEmpty(apiGatewayIntegrationNativeID(integration), apiGatewayIntegrationURI(integration), integration.HTTPMethod)}), ":")
}

func apiGatewayIntegrationAPIID(integration awsAPIGatewayIntegration) string {
	if integration.Version == "v2" {
		return awssdk.ToString(integration.API.ApiId)
	}
	return awssdk.ToString(integration.RestAPI.Id)
}

func apiGatewayIntegrationAPIName(integration awsAPIGatewayIntegration) string {
	if integration.Version == "v2" {
		return awssdk.ToString(integration.API.Name)
	}
	return awssdk.ToString(integration.RestAPI.Name)
}

func apiGatewayIntegrationAPIEndpoint(integration awsAPIGatewayIntegration) string {
	if integration.Version == "v2" {
		return awssdk.ToString(integration.API.ApiEndpoint)
	}
	return ""
}

func apiGatewayIntegrationNativeID(integration awsAPIGatewayIntegration) string {
	if integration.Version == "v2" {
		return awssdk.ToString(integration.IntegrationV2.IntegrationId)
	}
	return awssdk.ToString(integration.Resource.Id) + ":" + integration.HTTPMethod
}

func apiGatewayIntegrationName(integration awsAPIGatewayIntegration) string {
	return firstNonEmpty(apiGatewayIntegrationNativeID(integration), apiGatewayIntegrationURI(integration))
}

func apiGatewayIntegrationType(integration awsAPIGatewayIntegration) string {
	if integration.Version == "v2" {
		return string(integration.IntegrationV2.IntegrationType)
	}
	return string(integration.Integration.Type)
}

func apiGatewayIntegrationURI(integration awsAPIGatewayIntegration) string {
	if integration.Version == "v2" {
		return awssdk.ToString(integration.IntegrationV2.IntegrationUri)
	}
	return awssdk.ToString(integration.Integration.Uri)
}

func apiGatewayIntegrationMethod(integration awsAPIGatewayIntegration) string {
	if integration.Version == "v2" {
		return awssdk.ToString(integration.IntegrationV2.IntegrationMethod)
	}
	return awssdk.ToString(integration.Integration.HttpMethod)
}

func apiGatewayIntegrationConnectionType(integration awsAPIGatewayIntegration) string {
	if integration.Version == "v2" {
		return string(integration.IntegrationV2.ConnectionType)
	}
	return string(integration.Integration.ConnectionType)
}

func apiGatewayIntegrationConnectionID(integration awsAPIGatewayIntegration) string {
	if integration.Version == "v2" {
		return awssdk.ToString(integration.IntegrationV2.ConnectionId)
	}
	return awssdk.ToString(integration.Integration.ConnectionId)
}

func apiGatewayIntegrationCredentials(integration awsAPIGatewayIntegration) string {
	if integration.Version == "v2" {
		return awssdk.ToString(integration.IntegrationV2.CredentialsArn)
	}
	return awssdk.ToString(integration.Integration.Credentials)
}

func apiGatewayIntegrationTimeout(integration awsAPIGatewayIntegration) string {
	if integration.Version == "v2" {
		return int32AttrString(integration.IntegrationV2.TimeoutInMillis)
	}
	return int32ValueString(integration.Integration.TimeoutInMillis)
}

func apiGatewayIntegrationPublic(integration awsAPIGatewayIntegration) bool {
	return !strings.EqualFold(apiGatewayIntegrationConnectionType(integration), "VPC_LINK")
}

func cloudFrontKeyGroupID(group cloudfronttypes.KeyGroupSummary) string {
	if group.KeyGroup == nil {
		return ""
	}
	return awssdk.ToString(group.KeyGroup.Id)
}

func cloudFrontKeyGroupName(group cloudfronttypes.KeyGroupSummary) string {
	if group.KeyGroup == nil || group.KeyGroup.KeyGroupConfig == nil {
		return cloudFrontKeyGroupID(group)
	}
	return awssdk.ToString(group.KeyGroup.KeyGroupConfig.Name)
}

func cloudFrontKeyGroupComment(group cloudfronttypes.KeyGroupSummary) string {
	if group.KeyGroup == nil || group.KeyGroup.KeyGroupConfig == nil {
		return ""
	}
	return awssdk.ToString(group.KeyGroup.KeyGroupConfig.Comment)
}

func cloudFrontKeyGroupPublicKeyIDs(group cloudfronttypes.KeyGroupSummary) []string {
	if group.KeyGroup == nil || group.KeyGroup.KeyGroupConfig == nil {
		return nil
	}
	return cleanStrings(group.KeyGroup.KeyGroupConfig.Items)
}

func cloudFrontKeyGroupLastModified(group cloudfronttypes.KeyGroupSummary) *time.Time {
	if group.KeyGroup == nil {
		return nil
	}
	return group.KeyGroup.LastModifiedTime
}

func cloudFrontResponseHeadersPolicyID(policy cloudfronttypes.ResponseHeadersPolicySummary) string {
	if policy.ResponseHeadersPolicy == nil {
		return ""
	}
	return awssdk.ToString(policy.ResponseHeadersPolicy.Id)
}

func cloudFrontResponseHeadersPolicyName(policy cloudfronttypes.ResponseHeadersPolicySummary) string {
	if policy.ResponseHeadersPolicy == nil || policy.ResponseHeadersPolicy.ResponseHeadersPolicyConfig == nil {
		return cloudFrontResponseHeadersPolicyID(policy)
	}
	return awssdk.ToString(policy.ResponseHeadersPolicy.ResponseHeadersPolicyConfig.Name)
}

func cloudFrontResponseHeadersPolicyComment(policy cloudfronttypes.ResponseHeadersPolicySummary) string {
	if policy.ResponseHeadersPolicy == nil || policy.ResponseHeadersPolicy.ResponseHeadersPolicyConfig == nil {
		return ""
	}
	return awssdk.ToString(policy.ResponseHeadersPolicy.ResponseHeadersPolicyConfig.Comment)
}

func cloudFrontResponseHeadersPolicyLastModified(policy cloudfronttypes.ResponseHeadersPolicySummary) *time.Time {
	if policy.ResponseHeadersPolicy == nil {
		return nil
	}
	return policy.ResponseHeadersPolicy.LastModifiedTime
}

func cloudFrontResponseHeadersPolicyHasCORS(policy cloudfronttypes.ResponseHeadersPolicySummary) bool {
	return policy.ResponseHeadersPolicy != nil && policy.ResponseHeadersPolicy.ResponseHeadersPolicyConfig != nil && policy.ResponseHeadersPolicy.ResponseHeadersPolicyConfig.CorsConfig != nil
}

func cloudFrontResponseHeadersPolicyHasSecurityHeaders(policy cloudfronttypes.ResponseHeadersPolicySummary) bool {
	return policy.ResponseHeadersPolicy != nil && policy.ResponseHeadersPolicy.ResponseHeadersPolicyConfig != nil && policy.ResponseHeadersPolicy.ResponseHeadersPolicyConfig.SecurityHeadersConfig != nil
}

func cloudFrontResponseHeadersPolicyHasCustomHeaders(policy cloudfronttypes.ResponseHeadersPolicySummary) bool {
	return policy.ResponseHeadersPolicy != nil && policy.ResponseHeadersPolicy.ResponseHeadersPolicyConfig != nil && policy.ResponseHeadersPolicy.ResponseHeadersPolicyConfig.CustomHeadersConfig != nil
}

func elbCertificateARNs(certificates []elbv2types.Certificate) []string {
	arns := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		arns = append(arns, awssdk.ToString(certificate.CertificateArn))
	}
	return cleanStrings(arns)
}

func elbActionTypes(actions []elbv2types.Action) []string {
	types := make([]string, 0, len(actions))
	for _, action := range actions {
		types = append(types, string(action.Type))
	}
	return cleanStrings(types)
}

func elbActionTargetGroupARNs(actions []elbv2types.Action) []string {
	arns := make([]string, 0, len(actions))
	for _, action := range actions {
		arns = append(arns, awssdk.ToString(action.TargetGroupArn))
		if action.ForwardConfig != nil {
			for _, targetGroup := range action.ForwardConfig.TargetGroups {
				arns = append(arns, awssdk.ToString(targetGroup.TargetGroupArn))
			}
		}
	}
	return cleanStrings(arns)
}

func int32ValueString(value int32) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatInt(int64(value), 10)
}

func boolPtrString(value *bool) string {
	if value == nil {
		return ""
	}
	return boolString(awssdk.ToBool(value))
}

func awsSHA256Hex(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
