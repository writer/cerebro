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
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigatewaytypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	globalacceleratortypes "github.com/aws/aws-sdk-go-v2/service/globalaccelerator/types"
	"github.com/aws/aws-sdk-go-v2/service/vpclattice"
	vpclatticetypes "github.com/aws/aws-sdk-go-v2/service/vpclattice/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsGlobalAcceleratorListener struct {
	Accelerator globalacceleratortypes.Accelerator
	Listener    globalacceleratortypes.Listener
}

type awsGlobalAcceleratorEndpointGroup struct {
	Accelerator   globalacceleratortypes.Accelerator
	Listener      globalacceleratortypes.Listener
	EndpointGroup globalacceleratortypes.EndpointGroup
}

type awsVPCLatticeListener struct {
	Service  vpclatticetypes.ServiceSummary
	Listener vpclatticetypes.ListenerSummary
}

type awsAPIGatewayStage struct {
	Kind    string
	RestAPI apigatewaytypes.RestApi
	APIV2   apigatewayv2types.Api
	Rest    apigatewaytypes.Stage
	V2      apigatewayv2types.Stage
}

type awsAPIGatewayRoute struct {
	Kind       string
	RestAPI    apigatewaytypes.RestApi
	APIV2      apigatewayv2types.Api
	Resource   apigatewaytypes.Resource
	MethodName string
	Method     apigatewaytypes.Method
	Route      apigatewayv2types.Route
}

type awsAPIGatewayIntegration struct {
	Kind        string
	RestAPI     apigatewaytypes.RestApi
	APIV2       apigatewayv2types.Api
	Resource    apigatewaytypes.Resource
	MethodName  string
	Integration apigateway.GetIntegrationOutput
	V2          apigatewayv2types.Integration
}

type indexedPageCursor struct {
	Index int    `json:"index,omitempty"`
	Token string `json:"token,omitempty"`
}

func listGlobalAccelerators(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]globalacceleratortypes.Accelerator, string, error) {
	out, err := clients.globalAccel.ListAccelerators(ctx, &globalaccelerator.ListAcceleratorsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.Accelerators, awssdk.ToString(out.NextToken), nil
}

func listGlobalAcceleratorListeners(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsGlobalAcceleratorListener, string, error) {
	accelerators, err := listAllGlobalAccelerators(ctx, clients, settings)
	if err != nil {
		return nil, "", err
	}
	state, err := decodeIndexedCursor(cursor, "globalaccelerator listener")
	if err != nil {
		return nil, "", err
	}
	remaining := boundedAWSPageSize(limit, 1, maxPageSize)
	records := make([]awsGlobalAcceleratorListener, 0, remaining)
	for state.Index < len(accelerators) && len(records) < remaining {
		accelerator := accelerators[state.Index]
		acceleratorARN := awssdk.ToString(accelerator.AcceleratorArn)
		out, err := clients.globalAccel.ListListeners(ctx, &globalaccelerator.ListListenersInput{
			AcceleratorArn: awssdk.String(acceleratorARN),
			MaxResults:     awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 100))),
			NextToken:      stringPtr(state.Token),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list global accelerator listeners %q: %w", acceleratorARN, err)
		}
		for _, listener := range out.Listeners {
			records = append(records, awsGlobalAcceleratorListener{Accelerator: accelerator, Listener: listener})
		}
		if awssdk.ToString(out.NextToken) != "" {
			state.Token = awssdk.ToString(out.NextToken)
			return records, encodeIndexedCursor(state), nil
		}
		state.Index++
		state.Token = ""
	}
	if state.Index < len(accelerators) {
		return records, encodeIndexedCursor(state), nil
	}
	return records, "", nil
}

func listGlobalAcceleratorEndpointGroups(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsGlobalAcceleratorEndpointGroup, string, error) {
	listeners, err := listAllGlobalAcceleratorListeners(ctx, clients, settings)
	if err != nil {
		return nil, "", err
	}
	state, err := decodeIndexedCursor(cursor, "globalaccelerator endpoint group")
	if err != nil {
		return nil, "", err
	}
	remaining := boundedAWSPageSize(limit, 1, maxPageSize)
	records := make([]awsGlobalAcceleratorEndpointGroup, 0, remaining)
	for state.Index < len(listeners) && len(records) < remaining {
		parent := listeners[state.Index]
		listenerARN := awssdk.ToString(parent.Listener.ListenerArn)
		out, err := clients.globalAccel.ListEndpointGroups(ctx, &globalaccelerator.ListEndpointGroupsInput{
			ListenerArn: awssdk.String(listenerARN),
			MaxResults:  awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 100))),
			NextToken:   stringPtr(state.Token),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list global accelerator endpoint groups %q: %w", listenerARN, err)
		}
		for _, group := range out.EndpointGroups {
			records = append(records, awsGlobalAcceleratorEndpointGroup{Accelerator: parent.Accelerator, Listener: parent.Listener, EndpointGroup: group})
		}
		if awssdk.ToString(out.NextToken) != "" {
			state.Token = awssdk.ToString(out.NextToken)
			return records, encodeIndexedCursor(state), nil
		}
		state.Index++
		state.Token = ""
	}
	if state.Index < len(listeners) {
		return records, encodeIndexedCursor(state), nil
	}
	return records, "", nil
}

func listVPCLatticeServices(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]vpclatticetypes.ServiceSummary, string, error) {
	out, err := clients.vpcLattice.ListServices(ctx, &vpclattice.ListServicesInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.Items, awssdk.ToString(out.NextToken), nil
}

func listVPCLatticeListeners(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsVPCLatticeListener, string, error) {
	services, err := listAllVPCLatticeServices(ctx, clients, settings)
	if err != nil {
		return nil, "", err
	}
	state, err := decodeIndexedCursor(cursor, "vpclattice listener")
	if err != nil {
		return nil, "", err
	}
	remaining := boundedAWSPageSize(limit, 1, maxPageSize)
	records := make([]awsVPCLatticeListener, 0, remaining)
	for state.Index < len(services) && len(records) < remaining {
		service := services[state.Index]
		serviceID := firstNonEmpty(awssdk.ToString(service.Id), awssdk.ToString(service.Arn))
		out, err := clients.vpcLattice.ListListeners(ctx, &vpclattice.ListListenersInput{
			ServiceIdentifier: awssdk.String(serviceID),
			MaxResults:        awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 100))),
			NextToken:         stringPtr(state.Token),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list vpclattice listeners %q: %w", serviceID, err)
		}
		for _, listener := range out.Items {
			records = append(records, awsVPCLatticeListener{Service: service, Listener: listener})
		}
		if awssdk.ToString(out.NextToken) != "" {
			state.Token = awssdk.ToString(out.NextToken)
			return records, encodeIndexedCursor(state), nil
		}
		state.Index++
		state.Token = ""
	}
	if state.Index < len(services) {
		return records, encodeIndexedCursor(state), nil
	}
	return records, "", nil
}

func listVPCLatticeTargetGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]vpclatticetypes.TargetGroupSummary, string, error) {
	out, err := clients.vpcLattice.ListTargetGroups(ctx, &vpclattice.ListTargetGroupsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.Items, awssdk.ToString(out.NextToken), nil
}

func listELBV2Listeners(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]elbv2types.Listener, string, error) {
	loadBalancers, err := listAllELBV2LoadBalancers(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	state, err := decodeIndexedCursor(cursor, "elbv2 listener")
	if err != nil {
		return nil, "", err
	}
	remaining := boundedAWSPageSize(limit, 1, maxPageSize)
	records := make([]elbv2types.Listener, 0, remaining)
	for state.Index < len(loadBalancers) && len(records) < remaining {
		loadBalancerARN := awssdk.ToString(loadBalancers[state.Index].LoadBalancerArn)
		out, err := clients.elbv2.DescribeListeners(ctx, &elbv2.DescribeListenersInput{
			LoadBalancerArn: awssdk.String(loadBalancerARN),
			Marker:          stringPtr(state.Token),
			PageSize:        awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 400))),
		})
		if err != nil {
			return nil, "", fmt.Errorf("describe elbv2 listeners %q: %w", loadBalancerARN, err)
		}
		records = append(records, out.Listeners...)
		if awssdk.ToString(out.NextMarker) != "" {
			state.Token = awssdk.ToString(out.NextMarker)
			return records, encodeIndexedCursor(state), nil
		}
		state.Index++
		state.Token = ""
	}
	if state.Index < len(loadBalancers) {
		return records, encodeIndexedCursor(state), nil
	}
	return records, "", nil
}

func listELBV2TargetGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]elbv2types.TargetGroup, string, error) {
	out, err := clients.elbv2.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
		Marker:   stringPtr(cursor),
		PageSize: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 400))),
	})
	if err != nil {
		return nil, "", err
	}
	return out.TargetGroups, awssdk.ToString(out.NextMarker), nil
}

func listAPIGatewayStages(ctx context.Context, clients awsClients, settings settings, _ string, _ int) ([]awsAPIGatewayStage, string, error) {
	restAPIs, err := listAllRestAPIs(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	apiV2s, err := listAllAPIGatewayV2APIs(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	var records []awsAPIGatewayStage
	for _, api := range restAPIs {
		apiID := awssdk.ToString(api.Id)
		out, err := clients.apiGateway.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: awssdk.String(apiID)})
		if err != nil {
			return nil, "", fmt.Errorf("get apigateway stages %q: %w", apiID, err)
		}
		for _, stage := range out.Item {
			records = append(records, awsAPIGatewayStage{Kind: "rest", RestAPI: api, Rest: stage})
		}
	}
	for _, api := range apiV2s {
		apiID := awssdk.ToString(api.ApiId)
		var token string
		for {
			out, err := clients.apiGatewayV2.GetStages(ctx, &apigatewayv2.GetStagesInput{
				ApiId:      awssdk.String(apiID),
				MaxResults: stringPtr(strconv.Itoa(settings.perPage)),
				NextToken:  stringPtr(token),
			})
			if err != nil {
				return nil, "", fmt.Errorf("get apigatewayv2 stages %q: %w", apiID, err)
			}
			for _, stage := range out.Items {
				records = append(records, awsAPIGatewayStage{Kind: "v2", APIV2: api, V2: stage})
			}
			if awssdk.ToString(out.NextToken) == "" {
				break
			}
			token = awssdk.ToString(out.NextToken)
		}
	}
	return records, "", nil
}

func listAPIGatewayRoutes(ctx context.Context, clients awsClients, settings settings, _ string, _ int) ([]awsAPIGatewayRoute, string, error) {
	restAPIs, err := listAllRestAPIs(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	apiV2s, err := listAllAPIGatewayV2APIs(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	var records []awsAPIGatewayRoute
	for _, api := range restAPIs {
		resources, err := listAllRestResources(ctx, clients, awssdk.ToString(api.Id), settings.perPage)
		if err != nil {
			return nil, "", err
		}
		for _, resource := range resources {
			for methodName, method := range resource.ResourceMethods {
				records = append(records, awsAPIGatewayRoute{Kind: "rest", RestAPI: api, Resource: resource, MethodName: methodName, Method: method})
			}
		}
	}
	for _, api := range apiV2s {
		apiID := awssdk.ToString(api.ApiId)
		var token string
		for {
			out, err := clients.apiGatewayV2.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{
				ApiId:      awssdk.String(apiID),
				MaxResults: stringPtr(strconv.Itoa(settings.perPage)),
				NextToken:  stringPtr(token),
			})
			if err != nil {
				return nil, "", fmt.Errorf("get apigatewayv2 routes %q: %w", apiID, err)
			}
			for _, route := range out.Items {
				records = append(records, awsAPIGatewayRoute{Kind: "v2", APIV2: api, Route: route})
			}
			if awssdk.ToString(out.NextToken) == "" {
				break
			}
			token = awssdk.ToString(out.NextToken)
		}
	}
	return records, "", nil
}

func listAPIGatewayIntegrations(ctx context.Context, clients awsClients, settings settings, _ string, _ int) ([]awsAPIGatewayIntegration, string, error) {
	restAPIs, err := listAllRestAPIs(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	apiV2s, err := listAllAPIGatewayV2APIs(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	var records []awsAPIGatewayIntegration
	for _, api := range restAPIs {
		apiID := awssdk.ToString(api.Id)
		resources, err := listAllRestResources(ctx, clients, apiID, settings.perPage)
		if err != nil {
			return nil, "", err
		}
		for _, resource := range resources {
			for methodName, method := range resource.ResourceMethods {
				integration := method.MethodIntegration
				if integration == nil {
					got, err := clients.apiGateway.GetIntegration(ctx, &apigateway.GetIntegrationInput{RestApiId: awssdk.String(apiID), ResourceId: resource.Id, HttpMethod: awssdk.String(methodName)})
					if err != nil {
						return nil, "", fmt.Errorf("get apigateway integration %q/%q/%q: %w", apiID, awssdk.ToString(resource.Id), methodName, err)
					}
					records = append(records, awsAPIGatewayIntegration{Kind: "rest", RestAPI: api, Resource: resource, MethodName: methodName, Integration: *got})
					continue
				}
				records = append(records, awsAPIGatewayIntegration{Kind: "rest", RestAPI: api, Resource: resource, MethodName: methodName, Integration: restIntegrationOutput(*integration)})
			}
		}
	}
	for _, api := range apiV2s {
		apiID := awssdk.ToString(api.ApiId)
		var token string
		for {
			out, err := clients.apiGatewayV2.GetIntegrations(ctx, &apigatewayv2.GetIntegrationsInput{
				ApiId:      awssdk.String(apiID),
				MaxResults: stringPtr(strconv.Itoa(settings.perPage)),
				NextToken:  stringPtr(token),
			})
			if err != nil {
				return nil, "", fmt.Errorf("get apigatewayv2 integrations %q: %w", apiID, err)
			}
			for _, integration := range out.Items {
				records = append(records, awsAPIGatewayIntegration{Kind: "v2", APIV2: api, V2: integration})
			}
			if awssdk.ToString(out.NextToken) == "" {
				break
			}
			token = awssdk.ToString(out.NextToken)
		}
	}
	return records, "", nil
}

func listCloudFrontOACs(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]cloudfronttypes.OriginAccessControlSummary, string, error) {
	out, err := clients.cloudFront.ListOriginAccessControls(ctx, &cloudfront.ListOriginAccessControlsInput{Marker: stringPtr(cursor), MaxItems: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100)))})
	if err != nil {
		return nil, "", err
	}
	if out.OriginAccessControlList == nil {
		return nil, "", nil
	}
	return out.OriginAccessControlList.Items, awssdk.ToString(out.OriginAccessControlList.NextMarker), nil
}

func listCloudFrontKeyGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]cloudfronttypes.KeyGroupSummary, string, error) {
	out, err := clients.cloudFront.ListKeyGroups(ctx, &cloudfront.ListKeyGroupsInput{Marker: stringPtr(cursor), MaxItems: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100)))})
	if err != nil {
		return nil, "", err
	}
	if out.KeyGroupList == nil {
		return nil, "", nil
	}
	return out.KeyGroupList.Items, awssdk.ToString(out.KeyGroupList.NextMarker), nil
}

func listCloudFrontPublicKeys(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]cloudfronttypes.PublicKeySummary, string, error) {
	out, err := clients.cloudFront.ListPublicKeys(ctx, &cloudfront.ListPublicKeysInput{Marker: stringPtr(cursor), MaxItems: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100)))})
	if err != nil {
		return nil, "", err
	}
	if out.PublicKeyList == nil {
		return nil, "", nil
	}
	return out.PublicKeyList.Items, awssdk.ToString(out.PublicKeyList.NextMarker), nil
}

func listCloudFrontResponseHeadersPolicies(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]cloudfronttypes.ResponseHeadersPolicySummary, string, error) {
	out, err := clients.cloudFront.ListResponseHeadersPolicies(ctx, &cloudfront.ListResponseHeadersPoliciesInput{Marker: stringPtr(cursor), MaxItems: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100)))})
	if err != nil {
		return nil, "", err
	}
	if out.ResponseHeadersPolicyList == nil {
		return nil, "", nil
	}
	return out.ResponseHeadersPolicyList.Items, awssdk.ToString(out.ResponseHeadersPolicyList.NextMarker), nil
}

func globalAcceleratorEvent(settings settings, accelerator globalacceleratortypes.Accelerator) (*primitives.Event, error) {
	arn := awssdk.ToString(accelerator.AcceleratorArn)
	name := awssdk.ToString(accelerator.Name)
	attributes := commonCloudAssetAttributes(settings, "global", familyGlobalAccelerator, firstNonEmpty(arn, name), name, "globalaccelerator_accelerator", nil)
	attributes["arn"] = arn
	attributes["dns_name"] = awssdk.ToString(accelerator.DnsName)
	attributes["dual_stack_dns_name"] = awssdk.ToString(accelerator.DualStackDnsName)
	attributes["enabled"] = boolString(awssdk.ToBool(accelerator.Enabled))
	attributes["ip_address_type"] = string(accelerator.IpAddressType)
	attributes["state"] = string(accelerator.Status)
	attributes["public"] = boolString(awssdk.ToBool(accelerator.Enabled))
	attributes["internet_exposed"] = attributes["public"]
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "accelerator": accelerator})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-globalaccelerator-accelerator-"+firstNonEmpty(arn, name), "aws.globalaccelerator_accelerator", "aws/globalaccelerator_accelerator/v1", payload, attributes, firstTime(accelerator.LastModifiedTime, accelerator.CreatedTime))
}

func globalAcceleratorListenerEvent(settings settings, record awsGlobalAcceleratorListener) (*primitives.Event, error) {
	listener := record.Listener
	arn := awssdk.ToString(listener.ListenerArn)
	name := path.Base(arn)
	attributes := commonCloudAssetAttributes(settings, "global", familyGAListener, arn, name, "globalaccelerator_listener", nil)
	attributes["arn"] = arn
	attributes["accelerator_arn"] = awssdk.ToString(record.Accelerator.AcceleratorArn)
	attributes["accelerator_name"] = awssdk.ToString(record.Accelerator.Name)
	attributes["client_affinity"] = string(listener.ClientAffinity)
	attributes["port_ranges"] = globalAcceleratorPortRanges(listener.PortRanges)
	attributes["protocol"] = string(listener.Protocol)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "accelerator": record.Accelerator, "listener": listener})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-globalaccelerator-listener-"+arn, "aws.globalaccelerator_listener", "aws/globalaccelerator_listener/v1", payload, attributes, time.Now().UTC())
}

func globalAcceleratorEndpointGroupEvent(settings settings, record awsGlobalAcceleratorEndpointGroup) (*primitives.Event, error) {
	group := record.EndpointGroup
	arn := awssdk.ToString(group.EndpointGroupArn)
	region := firstNonEmpty(awssdk.ToString(group.EndpointGroupRegion), settings.region)
	attributes := commonCloudAssetAttributes(settings, region, familyGAEndpointGroup, arn, path.Base(arn), "globalaccelerator_endpoint_group", nil)
	attributes["arn"] = arn
	attributes["accelerator_arn"] = awssdk.ToString(record.Accelerator.AcceleratorArn)
	attributes["listener_arn"] = awssdk.ToString(record.Listener.ListenerArn)
	attributes["endpoint_ids"] = strings.Join(globalAcceleratorEndpointIDs(group.EndpointDescriptions), ",")
	attributes["health_check_path"] = awssdk.ToString(group.HealthCheckPath)
	attributes["health_check_port"] = int32AttrString(group.HealthCheckPort)
	attributes["health_check_protocol"] = string(group.HealthCheckProtocol)
	attributes["traffic_dial_percentage"] = float32AttrString(group.TrafficDialPercentage)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "accelerator": record.Accelerator, "listener": record.Listener, "endpoint_group": group})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-globalaccelerator-endpoint-group-"+arn, "aws.globalaccelerator_endpoint_group", "aws/globalaccelerator_endpoint_group/v1", payload, attributes, time.Now().UTC())
}

func vpcLatticeServiceEvent(settings settings, service vpclatticetypes.ServiceSummary) (*primitives.Event, error) {
	arn := awssdk.ToString(service.Arn)
	name := awssdk.ToString(service.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyVPCLatticeService, firstNonEmpty(arn, awssdk.ToString(service.Id), name), name, "vpclattice_service", nil)
	attributes["arn"] = arn
	attributes["service_id"] = awssdk.ToString(service.Id)
	attributes["custom_domain_name"] = awssdk.ToString(service.CustomDomainName)
	attributes["dns_name"] = vpcLatticeDNSName(service.DnsEntry)
	attributes["hosted_zone_id"] = vpcLatticeHostedZoneID(service.DnsEntry)
	attributes["state"] = string(service.Status)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "service": service})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-vpclattice-service-"+firstNonEmpty(arn, awssdk.ToString(service.Id), name), "aws.vpclattice_service", "aws/vpclattice_service/v1", payload, attributes, firstTime(service.LastUpdatedAt, service.CreatedAt))
}

func vpcLatticeListenerEvent(settings settings, record awsVPCLatticeListener) (*primitives.Event, error) {
	listener := record.Listener
	arn := awssdk.ToString(listener.Arn)
	name := awssdk.ToString(listener.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyVPCLatticeListener, firstNonEmpty(arn, awssdk.ToString(listener.Id), name), name, "vpclattice_listener", nil)
	attributes["arn"] = arn
	attributes["listener_id"] = awssdk.ToString(listener.Id)
	attributes["port"] = int32AttrString(listener.Port)
	attributes["protocol"] = string(listener.Protocol)
	attributes["service_arn"] = awssdk.ToString(record.Service.Arn)
	attributes["service_id"] = awssdk.ToString(record.Service.Id)
	attributes["service_name"] = awssdk.ToString(record.Service.Name)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "service": record.Service, "listener": listener})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-vpclattice-listener-"+firstNonEmpty(arn, awssdk.ToString(listener.Id), name), "aws.vpclattice_listener", "aws/vpclattice_listener/v1", payload, attributes, firstTime(listener.LastUpdatedAt, listener.CreatedAt))
}

func vpcLatticeTargetGroupEvent(settings settings, target vpclatticetypes.TargetGroupSummary) (*primitives.Event, error) {
	arn := awssdk.ToString(target.Arn)
	name := awssdk.ToString(target.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyVPCLatticeTG, firstNonEmpty(arn, awssdk.ToString(target.Id), name), name, "vpclattice_target_group", nil)
	attributes["arn"] = arn
	attributes["target_group_id"] = awssdk.ToString(target.Id)
	attributes["target_group_type"] = string(target.Type)
	attributes["ip_address_type"] = string(target.IpAddressType)
	attributes["port"] = int32AttrString(target.Port)
	attributes["protocol"] = string(target.Protocol)
	attributes["service_arns"] = strings.Join(cleanStrings(target.ServiceArns), ",")
	attributes["state"] = string(target.Status)
	attributes["vpc_id"] = awssdk.ToString(target.VpcIdentifier)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "target_group": target})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-vpclattice-target-group-"+firstNonEmpty(arn, awssdk.ToString(target.Id), name), "aws.vpclattice_target_group", "aws/vpclattice_target_group/v1", payload, attributes, firstTime(target.LastUpdatedAt, target.CreatedAt))
}

func elbv2ListenerEvent(settings settings, listener elbv2types.Listener) (*primitives.Event, error) {
	arn := awssdk.ToString(listener.ListenerArn)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyELBV2Listener, arn, path.Base(arn), "elbv2_listener", nil)
	attributes["arn"] = arn
	attributes["listener_arn"] = arn
	attributes["load_balancer_arn"] = awssdk.ToString(listener.LoadBalancerArn)
	attributes["port"] = int32AttrString(listener.Port)
	attributes["protocol"] = string(listener.Protocol)
	attributes["ssl_policy"] = awssdk.ToString(listener.SslPolicy)
	attributes["target_group_arns"] = strings.Join(elbv2ActionTargetGroupARNs(listener.DefaultActions), ",")
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "listener": listener})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-elbv2-listener-"+arn, "aws.elbv2_listener", "aws/elbv2_listener/v1", payload, attributes, time.Now().UTC())
}

func elbv2TargetGroupEvent(settings settings, target elbv2types.TargetGroup) (*primitives.Event, error) {
	arn := awssdk.ToString(target.TargetGroupArn)
	name := awssdk.ToString(target.TargetGroupName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyELBV2TargetGroup, firstNonEmpty(arn, name), name, "elbv2_target_group", nil)
	attributes["arn"] = arn
	attributes["target_group_arn"] = arn
	attributes["target_group_name"] = name
	attributes["target_type"] = string(target.TargetType)
	attributes["load_balancer_arns"] = strings.Join(cleanStrings(target.LoadBalancerArns), ",")
	attributes["port"] = int32AttrString(target.Port)
	attributes["protocol"] = string(target.Protocol)
	attributes["protocol_version"] = awssdk.ToString(target.ProtocolVersion)
	attributes["health_check_enabled"] = boolString(awssdk.ToBool(target.HealthCheckEnabled))
	attributes["health_check_path"] = awssdk.ToString(target.HealthCheckPath)
	attributes["health_check_protocol"] = string(target.HealthCheckProtocol)
	attributes["vpc_id"] = awssdk.ToString(target.VpcId)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "target_group": target})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-elbv2-target-group-"+firstNonEmpty(arn, name), "aws.elbv2_target_group", "aws/elbv2_target_group/v1", payload, attributes, time.Now().UTC())
}

func apiGatewayStageEvent(settings settings, record awsAPIGatewayStage) (*primitives.Event, error) {
	apiID, apiName, stageName := record.apiID(), record.apiName(), record.stageName()
	resourceID := apiID + "/" + stageName
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAPIGatewayStage, resourceID, firstNonEmpty(stageName, resourceID), "apigateway_stage", record.tags())
	attributes["api_id"] = apiID
	attributes["api_name"] = apiName
	attributes["api_kind"] = record.Kind
	attributes["stage_name"] = stageName
	attributes["deployment_id"] = record.deploymentID()
	attributes["auto_deploy"] = record.autoDeploy()
	attributes["tracing_enabled"] = record.tracingEnabled()
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "record": record})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-apigateway-stage-"+resourceID, "aws.apigateway_stage", "aws/apigateway_stage/v1", payload, attributes, firstTime(record.updatedAt(), record.createdAt()))
}

func apiGatewayRouteEvent(settings settings, record awsAPIGatewayRoute) (*primitives.Event, error) {
	apiID, apiName, routeID := record.apiID(), record.apiName(), record.routeID()
	resourceID := apiID + "/" + routeID
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAPIGatewayRoute, resourceID, firstNonEmpty(record.routeKey(), routeID), "apigateway_route", nil)
	attributes["api_id"] = apiID
	attributes["api_name"] = apiName
	attributes["api_kind"] = record.Kind
	attributes["route_id"] = routeID
	attributes["route_key"] = record.routeKey()
	attributes["authorization_type"] = record.authorizationType()
	attributes["authorizer_id"] = record.authorizerID()
	attributes["target"] = record.target()
	attributes["resource_path"] = awssdk.ToString(record.Resource.Path)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "record": record})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-apigateway-route-"+resourceID, "aws.apigateway_route", "aws/apigateway_route/v1", payload, attributes, time.Now().UTC())
}

func apiGatewayIntegrationEvent(settings settings, record awsAPIGatewayIntegration) (*primitives.Event, error) {
	apiID, apiName, integrationID := record.apiID(), record.apiName(), record.integrationID()
	resourceID := apiID + "/" + integrationID
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAPIGatewayInteg, resourceID, integrationID, "apigateway_integration", nil)
	attributes["api_id"] = apiID
	attributes["api_name"] = apiName
	attributes["api_kind"] = record.Kind
	attributes["integration_id"] = integrationID
	attributes["integration_type"] = record.integrationType()
	attributes["integration_uri"] = record.integrationURI()
	attributes["connection_id"] = record.connectionID()
	attributes["connection_type"] = record.connectionType()
	attributes["credentials_arn"] = record.credentialsARN()
	attributes["route_target"] = record.routeTarget()
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "record": record})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-apigateway-integration-"+resourceID, "aws.apigateway_integration", "aws/apigateway_integration/v1", payload, attributes, time.Now().UTC())
}

func cloudFrontOACEvent(settings settings, record cloudfronttypes.OriginAccessControlSummary) (*primitives.Event, error) {
	id := awssdk.ToString(record.Id)
	arn := cloudFrontResourceARN(settings, "origin-access-control", id)
	attributes := commonCloudAssetAttributes(settings, "global", familyCloudFrontOAC, firstNonEmpty(arn, id), awssdk.ToString(record.Name), "cloudfront_origin_access_control", nil)
	attributes["arn"] = arn
	attributes["origin_access_control_id"] = id
	attributes["description"] = awssdk.ToString(record.Description)
	attributes["origin_type"] = string(record.OriginAccessControlOriginType)
	attributes["signing_behavior"] = string(record.SigningBehavior)
	attributes["signing_protocol"] = string(record.SigningProtocol)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "origin_access_control": record})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudfront-origin-access-control-"+id, "aws.cloudfront_origin_access_control", "aws/cloudfront_origin_access_control/v1", payload, attributes, time.Now().UTC())
}

func cloudFrontKeyGroupEvent(settings settings, summary cloudfronttypes.KeyGroupSummary) (*primitives.Event, error) {
	group := summary.KeyGroup
	if group == nil {
		group = &cloudfronttypes.KeyGroup{}
	}
	id := awssdk.ToString(group.Id)
	name := ""
	var publicKeys []string
	if group.KeyGroupConfig != nil {
		name = awssdk.ToString(group.KeyGroupConfig.Name)
		publicKeys = group.KeyGroupConfig.Items
	}
	arn := cloudFrontResourceARN(settings, "key-group", id)
	attributes := commonCloudAssetAttributes(settings, "global", familyCloudFrontKeyGroup, firstNonEmpty(arn, id), name, "cloudfront_key_group", nil)
	attributes["arn"] = arn
	attributes["key_group_id"] = id
	attributes["public_key_ids"] = strings.Join(cleanStrings(publicKeys), ",")
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "key_group": group})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudfront-key-group-"+id, "aws.cloudfront_key_group", "aws/cloudfront_key_group/v1", payload, attributes, firstTime(group.LastModifiedTime))
}

func cloudFrontPublicKeyEvent(settings settings, key cloudfronttypes.PublicKeySummary) (*primitives.Event, error) {
	id := awssdk.ToString(key.Id)
	arn := cloudFrontResourceARN(settings, "public-key", id)
	attributes := commonCloudAssetAttributes(settings, "global", familyCloudFrontPublicKey, firstNonEmpty(arn, id), awssdk.ToString(key.Name), "cloudfront_public_key", nil)
	attributes["arn"] = arn
	attributes["public_key_id"] = id
	attributes["comment"] = awssdk.ToString(key.Comment)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "public_key": key})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudfront-public-key-"+id, "aws.cloudfront_public_key", "aws/cloudfront_public_key/v1", payload, attributes, firstTime(key.CreatedTime))
}

func cloudFrontResponseHeadersPolicyEvent(settings settings, summary cloudfronttypes.ResponseHeadersPolicySummary) (*primitives.Event, error) {
	policy := summary.ResponseHeadersPolicy
	if policy == nil {
		policy = &cloudfronttypes.ResponseHeadersPolicy{}
	}
	id := awssdk.ToString(policy.Id)
	name := ""
	if policy.ResponseHeadersPolicyConfig != nil {
		name = awssdk.ToString(policy.ResponseHeadersPolicyConfig.Name)
	}
	arn := cloudFrontResourceARN(settings, "response-headers-policy", id)
	attributes := commonCloudAssetAttributes(settings, "global", familyCloudFrontRHP, firstNonEmpty(arn, id), name, "cloudfront_response_headers_policy", nil)
	attributes["arn"] = arn
	attributes["policy_id"] = id
	attributes["policy_type"] = string(summary.Type)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "response_headers_policy": policy, "type": summary.Type})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudfront-response-headers-policy-"+id, "aws.cloudfront_response_headers_policy", "aws/cloudfront_response_headers_policy/v1", payload, attributes, firstTime(policy.LastModifiedTime))
}

func listAllGlobalAccelerators(ctx context.Context, clients awsClients, settings settings) ([]globalacceleratortypes.Accelerator, error) {
	var records []globalacceleratortypes.Accelerator
	var cursor string
	for {
		page, next, err := listGlobalAccelerators(ctx, clients, settings, cursor, maxPageSize)
		if err != nil {
			return nil, err
		}
		records = append(records, page...)
		if next == "" {
			break
		}
		cursor = next
	}
	sort.Slice(records, func(i, j int) bool {
		return awssdk.ToString(records[i].AcceleratorArn) < awssdk.ToString(records[j].AcceleratorArn)
	})
	return records, nil
}

func listAllGlobalAcceleratorListeners(ctx context.Context, clients awsClients, settings settings) ([]awsGlobalAcceleratorListener, error) {
	var records []awsGlobalAcceleratorListener
	var cursor string
	for {
		page, next, err := listGlobalAcceleratorListeners(ctx, clients, settings, cursor, maxPageSize)
		if err != nil {
			return nil, err
		}
		records = append(records, page...)
		if next == "" {
			break
		}
		cursor = next
	}
	sort.Slice(records, func(i, j int) bool {
		return awssdk.ToString(records[i].Listener.ListenerArn) < awssdk.ToString(records[j].Listener.ListenerArn)
	})
	return records, nil
}

func listAllVPCLatticeServices(ctx context.Context, clients awsClients, settings settings) ([]vpclatticetypes.ServiceSummary, error) {
	var records []vpclatticetypes.ServiceSummary
	var cursor string
	for {
		page, next, err := listVPCLatticeServices(ctx, clients, settings, cursor, maxPageSize)
		if err != nil {
			return nil, err
		}
		records = append(records, page...)
		if next == "" {
			break
		}
		cursor = next
	}
	sort.Slice(records, func(i, j int) bool { return awssdk.ToString(records[i].Arn) < awssdk.ToString(records[j].Arn) })
	return records, nil
}

func listAllELBV2LoadBalancers(ctx context.Context, clients awsClients) ([]elbv2types.LoadBalancer, error) {
	var records []elbv2types.LoadBalancer
	var cursor string
	for {
		out, err := clients.elbv2.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{
			Marker:   stringPtr(cursor),
			PageSize: awssdk.Int32(int32(boundedAWSPageSize(maxPageSize, 1, 400))),
		})
		if err != nil {
			return nil, fmt.Errorf("describe elbv2 load balancers: %w", err)
		}
		records = append(records, out.LoadBalancers...)
		if awssdk.ToString(out.NextMarker) == "" {
			break
		}
		cursor = awssdk.ToString(out.NextMarker)
	}
	sort.Slice(records, func(i, j int) bool {
		return awssdk.ToString(records[i].LoadBalancerArn) < awssdk.ToString(records[j].LoadBalancerArn)
	})
	return records, nil
}

func listAllRestAPIs(ctx context.Context, clients awsClients) ([]apigatewaytypes.RestApi, error) {
	var records []apigatewaytypes.RestApi
	var cursor string
	for {
		out, err := clients.apiGateway.GetRestApis(ctx, &apigateway.GetRestApisInput{Position: stringPtr(cursor), Limit: awssdk.Int32(500)})
		if err != nil {
			return nil, fmt.Errorf("get apigateway rest apis: %w", err)
		}
		records = append(records, out.Items...)
		if awssdk.ToString(out.Position) == "" {
			break
		}
		cursor = awssdk.ToString(out.Position)
	}
	return records, nil
}

func listAllAPIGatewayV2APIs(ctx context.Context, clients awsClients) ([]apigatewayv2types.Api, error) {
	var records []apigatewayv2types.Api
	var cursor string
	for {
		out, err := clients.apiGatewayV2.GetApis(ctx, &apigatewayv2.GetApisInput{NextToken: stringPtr(cursor), MaxResults: awssdk.String("100")})
		if err != nil {
			return nil, fmt.Errorf("get apigatewayv2 apis: %w", err)
		}
		records = append(records, out.Items...)
		if awssdk.ToString(out.NextToken) == "" {
			break
		}
		cursor = awssdk.ToString(out.NextToken)
	}
	return records, nil
}

func listAllRestResources(ctx context.Context, clients awsClients, apiID string, limit int) ([]apigatewaytypes.Resource, error) {
	var records []apigatewaytypes.Resource
	var cursor string
	for {
		out, err := clients.apiGateway.GetResources(ctx, &apigateway.GetResourcesInput{RestApiId: awssdk.String(apiID), Embed: []string{"methods"}, Limit: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 500))), Position: stringPtr(cursor)})
		if err != nil {
			return nil, fmt.Errorf("get apigateway resources %q: %w", apiID, err)
		}
		records = append(records, out.Items...)
		if awssdk.ToString(out.Position) == "" {
			break
		}
		cursor = awssdk.ToString(out.Position)
	}
	return records, nil
}

func decodeIndexedCursor(raw string, label string) (indexedPageCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return indexedPageCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return indexedPageCursor{}, fmt.Errorf("decode %s cursor: %w", label, err)
	}
	var cursor indexedPageCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return indexedPageCursor{}, fmt.Errorf("parse %s cursor: %w", label, err)
	}
	return cursor, nil
}

func encodeIndexedCursor(cursor indexedPageCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func globalAcceleratorPortRanges(values []globalacceleratortypes.PortRange) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		from := awssdk.ToInt32(value.FromPort)
		to := awssdk.ToInt32(value.ToPort)
		if from == 0 && to == 0 {
			continue
		}
		if from == to || to == 0 {
			parts = append(parts, strconv.Itoa(int(from)))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d-%d", from, to))
	}
	return strings.Join(parts, ",")
}

func globalAcceleratorEndpointIDs(values []globalacceleratortypes.EndpointDescription) []string {
	ids := make([]string, 0, len(values))
	for _, value := range values {
		ids = append(ids, awssdk.ToString(value.EndpointId))
	}
	return cleanStrings(ids)
}

func elbv2ActionTargetGroupARNs(actions []elbv2types.Action) []string {
	var arns []string
	for _, action := range actions {
		arns = append(arns, awssdk.ToString(action.TargetGroupArn))
		if action.ForwardConfig != nil {
			for _, group := range action.ForwardConfig.TargetGroups {
				arns = append(arns, awssdk.ToString(group.TargetGroupArn))
			}
		}
	}
	return cleanStrings(arns)
}

func float32AttrString(value *float32) string {
	if value == nil {
		return ""
	}
	return strconv.FormatFloat(float64(*value), 'f', -1, 32)
}

func vpcLatticeDNSName(entry *vpclatticetypes.DnsEntry) string {
	if entry == nil {
		return ""
	}
	return awssdk.ToString(entry.DomainName)
}

func vpcLatticeHostedZoneID(entry *vpclatticetypes.DnsEntry) string {
	if entry == nil {
		return ""
	}
	return awssdk.ToString(entry.HostedZoneId)
}

func restIntegrationOutput(value apigatewaytypes.Integration) apigateway.GetIntegrationOutput {
	return apigateway.GetIntegrationOutput{
		CacheKeyParameters:   value.CacheKeyParameters,
		CacheNamespace:       value.CacheNamespace,
		ConnectionId:         value.ConnectionId,
		ConnectionType:       value.ConnectionType,
		ContentHandling:      value.ContentHandling,
		Credentials:          value.Credentials,
		HttpMethod:           value.HttpMethod,
		IntegrationResponses: value.IntegrationResponses,
		IntegrationTarget:    value.IntegrationTarget,
		PassthroughBehavior:  value.PassthroughBehavior,
		RequestParameters:    value.RequestParameters,
		RequestTemplates:     value.RequestTemplates,
		TimeoutInMillis:      value.TimeoutInMillis,
		TlsConfig:            value.TlsConfig,
		Type:                 value.Type,
		Uri:                  value.Uri,
	}
}

func (record awsAPIGatewayStage) apiID() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.APIV2.ApiId)
	}
	return awssdk.ToString(record.RestAPI.Id)
}

func (record awsAPIGatewayStage) apiName() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.APIV2.Name)
	}
	return awssdk.ToString(record.RestAPI.Name)
}

func (record awsAPIGatewayStage) stageName() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.V2.StageName)
	}
	return awssdk.ToString(record.Rest.StageName)
}

func (record awsAPIGatewayStage) deploymentID() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.V2.DeploymentId)
	}
	return awssdk.ToString(record.Rest.DeploymentId)
}

func (record awsAPIGatewayStage) autoDeploy() string {
	if record.Kind == "v2" {
		return boolString(awssdk.ToBool(record.V2.AutoDeploy))
	}
	return ""
}

func (record awsAPIGatewayStage) tracingEnabled() string {
	if record.Kind == "rest" {
		return boolString(record.Rest.TracingEnabled)
	}
	return ""
}

func (record awsAPIGatewayStage) tags() map[string]string {
	if record.Kind == "v2" {
		return record.V2.Tags
	}
	return record.Rest.Tags
}

func (record awsAPIGatewayStage) createdAt() *time.Time {
	if record.Kind == "v2" {
		return record.V2.CreatedDate
	}
	return record.Rest.CreatedDate
}

func (record awsAPIGatewayStage) updatedAt() *time.Time {
	if record.Kind == "v2" {
		return record.V2.LastUpdatedDate
	}
	return record.Rest.LastUpdatedDate
}

func (record awsAPIGatewayRoute) apiID() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.APIV2.ApiId)
	}
	return awssdk.ToString(record.RestAPI.Id)
}

func (record awsAPIGatewayRoute) apiName() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.APIV2.Name)
	}
	return awssdk.ToString(record.RestAPI.Name)
}

func (record awsAPIGatewayRoute) routeID() string {
	if record.Kind == "v2" {
		return firstNonEmpty(awssdk.ToString(record.Route.RouteId), awssdk.ToString(record.Route.RouteKey))
	}
	return firstNonEmpty(awssdk.ToString(record.Resource.Id)+":"+record.MethodName, awssdk.ToString(record.Resource.Path)+":"+record.MethodName)
}

func (record awsAPIGatewayRoute) routeKey() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.Route.RouteKey)
	}
	return strings.TrimSpace(record.MethodName + " " + awssdk.ToString(record.Resource.Path))
}

func (record awsAPIGatewayRoute) authorizationType() string {
	if record.Kind == "v2" {
		return string(record.Route.AuthorizationType)
	}
	return awssdk.ToString(record.Method.AuthorizationType)
}

func (record awsAPIGatewayRoute) authorizerID() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.Route.AuthorizerId)
	}
	return awssdk.ToString(record.Method.AuthorizerId)
}

func (record awsAPIGatewayRoute) target() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.Route.Target)
	}
	return ""
}

func (record awsAPIGatewayIntegration) apiID() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.APIV2.ApiId)
	}
	return awssdk.ToString(record.RestAPI.Id)
}

func (record awsAPIGatewayIntegration) apiName() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.APIV2.Name)
	}
	return awssdk.ToString(record.RestAPI.Name)
}

func (record awsAPIGatewayIntegration) integrationID() string {
	if record.Kind == "v2" {
		return firstNonEmpty(awssdk.ToString(record.V2.IntegrationId), awssdk.ToString(record.V2.IntegrationUri))
	}
	return firstNonEmpty(awssdk.ToString(record.Resource.Id)+":"+record.MethodName, awssdk.ToString(record.Integration.Uri))
}

func (record awsAPIGatewayIntegration) integrationType() string {
	if record.Kind == "v2" {
		return string(record.V2.IntegrationType)
	}
	return string(record.Integration.Type)
}

func (record awsAPIGatewayIntegration) integrationURI() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.V2.IntegrationUri)
	}
	return awssdk.ToString(record.Integration.Uri)
}

func (record awsAPIGatewayIntegration) connectionID() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.V2.ConnectionId)
	}
	return awssdk.ToString(record.Integration.ConnectionId)
}

func (record awsAPIGatewayIntegration) connectionType() string {
	if record.Kind == "v2" {
		return string(record.V2.ConnectionType)
	}
	return string(record.Integration.ConnectionType)
}

func (record awsAPIGatewayIntegration) credentialsARN() string {
	if record.Kind == "v2" {
		return awssdk.ToString(record.V2.CredentialsArn)
	}
	return awssdk.ToString(record.Integration.Credentials)
}

func (record awsAPIGatewayIntegration) routeTarget() string {
	if record.Kind == "rest" {
		return strings.TrimSpace(record.MethodName + " " + awssdk.ToString(record.Resource.Path))
	}
	return ""
}

func cloudFrontResourceARN(settings settings, resourceType string, id string) string {
	if strings.TrimSpace(id) == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:cloudfront::%s:%s/%s", settings.accountID, resourceType, id)
}
