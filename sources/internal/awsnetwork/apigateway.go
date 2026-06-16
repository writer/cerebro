package awsnetwork

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
)

type APIGatewayMethod struct {
	RestAPI    types.RestApi
	Resource   types.Resource
	MethodName string
	Method     types.Method
}

type EventEnvelope struct {
	ID         string
	Kind       string
	SchemaRef  string
	Payload    []byte
	Attributes map[string]string
	OccurredAt time.Time
}

func APIGatewayRestAPIEvent(accountID, region string, api types.RestApi, attributes map[string]string) (EventEnvelope, error) {
	apiID := awssdk.ToString(api.Id)
	name := awssdk.ToString(api.Name)
	public := !APIGatewayRestAPIPrivate(api) && !api.DisableExecuteApiEndpoint
	put(attributes, map[string]string{"arn": APIGatewayRestAPIARN(region, apiID), "api_id": apiID, "api_name": name, "description": awssdk.ToString(api.Description), "api_key_source": string(api.ApiKeySource), "binary_media_types": strings.Join(clean(api.BinaryMediaTypes), ","), "disable_execute_api_endpoint": boolString(api.DisableExecuteApiEndpoint), "endpoint_types": APIGatewayEndpointTypes(api.EndpointConfiguration), "minimum_compression_size": int32String(api.MinimumCompressionSize), "policy_configured": boolString(strings.TrimSpace(awssdk.ToString(api.Policy)) != ""), "root_resource_id": awssdk.ToString(api.RootResourceId), "public": boolString(public), "internet_exposed": boolString(public)})
	payload, err := json.Marshal(map[string]any{"account_id": accountID, "region": region, "rest_api": api})
	if err != nil {
		return EventEnvelope{}, err
	}
	return EventEnvelope{ID: "aws-apigateway-rest-api-" + apiID, Kind: "aws.apigateway_rest_api", SchemaRef: "aws/apigateway_rest_api/v1", Payload: payload, Attributes: attributes, OccurredAt: firstTime(api.CreatedDate)}, nil
}

func APIGatewayMethodEvent(accountID, region string, record APIGatewayMethod, attributes map[string]string) (EventEnvelope, error) {
	apiID, apiName := awssdk.ToString(record.RestAPI.Id), awssdk.ToString(record.RestAPI.Name)
	resourceID := awssdk.ToString(record.Resource.Id)
	methodName := MethodName(record)
	routeKey := strings.TrimSpace(methodName + " " + awssdk.ToString(record.Resource.Path))
	recordID := APIGatewayMethodRecordID(record)
	put(attributes, map[string]string{"api_id": apiID, "api_name": apiName, "api_gateway_resource_id": resourceID, "resource_path": awssdk.ToString(record.Resource.Path), "http_method": methodName, "route_key": routeKey, "authorization_type": awssdk.ToString(record.Method.AuthorizationType), "authorizer_id": awssdk.ToString(record.Method.AuthorizerId), "api_key_required": boolString(awssdk.ToBool(record.Method.ApiKeyRequired)), "operation_name": awssdk.ToString(record.Method.OperationName), "request_parameters": strings.Join(sortedBoolMapKeys(record.Method.RequestParameters), ","), "request_models": strings.Join(sortedStringMapKeys(record.Method.RequestModels), ","), "request_validator_id": awssdk.ToString(record.Method.RequestValidatorId), "authorization_scopes": strings.Join(clean(record.Method.AuthorizationScopes), ","), "method_response_status_codes": strings.Join(sortedMethodResponseStatusCodes(record.Method.MethodResponses), ",")})
	payload, err := json.Marshal(map[string]any{"account_id": accountID, "region": region, "record": record})
	if err != nil {
		return EventEnvelope{}, err
	}
	return EventEnvelope{ID: "aws-apigateway-method-" + recordID, Kind: "aws.apigateway_method", SchemaRef: "aws/apigateway_method/v1", Payload: payload, Attributes: attributes, OccurredAt: time.Now().UTC()}, nil
}

func APIGatewayMethodRecordID(record APIGatewayMethod) string {
	return awssdk.ToString(record.RestAPI.Id) + "/" + awssdk.ToString(record.Resource.Id) + ":" + MethodName(record)
}

func MethodName(record APIGatewayMethod) string {
	if strings.TrimSpace(record.MethodName) != "" {
		return record.MethodName
	}
	return awssdk.ToString(record.Method.HttpMethod)
}

func MethodRouteKey(record APIGatewayMethod) string {
	return strings.TrimSpace(MethodName(record) + " " + awssdk.ToString(record.Resource.Path))
}

func APIGatewayRestAPIARN(region, apiID string) string {
	return fmt.Sprintf("arn:%s:apigateway:%s::/restapis/%s", Partition(region), region, apiID)
}

func Partition(region string) string {
	region = strings.TrimSpace(region)
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	default:
		return "aws"
	}
}

func APIGatewayRestAPIPrivate(api types.RestApi) bool {
	if api.EndpointConfiguration == nil {
		return false
	}
	for _, value := range api.EndpointConfiguration.Types {
		if value == types.EndpointTypePrivate {
			return true
		}
	}
	return false
}

func APIGatewayEndpointTypes(config *types.EndpointConfiguration) string {
	if config == nil {
		return ""
	}
	values := make([]string, 0, len(config.Types))
	for _, endpointType := range config.Types {
		values = append(values, string(endpointType))
	}
	return strings.Join(clean(values), ",")
}

func put(attributes map[string]string, values map[string]string) {
	for key, value := range values {
		attributes[key] = value
	}
}

func clean(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func boolString(value bool) string { return fmt.Sprintf("%t", value) }

func int32String(value *int32) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}

func firstTime(values ...*time.Time) time.Time {
	for _, value := range values {
		if value != nil {
			return value.UTC()
		}
	}
	return time.Now().UTC()
}

func sortedBoolMapKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedStringMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedMethodResponseStatusCodes(values map[string]types.MethodResponse) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
