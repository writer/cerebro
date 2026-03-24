package builders

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	apiEndpointProjectionAWSRest       = apiEndpointProjectionSourcePrefix + "aws_apigateway_rest"
	apiEndpointProjectionAWSHTTP       = apiEndpointProjectionSourcePrefix + "aws_apigateway_v2"
	apiEndpointProjectionAWSLoadBal    = apiEndpointProjectionSourcePrefix + "aws_elbv2_listener"
	apiEndpointProjectionAWSCloudFront = apiEndpointProjectionSourcePrefix + "aws_cloudfront_distribution"
)

func (b *Builder) projectAWSAPIEndpoints(ctx context.Context) {
	if b == nil {
		return
	}
	b.projectAWSAPIGatewayRestEndpoints(ctx)
	b.projectAWSAPIGatewayV2Endpoints(ctx)
	b.projectAWSLoadBalancerEndpoints(ctx)
	b.projectAWSCloudFrontEndpoints(ctx)
}

func (b *Builder) projectAWSAPIGatewayRestEndpoints(ctx context.Context) {
	apis, err := b.queryIfExists(ctx, "aws_apigateway_rest_apis", `SELECT id, region, account_id, endpoint_configuration FROM aws_apigateway_rest_apis`)
	if err != nil || apis == nil {
		return
	}
	stages, err := b.queryIfExists(ctx, "aws_apigateway_stages", `SELECT rest_api_id, stage_name, region, account_id FROM aws_apigateway_stages`)
	if err != nil || stages == nil {
		return
	}
	methods, err := b.queryIfExists(ctx, "aws_apigateway_rest_api_methods", `SELECT rest_api_id, resource_path, http_method, authorization_type, api_key_required, authorizer_id, region, account_id FROM aws_apigateway_rest_api_methods`)
	if err != nil || methods == nil {
		return
	}

	apiRows := make(map[string]map[string]any, len(apis.Rows))
	for _, row := range apis.Rows {
		apiID := strings.TrimSpace(queryRowString(row, "id"))
		if apiID == "" {
			continue
		}
		apiRows[apiID] = row
	}

	stagesByAPI := make(map[string][]map[string]any)
	for _, row := range stages.Rows {
		apiID := strings.TrimSpace(queryRowString(row, "rest_api_id"))
		if apiID == "" {
			continue
		}
		stagesByAPI[apiID] = append(stagesByAPI[apiID], row)
	}

	for _, row := range methods.Rows {
		if ctx != nil && ctx.Err() != nil {
			return
		}
		apiID := strings.TrimSpace(queryRowString(row, "rest_api_id"))
		apiRow := apiRows[apiID]
		if apiID == "" || apiRow == nil {
			continue
		}
		stageRows := stagesByAPI[apiID]
		if len(stageRows) == 0 {
			stageRows = []map[string]any{{"stage_name": "", "region": queryRow(apiRow, "region"), "account_id": queryRow(apiRow, "account_id")}}
		}
		public := !awsAPIGatewayEndpointPrivate(queryRow(apiRow, "endpoint_configuration"))
		resourcePath := normalizeEndpointPath(queryRowString(row, "resource_path"))
		method := strings.ToUpper(strings.TrimSpace(queryRowString(row, "http_method")))
		authType := normalizeEndpointAuthType(queryRowString(row, "authorization_type"))
		apiKeyRequired := toBool(queryRow(row, "api_key_required"))
		if authType == "" && strings.TrimSpace(queryRowString(row, "authorizer_id")) != "" {
			authType = "custom"
		}
		for _, stage := range stageRows {
			stageName := strings.TrimSpace(queryRowString(stage, "stage_name"))
			region := firstNonEmpty(queryRowString(stage, "region"), queryRowString(row, "region"), queryRowString(apiRow, "region"))
			accountID := firstNonEmpty(queryRowString(stage, "account_id"), queryRowString(row, "account_id"), queryRowString(apiRow, "account_id"))
			if region == "" {
				continue
			}
			rawURL := awsExecuteAPIURL(apiID, region, stageName, resourcePath)
			normalizedURL, scheme, host, path, ok := normalizeAPIEndpointURL(rawURL)
			if !ok {
				continue
			}
			b.addAPIEndpointProjection(apiEndpointProjection{
				ID:              apiEndpointMethodNodeID(method, normalizedURL),
				URL:             normalizedURL,
				Scheme:          scheme,
				Host:            host,
				Path:            path,
				Method:          method,
				Public:          public,
				AuthType:        authType,
				APIKeyRequired:  apiKeyRequired,
				ExposureSource:  apiEndpointProjectionAWSRest,
				ProviderService: "aws_apigateway_rest",
				Provider:        "aws",
				Account:         accountID,
				Region:          region,
			}, nil)
		}
	}
}

func (b *Builder) projectAWSAPIGatewayV2Endpoints(ctx context.Context) {
	apis, err := b.queryIfExists(ctx, "aws_apigatewayv2_apis", `SELECT api_id, api_endpoint, region, account_id, protocol_type, cors_configuration, disable_execute_api_endpoint FROM aws_apigatewayv2_apis`)
	if err != nil || apis == nil {
		return
	}
	stages, err := b.queryIfExists(ctx, "aws_apigatewayv2_stages", `SELECT api_id, stage_name, region, account_id FROM aws_apigatewayv2_stages`)
	if err != nil || stages == nil {
		return
	}

	apiRows := make(map[string]map[string]any, len(apis.Rows))
	for _, row := range apis.Rows {
		apiID := strings.TrimSpace(queryRowString(row, "api_id"))
		if apiID == "" {
			continue
		}
		apiRows[apiID] = row
	}

	stagesByAPI := make(map[string][]map[string]any)
	for _, row := range stages.Rows {
		apiID := strings.TrimSpace(queryRowString(row, "api_id"))
		if apiID == "" {
			continue
		}
		stagesByAPI[apiID] = append(stagesByAPI[apiID], row)
	}

	for apiID, apiRow := range apiRows {
		if ctx != nil && ctx.Err() != nil {
			return
		}
		baseURL := strings.TrimSpace(queryRowString(apiRow, "api_endpoint"))
		if baseURL == "" {
			continue
		}
		public := !toBool(queryRow(apiRow, "disable_execute_api_endpoint"))
		corsPermissive := apiEndpointCORSPermissive(queryRow(apiRow, "cors_configuration"))
		stageRows := stagesByAPI[apiID]
		if len(stageRows) == 0 {
			stageRows = []map[string]any{{"stage_name": "", "region": queryRow(apiRow, "region"), "account_id": queryRow(apiRow, "account_id")}}
		}
		for _, stage := range stageRows {
			stageName := strings.TrimSpace(queryRowString(stage, "stage_name"))
			region := firstNonEmpty(queryRowString(stage, "region"), queryRowString(apiRow, "region"))
			accountID := firstNonEmpty(queryRowString(stage, "account_id"), queryRowString(apiRow, "account_id"))
			rawURL := joinEndpointURLPath(baseURL, stageName)
			normalizedURL, scheme, host, path, ok := normalizeAPIEndpointURL(rawURL)
			if !ok {
				continue
			}
			b.addAPIEndpointProjection(apiEndpointProjection{
				ID:              apiEndpointNodeID(normalizedURL),
				URL:             normalizedURL,
				Scheme:          scheme,
				Host:            host,
				Path:            path,
				Public:          public,
				AuthType:        "unknown",
				CORSPermissive:  corsPermissive,
				ExposureSource:  apiEndpointProjectionAWSHTTP,
				ProviderService: "aws_apigateway_v2",
				Provider:        "aws",
				Account:         accountID,
				Region:          region,
			}, nil)
		}
	}
}

func (b *Builder) projectAWSLoadBalancerEndpoints(ctx context.Context) {
	loadBalancers, err := b.queryIfExists(ctx, "aws_elbv2_load_balancers", `SELECT arn, dns_name, scheme, region, account_id FROM aws_elbv2_load_balancers`)
	if err != nil || loadBalancers == nil {
		return
	}
	listeners, err := b.queryIfExists(ctx, "aws_lb_listeners", `SELECT listener_arn, load_balancer_arn, port, protocol, region, account_id FROM aws_lb_listeners`)
	if err != nil || listeners == nil {
		return
	}
	actions, err := b.queryIfExists(ctx, "default_actions", `SELECT listener_arn, type, target_group_arn, authenticate_oidc_config, authenticate_cognito_config FROM default_actions`)
	if err != nil {
		actions = nil
	}

	lbRows := make(map[string]map[string]any, len(loadBalancers.Rows))
	for _, row := range loadBalancers.Rows {
		arn := strings.TrimSpace(queryRowString(row, "arn"))
		if arn == "" {
			continue
		}
		lbRows[arn] = row
	}

	actionsByListener := make(map[string][]map[string]any)
	if actions != nil {
		for _, row := range actions.Rows {
			listenerARN := strings.TrimSpace(queryRowString(row, "listener_arn"))
			if listenerARN == "" {
				continue
			}
			actionsByListener[listenerARN] = append(actionsByListener[listenerARN], row)
		}
	}

	for _, row := range listeners.Rows {
		if ctx != nil && ctx.Err() != nil {
			return
		}
		lbARN := strings.TrimSpace(queryRowString(row, "load_balancer_arn"))
		lbRow := lbRows[lbARN]
		if lbARN == "" || lbRow == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(queryRowString(lbRow, "scheme")), "internet-facing") {
			continue
		}
		host := strings.TrimSpace(queryRowString(lbRow, "dns_name"))
		if host == "" {
			continue
		}
		protocol := strings.ToUpper(strings.TrimSpace(queryRowString(row, "protocol")))
		port := strings.TrimSpace(toString(queryRow(row, "port")))
		scheme := "http"
		if strings.Contains(protocol, "HTTPS") || strings.Contains(protocol, "TLS") {
			scheme = "https"
		}
		rawURL := listenerURL(scheme, host, port)
		normalizedURL, normalizedScheme, normalizedHost, path, ok := normalizeAPIEndpointURL(rawURL)
		if !ok {
			continue
		}
		authType, backendTargets := loadBalancerListenerSecurity(actionsByListener[strings.TrimSpace(queryRowString(row, "listener_arn"))])
		b.addAPIEndpointProjection(apiEndpointProjection{
			ID:              apiEndpointNodeID(normalizedURL),
			URL:             normalizedURL,
			Scheme:          normalizedScheme,
			Host:            normalizedHost,
			Path:            path,
			Public:          true,
			AuthType:        authType,
			ExposureSource:  apiEndpointProjectionAWSLoadBal,
			ProviderService: "aws_elbv2_listener",
			Provider:        "aws",
			Account:         firstNonEmpty(queryRowString(row, "account_id"), queryRowString(lbRow, "account_id")),
			Region:          firstNonEmpty(queryRowString(row, "region"), queryRowString(lbRow, "region")),
			BackendTargets:  backendTargets,
		}, nil)
	}
}

func (b *Builder) projectAWSCloudFrontEndpoints(ctx context.Context) {
	distributions, err := b.queryIfExists(ctx, "aws_cloudfront_distributions", `SELECT id, domain_name, aliases, enabled, account_id FROM aws_cloudfront_distributions`)
	if err != nil || distributions == nil {
		return
	}
	for _, row := range distributions.Rows {
		if ctx != nil && ctx.Err() != nil {
			return
		}
		if !toBool(queryRow(row, "enabled")) {
			continue
		}
		hosts := cloudFrontHosts(queryRow(row, "aliases"))
		if len(hosts) == 0 {
			if host := strings.TrimSpace(queryRowString(row, "domain_name")); host != "" {
				hosts = []string{host}
			}
		}
		for _, host := range hosts {
			rawURL := "https://" + host
			normalizedURL, scheme, normalizedHost, path, ok := normalizeAPIEndpointURL(rawURL)
			if !ok {
				continue
			}
			b.addAPIEndpointProjection(apiEndpointProjection{
				ID:              apiEndpointNodeID(normalizedURL),
				URL:             normalizedURL,
				Scheme:          scheme,
				Host:            normalizedHost,
				Path:            path,
				Public:          true,
				ExposureSource:  apiEndpointProjectionAWSCloudFront,
				ProviderService: "aws_cloudfront_distribution",
				Provider:        "aws",
				Account:         queryRowString(row, "account_id"),
				Region:          "global",
			}, nil)
		}
	}
}

func awsExecuteAPIURL(apiID, region, stageName, resourcePath string) string {
	base := fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com", strings.TrimSpace(apiID), strings.TrimSpace(region))
	if stageName != "" {
		base = joinEndpointURLPath(base, stageName)
	}
	if resourcePath != "" {
		base = joinEndpointURLPath(base, resourcePath)
	}
	return base
}

func joinEndpointURLPath(baseURL, segment string) string {
	baseURL = strings.TrimSpace(baseURL)
	segment = strings.TrimSpace(segment)
	if baseURL == "" || segment == "" || segment == "$default" || segment == "/" {
		return baseURL
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	segment = strings.TrimPrefix(segment, "/")
	u.Path = strings.TrimRight(u.Path, "/") + "/" + segment
	return u.String()
}

func normalizeEndpointPath(path string) string {
	path = strings.TrimSpace(path)
	switch path {
	case "", "/":
		return ""
	default:
		if !strings.HasPrefix(path, "/") {
			return "/" + path
		}
		return path
	}
}

func awsAPIGatewayEndpointPrivate(value any) bool {
	text := strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", value)))
	return strings.Contains(text, "PRIVATE")
}

func apiEndpointCORSPermissive(value any) bool {
	return sliceContainsWildcard(stringSliceFromAny(value))
}

func loadBalancerListenerSecurity(rows []map[string]any) (string, []string) {
	authType := "none"
	backendTargets := make(map[string]struct{})
	for _, row := range rows {
		actionType := strings.ToLower(strings.TrimSpace(queryRowString(row, "type")))
		switch actionType {
		case "authenticate-oidc", "authenticate_oidc":
			authType = "oidc"
		case "authenticate-cognito", "authenticate_cognito":
			authType = "cognito"
		}
		if target := strings.TrimSpace(queryRowString(row, "target_group_arn")); target != "" {
			backendTargets[target] = struct{}{}
		}
	}
	return authType, sortedStringSet(backendTargets)
}

func listenerURL(scheme, host, port string) string {
	scheme = strings.TrimSpace(strings.ToLower(scheme))
	host = strings.TrimSpace(strings.ToLower(host))
	port = strings.TrimSpace(port)
	if host == "" {
		return ""
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") || port == "" {
		return scheme + "://" + host
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

func cloudFrontHosts(value any) []string {
	return uniqueNormalizedHosts(stringSliceFromAny(value))
}

func uniqueNormalizedHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		host = strings.TrimPrefix(host, "https://")
		host = strings.TrimPrefix(host, "http://")
		host = strings.TrimSuffix(host, "/")
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func stringSliceFromAny(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(toString(item))
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	case map[string]any:
		for _, key := range []string{"items", "Items", "allow_origins", "AllowOrigins"} {
			if values, ok := queryRowValue(typed, key); ok {
				return stringSliceFromAny(values)
			}
		}
	case string:
		if strings.Contains(typed, "[") {
			text := strings.NewReplacer("[", "", "]", "", "\"", "").Replace(typed)
			parts := strings.Split(text, ",")
			out := make([]string, 0, len(parts))
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					out = append(out, part)
				}
			}
			return out
		}
		if trimmed := strings.TrimSpace(typed); trimmed != "" {
			return []string{trimmed}
		}
	}
	return nil
}

func sliceContainsWildcard(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "*" {
			return true
		}
	}
	return false
}

func sortedStringSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
