package jsonapi

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	defaultPageSize = 100
	maxPageSize     = 500
)

type settings struct {
	tenantID                 string
	family                   string
	baseURL                  string
	host                     string
	authModel                string
	token                    string
	authPrincipal            string
	authSecret               string
	clientID                 string
	clientSecret             string
	refreshToken             string
	tokenURL                 string
	apiKey                   string
	oauthScopes              []string
	oauthTokenParams         map[string]string
	oauthTokenRequestMethod  string
	path                     string
	request                  requestSettings
	perPage                  int
	privateEndpointAllowlist []string
	region                   string
	service                  string
	familyMethod             string
}

type requestSettings struct {
	pathParams       map[string]string
	headers          map[string]string
	configAttributes map[string]string
	query            url.Values
}

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	if s == nil {
		return settings{}, fmt.Errorf("jsonapi source is required")
	}
	var err error
	configuredTokenURL := sourcecdk.ConfigValue(cfg, "token_url")
	resolved := settings{
		tenantID:                firstNonEmpty(sourcecdk.ConfigValue(cfg, "tenant_id"), sourcecdk.ConfigValue(cfg, sourceconfig.RuntimeTenantIDKey)),
		family:                  strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family")),
		baseURL:                 strings.TrimSpace(sourcecdk.ConfigValue(cfg, "base_url")),
		authModel:               normalizedAuthModel(s.options.AuthModel),
		token:                   firstNonEmpty(sourcecdk.ConfigValue(cfg, "token"), sourcecdk.ConfigValue(cfg, "api_token"), sourcecdk.ConfigValue(cfg, "api_key"), sourcecdk.ConfigValue(cfg, "access_token"), sourcecdk.ConfigValue(cfg, "jwt"), sourcecdk.ConfigValue(cfg, "signature")),
		authPrincipal:           firstNonEmpty(sourcecdk.ConfigValue(cfg, "username"), sourcecdk.ConfigValue(cfg, "public_key")),
		authSecret:              firstNonEmpty(sourcecdk.ConfigValue(cfg, "password"), sourcecdk.ConfigValue(cfg, "secret_key")),
		clientID:                firstNonEmpty(sourcecdk.ConfigValue(cfg, "client_id"), sourcecdk.ConfigValue(cfg, "access_key")),
		clientSecret:            firstNonEmpty(sourcecdk.ConfigValue(cfg, "client_secret"), sourcecdk.ConfigValue(cfg, "secret_key")),
		refreshToken:            sourcecdk.ConfigValue(cfg, "refresh_token"),
		tokenURL:                firstNonEmpty(configuredTokenURL, s.options.OAuthTokenURL),
		oauthScopes:             cloneStrings(s.options.OAuthScopes),
		oauthTokenParams:        cloneStringMap(s.options.OAuthTokenParams),
		oauthTokenRequestMethod: firstNonEmpty(sourcecdk.ConfigValue(cfg, "token_request_auth_method"), s.options.OAuthTokenRequestAuthMethod),
		perPage:                 defaultPageSize,
		region:                  sourcecdk.ConfigValue(cfg, "region"),
		service:                 sourcecdk.ConfigValue(cfg, "service"),
		apiKey:                  sourcecdk.ConfigValue(cfg, "api_key"),
	}
	if resolved.family == "" {
		resolved.family = strings.TrimSpace(s.options.DefaultFamily)
	}
	rawAuthModel := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "auth_model"))
	if rawAuthModel != "" {
		authModel := normalizedAuthModel(rawAuthModel)
		if !authModelAllowed(authModel, s.options.ConfigurableAuthModels) {
			return resolved, fmt.Errorf("%s auth_model %q is not supported", s.options.SourceID, rawAuthModel)
		}
		resolved.authModel = authModel
	}
	family, ok := familyByName(s.options, resolved.family)
	if !ok {
		return resolved, fmt.Errorf("%s family must be one of %s", s.options.SourceID, strings.Join(familyNames(s.options), ", "))
	}
	if rawAuthModel == "" {
		if familyAuthModel := normalizedAuthModel(family.AuthModel); familyAuthModel != "" {
			resolved.authModel = familyAuthModel
		}
	}
	resolved.familyMethod = strings.TrimSpace(family.Config.Method)
	if s.options.RequireTenantID && resolved.tenantID == "" {
		return resolved, fmt.Errorf("%s tenant_id is required", s.options.SourceID)
	}
	if strings.TrimSpace(configuredTokenURL) != "" && strings.TrimSpace(s.options.OAuthTokenURL) != "" && !providerManagedTokenURLOverrideAllowed(configuredTokenURL, s.AllowLoopbackBaseURL) {
		return resolved, fmt.Errorf("%w: %s token_url is provider-managed and cannot be overridden", sourcecdk.ErrInvalidConfig, s.options.SourceID)
	}
	if familyBaseURL := firstNonEmpty(sourcecdk.ConfigValue(cfg, resolved.family+"_base_url"), family.Config.BaseURL); familyBaseURL != "" {
		resolved.baseURL = strings.TrimSpace(familyBaseURL)
	}
	if resolved.baseURL == "" {
		resolved.baseURL = strings.TrimSpace(s.options.DefaultBaseURL)
	}
	if resolved.baseURL == "" {
		return resolved, fmt.Errorf("%s base_url is required", s.options.SourceID)
	}
	resolved.baseURL, err = resolveConfigTemplate(s.options.SourceID, resolved.baseURL, cfg)
	if err != nil {
		return resolved, err
	}
	if resolved.tokenURL != "" {
		resolved.tokenURL, err = resolveConfigTemplate(s.options.SourceID, resolved.tokenURL, cfg)
		if err != nil {
			return resolved, err
		}
	}
	for i, scope := range resolved.oauthScopes {
		resolved.oauthScopes[i], err = resolveConfigTemplate(s.options.SourceID, scope, cfg)
		if err != nil {
			return resolved, err
		}
	}
	for key, value := range resolved.oauthTokenParams {
		resolved.oauthTokenParams[key], err = resolveConfigTemplate(s.options.SourceID, value, cfg)
		if err != nil {
			return resolved, err
		}
	}
	resolved.request.headers = mergeStaticHeaders(family.Config.StaticHeaders, headersFromConfig(cfg, s.options.ConfigHeaders))
	if key := strings.TrimSpace(s.options.PrivateEndpointAllowlistConfigKey); key != "" {
		allowlist, err := sourcehttp.ParsePrivateEndpointAllowlist(s.options.SourceID, sourcecdk.ConfigValue(cfg, key))
		if err != nil {
			return resolved, err
		}
		resolved.privateEndpointAllowlist = allowlist
	}
	baseURL, host, err := sourcehttp.NormalizeBaseURLWithOptions(s.options.SourceID, resolved.baseURL, sourcehttp.URLValidationOptions{
		AllowLoopback:            s.AllowLoopbackBaseURL,
		PrivateEndpointAllowlist: resolved.privateEndpointAllowlist,
	})
	if err != nil {
		return resolved, err
	}
	resolved.baseURL = baseURL
	resolved.host = host
	if resolved.tenantID == "" {
		resolved.tenantID = host
	}
	if rawPerPage := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "per_page")); rawPerPage != "" {
		perPage, err := strconv.Atoi(rawPerPage)
		if err != nil {
			return resolved, fmt.Errorf("parse %s per_page: %w", s.options.SourceID, err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return resolved, fmt.Errorf("%s per_page must be between 1 and %d", s.options.SourceID, maxPageSize)
		}
		resolved.perPage = perPage
	}
	path := firstNonEmpty(sourcecdk.ConfigValue(cfg, resolved.family+"_path"), sourcecdk.ConfigValue(cfg, "path"), family.Path)
	path, err = resolveConfigTemplate(s.options.SourceID, path, cfg)
	if err != nil {
		return resolved, err
	}
	path, pathParams, err := resolvePathParams(s.options.SourceID, path, cfg, family.PathParams)
	if err != nil {
		return resolved, err
	}
	resolved.request.pathParams = pathParams
	resolved.path, err = sourcehttp.NormalizeRequestPath(s.options.SourceID, path)
	if err != nil {
		return resolved, err
	}
	resolved.request.configAttributes = attributesFromConfig(cfg, family.Config.ConfigAttributes)
	resolved.request.query = queryFromConfig(cfg, family.Config.ConfigQuery)
	return resolved, nil
}

func mergeStaticHeaders(static map[string]string, configured map[string]string) map[string]string {
	if len(static) == 0 {
		return configured
	}
	headers := map[string]string{}
	for header, value := range static {
		header = strings.TrimSpace(header)
		value = strings.TrimSpace(value)
		if header != "" && value != "" {
			headers[header] = value
		}
	}
	for header, value := range configured {
		header = strings.TrimSpace(header)
		value = strings.TrimSpace(value)
		if header != "" && value != "" {
			headers[header] = value
		}
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

func headersFromConfig(cfg sourcecdk.Config, configHeaders map[string]string) map[string]string {
	if len(configHeaders) == 0 {
		return nil
	}
	headers := map[string]string{}
	for header, configKey := range configHeaders {
		header = strings.TrimSpace(header)
		configKey = strings.TrimSpace(configKey)
		if header == "" || configKey == "" {
			continue
		}
		if value := strings.TrimSpace(sourcecdk.ConfigValue(cfg, configKey)); value != "" {
			headers[header] = value
		}
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

func attributesFromConfig(cfg sourcecdk.Config, configAttributes map[string]string) map[string]string {
	if len(configAttributes) == 0 {
		return nil
	}
	attrs := map[string]string{}
	for attr, configKey := range configAttributes {
		attr = strings.TrimSpace(attr)
		configKey = strings.TrimSpace(configKey)
		if attr == "" || configKey == "" {
			continue
		}
		if value := strings.TrimSpace(sourcecdk.ConfigValue(cfg, configKey)); value != "" {
			attrs[attr] = value
		}
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
