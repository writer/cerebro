package sourcegen

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

const (
	SourceTypeJSONAPI = "json_api"

	AuthModelBearerToken            = "bearer_token"
	AuthModelAPIToken               = "api_token"
	AuthModelAPIKey                 = "api_key"
	AuthModelBasic                  = "basic"
	AuthModelOAuthAuthorizationCode = "oauth_authorization_code"
	AuthModelOAuthClientCredentials = "oauth_client_credentials" // #nosec G101 -- auth model identifier, not credential material.
	AuthModelJWT                    = "jwt"
	AuthModelSignature              = "signature"
	AuthModelAWSSigV4               = "aws_sigv4"
	AuthModelTwoStep                = "two_step"
	AuthModelDuoHMAC                = "duo_hmac"
	AuthModelDuoHMACV5              = "duo_hmac_v5"

	defaultFreshnessExpectation = 24 * time.Hour
	defaultHealthPath           = "/healthz"
)

var errMissingSchemas = errors.New("at least one asset_schemas or finding_schemas entry is required")
var errGeneratedNameCollision = errors.New("generated source names collide")
var errUnsupportedDefinition = errors.New("connector definition is not executable by sourcegen")

// Request describes a generated Source Runtime SDK integration.
type Request struct {
	SourceID             string
	SourceType           string
	AuthModel            string
	DefinitionPath       string
	AssetSchemas         []string
	FindingSchemas       []string
	FreshnessExpectation string
	FailureModes         []string
	Name                 string
	Description          string
	HealthPath           string
	OutputDir            string
	DryRun               bool
	Force                bool
}

// DefinitionRequest describes a generated integration backed by a connector definition.
type DefinitionRequest struct {
	Definition           connectordefinitions.Definition
	FreshnessExpectation string
	HealthPath           string
	OutputDir            string
	DryRun               bool
	Force                bool
}

// Result describes the files and operator receipt produced by the generator.
type Result struct {
	SourceID            string   `json:"source_id"`
	SourceType          string   `json:"source_type"`
	AuthModel           string   `json:"auth_model"`
	DryRun              bool     `json:"dry_run"`
	Files               []string `json:"files"`
	HealthEndpoint      string   `json:"health_endpoint"`
	SourceHealthReceipt string   `json:"source_health_receipt"`
	PRBody              string   `json:"pr_body"`
	NextSteps           []string `json:"next_steps"`
}

type normalizedRequest struct {
	Request
	FreshnessDuration time.Duration
	TokenHeader       string
	TokenScheme       string
	TokenConfigKey    string
	AuthTokenURL      string
	OAuthScopes       []string
	OAuthTokenParams  map[string]string
	OAuthTokenMethod  string
	ProviderAPI       *connectordefinitions.ProviderAPISpec
	EnvPrefix         string
	PackageName       string
	DefaultFamily     string
	DefaultPath       string
	BaseURLTemplate   string
	StaticHeaders     map[string]string
	ConfigKeys        []string
	CredentialKeys    []string
	OAuth             *oauthClientCredentialsData
	Families          []familyData
}

type familyData struct {
	Name                  string
	Schema                string
	Class                 string
	ConstName             string
	ProjectorName         string
	Path                  string
	Method                string
	AuthModel             string
	RecordSelector        string
	URNKind               string
	EventKind             string
	SchemaRef             string
	IDKeys                []string
	ListKeys              []string
	Singleton             bool
	CursorParam           string
	NextCursorKeys        []string
	LinkHeader            string
	PageSizeParams        []string
	DisablePageSize       bool
	Config                familyConfigData
	RequiredAttributes    []string
	RequiredPayloadFields []string
	Projection            *connectordefinitions.ProjectionSpec
}

type familyConfigData struct {
	StaticQuery  map[string]string
	ConfigQuery  map[string]string
	IdentityKeys []string
}

type oauthClientCredentialsData struct {
	TokenURLTemplate        string
	Scopes                  []string
	ScopeSeparator          string
	TokenParams             map[string]string
	ExpirationBufferSeconds int
}

type generatedFile struct {
	Path    string
	Content string
}

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

// Generate writes a Source Runtime SDK scaffold, or returns the file plan in dry-run mode.
func Generate(request Request) (*Result, error) {
	normalized, err := normalizeRequest(request)
	if err != nil {
		return nil, err
	}
	return generateNormalized(normalized)
}

// GenerateDefinition writes a Source Runtime SDK scaffold from a validated
// integration definition, or returns the file plan in dry-run mode.
func GenerateDefinition(request DefinitionRequest) (*Result, error) {
	normalized, err := normalizeDefinitionRequest(request)
	if err != nil {
		return nil, err
	}
	return generateNormalized(normalized)
}

func generateNormalized(normalized normalizedRequest) (*Result, error) {
	files, err := renderFiles(normalized)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	result := &Result{
		SourceID:            normalized.SourceID,
		SourceType:          normalized.SourceType,
		AuthModel:           normalized.AuthModel,
		DryRun:              normalized.DryRun,
		Files:               paths,
		HealthEndpoint:      healthEndpoint(normalized.SourceID),
		SourceHealthReceipt: filepath.Join(normalized.OutputDir, "sources", normalized.SourceID, "source_health_receipt.json"),
		PRBody:              filepath.Join(normalized.OutputDir, "sources", normalized.SourceID, "PR_BODY.md"),
		NextSteps: []string{
			"Review generated adapter field mappings and provider paths.",
			"Register the source loader in internal/sourceregistry/registry.go.",
			"Register generated projector functions in internal/sourceprojection/registry.go.",
			fmt.Sprintf("Run: go test ./sources/%s ./internal/sourceprojection -count=1", normalized.SourceID),
			"Run: make catalog-check",
		},
	}
	if normalized.DryRun {
		return result, nil
	}
	if err := ensureWritable(files, normalized.Force); err != nil {
		return nil, err
	}
	for _, file := range files {
		if err := os.MkdirAll(filepath.Dir(file.Path), 0o750); err != nil {
			return nil, err
		}
		if err := os.WriteFile(file.Path, []byte(file.Content), 0o600); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func normalizeDefinitionRequest(request DefinitionRequest) (normalizedRequest, error) {
	definition, err := connectordefinitions.Normalize(request.Definition)
	if err != nil {
		return normalizedRequest{}, err
	}
	report, err := connectordefinitions.Classify(definition, connectordefinitions.DefaultGrammar())
	if err != nil {
		return normalizedRequest{}, err
	}
	if report.Validation.Status == connectordefinitions.ValidationBlocked {
		return normalizedRequest{}, fmt.Errorf("%w: definition validation is blocked: %s", errUnsupportedDefinition, strings.Join(report.MissingFeatures, ", "))
	}
	if report.Verdict != connectordefinitions.SupportVerdictSupported {
		return normalizedRequest{}, fmt.Errorf("%w: definition is outside the generic grammar: %s", errUnsupportedDefinition, strings.Join(report.MissingFeatures, ", "))
	}
	authModel, err := executableAuthModel(definition.Auth.Model)
	if err != nil {
		return normalizedRequest{}, err
	}
	tokenScheme, tokenConfigKey, err := authModelConfig(authModel)
	if err != nil {
		return normalizedRequest{}, err
	}
	if customScheme := strings.TrimSpace(definition.Auth.TokenScheme); customScheme != "" {
		tokenScheme = customScheme
	}
	oauth, err := oauthClientCredentialsForDefinition(definition.Auth)
	if err != nil {
		return normalizedRequest{}, err
	}
	sourceID := strings.TrimSpace(definition.SourceID)
	if !identifierPattern.MatchString(sourceID) {
		return normalizedRequest{}, fmt.Errorf("source_id %q must start with a lowercase letter and use lowercase letters, digits, underscores, or hyphens", definition.SourceID)
	}
	failureModes := []string{"api_error", "auth_error", "rate_limit", "schema_drift"}
	freshness, err := parseFreshnessExpectation(request.FreshnessExpectation)
	if err != nil {
		return normalizedRequest{}, err
	}
	healthPath := strings.TrimSpace(request.HealthPath)
	if healthPath == "" && definition.Transport != nil && definition.Transport.Verification != nil {
		healthPath = strings.TrimSpace(definition.Transport.Verification.Path)
	}
	if healthPath == "" {
		healthPath = defaultHealthPath
	}
	if !strings.HasPrefix(healthPath, "/") || strings.Contains(healthPath, "#") {
		return normalizedRequest{}, fmt.Errorf("health_path must be an absolute path without fragment")
	}
	if strings.ContainsAny(healthPath, "\r\n\t ") {
		return normalizedRequest{}, fmt.Errorf("health_path must not contain whitespace")
	}
	outputDir := strings.TrimSpace(request.OutputDir)
	if outputDir == "" {
		outputDir = "."
	}
	normalized := normalizedRequest{
		Request: Request{
			SourceID:             sourceID,
			SourceType:           SourceTypeJSONAPI,
			AuthModel:            authModel,
			FreshnessExpectation: freshness.String(),
			FailureModes:         failureModes,
			Name:                 firstNonEmptyString(definition.DisplayName, titleFromID(sourceID)+" Source Runtime"),
			Description:          firstNonEmptyString(definition.Description, fmt.Sprintf("%s source runtime generated from a connector definition.", titleFromID(sourceID))),
			HealthPath:           healthPath,
			OutputDir:            outputDir,
			DryRun:               request.DryRun,
			Force:                request.Force,
		},
		FreshnessDuration: freshness,
		TokenHeader:       strings.TrimSpace(definition.Auth.TokenHeader),
		TokenScheme:       tokenScheme,
		TokenConfigKey:    tokenConfigKey,
		AuthTokenURL:      strings.TrimSpace(definition.Auth.TokenURL),
		OAuthScopes:       append([]string(nil), definition.Auth.Scopes...),
		OAuthTokenParams:  cloneStringMap(definition.Auth.TokenParams),
		OAuthTokenMethod:  strings.TrimSpace(definition.Auth.TokenRequestAuthMethod),
		ProviderAPI:       cloneProviderAPI(definition.ProviderAPI),
		EnvPrefix:         strings.ToUpper(strings.NewReplacer("-", "_").Replace(sourceID)),
		PackageName:       packageName(sourceID),
		BaseURLTemplate:   transportBaseURL(definition.Transport),
		StaticHeaders:     transportHeaders(definition.Transport),
		ConfigKeys:        fieldKeys(definition.ConfigFields),
		CredentialKeys:    fieldKeys(definition.Auth.CredentialFields),
		OAuth:             oauth,
	}
	normalized.Families, err = familiesForDefinition(normalized, definition)
	if err != nil {
		return normalizedRequest{}, err
	}
	if len(normalized.Families) == 0 {
		return normalizedRequest{}, fmt.Errorf("%w: definition must include at least one executable resource family", errUnsupportedDefinition)
	}
	if err := validateGeneratedFamilies(normalized.Families); err != nil {
		return normalizedRequest{}, err
	}
	normalized.DefaultFamily = normalized.Families[0].Name
	normalized.DefaultPath = normalized.Families[0].Path
	return normalized, nil
}

func normalizeRequest(request Request) (normalizedRequest, error) {
	sourceID := strings.TrimSpace(request.SourceID)
	if !identifierPattern.MatchString(sourceID) {
		return normalizedRequest{}, fmt.Errorf("source_id %q must start with a lowercase letter and use lowercase letters, digits, underscores, or hyphens", request.SourceID)
	}
	sourceType := strings.TrimSpace(request.SourceType)
	if sourceType == "" {
		sourceType = SourceTypeJSONAPI
	}
	if sourceType != SourceTypeJSONAPI {
		return normalizedRequest{}, fmt.Errorf("source_type %q is not supported; use %s", sourceType, SourceTypeJSONAPI)
	}
	authModel := strings.TrimSpace(request.AuthModel)
	if authModel == "" {
		authModel = AuthModelBearerToken
	}
	tokenScheme, tokenConfigKey, err := authModelConfig(authModel)
	if err != nil {
		return normalizedRequest{}, err
	}
	assetSchemas, err := normalizeIdentifiers("asset_schemas", request.AssetSchemas)
	if err != nil {
		return normalizedRequest{}, err
	}
	findingSchemas, err := normalizeIdentifiers("finding_schemas", request.FindingSchemas)
	if err != nil {
		return normalizedRequest{}, err
	}
	if len(assetSchemas) == 0 && len(findingSchemas) == 0 {
		return normalizedRequest{}, errMissingSchemas
	}
	failureModes, err := normalizeIdentifiers("failure_modes", request.FailureModes)
	if err != nil {
		return normalizedRequest{}, err
	}
	if len(failureModes) == 0 {
		failureModes = []string{"api_error", "auth_error", "rate_limit", "schema_drift"}
	}
	freshness, err := parseFreshnessExpectation(request.FreshnessExpectation)
	if err != nil {
		return normalizedRequest{}, err
	}
	healthPath := strings.TrimSpace(request.HealthPath)
	if healthPath == "" {
		healthPath = defaultHealthPath
	}
	if !strings.HasPrefix(healthPath, "/") || strings.Contains(healthPath, "#") {
		return normalizedRequest{}, fmt.Errorf("health_path must be an absolute path without fragment")
	}
	if strings.ContainsAny(healthPath, "\r\n\t ") {
		return normalizedRequest{}, fmt.Errorf("health_path must not contain whitespace")
	}
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = titleFromID(sourceID) + " Source Runtime"
	}
	description := strings.TrimSpace(request.Description)
	if description == "" {
		description = fmt.Sprintf("%s source runtime generated from the Source Runtime SDK.", name)
	}
	outputDir := strings.TrimSpace(request.OutputDir)
	if outputDir == "" {
		outputDir = "."
	}
	normalized := normalizedRequest{
		Request: Request{
			SourceID:             sourceID,
			SourceType:           sourceType,
			AuthModel:            authModel,
			AssetSchemas:         assetSchemas,
			FindingSchemas:       findingSchemas,
			FreshnessExpectation: freshness.String(),
			FailureModes:         failureModes,
			Name:                 name,
			Description:          description,
			HealthPath:           healthPath,
			OutputDir:            outputDir,
			DryRun:               request.DryRun,
			Force:                request.Force,
		},
		FreshnessDuration: freshness,
		TokenScheme:       tokenScheme,
		TokenConfigKey:    tokenConfigKey,
		EnvPrefix:         strings.ToUpper(strings.NewReplacer("-", "_").Replace(sourceID)),
		PackageName:       packageName(sourceID),
	}
	normalized.Families = familiesForRequest(normalized)
	if err := validateGeneratedFamilies(normalized.Families); err != nil {
		return normalizedRequest{}, err
	}
	normalized.DefaultFamily = normalized.Families[0].Name
	normalized.DefaultPath = normalized.Families[0].Path
	return normalized, nil
}

func ensureWritable(files []generatedFile, force bool) error {
	if force {
		return nil
	}
	for _, file := range files {
		if _, err := os.Stat(file.Path); err == nil {
			return fmt.Errorf("%s already exists; pass force=true to overwrite", file.Path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func authModelConfig(authModel string) (string, string, error) {
	switch authModel {
	case AuthModelBearerToken, "bearer":
		return "Bearer", "token", nil
	case AuthModelAPIToken, AuthModelAPIKey:
		return "Token", "api_token", nil
	case AuthModelBasic:
		return "Basic", "token", nil
	case AuthModelOAuthAuthorizationCode, AuthModelOAuthClientCredentials, AuthModelJWT:
		return "Bearer", "token", nil
	case AuthModelSignature:
		return "Signature", "token", nil
	case AuthModelAWSSigV4:
		return "AWS4-HMAC-SHA256", "client_id", nil
	case AuthModelTwoStep:
		return "Bearer", "api_key", nil
	case AuthModelDuoHMAC, AuthModelDuoHMACV5:
		return "Basic", "client_id", nil
	default:
		return "", "", fmt.Errorf("auth_model %q must be executable by a JSON API runtime", authModel)
	}
}

func executableAuthModel(authModel string) (string, error) {
	switch strings.TrimSpace(authModel) {
	case AuthModelBearerToken, "bearer":
		return AuthModelBearerToken, nil
	case AuthModelAPIToken, AuthModelAPIKey:
		return AuthModelAPIKey, nil
	case AuthModelBasic:
		return AuthModelBasic, nil
	case AuthModelOAuthAuthorizationCode:
		return AuthModelOAuthAuthorizationCode, nil
	case AuthModelJWT:
		return AuthModelJWT, nil
	case AuthModelSignature:
		return AuthModelSignature, nil
	case AuthModelOAuthClientCredentials:
		return AuthModelOAuthClientCredentials, nil
	case AuthModelAWSSigV4:
		return AuthModelAWSSigV4, nil
	case AuthModelTwoStep:
		return AuthModelTwoStep, nil
	case AuthModelDuoHMAC:
		return AuthModelDuoHMAC, nil
	case AuthModelDuoHMACV5:
		return AuthModelDuoHMACV5, nil
	default:
		return "", fmt.Errorf("%w: auth model %q needs provider auth runtime support before sourcegen can emit executable code", errUnsupportedDefinition, authModel)
	}
}

func oauthClientCredentialsForDefinition(auth connectordefinitions.AuthSpec) (*oauthClientCredentialsData, error) {
	if strings.TrimSpace(auth.Model) != AuthModelOAuthClientCredentials {
		return nil, nil
	}
	if strings.TrimSpace(auth.TokenURL) == "" {
		return nil, fmt.Errorf("%w: oauth_client_credentials requires token_url", errUnsupportedDefinition)
	}
	if !hasCredentialField(auth.CredentialFields, "client_id") {
		return nil, fmt.Errorf("%w: oauth_client_credentials requires client_id credential field", errUnsupportedDefinition)
	}
	if !hasCredentialField(auth.CredentialFields, "client_secret") {
		return nil, fmt.Errorf("%w: oauth_client_credentials requires client_secret credential field", errUnsupportedDefinition)
	}
	separator := strings.TrimSpace(auth.ScopeSeparator)
	if separator == "" {
		separator = " "
	}
	buffer := auth.TokenExpirationBufferSeconds
	if buffer == 0 {
		buffer = 60
	}
	return &oauthClientCredentialsData{
		TokenURLTemplate:        strings.TrimSpace(auth.TokenURL),
		Scopes:                  append([]string{}, auth.Scopes...),
		ScopeSeparator:          separator,
		TokenParams:             cloneStringMap(auth.TokenParams),
		ExpirationBufferSeconds: buffer,
	}, nil
}

func transportBaseURL(transport *connectordefinitions.TransportSpec) string {
	if transport == nil {
		return ""
	}
	return strings.TrimSpace(transport.BaseURL)
}

func transportHeaders(transport *connectordefinitions.TransportSpec) map[string]string {
	if transport == nil || len(transport.Headers) == 0 {
		return nil
	}
	return cloneStringMap(transport.Headers)
}

func fieldKeys(fields []connectordefinitions.Field) []string {
	keys := make([]string, 0, len(fields))
	seen := map[string]struct{}{}
	for _, field := range fields {
		key := strings.TrimSpace(field.Key)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func hasCredentialField(fields []connectordefinitions.Field, key string) bool {
	key = strings.TrimSpace(key)
	for _, field := range fields {
		if strings.TrimSpace(field.Key) == key {
			return true
		}
	}
	return false
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

func mergeStringMaps(first map[string]string, second map[string]string) map[string]string {
	if len(first) == 0 {
		return cloneStringMap(second)
	}
	if len(second) == 0 {
		return cloneStringMap(first)
	}
	merged := cloneStringMap(first)
	for key, value := range second {
		merged[key] = value
	}
	return merged
}

func cloneProviderAPI(api *connectordefinitions.ProviderAPISpec) *connectordefinitions.ProviderAPISpec {
	if api == nil {
		return nil
	}
	cloned := *api
	cloned.References = append([]string(nil), api.References...)
	cloned.Families = append([]connectordefinitions.ProviderAPIFamilySpec(nil), api.Families...)
	return &cloned
}

func normalizeIdentifiers(label string, values []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			normalized := strings.TrimSpace(part)
			if normalized == "" {
				continue
			}
			if !identifierPattern.MatchString(normalized) {
				return nil, fmt.Errorf("%s entry %q must start with a lowercase letter and use lowercase letters, digits, underscores, or hyphens", label, normalized)
			}
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			out = append(out, normalized)
		}
	}
	return out, nil
}

func parseFreshnessExpectation(value string) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return defaultFreshnessExpectation, nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("parse freshness_expectation: %w", err)
	}
	if parsed < time.Minute {
		return 0, fmt.Errorf("freshness_expectation must be at least 1m")
	}
	return parsed, nil
}

func familiesForRequest(request normalizedRequest) []familyData {
	families := make([]familyData, 0, len(request.AssetSchemas)+len(request.FindingSchemas)+1)
	for _, schema := range request.AssetSchemas {
		name := "asset_" + schema
		families = append(families, familyData{
			Name:                  name,
			Schema:                schema,
			Class:                 "asset",
			ConstName:             "family" + pascalIdentifier(name),
			ProjectorName:         lowerCamelIdentifier(request.SourceID + "_" + name + "_projections"),
			Path:                  "/assets/" + schema,
			URNKind:               "runtime_asset_" + schema,
			EventKind:             request.SourceID + "." + name,
			SchemaRef:             request.SourceID + "/" + name + "/v1",
			RequiredAttributes:    []string{"tenant_id", "source_event_id", "resource_urn", "resource_type", "resource_id"},
			RequiredPayloadFields: []string{"id"},
		})
	}
	for _, schema := range request.FindingSchemas {
		name := "finding_" + schema
		families = append(families, familyData{
			Name:                  name,
			Schema:                schema,
			Class:                 "finding",
			ConstName:             "family" + pascalIdentifier(name),
			ProjectorName:         lowerCamelIdentifier(request.SourceID + "_" + name + "_projections"),
			Path:                  "/findings/" + schema,
			URNKind:               "runtime_finding_" + schema,
			EventKind:             request.SourceID + "." + name,
			SchemaRef:             request.SourceID + "/" + name + "/v1",
			RequiredAttributes:    []string{"tenant_id", "source_event_id", "finding_id", "resource_urn", "severity", "status"},
			RequiredPayloadFields: []string{"id"},
		})
	}
	name := "evidence_cas_reference"
	families = append(families, familyData{
		Name:                  name,
		Schema:                "evidence_cas_reference",
		Class:                 "evidence_cas_reference",
		ConstName:             "family" + pascalIdentifier(name),
		ProjectorName:         lowerCamelIdentifier(request.SourceID + "_" + name + "_projections"),
		Path:                  "/evidence-cas/references",
		URNKind:               "runtime_evidence",
		EventKind:             request.SourceID + "." + name,
		SchemaRef:             request.SourceID + "/" + name + "/v1",
		RequiredAttributes:    []string{"tenant_id", "source_event_id", "evidence_id", "evidence_type", "evidence_cas_uri", "evidence_cas_digest"},
		RequiredPayloadFields: []string{"uri", "digest"},
	})
	return families
}

func familiesForDefinition(request normalizedRequest, definition connectordefinitions.Definition) ([]familyData, error) {
	families := make([]familyData, 0, len(definition.ResourceFamilies))
	for _, resource := range definition.ResourceFamilies {
		class, err := executableProjectionClass(resource)
		if err != nil {
			return nil, err
		}
		name := strings.TrimSpace(resource.ID)
		eventKind := strings.TrimSpace(resource.Event.Kind)
		if eventKind == "" {
			eventKind = request.SourceID + "." + name
		}
		schemaRef := strings.TrimSpace(resource.Event.SchemaRef)
		if schemaRef == "" {
			schemaRef = request.SourceID + "/" + name + "/v1"
		}
		urnKind := strings.TrimSpace(resource.Event.URNKind)
		if urnKind == "" {
			urnKind = "runtime_" + name
		}
		requiredAttributes := resource.Event.RequiredAttributes
		if len(requiredAttributes) == 0 {
			requiredAttributes = requiredAttributesForClass(class)
		}
		requiredPayloadFields := resource.Event.RequiredPayloadFields
		if len(requiredPayloadFields) == 0 {
			requiredPayloadFields = []string{firstNonEmptyString(resource.IDField, "id")}
		}
		authModel := ""
		if resource.Config != nil {
			authModel = strings.TrimSpace(resource.Config.AuthModel)
		}
		if authModel != "" {
			var err error
			authModel, err = executableAuthModel(authModel)
			if err != nil {
				return nil, err
			}
		}
		families = append(families, familyData{
			Name:                  name,
			Schema:                schemaNameFromRef(schemaRef, name),
			Class:                 class,
			ConstName:             "family" + pascalIdentifier(name),
			ProjectorName:         lowerCamelIdentifier(request.SourceID + "_" + name + "_projections"),
			Path:                  resource.Path,
			Method:                methodForResource(resource),
			AuthModel:             authModel,
			RecordSelector:        strings.TrimSpace(resource.RecordSelector),
			URNKind:               urnKind,
			EventKind:             eventKind,
			SchemaRef:             schemaRef,
			IDKeys:                idKeysForResource(resource),
			ListKeys:              listKeysForResource(resource),
			Singleton:             singletonForResource(resource),
			CursorParam:           cursorParamForResource(resource),
			NextCursorKeys:        nextCursorKeysForResource(resource),
			LinkHeader:            linkHeaderForResource(resource),
			PageSizeParams:        pageSizeParamsForResource(resource),
			DisablePageSize:       disablePageSizeForResource(resource),
			Config:                familyConfig(resource),
			RequiredAttributes:    requiredAttributes,
			RequiredPayloadFields: requiredPayloadFields,
			Projection:            resource.Projection,
		})
	}
	return families, nil
}

func methodForResource(resource connectordefinitions.ResourceFamily) string {
	method := strings.ToUpper(strings.TrimSpace(resource.Method))
	if method == "" || method == "GET" {
		return ""
	}
	return method
}

func idKeysForResource(resource connectordefinitions.ResourceFamily) []string {
	keys := []string{}
	for _, key := range []string{resource.IDField, resource.NameField} {
		if key = strings.TrimSpace(key); key != "" {
			keys = append(keys, key)
		}
	}
	return uniqueStrings(keys)
}

func familyConfig(resource connectordefinitions.ResourceFamily) familyConfigData {
	config := familyConfigData{
		StaticQuery: cloneStringMap(resource.StaticQuery),
		ConfigQuery: cloneStringMap(resource.ConfigQuery),
	}
	if resource.Config == nil {
		return config
	}
	config.StaticQuery = mergeStringMaps(config.StaticQuery, resource.Config.StaticQuery)
	config.ConfigQuery = mergeStringMaps(config.ConfigQuery, resource.Config.ConfigQuery)
	config.IdentityKeys = append([]string(nil), resource.Config.IdentityKeys...)
	return config
}

func listKeysForResource(resource connectordefinitions.ResourceFamily) []string {
	keys := []string{}
	if key := strings.TrimSpace(resource.ListKey); key != "" {
		keys = append(keys, key)
	}
	selector := strings.TrimSpace(resource.RecordSelector)
	if strings.HasPrefix(selector, "$.") && strings.HasSuffix(selector, "[*]") {
		key := strings.TrimSuffix(strings.TrimPrefix(selector, "$."), "[*]")
		key = strings.Trim(strings.TrimSpace(key), ".")
		if key != "" {
			keys = append(keys, key)
		}
	}
	return uniqueStrings(keys)
}

func cursorParamForResource(resource connectordefinitions.ResourceFamily) string {
	if resource.Pagination == nil {
		return ""
	}
	return strings.TrimSpace(resource.Pagination.CursorParam)
}

func nextCursorKeysForResource(resource connectordefinitions.ResourceFamily) []string {
	if resource.Pagination == nil {
		return nil
	}
	if strings.TrimSpace(resource.Pagination.Type) == "next_url" {
		key := cursorJSONPathKey(resource.Pagination.NextURLJSONPath)
		if key == "" {
			key = "nextLink"
		}
		return []string{key}
	}
	key := cursorJSONPathKey(resource.Pagination.CursorJSONPath)
	if key == "" {
		return nil
	}
	return []string{key}
}

func cursorJSONPathKey(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "$" {
		return ""
	}
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, ".")
	if path == "" || strings.ContainsAny(path, "[]*") {
		return ""
	}
	return path
}

func linkHeaderForResource(resource connectordefinitions.ResourceFamily) string {
	if resource.Pagination == nil || strings.TrimSpace(resource.Pagination.Type) != "link" {
		return ""
	}
	return firstNonEmptyString(resource.Pagination.LinkHeader, "Link")
}

func pageSizeParamsForResource(resource connectordefinitions.ResourceFamily) []string {
	if resource.Pagination == nil {
		return nil
	}
	params := []string{}
	if param := strings.TrimSpace(resource.Pagination.PageSizeParam); param != "" {
		params = append(params, param)
	}
	if param := strings.TrimSpace(resource.Pagination.LimitParam); param != "" {
		params = append(params, param)
	}
	return uniqueStrings(params)
}

func disablePageSizeForResource(resource connectordefinitions.ResourceFamily) bool {
	if resource.Read != nil && resource.Read.DisablePageSize {
		return true
	}
	return resource.Pagination != nil && resource.Pagination.DisablePageSize
}

func singletonForResource(resource connectordefinitions.ResourceFamily) bool {
	if resource.Singleton {
		return true
	}
	return resource.Read != nil && resource.Read.Singleton
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func executableProjectionClass(resource connectordefinitions.ResourceFamily) (string, error) {
	template := ""
	if resource.Projection != nil {
		template = strings.TrimSpace(resource.Projection.Template)
	}
	if template == "" {
		return "", fmt.Errorf("%w: family %q needs a projection template before sourcegen can emit executable code", errUnsupportedDefinition, resource.ID)
	}
	switch template {
	case "asset", "cloud_resource", "endpoint_device", "repository":
		return "asset", nil
	case "finding", "vulnerability":
		return "finding", nil
	case "secret":
		return "secret", nil
	case "policy", "compliance_control":
		return "policy", nil
	case "deployment":
		return "deployment", nil
	case "alert":
		return "alert", nil
	case "identity_user", "identity_group", "group_membership", "audit_event", "evidence_cas_reference":
		return template, nil
	default:
		return "", fmt.Errorf("%w: projection template %q is not executable by sourcegen yet", errUnsupportedDefinition, template)
	}
}

func requiredAttributesForClass(class string) []string {
	switch class {
	case "finding":
		return []string{"tenant_id", "source_event_id", "finding_id", "resource_urn", "severity", "status"}
	case "identity_user":
		return []string{"tenant_id", "source_event_id", "user_id"}
	case "identity_group":
		return []string{"tenant_id", "source_event_id", "group_id"}
	case "group_membership":
		return []string{"tenant_id", "source_event_id", "group_id", "member_id"}
	case "audit_event":
		return []string{"tenant_id", "source_event_id", "event_type", "actor_id"}
	case "evidence_cas_reference":
		return []string{"tenant_id", "source_event_id", "evidence_id", "evidence_type", "evidence_cas_uri", "evidence_cas_digest"}
	case "secret":
		return []string{"tenant_id", "source_event_id", "secret_id", "secret_name"}
	case "policy":
		return []string{"tenant_id", "source_event_id", "policy_id", "policy_name"}
	case "deployment":
		return []string{"tenant_id", "source_event_id", "deployment_id", "deployment_name"}
	case "alert":
		return []string{"tenant_id", "source_event_id", "alert_id", "alert_severity"}
	default:
		return []string{"tenant_id", "source_event_id", "resource_urn", "resource_type", "resource_id"}
	}
}

func schemaNameFromRef(schemaRef string, fallback string) string {
	parts := strings.Split(strings.Trim(schemaRef, "/"), "/")
	if len(parts) >= 2 && strings.TrimSpace(parts[len(parts)-2]) != "" {
		return strings.TrimSpace(parts[len(parts)-2])
	}
	return fallback
}

func validateGeneratedFamilies(families []familyData) error {
	seen := map[string]string{}
	for _, family := range families {
		for label, value := range map[string]string{
			"const":     family.ConstName,
			"projector": family.ProjectorName,
			"event":     family.EventKind,
			"schema":    family.SchemaRef,
		} {
			key := label + ":" + value
			if existing := seen[key]; existing != "" {
				return fmt.Errorf("%w: %s %q for %s and %s", errGeneratedNameCollision, label, value, existing, family.Name)
			}
			seen[key] = family.Name
		}
	}
	return nil
}

func renderFiles(request normalizedRequest) ([]generatedFile, error) {
	sourceRoot := filepath.Join(request.OutputDir, "sources", request.SourceID)
	files := []generatedFile{
		{Path: filepath.Join(sourceRoot, "catalog.yaml"), Content: renderCatalog(request)},
		{Path: filepath.Join(sourceRoot, "deploy.yaml"), Content: renderDeploy(request)},
		{Path: filepath.Join(sourceRoot, "source.go"), Content: renderSourceGo(request)},
		{Path: filepath.Join(sourceRoot, "fixture.go"), Content: renderFixtureGo(request)},
		{Path: filepath.Join(sourceRoot, "source_test.go"), Content: renderSourceTestGo(request)},
		{Path: filepath.Join(sourceRoot, "source_health_receipt.json"), Content: renderSourceHealthReceipt(request)},
		{Path: filepath.Join(sourceRoot, "SOURCE_RUNTIME.md"), Content: renderRuntimeDocs(request)},
		{Path: filepath.Join(sourceRoot, "PR_BODY.md"), Content: renderPRBody(request)},
		{Path: filepath.Join(request.OutputDir, "internal", "sourceprojection", request.SourceID+".go"), Content: renderProjectionGo(request)},
		{Path: filepath.Join(request.OutputDir, "internal", "sourceprojection", request.SourceID+"_test.go"), Content: renderProjectionTestGo(request)},
	}
	for _, family := range request.Families {
		files = append(files,
			generatedFile{Path: filepath.Join(sourceRoot, "testdata", "discover_"+family.Name+".json"), Content: renderDiscoverFixture(request, family)},
			generatedFile{Path: filepath.Join(sourceRoot, "testdata", "read_"+family.Name+".json"), Content: renderReadFixture(request, family)},
		)
	}
	for i := range files {
		if strings.HasSuffix(files[i].Path, ".go") {
			formatted, err := format.Source([]byte(files[i].Content))
			if err != nil {
				return nil, fmt.Errorf("format %s: %w", files[i].Path, err)
			}
			files[i].Content = string(formatted)
		}
	}
	return files, nil
}

func renderCatalog(request normalizedRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "id: %s\n", request.SourceID)
	fmt.Fprintf(&b, "name: %s\n", yamlString(request.Name))
	fmt.Fprintf(&b, "description: %s\n", yamlString(request.Description))
	if request.ProviderAPI != nil {
		renderProviderAPI(&b, request.ProviderAPI)
	}
	fmt.Fprintf(&b, "emitted_kinds:\n")
	for _, family := range request.Families {
		fmt.Fprintf(&b, "  - %s\n", family.EventKind)
	}
	fmt.Fprintf(&b, "runtime_families:\n")
	for _, family := range request.Families {
		fmt.Fprintf(&b, "  - %s\n", family.Name)
	}
	fmt.Fprintf(&b, "kind_lifecycle:\n")
	for _, family := range request.Families {
		fmt.Fprintf(&b, "  - kind: %s\n", family.EventKind)
		fmt.Fprintf(&b, "    status: active\n")
	}
	fmt.Fprintf(&b, "coverage_contract:\n")
	fmt.Fprintf(&b, "  owner_domain: source_runtime\n")
	fmt.Fprintf(&b, "  authority_domain: %s\n", request.SourceID)
	fmt.Fprintf(&b, "  dimensions:\n")
	for _, family := range request.Families {
		dimensionType := coverageDimensionType(family.Class)
		fmt.Fprintf(&b, "    - id: %s\n", family.Name)
		fmt.Fprintf(&b, "      type: %s\n", dimensionType)
		fmt.Fprintf(&b, "      title: %s\n", yamlString(titleFromID(family.Name)))
		fmt.Fprintf(&b, "      families: [%s]\n", family.Name)
		fmt.Fprintf(&b, "      support: partial\n")
		fmt.Fprintf(&b, "      high_value: true\n")
		fmt.Fprintf(&b, "      evidence_types: [%s]\n", strings.Join(coverageEvidenceTypes(dimensionType), ", "))
		fmt.Fprintf(&b, "      control_domains: [%s]\n", strings.Join(coverageControlDomains(dimensionType), ", "))
		fmt.Fprintf(&b, "      notes:\n")
		fmt.Fprintf(&b, "        - Generated Source Runtime SDK mapping requires provider field review before certification.\n")
	}
	fmt.Fprintf(&b, "    - id: incremental_sync\n")
	fmt.Fprintf(&b, "      type: incremental_sync\n")
	fmt.Fprintf(&b, "      title: Incremental cursor sync\n")
	fmt.Fprintf(&b, "      support: planned\n")
	fmt.Fprintf(&b, "      evidence_types: [source_sync_status]\n")
	fmt.Fprintf(&b, "      control_domains: [source_operations]\n")
	fmt.Fprintf(&b, "event_contracts:\n")
	for _, family := range request.Families {
		fmt.Fprintf(&b, "  - kind: %s\n", family.EventKind)
		fmt.Fprintf(&b, "    schema_ref: %s\n", family.SchemaRef)
		fmt.Fprintf(&b, "    required_attributes:\n")
		for _, attr := range family.RequiredAttributes {
			fmt.Fprintf(&b, "      - %s\n", attr)
		}
		fmt.Fprintf(&b, "    required_payload_fields:\n")
		for _, field := range family.RequiredPayloadFields {
			fmt.Fprintf(&b, "      - %s\n", field)
		}
	}
	return b.String()
}

func renderProviderAPI(b *strings.Builder, api *connectordefinitions.ProviderAPISpec) {
	fmt.Fprintf(b, "provider_api:\n")
	if strings.TrimSpace(api.Status) != "" {
		fmt.Fprintf(b, "  status: %s\n", yamlString(api.Status))
	}
	if strings.TrimSpace(api.Transport) != "" {
		fmt.Fprintf(b, "  transport: %s\n", yamlString(api.Transport))
	}
	if strings.TrimSpace(api.Auth) != "" {
		fmt.Fprintf(b, "  auth: %s\n", yamlString(api.Auth))
	}
	if strings.TrimSpace(api.BaseURL) != "" {
		fmt.Fprintf(b, "  base_url: %s\n", yamlString(api.BaseURL))
	}
	if strings.TrimSpace(api.Endpoint) != "" {
		fmt.Fprintf(b, "  endpoint: %s\n", yamlString(api.Endpoint))
	}
	if len(api.References) > 0 {
		fmt.Fprintf(b, "  references:\n")
		for _, ref := range api.References {
			if strings.TrimSpace(ref) != "" {
				fmt.Fprintf(b, "    - %s\n", yamlString(ref))
			}
		}
	}
	if len(api.Families) > 0 {
		fmt.Fprintf(b, "  families:\n")
		for _, family := range api.Families {
			if strings.TrimSpace(family.ID) == "" {
				continue
			}
			fmt.Fprintf(b, "    - id: %s\n", family.ID)
			if strings.TrimSpace(family.Method) != "" {
				fmt.Fprintf(b, "      method: %s\n", yamlString(family.Method))
			}
			if strings.TrimSpace(family.Path) != "" {
				fmt.Fprintf(b, "      path: %s\n", yamlString(family.Path))
			}
			if strings.TrimSpace(family.Operation) != "" {
				fmt.Fprintf(b, "      operation: %s\n", yamlString(family.Operation))
			}
		}
	}
}

func renderDeploy(request normalizedRequest) string {
	tokenEnv := request.EnvPrefix + "_TOKEN"
	if request.TokenConfigKey == "api_token" {
		tokenEnv = request.EnvPrefix + "_API_TOKEN"
	}
	authConfigKeys := deployAuthConfigKeys(request)
	var b strings.Builder
	fmt.Fprintf(&b, "sourceId: %s\n", request.SourceID)
	fmt.Fprintf(&b, "secretKeys:\n")
	secretKeys := []string{}
	if len(request.ConfigKeys) == 0 && strings.TrimSpace(request.BaseURLTemplate) == "" {
		secretKeys = append(secretKeys, request.EnvPrefix+"_BASE_URL")
	}
	for _, key := range request.ConfigKeys {
		secretKeys = append(secretKeys, envNameForConfigKey(request, key))
	}
	for _, key := range authConfigKeys {
		secretKeys = append(secretKeys, deployAuthEnvName(request, key, tokenEnv))
	}
	for _, key := range uniqueStrings(secretKeys) {
		fmt.Fprintf(&b, "  - %s\n", key)
	}
	fmt.Fprintf(&b, "runtimes:\n")
	for _, family := range request.Families {
		fmt.Fprintf(&b, "  - localId: %s\n", strings.ReplaceAll(family.Name, "_", "-"))
		fmt.Fprintf(&b, "    config:\n")
		if len(request.ConfigKeys) == 0 && strings.TrimSpace(request.BaseURLTemplate) == "" {
			fmt.Fprintf(&b, "      base_url: env:%s_BASE_URL\n", request.EnvPrefix)
		}
		writtenConfigKeys := map[string]struct{}{}
		for _, key := range request.ConfigKeys {
			writtenConfigKeys[key] = struct{}{}
			fmt.Fprintf(&b, "      %s: env:%s\n", key, envNameForConfigKey(request, key))
		}
		fmt.Fprintf(&b, "      family: %s\n", family.Name)
		fmt.Fprintf(&b, "      failure_modes: %s\n", strings.Join(request.FailureModes, ","))
		fmt.Fprintf(&b, "      health_path: %s\n", request.HealthPath)
		fmt.Fprintf(&b, "      expected_cadence_seconds: %q\n", strconv.FormatInt(int64(request.FreshnessDuration.Seconds()), 10))
		fmt.Fprintf(&b, "      stale_after_seconds: %q\n", strconv.FormatInt(int64(request.FreshnessDuration.Seconds()), 10))
		fmt.Fprintf(&b, "      per_page: %q\n", "100")
		for _, key := range authConfigKeys {
			if _, ok := writtenConfigKeys[key]; ok {
				continue
			}
			writtenConfigKeys[key] = struct{}{}
			fmt.Fprintf(&b, "      %s: env:%s\n", key, deployAuthEnvName(request, key, tokenEnv))
		}
	}
	return b.String()
}

func deployAuthEnvName(request normalizedRequest, key string, tokenEnv string) string {
	if request.OAuth == nil && request.AuthModel != AuthModelAWSSigV4 && !isDuoHMACAuthModel(request.AuthModel) && key == request.TokenConfigKey {
		return tokenEnv
	}
	return envNameForConfigKey(request, key)
}

func coverageDimensionType(class string) string {
	switch strings.TrimSpace(class) {
	case "audit_event":
		return "audit_event"
	case "finding":
		return "remediation_state"
	case "policy":
		return "lifecycle_state"
	case "deployment":
		return "deployment_state"
	case "alert":
		return "alert_state"
	default:
		return "entity_family"
	}
}

func coverageEvidenceTypes(dimensionType string) []string {
	switch strings.TrimSpace(dimensionType) {
	case "alert_state":
		return []string{"security_monitoring"}
	case "audit_event":
		return []string{"logging_configuration"}
	case "deployment_state":
		return []string{"change_management"}
	case "lifecycle_state":
		return []string{"configuration_state"}
	case "remediation_state":
		return []string{"remediation_state"}
	default:
		return []string{"source_snapshot"}
	}
}

func coverageControlDomains(dimensionType string) []string {
	switch strings.TrimSpace(dimensionType) {
	case "alert_state":
		return []string{"logging_monitoring", "security_operations"}
	case "audit_event":
		return []string{"logging_monitoring"}
	case "deployment_state":
		return []string{"secure_delivery"}
	case "lifecycle_state":
		return []string{"security_operations"}
	case "remediation_state":
		return []string{"remediation"}
	default:
		return []string{"asset_inventory"}
	}
}

func deployAuthConfigKeys(request normalizedRequest) []string {
	keys := []string{}
	if request.OAuth != nil {
		keys = append(keys, request.CredentialKeys...)
	} else if request.AuthModel == AuthModelAWSSigV4 {
		keys = append(keys, request.CredentialKeys...)
		hasAccessKey := false
		hasSecretKey := false
		for _, key := range keys {
			switch strings.TrimSpace(key) {
			case "access_key", "client_id":
				hasAccessKey = true
			case "secret_key", "client_secret":
				hasSecretKey = true
			}
		}
		if !hasAccessKey {
			keys = append(keys, "access_key")
		}
		if !hasSecretKey {
			keys = append(keys, "secret_key")
		}
	} else if isDuoHMACAuthModel(request.AuthModel) {
		keys = append(keys, request.CredentialKeys...)
	} else {
		keys = append(keys, request.TokenConfigKey)
	}
	if usesDuoHMACAuth(request) {
		keys = append(keys, "client_id", "client_secret")
	}
	return uniqueStrings(keys)
}

func envNameForConfigKey(request normalizedRequest, key string) string {
	return request.EnvPrefix + "_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(strings.TrimSpace(key)))
}

func renderSourceGo(request normalizedRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "package %s\n\n", request.PackageName)
	fmt.Fprintf(&b, "import (\n")
	fmt.Fprintf(&b, "\t\"context\"\n")
	fmt.Fprintf(&b, "\t\"embed\"\n")
	fmt.Fprintf(&b, "\t\"fmt\"\n")
	fmt.Fprintf(&b, "\t\"strings\"\n")
	if request.OAuth != nil {
		fmt.Fprintf(&b, "\t\"time\"\n")
	}
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "\tcerebrov1 \"github.com/writer/cerebro/gen/cerebro/v1\"\n")
	fmt.Fprintf(&b, "\t\"github.com/writer/cerebro/internal/sourcecdk\"\n")
	if request.OAuth != nil {
		fmt.Fprintf(&b, "\t\"github.com/writer/cerebro/internal/sourcehttp\"\n")
	}
	fmt.Fprintf(&b, "\t\"github.com/writer/cerebro/sources/internal/jsonapi\"\n")
	fmt.Fprintf(&b, ")\n\n")
	fmt.Fprintf(&b, "//go:embed catalog.yaml\nvar catalogFS embed.FS\n\n")
	fmt.Fprintf(&b, "const (\n")
	fmt.Fprintf(&b, "\tsourceID = %s\n", strconv.Quote(request.SourceID))
	fmt.Fprintf(&b, "\tdefaultFamily = %s\n", request.Families[0].ConstName)
	fmt.Fprintf(&b, "\tdefaultHealthPath = %s\n", strconv.Quote(request.HealthPath))
	fmt.Fprintf(&b, "\tdefaultBaseURLTemplate = %s\n", strconv.Quote(request.BaseURLTemplate))
	fmt.Fprintf(&b, "\ttokenHeader = %s\n", strconv.Quote(request.TokenHeader))
	fmt.Fprintf(&b, "\ttokenScheme = %s\n", strconv.Quote(request.TokenScheme))
	if request.OAuth != nil {
		fmt.Fprintf(&b, "\toauthTokenURLTemplate = %s // #nosec G101 -- token endpoint URL template, not credential material.\n", strconv.Quote(request.OAuth.TokenURLTemplate))
		fmt.Fprintf(&b, "\toauthScopeSeparator = %s\n", strconv.Quote(request.OAuth.ScopeSeparator))
		fmt.Fprintf(&b, "\toauthTokenExpirationBuffer = %d * time.Second\n", request.OAuth.ExpirationBufferSeconds)
	}
	for _, family := range request.Families {
		fmt.Fprintf(&b, "\t%s = %s\n", family.ConstName, strconv.Quote(family.Name))
	}
	fmt.Fprintf(&b, ")\n\n")
	templateKeys := uniqueStrings(append(append([]string{}, request.ConfigKeys...), request.CredentialKeys...))
	templateKeys = append(templateKeys, extractTemplateKeys(request.BaseURLTemplate)...)
	templateKeys = uniqueStrings(templateKeys)
	fmt.Fprintf(&b, "var templateKeys = []string{%s}\n\n", quotedStrings(templateKeys))
	if request.OAuth != nil {
		fmt.Fprintf(&b, "var oauthScopes = []string{%s}\n\n", quotedStrings(request.OAuth.Scopes))
		fmt.Fprintf(&b, "var oauthTokenParams = map[string]string{%s}\n\n", renderedAttributeMap(request.OAuth.TokenParams))
		fmt.Fprintf(&b, "var oauthRuntimeConfigOptions = sourcehttp.ClientCredentialsRuntimeConfigOptions{\n\tSourceID: sourceID,\n\tDefaultBaseURLTemplate: defaultBaseURLTemplate,\n\tTemplateKeys: templateKeys,\n\tTokenURLTemplate: oauthTokenURLTemplate,\n\tScopes: oauthScopes,\n\tScopeSeparator: oauthScopeSeparator,\n\tTokenParams: oauthTokenParams,\n\tExpirationBuffer: oauthTokenExpirationBuffer,\n}\n\n")
	}
	fmt.Fprintf(&b, "type Source struct {\n\tinner *jsonapi.Source\n\tallowLoopback bool\n")
	if request.OAuth != nil {
		fmt.Fprintf(&b, "\ttokenCache sourcehttp.ClientCredentialsCache\n")
	}
	fmt.Fprintf(&b, "}\n\n")
	fmt.Fprintf(&b, "func New() (*Source, error) {\n")
	fmt.Fprintf(&b, "\tspec, err := loadSpec()\n\tif err != nil {\n\t\treturn nil, err\n\t}\n")
	fmt.Fprintf(&b, "\tinner, err := jsonapi.New(spec, jsonapi.Options{\n")
	fmt.Fprintf(&b, "\t\tSourceID: sourceID,\n\t\tDefaultFamily: defaultFamily,\n\t\tRequireTenantID: true,\n\t\tAuthModel: %s,\n\t\tTokenHeader: tokenHeader,\n\t\tTokenScheme: tokenScheme,\n", strconv.Quote(request.AuthModel))
	if strings.TrimSpace(request.AuthTokenURL) != "" {
		fmt.Fprintf(&b, "\t\tOAuthTokenURL: %s,\n", strconv.Quote(request.AuthTokenURL))
	}
	if len(request.OAuthScopes) != 0 {
		fmt.Fprintf(&b, "\t\tOAuthScopes: []string{%s},\n", quotedStrings(request.OAuthScopes))
	}
	if len(request.OAuthTokenParams) != 0 {
		fmt.Fprintf(&b, "\t\tOAuthTokenParams: map[string]string{%s},\n", renderedAttributeMap(request.OAuthTokenParams))
	}
	if strings.TrimSpace(request.OAuthTokenMethod) != "" {
		fmt.Fprintf(&b, "\t\tOAuthTokenRequestAuthMethod: %s,\n", strconv.Quote(request.OAuthTokenMethod))
	}
	if len(request.StaticHeaders) != 0 {
		fmt.Fprintf(&b, "\t\tStaticHeaders: map[string]string{%s},\n", renderedAttributeMap(request.StaticHeaders))
	}
	fmt.Fprintf(&b, "\t\tFamilies: []jsonapi.Family{\n")
	for _, family := range request.Families {
		fmt.Fprintf(&b, "\t\t\t{\n")
		fmt.Fprintf(&b, "\t\t\t\tName: %s,\n", family.ConstName)
		fmt.Fprintf(&b, "\t\t\t\tPath: %s,\n", strconv.Quote(family.Path))
		fmt.Fprintf(&b, "\t\t\t\tURNKind: %s,\n", strconv.Quote(family.URNKind))
		fmt.Fprintf(&b, "\t\t\t\tIDKeys: []string{%s},\n", quotedStrings(idKeysForFamily(family)))
		if strings.TrimSpace(family.CursorParam) != "" {
			fmt.Fprintf(&b, "\t\t\t\tCursorParam: %s,\n", strconv.Quote(family.CursorParam))
		}
		if len(family.NextCursorKeys) != 0 {
			fmt.Fprintf(&b, "\t\t\t\tNextCursorKeys: []string{%s},\n", quotedStrings(family.NextCursorKeys))
		}
		if strings.TrimSpace(family.LinkHeader) != "" {
			fmt.Fprintf(&b, "\t\t\t\tLinkHeader: %s,\n", strconv.Quote(family.LinkHeader))
		}
		if len(family.PageSizeParams) != 0 {
			fmt.Fprintf(&b, "\t\t\t\tPageSizeParams: []string{%s},\n", quotedStrings(family.PageSizeParams))
		}
		if family.DisablePageSize {
			fmt.Fprintf(&b, "\t\t\t\tDisablePageSize: true,\n")
		}
		if len(family.ListKeys) != 0 {
			fmt.Fprintf(&b, "\t\t\t\tListKeys: []string{%s},\n", quotedStrings(family.ListKeys))
		}
		if family.Singleton {
			fmt.Fprintf(&b, "\t\t\t\tSingleton: true,\n")
		}
		fmt.Fprintf(&b, "\t\t\t\tTimestampKeys: []string{%s},\n", quotedStrings([]string{"observed_at", "updated_at", "last_seen_at", "created_at"}))
		fmt.Fprintf(&b, "\t\t\t\tAttributes: map[string]string{%s},\n", renderedAttributeMap(attributePathsForFamily(family)))
		fmt.Fprintf(&b, "\t\t\t\tStaticAttributes: map[string]string{%s},\n", renderedAttributeMap(staticAttributesForFamily(request, family)))
		if strings.TrimSpace(family.Method) != "" || strings.TrimSpace(family.AuthModel) != "" || len(family.Config.StaticQuery) != 0 || len(family.Config.ConfigQuery) != 0 || len(family.Config.IdentityKeys) != 0 {
			fmt.Fprintf(&b, "\t\t\t\tConfig: jsonapi.FamilyConfig{\n")
			if strings.TrimSpace(family.Method) != "" {
				fmt.Fprintf(&b, "\t\t\t\t\tMethod: %s,\n", strconv.Quote(family.Method))
			}
			if strings.TrimSpace(family.AuthModel) != "" {
				fmt.Fprintf(&b, "\t\t\t\t\tAuthModel: %s,\n", strconv.Quote(family.AuthModel))
			}
			if len(family.Config.StaticQuery) != 0 {
				fmt.Fprintf(&b, "\t\t\t\t\tStaticQuery: map[string]string{%s},\n", renderedAttributeMap(family.Config.StaticQuery))
			}
			if len(family.Config.ConfigQuery) != 0 {
				fmt.Fprintf(&b, "\t\t\t\t\tConfigQuery: map[string]string{%s},\n", renderedAttributeMap(family.Config.ConfigQuery))
			}
			if len(family.Config.IdentityKeys) != 0 {
				fmt.Fprintf(&b, "\t\t\t\t\tIdentityKeys: []string{%s},\n", quotedStrings(family.Config.IdentityKeys))
			}
			fmt.Fprintf(&b, "\t\t\t\t},\n")
		}
		fmt.Fprintf(&b, "\t\t\t},\n")
	}
	fmt.Fprintf(&b, "\t\t},\n\t})\n")
	fmt.Fprintf(&b, "\tif err != nil {\n\t\treturn nil, err\n\t}\n")
	fmt.Fprintf(&b, "\treturn &Source{inner: inner}, nil\n}\n\n")
	fmt.Fprintf(&b, "func (s *Source) Spec() *cerebrov1.SourceSpec {\n\tif s == nil || s.inner == nil {\n\t\treturn nil\n\t}\n\treturn s.inner.Spec()\n}\n\n")
	fmt.Fprintf(&b, "func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {\n\truntimeCfg, err := s.runtimeConfig(ctx, cfg)\n\tif err != nil {\n\t\treturn err\n\t}\n\tif err := s.checkHealth(ctx, runtimeCfg); err != nil {\n\t\treturn err\n\t}\n\treturn s.inner.Check(ctx, runtimeCfg)\n}\n\n")
	fmt.Fprintf(&b, "func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {\n\truntimeCfg, err := s.runtimeConfig(ctx, cfg)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\treturn s.inner.Discover(ctx, runtimeCfg)\n}\n\n")
	fmt.Fprintf(&b, "func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {\n\truntimeCfg, err := s.runtimeConfig(ctx, cfg)\n\tif err != nil {\n\t\treturn sourcecdk.Pull{}, err\n\t}\n\treturn s.inner.Read(ctx, runtimeCfg, cursor)\n}\n\n")
	if request.OAuth != nil {
		fmt.Fprintf(&b, "func (s *Source) runtimeConfig(ctx context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {\n\tif s == nil {\n\t\treturn sourcecdk.Config{}, fmt.Errorf(\"%%s source is required\", sourceID)\n\t}\n\toptions := oauthRuntimeConfigOptions\n\toptions.TokenCache = &s.tokenCache\n\toptions.AllowLoopback = s.allowLoopback\n\treturn sourcehttp.ResolveClientCredentialsRuntimeConfig(ctx, cfg, options)\n}\n\n")
	} else {
		// Non-OAuth sources delegate base-URL resolution to the shared CDK
		// helper so the body stays below the cross-source duplication threshold
		// (see tools/archtests/source_helper_duplication_test.go).
		fmt.Fprintf(&b, "func (s *Source) runtimeConfig(_ context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {\n\treturn sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)\n}\n\n")
	}
	fmt.Fprintf(&b, "func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {\n\tpath := firstNonEmpty(sourcecdk.ConfigValue(cfg, \"health_path\"), defaultHealthPath)\n\treturn s.inner.CheckPath(ctx, cfg, path, nil)\n}\n\n")
	fmt.Fprintf(&b, "func loadSpec() (*cerebrov1.SourceSpec, error) {\n\tspecBytes, err := catalogFS.ReadFile(\"catalog.yaml\")\n\tif err != nil {\n\t\treturn nil, fmt.Errorf(\"read catalog: %%w\", err)\n\t}\n\tspec, err := sourcecdk.LoadCatalog(specBytes)\n\tif err != nil {\n\t\treturn nil, fmt.Errorf(\"load catalog: %%w\", err)\n\t}\n\treturn spec, nil\n}\n\n")
	fmt.Fprintf(&b, "func firstNonEmpty(values ...string) string {\n\tfor _, value := range values {\n\t\tif strings.TrimSpace(value) != \"\" {\n\t\t\treturn strings.TrimSpace(value)\n\t\t}\n\t}\n\treturn \"\"\n}\n\n")
	fmt.Fprintf(&b, "func (s *Source) allowLoopbackForTest() {\n\tif s != nil && s.inner != nil {\n\t\ts.inner.AllowLoopbackBaseURL = true\n\t\ts.allowLoopback = true\n\t}\n}\n")
	return b.String()
}

func idKeysForFamily(family familyData) []string {
	base := append([]string{}, family.IDKeys...)
	switch family.Class {
	case "evidence_cas_reference":
		base = append(base, "evidence_id", "uri", "digest", "id")
	case "finding":
		base = append(base, "finding_id", "id", "resource_urn")
	case "identity_user":
		base = append(base, "user_id", "id", "email", "primary_email", "login")
	case "identity_group":
		base = append(base, "group_id", "id", "group_email", "email")
	case "group_membership":
		base = append(base, "membership_id", "id", "group_id", "member_id", "user_id", "email")
	case "audit_event":
		base = append(base, "event_id", "id", "uuid", "request_id")
	case "secret":
		base = append(base, "secret_id", "id", "name", "key", "sid")
	case "policy":
		base = append(base, "policy_id", "id", "name", "key", "control_id")
	case "deployment":
		base = append(base, "deployment_id", "id", "name", "url", "uid")
	case "alert":
		base = append(base, "alert_id", "id", "sid", "incident_id", "uuid")
	default:
		base = append(base, "id", "urn", "resource_urn", "name")
	}
	return uniqueStrings(base)
}

func attributePathsForFamily(family familyData) map[string]string {
	base := map[string]string{
		"tenant_id":                "tenant_id|metadata.tenant_id",
		"source_event_id":          "event_id|id|metadata.event_id",
		"observed_at":              "observed_at|updated_at|last_seen_at",
		"resource_urn":             "resource_urn|urn|metadata.resource_urn",
		"resource_type":            "resource_type|type|metadata.resource_type",
		"resource_id":              "resource_id|id|metadata.resource_id",
		"resource_name":            "name|display_name|hostname|metadata.resource_name",
		"evidence_cas_uri":         "evidence_cas.uri|evidence_cas_uri|uri",
		"evidence_cas_digest":      "evidence_cas.digest|evidence_cas_digest|digest",
		"evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root",
		"evidence_cas_commit_id":   "evidence_cas.commit_id|evidence_cas_commit_id|commit_id",
		"evidence_cas_ref_type":    "evidence_cas.ref_type|evidence_cas_ref_type|ref_type",
	}
	switch family.Class {
	case "finding":
		base["finding_id"] = "finding_id|id"
		base["severity"] = "severity"
		base["status"] = "status|state"
		base["title"] = "title|name|summary"
		base["description"] = "description|summary"
	case "identity_user":
		base["user_id"] = "user_id|id|uid"
		base["email"] = "email|primary_email|profile.email"
		base["primary_email"] = "primary_email|email|profile.email"
		base["login"] = "login|username|email|profile.login"
		base["display_name"] = "display_name|name|profile.display_name|profile.name"
		base["domain"] = "domain|tenant_domain|organization_domain"
		base["status"] = "status|state|lifecycle_state"
		base["created_at"] = "created_at|created|profile.created_at"
		base["last_login_at"] = "last_login_at|last_login|last_seen_at"
		base["department"] = "department|profile.department"
		base["job_title"] = "job_title|title|profile.title"
		base["manager"] = "manager|profile.manager"
	case "identity_group":
		base["group_id"] = "group_id|id"
		base["group_email"] = "group_email|email"
		base["group_name"] = "group_name|name|display_name"
		base["domain"] = "domain|tenant_domain|organization_domain"
		base["description"] = "description|summary"
	case "group_membership":
		base["group_id"] = "group_id|group.id|groupId"
		base["group_email"] = "group_email|group.email"
		base["group_name"] = "group_name|group.name"
		base["member_id"] = "member_id|member.id|user_id|user.id|id"
		base["member_user_id"] = "member_user_id|user_id|user.id|member.id"
		base["member_email"] = "member_email|user_email|email|member.email|user.email"
		base["member_name"] = "member_name|name|member.name|user.name"
		base["member_type"] = "member_type|type|member.type"
		base["role"] = "role|membership_role"
	case "audit_event":
		base["event_type"] = "event_type|event_name|action|type"
		base["actor_id"] = "actor_id|actor.id|actorId|user_id|user.id"
		base["actor_email"] = "actor_email|actor.email|email|user.email"
		base["actor_name"] = "actor_name|actor.name|user.name"
		base["resource_id"] = "resource_id|target_id|target.id|resource.id|object_id"
		base["resource_type"] = "resource_type|target_type|target.type|object_type"
		base["resource_name"] = "resource_name|target_name|target.name|resource.name|object_name"
		base["resource_email"] = "resource_email|target_email|target.email"
	case "evidence_cas_reference":
		base["evidence_id"] = "evidence_id|id|uri"
		base["evidence_type"] = "evidence_type|type"
		base["evidence_cas_uri"] = "uri|evidence_cas_uri|evidence_cas.uri"
		base["evidence_cas_digest"] = "digest|evidence_cas_digest|evidence_cas.digest"
		base["evidence_cas_manifest_version"] = "manifest_version|evidence_cas_manifest_version"
	case "secret":
		base["secret_id"] = "secret_id|id|key|sid|name"
		base["secret_name"] = "secret_name|name|display_name|label|title"
		base["secret_type"] = "secret_type|type|kind"
		base["secret_status"] = "secret_status|status|state"
		base["secret_rotation_enabled"] = "secret_rotation_enabled|rotation_enabled|auto_rotate"
		base["secret_last_rotated_at"] = "secret_last_rotated_at|last_rotated_at|last_rotated|rotated_at"
		base["secret_created_at"] = "created_at|created|date_created"
	case "policy":
		base["policy_id"] = "policy_id|id|control_id|key|sid"
		base["policy_name"] = "policy_name|name|display_name|title|label"
		base["policy_type"] = "policy_type|type|kind|category"
		base["policy_status"] = "policy_status|status|state|enabled"
		base["policy_description"] = "description|summary|body"
		base["policy_severity"] = "severity|risk|priority"
		base["policy_created_at"] = "created_at|created|date_created"
	case "deployment":
		base["deployment_id"] = "deployment_id|id|name|uid"
		base["deployment_name"] = "deployment_name|name|display_name|title|label"
		base["deployment_environment"] = "environment|env|stage|target"
		base["deployment_status"] = "status|state|ready"
		base["deployment_url"] = "url|deployment_url|endpoint|domain"
		base["deployment_commit_sha"] = "commit_sha|commit|sha|revision|git_sha"
		base["deployment_branch"] = "branch|ref|git_branch|head_branch"
		base["deployment_created_at"] = "created_at|created|date_created"
		base["deployment_updated_at"] = "updated_at|updated|last_modified"
	case "alert":
		base["alert_id"] = "alert_id|id|sid|incident_id|uuid"
		base["alert_name"] = "alert_name|name|title|summary|subject"
		base["alert_severity"] = "severity|priority|level|risk"
		base["alert_status"] = "status|state|resolved|acknowledged"
		base["alert_type"] = "alert_type|type|category|kind"
		base["alert_source"] = "source|alert_source|monitor|check"
		base["alert_fired_at"] = "fired_at|triggered_at|created_at|occurred_at|timestamp"
		base["alert_resolved_at"] = "resolved_at|closed_at|acknowledged_at"
		base["alert_description"] = "description|summary|message|body"
	}
	if family.Projection != nil {
		for key, value := range family.Projection.Fields {
			if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
				base[strings.TrimSpace(key)] = strings.TrimSpace(value)
			}
		}
	}
	return base
}

func staticAttributesForFamily(request normalizedRequest, family familyData) map[string]string {
	attrs := map[string]string{
		"source_system": request.SourceID,
		"record_class":  family.Class,
		"schema":        family.Schema,
	}
	if family.Class == "evidence_cas_reference" {
		attrs["evidence_type"] = "evidence_cas.artifact"
	}
	return attrs
}

func renderFixtureGo(request normalizedRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// Code generated by sourcegen; DO NOT EDIT.\n\n")
	fmt.Fprintf(&b, "package %s\n\n", request.PackageName)
	fmt.Fprintf(&b, "import (\n")
	fmt.Fprintf(&b, "\t\"context\"\n")
	fmt.Fprintf(&b, "\t\"embed\"\n")
	fmt.Fprintf(&b, "\t\"fmt\"\n")
	fmt.Fprintf(&b, "\t\"strings\"\n\n")
	fmt.Fprintf(&b, "\t\"github.com/writer/cerebro/internal/sourcecdk\"\n")
	fmt.Fprintf(&b, ")\n\n")
	fmt.Fprintf(&b, "//go:embed testdata/*.json\nvar fixtureFS embed.FS\n\n")
	fmt.Fprintf(&b, "// NewFixture constructs the deterministic %s source used by tests.\n", request.Name)
	fmt.Fprintf(&b, "func NewFixture() (sourcecdk.Source, error) {\n")
	fmt.Fprintf(&b, "\tcatalogBytes, err := catalogFS.ReadFile(\"catalog.yaml\")\n\tif err != nil {\n\t\treturn nil, fmt.Errorf(\"read catalog: %%w\", err)\n\t}\n")
	fmt.Fprintf(&b, "\tcatalog, err := sourcecdk.LoadSourceCatalog(catalogBytes)\n\tif err != nil {\n\t\treturn nil, fmt.Errorf(\"load catalog: %%w\", err)\n\t}\n")
	fmt.Fprintf(&b, "\tfamilies := []sourcecdk.FixtureFamily{}\n")
	fmt.Fprintf(&b, "\tfor _, family := range []string{%s} {\n", familyConstList(request.Families))
	fmt.Fprintf(&b, "\t\turns, err := sourcecdk.LoadFixtureURNs(fixtureFS, \"testdata/discover_\"+family+\".json\")\n\t\tif err != nil {\n\t\t\treturn nil, err\n\t\t}\n")
	fmt.Fprintf(&b, "\t\tevents, err := sourcecdk.LoadFixtureEventsWithContracts(fixtureFS, \"testdata/read_\"+family+\".json\", catalog.EventContracts)\n\t\tif err != nil {\n\t\t\treturn nil, err\n\t\t}\n")
	fmt.Fprintf(&b, "\t\tfamilies = append(families, sourcecdk.FixtureFamily{Name: family, URNs: urns, Events: events})\n\t}\n")
	fmt.Fprintf(&b, "\treturn sourcecdk.NewFixtureSource(sourcecdk.FixtureSourceOptions{\n")
	fmt.Fprintf(&b, "\t\tSpec:          catalog.Spec,\n\t\tContracts:     catalog.EventContracts,\n\t\tDefaultFamily: defaultFamily,\n\t\tCheck:         checkFixtureConfig,\n\t\tResolveFamily: resolveFixtureFamily,\n\t\tFamilies:      families,\n\t})\n")
	fmt.Fprintf(&b, "}\n\n")
	fmt.Fprintf(&b, "func checkFixtureConfig(_ context.Context, cfg sourcecdk.Config) error {\n\tif fixtureTenantID(cfg) == \"\" {\n\t\treturn fmt.Errorf(\"tenant_id is required\")\n\t}\n\treturn nil\n}\n\n")
	fmt.Fprintf(&b, "func resolveFixtureFamily(cfg sourcecdk.Config) (string, error) {\n\tif fixtureTenantID(cfg) == \"\" {\n\t\treturn \"\", fmt.Errorf(\"tenant_id is required\")\n\t}\n\tfamily := strings.TrimSpace(sourcecdk.ConfigValue(cfg, \"family\"))\n\tif family == \"\" {\n\t\treturn defaultFamily, nil\n\t}\n\treturn family, nil\n}\n\n")
	fmt.Fprintf(&b, "func fixtureTenantID(cfg sourcecdk.Config) string {\n\treturn strings.TrimSpace(sourcecdk.ConfigValue(cfg, \"tenant_id\"))\n}\n")
	return b.String()
}

func familyConstList(families []familyData) string {
	values := make([]string, 0, len(families))
	for _, family := range families {
		values = append(values, family.ConstName)
	}
	return strings.Join(values, ", ")
}

func renderSourceTestGo(request normalizedRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "package %s\n\n", request.PackageName)
	fmt.Fprintf(&b, "import (\n\t\"context\"\n")
	if usesDuoHMACAuth(request) {
		fmt.Fprintf(&b, "\t\"encoding/base64\"\n")
	}
	fmt.Fprintf(&b, "\t\"encoding/json\"\n\t\"net/http\"\n\t\"net/http/httptest\"\n\t\"strings\"\n\t\"testing\"\n\n\t\"github.com/writer/cerebro/internal/sourcecdk\"\n)\n\n")
	fmt.Fprintf(&b, "func TestSourceCheckAndRead(t *testing.T) {\n")
	fmt.Fprintf(&b, "\tsource, err := New()\n\tif err != nil {\n\t\tt.Fatalf(\"New() error = %%v\", err)\n\t}\n\tsource.allowLoopbackForTest()\n")
	fmt.Fprintf(&b, "\tfamilyCases := []struct {\n\t\tname string\n\t\tpath string\n\t\tkind string\n\t\texpectedAttributes map[string]string\n")
	if usesDuoHMACAuth(request) {
		fmt.Fprintf(&b, "\t\tauthHeaderName string\n\t\tauthHeaderValue string\n\t\tduoSignatureLength int\n")
	}
	fmt.Fprintf(&b, "\t\tresponseBody json.RawMessage\n\t}{\n")
	for _, family := range request.Families {
		fmt.Fprintf(&b, "\t\t{\n")
		fmt.Fprintf(&b, "\t\t\tname: %s,\n", family.ConstName)
		fmt.Fprintf(&b, "\t\t\tpath: %s,\n", strconv.Quote(renderTestPath(family.Path)))
		fmt.Fprintf(&b, "\t\t\tkind: %s,\n", strconv.Quote(family.EventKind))
		fmt.Fprintf(&b, "\t\t\texpectedAttributes: map[string]string{%s},\n", renderedAttributeMap(sourceTestExpectedAttributes(request, family)))
		if usesDuoHMACAuth(request) {
			authHeaderName, authHeaderValue := sourceTestExpectedAuthHeader(request, family)
			fmt.Fprintf(&b, "\t\t\tauthHeaderName: %s,\n", strconv.Quote(authHeaderName))
			fmt.Fprintf(&b, "\t\t\tauthHeaderValue: %s,\n", strconv.Quote(authHeaderValue))
			fmt.Fprintf(&b, "\t\t\tduoSignatureLength: %d,\n", duoHMACSignatureLength(firstNonEmptyString(family.AuthModel, request.AuthModel)))
		}
		fmt.Fprintf(&b, "\t\t\tresponseBody: json.RawMessage(`%s`),\n", sourceTestResponseBody(request, family))
		fmt.Fprintf(&b, "\t\t},\n")
	}
	fmt.Fprintf(&b, "\t}\n")
	if request.OAuth != nil {
		fmt.Fprintf(&b, "\ttokenRequests := 0\n")
	}
	fmt.Fprintf(&b, "\tserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n")
	if request.OAuth != nil {
		fmt.Fprintf(&b, "\t\tif r.URL.Path == \"/oauth/token\" {\n\t\t\ttokenRequests++\n\t\t\tif r.Method != http.MethodPost {\n\t\t\t\thttp.Error(w, \"token method must be POST\", http.StatusMethodNotAllowed)\n\t\t\t\treturn\n\t\t\t}\n\t\t\tr.Body = http.MaxBytesReader(w, r.Body, 1<<20)\n\t\t\tif err := r.ParseForm(); err != nil {\n\t\t\t\thttp.Error(w, \"invalid token form\", http.StatusBadRequest)\n\t\t\t\treturn\n\t\t\t}\n\t\t\tif got := r.Form.Get(\"grant_type\"); got != \"client_credentials\" {\n\t\t\t\thttp.Error(w, \"grant_type must be client_credentials\", http.StatusBadRequest)\n\t\t\t\treturn\n\t\t\t}\n\t\t\tif got := r.Form.Get(\"client_id\"); got != \"client-id\" {\n\t\t\t\thttp.Error(w, \"client_id mismatch\", http.StatusUnauthorized)\n\t\t\t\treturn\n\t\t\t}\n\t\t\tif got := r.Form.Get(\"client_secret\"); got != \"client-secret\" {\n\t\t\t\thttp.Error(w, \"client_secret mismatch\", http.StatusUnauthorized)\n\t\t\t\treturn\n\t\t\t}\n\t\t\tw.Header().Set(\"Content-Type\", \"application/json\")\n\t\t\t_ = json.NewEncoder(w).Encode(map[string]any{\"access_token\": \"test-token\", \"expires_in\": 600})\n\t\t\treturn\n\t\t}\n")
	}
	fmt.Fprint(&b, generatedTestAuthAssertion(request))
	if request.HealthPath != request.DefaultPath {
		fmt.Fprintf(&b, "\t\tif r.URL.RequestURI() == %s {\n\t\t\tw.WriteHeader(http.StatusNoContent)\n\t\t\treturn\n\t\t}\n", strconv.Quote(renderTestPath(request.HealthPath)))
	}
	fmt.Fprintf(&b, "\t\tfor _, tc := range familyCases {\n\t\t\tif r.URL.Path != tc.path {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tw.Header().Set(\"Content-Type\", \"application/json\")\n\t\t\t_, _ = w.Write(tc.responseBody)\n\t\t\treturn\n\t\t}\n")
	fmt.Fprintf(&b, "\t\thttp.NotFound(w, r)\n")
	fmt.Fprintf(&b, "\t}))\n\tdefer server.Close()\n")
	// cfgValues must satisfy every config/credential key referenced by the
	// source's templates (base URL, health path, and family paths) so Check and
	// Read resolve cleanly. Keys are deduped to keep the map literal valid.
	fmt.Fprintf(&b, "\tcfgValues := map[string]string{\"tenant_id\": \"tenant\", \"base_url\": server.URL, \"family\": defaultFamily")
	emittedCfg := map[string]bool{"tenant_id": true, "base_url": true, "family": true}
	emitCfgValue := func(key, valueExpr string) {
		key = strings.TrimSpace(key)
		if key == "" || emittedCfg[key] {
			return
		}
		emittedCfg[key] = true
		fmt.Fprintf(&b, ", %s: %s", strconv.Quote(key), valueExpr)
	}
	if request.OAuth != nil {
		emitCfgValue("token_url", "server.URL + \"/oauth/token\"")
		emitCfgValue("client_id", strconv.Quote("client-id"))
		emitCfgValue("client_secret", strconv.Quote("client-secret"))
	} else if request.AuthModel == AuthModelAWSSigV4 {
		emitCfgValue("access_key", strconv.Quote("test-access-key"))
		emitCfgValue("secret_key", strconv.Quote("test-secret-key"))
	} else {
		if !isDuoHMACAuthModel(request.AuthModel) {
			emitCfgValue(request.TokenConfigKey, strconv.Quote("test-token"))
		}
	}
	if request.OAuth == nil && usesDuoHMACAuth(request) {
		emitCfgValue("client_id", strconv.Quote("DIXXXXXXXXXXXXXXXXXX"))
		emitCfgValue("client_secret", strconv.Quote("deadbeefsecret"))
	}
	for _, key := range request.CredentialKeys {
		emitCfgValue(key, strconv.Quote(testConfigValue(key)))
	}
	for _, key := range request.ConfigKeys {
		emitCfgValue(key, strconv.Quote(testConfigValue(key)))
	}
	for _, key := range extractTemplateKeys(request.BaseURLTemplate) {
		emitCfgValue(key, strconv.Quote(testConfigValue(key)))
	}
	for _, key := range extractTemplateKeys(request.HealthPath) {
		emitCfgValue(key, strconv.Quote(testConfigValue(key)))
	}
	for _, family := range request.Families {
		for _, key := range extractTemplateKeys(family.Path) {
			emitCfgValue(key, strconv.Quote(testConfigValue(key)))
		}
	}
	fmt.Fprintf(&b, "}\n\tcfg := sourcecdk.NewConfig(cfgValues)\n")
	fmt.Fprintf(&b, "\tif err := source.Check(context.Background(), cfg); err != nil {\n\t\tt.Fatalf(\"Check() error = %%v\", err)\n\t}\n")
	fmt.Fprintf(&b, "\tfor _, tc := range familyCases {\n\t\tt.Run(tc.name, func(t *testing.T) {\n\t\t\treadCfgValues := map[string]string{}\n\t\t\tfor key, value := range cfgValues {\n\t\t\t\treadCfgValues[key] = value\n\t\t\t}\n\t\t\treadCfgValues[\"family\"] = tc.name\n\t\t\tpull, err := source.Read(context.Background(), sourcecdk.NewConfig(readCfgValues), nil)\n\t\t\tif err != nil {\n\t\t\t\tt.Fatalf(\"Read() error = %%v\", err)\n\t\t\t}\n\t\t\tif len(pull.Events) != 1 {\n\t\t\t\tt.Fatalf(\"events = %%d, want 1\", len(pull.Events))\n\t\t\t}\n\t\t\tevent := pull.Events[0]\n\t\t\tif event.Kind != tc.kind {\n\t\t\t\tt.Fatalf(\"kind = %%q, want %%q\", event.Kind, tc.kind)\n\t\t\t}\n\t\t\tif strings.TrimSpace(event.Id) == \"\" {\n\t\t\t\tt.Fatalf(\"event id is empty: %%#v\", event)\n\t\t\t}\n\t\t\tfor attr, want := range tc.expectedAttributes {\n\t\t\t\tif got := event.Attributes[attr]; got != want {\n\t\t\t\t\tt.Fatalf(\"attribute %%s = %%q, want %%q\", attr, got, want)\n\t\t\t\t}\n\t\t\t}\n\t\t})\n\t}\n")
	if request.OAuth != nil {
		fmt.Fprintf(&b, "\tif tokenRequests < 1 || tokenRequests > len(familyCases) {\n\t\tt.Fatalf(\"token requests = %%d, want between 1 and %%d\", tokenRequests, len(familyCases))\n\t}\n")
	}
	fmt.Fprintf(&b, "}\n")
	fmt.Fprintf(&b, "\nfunc TestNewFixtureReplaysGeneratedFamilies(t *testing.T) {\n")
	fmt.Fprintf(&b, "\tsource, err := NewFixture()\n\tif err != nil {\n\t\tt.Fatalf(\"NewFixture() error = %%v\", err)\n\t}\n")
	fmt.Fprintf(&b, "\tfamilyConfigs := map[string]sourcecdk.Config{}\n")
	fmt.Fprintf(&b, "\tfor _, family := range []string{%s} {\n", familyConstList(request.Families))
	fmt.Fprintf(&b, "\t\tfamilyConfigs[family] = sourcecdk.NewConfig(map[string]string{\n\t\t\t\"family\": family,\n\t\t\t\"tenant_id\": \"tenant\",\n\t\t})\n\t}\n")
	fmt.Fprintf(&b, "\tsourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{\n\t\tSource: source,\n\t\tFamilyConfigs: familyConfigs,\n\t\tRequireDiscover: true,\n\t})\n}\n")
	return b.String()
}

func sourceTestResponseBody(request normalizedRequest, family familyData) string {
	record := sourceTestRecord(request, family)
	var response any
	switch {
	case family.Singleton:
		response = record
	case sourceTestUsesBareArray(family):
		response = []map[string]any{record}
	default:
		response = map[string]any{sourceTestListKey(family): []map[string]any{record}}
	}
	payload, _ := json.Marshal(response)
	return string(payload)
}

func sourceTestRecord(request normalizedRequest, family familyData) map[string]any {
	payload := map[string]any{
		"id":         fixtureRecordID(request, family),
		"updated_at": "2026-06-01T00:00:00Z",
	}
	for _, field := range family.RequiredPayloadFields {
		setFixturePayloadField(payload, field, fixturePayloadValue(request, field, family))
	}
	for _, key := range idKeysForFamily(family) {
		setFixturePayloadMappedField(payload, key, fixturePayloadValue(request, key, family))
	}
	paths := attributePathsForFamily(family)
	for _, attr := range family.RequiredAttributes {
		if path := strings.TrimSpace(paths[attr]); path != "" {
			value := fixtureAttributeValueForMapping(request, attr, path, family)
			if strings.TrimSpace(value) != "" {
				setFixturePayloadMappedField(payload, path, value)
			}
		}
	}
	if family.Projection != nil {
		for attr := range family.Projection.Fields {
			if path := strings.TrimSpace(paths[attr]); path != "" {
				value := fixtureAttributeValueForMapping(request, attr, path, family)
				if strings.TrimSpace(value) != "" {
					setFixturePayloadMappedField(payload, path, value)
				}
			}
		}
	}
	return payload
}

func sourceTestUsesBareArray(family familyData) bool {
	return strings.TrimSpace(family.RecordSelector) == "$[*]"
}

func sourceTestListKey(family familyData) string {
	if len(family.ListKeys) != 0 {
		return strings.TrimSpace(family.ListKeys[0])
	}
	selector := strings.TrimSpace(family.RecordSelector)
	if strings.HasPrefix(selector, "$.") && strings.HasSuffix(selector, "[*]") {
		key := strings.TrimSuffix(strings.TrimPrefix(selector, "$."), "[*]")
		key = strings.Trim(strings.TrimSpace(key), ".")
		if key != "" {
			return key
		}
	}
	return "items"
}

func sourceTestExpectedAttributes(request normalizedRequest, family familyData) map[string]string {
	attributes := map[string]string{
		"external_id": fixturePayloadValue(request, firstNonEmptyString(familyPrimaryIDField(family), "id"), family),
	}
	paths := attributePathsForFamily(family)
	for _, attr := range family.RequiredAttributes {
		attr = strings.TrimSpace(attr)
		if attr == "" {
			continue
		}
		value := fixtureAttributeValue(request, attr, family)
		if path := strings.TrimSpace(paths[attr]); path != "" {
			value = fixtureAttributeValueForMapping(request, attr, path, family)
		}
		if strings.TrimSpace(value) != "" {
			attributes[attr] = value
		}
	}
	return attributes
}

func testConfigValue(key string) string {
	switch strings.TrimSpace(key) {
	case "domain":
		return "example.test"
	default:
		return "test-" + strings.TrimSpace(key)
	}
}

func generatedTestAuthHeader(request normalizedRequest) (string, string) {
	header := strings.TrimSpace(request.TokenHeader)
	if header == "" {
		header = "Authorization"
	}
	if !strings.EqualFold(header, "Authorization") {
		return header, "test-token"
	}
	scheme := strings.TrimSpace(request.TokenScheme)
	if scheme == "" {
		return header, "test-token"
	}
	if strings.HasSuffix(scheme, "=") {
		return header, scheme + "test-token"
	}
	return header, scheme + " test-token"
}

func sourceTestExpectedAuthHeader(request normalizedRequest, family familyData) (string, string) {
	authModel := firstNonEmptyString(family.AuthModel, request.AuthModel)
	switch authModel {
	case AuthModelBearerToken:
		return "Authorization", "Bearer test-token"
	case AuthModelBasic:
		return "Authorization", "Basic test-token"
	case AuthModelOAuthAuthorizationCode, AuthModelOAuthClientCredentials, AuthModelJWT, AuthModelTwoStep:
		return "Authorization", "Bearer test-token"
	case AuthModelDuoHMAC, AuthModelDuoHMACV5:
		return "Authorization", ""
	case AuthModelAPIKey, AuthModelAPIToken:
		header := firstNonEmptyString(request.TokenHeader, "Authorization")
		scheme := firstNonEmptyString(request.TokenScheme, "Token")
		if strings.EqualFold(header, "Authorization") {
			return header, scheme + " test-token"
		}
		return header, "test-token"
	case AuthModelSignature:
		return "Authorization", firstNonEmptyString(request.TokenScheme, "Signature") + " test-token"
	default:
		return generatedTestAuthHeader(request)
	}
}

func generatedTestAuthAssertion(request normalizedRequest) string {
	if usesDuoHMACAuth(request) {
		defaultFamily := familyData{}
		if len(request.Families) != 0 {
			defaultFamily = request.Families[0]
		}
		authHeaderName, authHeaderValue := sourceTestExpectedAuthHeader(request, defaultFamily)
		return fmt.Sprintf("\t\twantSignatureLength := %d\n\t\texpectedAuthHeaderName := %s\n\t\texpectedAuthHeaderValue := %s\n\t\tfor _, tc := range familyCases {\n\t\t\tif r.URL.Path == tc.path {\n\t\t\t\twantSignatureLength = tc.duoSignatureLength\n\t\t\t\texpectedAuthHeaderName = tc.authHeaderName\n\t\t\t\texpectedAuthHeaderValue = tc.authHeaderValue\n\t\t\t\tbreak\n\t\t\t}\n\t\t}\n\t\tif wantSignatureLength == 0 {\n\t\t\tif r.Header.Get(expectedAuthHeaderName) != expectedAuthHeaderValue {\n\t\t\t\thttp.Error(w, expectedAuthHeaderName+\" mismatch\", http.StatusUnauthorized)\n\t\t\t\treturn\n\t\t\t}\n\t\t} else {\n\t\t\tdecodedAuth, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get(\"Authorization\"), \"Basic \"))\n\t\t\tif err != nil {\n\t\t\t\tt.Fatalf(\"decode Authorization: %%v\", err)\n\t\t\t}\n\t\t\tusername, signature, ok := strings.Cut(string(decodedAuth), \":\")\n\t\t\tif !ok {\n\t\t\t\tt.Fatalf(\"Authorization payload = %%q\", decodedAuth)\n\t\t\t}\n\t\t\tif username != \"DIXXXXXXXXXXXXXXXXXX\" {\n\t\t\t\tt.Fatalf(\"Duo integration key = %%q\", username)\n\t\t\t}\n\t\t\tif len(signature) != wantSignatureLength {\n\t\t\t\tt.Fatalf(\"Duo signature length = %%d, want %%d\", len(signature), wantSignatureLength)\n\t\t\t}\n\t\t}\n", duoHMACSignatureLength(firstNonEmptyString(defaultFamily.AuthModel, request.AuthModel)), strconv.Quote(authHeaderName), strconv.Quote(authHeaderValue))
	}
	return generatedSourceTestAuthAssertion(request)
}

func generatedSourceTestAuthAssertion(request normalizedRequest) string {
	header, value := generatedTestAuthHeader(request)
	if request.AuthModel != AuthModelAWSSigV4 {
		return fmt.Sprintf("\t\tif r.Header.Get(%s) != %s {\n\t\t\thttp.Error(w, %s+\" mismatch\", http.StatusUnauthorized)\n\t\t\treturn\n\t\t}\n", strconv.Quote(header), strconv.Quote(value), strconv.Quote(header))
	}
	return fmt.Sprintf("\t\tauth := r.Header.Get(%s)\n\t\tif !strings.HasPrefix(auth, %s) {\n\t\t\thttp.Error(w, %s+\" missing SigV4 prefix\", http.StatusUnauthorized)\n\t\t\treturn\n\t\t}\n\t\tif !strings.Contains(auth, %s) {\n\t\t\thttp.Error(w, %s+\" missing credential scope\", http.StatusUnauthorized)\n\t\t\treturn\n\t\t}\n", strconv.Quote(header), strconv.Quote("AWS4-HMAC-SHA256 "), strconv.Quote(header), strconv.Quote("Credential=test-access-key/"), strconv.Quote(header))
}

func usesDuoHMACAuth(request normalizedRequest) bool {
	if isDuoHMACAuthModel(request.AuthModel) {
		return true
	}
	for _, family := range request.Families {
		if isDuoHMACAuthModel(family.AuthModel) {
			return true
		}
	}
	return false
}

func duoHMACSignatureLength(authModel string) int {
	switch strings.TrimSpace(authModel) {
	case AuthModelDuoHMACV5:
		return 128
	case AuthModelDuoHMAC:
		return 40
	default:
		return 0
	}
}

func isDuoHMACAuthModel(authModel string) bool {
	switch strings.TrimSpace(authModel) {
	case AuthModelDuoHMAC, AuthModelDuoHMACV5:
		return true
	default:
		return false
	}
}

// renderTestPath substitutes ${config.key}/${credential.key}/${connection.key}
// placeholders with their testConfigValue so generated test assertions match the
// concrete request paths the runtime produces for sources with path parameters.
func renderTestPath(template string) string {
	rendered := template
	for _, key := range extractTemplateKeys(template) {
		value := testConfigValue(key)
		for _, prefix := range []string{"config", "credential", "connection"} {
			rendered = strings.ReplaceAll(rendered, "${"+prefix+"."+key+"}", value)
		}
	}
	return rendered
}

func renderDiscoverFixture(request normalizedRequest, family familyData) string {
	fixture := []string{fixtureURN(request, family)}
	payload, _ := json.MarshalIndent(fixture, "", "  ")
	return string(append(payload, '\n'))
}

func renderReadFixture(request normalizedRequest, family familyData) string {
	payload := fixturePayload(request, family)
	attributes := fixtureAttributes(request, family)
	for attr, path := range attributePathsForFamily(family) {
		value := fixtureAttributeValueForMapping(request, attr, path, family)
		if strings.TrimSpace(value) == "" {
			continue
		}
		setFixturePayloadMappedField(payload, path, value)
		attributes[attr] = value
	}
	for _, field := range family.RequiredPayloadFields {
		setFixturePayloadField(payload, field, fixturePayloadValue(request, field, family))
	}
	for _, attr := range family.RequiredAttributes {
		if strings.TrimSpace(attributes[attr]) == "" {
			attributes[attr] = fixtureAttributeValue(request, attr, family)
		}
	}
	events := []map[string]any{{
		"id":          fixtureEventID(request, family),
		"tenant_id":   "tenant",
		"source_id":   request.SourceID,
		"kind":        family.EventKind,
		"occurred_at": "2026-06-01T00:00:00Z",
		"schema_ref":  family.SchemaRef,
		"payload":     payload,
		"attributes":  attributes,
	}}
	rendered, _ := json.MarshalIndent(events, "", "  ")
	return string(append(rendered, '\n'))
}

func fixturePayload(request normalizedRequest, family familyData) map[string]any {
	recordID := fixtureRecordID(request, family)
	displayName := fixtureDisplayName(request, family)
	evidenceURI := fixtureEvidenceURI(request, family)
	payload := map[string]any{
		"api_method":          fixtureAPIMethod(family),
		"api_path":            family.Path,
		"family":              family.Name,
		"id":                  recordID,
		"name":                displayName,
		"record_class":        family.Class,
		"resource_urn":        fixtureURN(request, family),
		"resource_type":       fixtureResourceType(family),
		"resource_id":         recordID,
		"schema_ref":          family.SchemaRef,
		"source_id":           request.SourceID,
		"updated_at":          "2026-06-01T00:00:00Z",
		"evidence_cas_uri":    evidenceURI,
		"evidence_cas_digest": "sha256:test",
	}
	if family.RecordSelector != "" {
		payload["record_selector"] = family.RecordSelector
	}
	switch family.Class {
	case "finding":
		payload["finding_id"] = recordID
		payload["severity"] = "high"
		payload["status"] = "open"
		payload["title"] = displayName
		payload["description"] = displayName + " finding"
	case "identity_user":
		payload["user_id"] = recordID
		payload["email"] = fixtureEmail(request, "user")
		payload["display_name"] = displayName
	case "identity_group":
		payload["group_id"] = recordID
		payload["group_email"] = fixtureEmail(request, "group")
		payload["group_name"] = displayName
	case "group_membership":
		payload["group_id"] = fixtureRelatedRecordID(request, "groups")
		payload["member_id"] = fixtureRelatedRecordID(request, "users")
		payload["member_email"] = fixtureEmail(request, "user")
	case "audit_event":
		payload["event_id"] = recordID
		payload["event_type"] = request.SourceID + "." + family.Name + ".observed"
		payload["actor_id"] = fixtureRelatedRecordID(request, "users")
	case "evidence_cas_reference":
		payload["evidence_id"] = recordID
		payload["evidence_type"] = "evidence_cas.artifact"
		payload["uri"] = evidenceURI
		payload["digest"] = "sha256:test"
	case "secret":
		payload["secret_id"] = recordID
		payload["secret_name"] = displayName
	case "policy":
		payload["policy_id"] = recordID
		payload["policy_name"] = displayName
	case "deployment":
		payload["deployment_id"] = recordID
		payload["deployment_name"] = displayName
	case "alert":
		payload["alert_id"] = recordID
		payload["alert_name"] = displayName
		payload["alert_severity"] = "critical"
		payload["alert_status"] = "open"
	}
	return payload
}

func fixtureAttributes(request normalizedRequest, family familyData) map[string]string {
	recordID := fixtureRecordID(request, family)
	displayName := fixtureDisplayName(request, family)
	evidenceURI := fixtureEvidenceURI(request, family)
	attributes := map[string]string{
		"api_method":            fixtureAPIMethod(family),
		"api_path":              family.Path,
		"external_id":           recordID,
		"family":                family.Name,
		"provider":              request.SourceID,
		"record_class":          family.Class,
		"schema":                family.Schema,
		"source_provider":       request.SourceID,
		"source_system":         request.SourceID,
		"tenant_id":             "tenant",
		"source_event_id":       recordID,
		"resource_urn":          fixtureURN(request, family),
		"resource_type":         fixtureResourceType(family),
		"resource_id":           recordID,
		"resource_name":         displayName,
		"observed_at":           "2026-06-01T00:00:00Z",
		"evidence_cas_uri":      evidenceURI,
		"evidence_cas_digest":   "sha256:test",
		"evidence_cas_ref_type": "source_fixture",
	}
	if family.RecordSelector != "" {
		attributes["record_selector"] = family.RecordSelector
	}
	switch family.Class {
	case "finding":
		attributes["finding_id"] = recordID
		attributes["severity"] = "high"
		attributes["status"] = "open"
		attributes["title"] = displayName
	case "identity_user":
		attributes["user_id"] = recordID
		attributes["email"] = fixtureEmail(request, "user")
		attributes["display_name"] = displayName
	case "identity_group":
		attributes["group_id"] = recordID
		attributes["group_email"] = fixtureEmail(request, "group")
		attributes["group_name"] = displayName
	case "group_membership":
		attributes["group_id"] = fixtureRelatedRecordID(request, "groups")
		attributes["member_id"] = fixtureRelatedRecordID(request, "users")
		attributes["member_email"] = fixtureEmail(request, "user")
	case "audit_event":
		attributes["event_type"] = request.SourceID + "." + family.Name + ".observed"
		attributes["actor_id"] = fixtureRelatedRecordID(request, "users")
		attributes["actor_email"] = fixtureEmail(request, "user")
	case "evidence_cas_reference":
		attributes["evidence_id"] = recordID
		attributes["evidence_type"] = "evidence_cas.artifact"
		attributes["evidence_cas_uri"] = evidenceURI
		attributes["evidence_cas_digest"] = "sha256:test"
	case "secret":
		attributes["secret_id"] = recordID
		attributes["secret_name"] = displayName
	case "policy":
		attributes["policy_id"] = recordID
		attributes["policy_name"] = displayName
	case "deployment":
		attributes["deployment_id"] = recordID
		attributes["deployment_name"] = displayName
	case "alert":
		attributes["alert_id"] = recordID
		attributes["alert_name"] = displayName
		attributes["alert_severity"] = "critical"
		attributes["alert_status"] = "open"
	}
	return attributes
}

func fixtureURN(request normalizedRequest, family familyData) string {
	kind := strings.TrimSpace(family.URNKind)
	if kind == "" {
		kind = "runtime_" + family.Name
	}
	return "urn:cerebro:tenant:" + kind + ":" + fixtureRecordID(request, family)
}

func fixturePayloadValue(request normalizedRequest, field string, family familyData) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return fixtureRecordID(request, family)
	}
	switch field {
	case "uri", "evidence_cas_uri":
		return fixtureEvidenceURI(request, family)
	case "digest", "evidence_cas_digest":
		return "sha256:test"
	default:
		if field == familyPrimaryIDField(family) && fixtureIDFieldUsesRecordID(field) {
			return fixtureRecordID(request, family)
		}
		return fixtureAttributeValue(request, field, family)
	}
}

func familyPrimaryIDField(family familyData) string {
	if len(family.IDKeys) == 0 {
		return ""
	}
	return strings.TrimSpace(family.IDKeys[0])
}

func fixtureIDFieldUsesRecordID(field string) bool {
	switch strings.TrimSpace(field) {
	case "", "email", "primary_email", "login", "name", "display_name", "uri", "evidence_cas_uri", "digest", "evidence_cas_digest":
		return false
	default:
		return true
	}
}

func fixtureAttributeValue(request normalizedRequest, attr string, family familyData) string {
	attr = strings.TrimSpace(attr)
	recordID := fixtureRecordID(request, family)
	switch attr {
	case "tenant_id":
		return "tenant"
	case "api_method":
		return fixtureAPIMethod(family)
	case "api_path":
		return family.Path
	case "record_selector":
		return family.RecordSelector
	case "external_id", "id", "source_event_id":
		return recordID
	case "source_id", "source_provider", "source_system", "provider", "alert_source":
		return request.SourceID
	case "family":
		return family.Name
	case "record_class":
		return family.Class
	case "schema":
		return family.Schema
	case "resource_urn":
		return fixtureURN(request, family)
	case "resource_type":
		return fixtureResourceType(family)
	case "resource_id", "alert_id", "deployment_id", "evidence_id", "finding_id", "policy_id", "secret_id", "user_id":
		return recordID
	case "group_id":
		if family.Class == "group_membership" {
			return fixtureRelatedRecordID(request, "groups")
		}
		return recordID
	case "member_id", "member_user_id":
		return fixtureRelatedRecordID(request, "users")
	case "resource_name", "alert_name", "deployment_name", "display_name", "group_name", "member_name", "name", "policy_name", "secret_name", "title":
		return fixtureDisplayName(request, family)
	case "email", "primary_email", "login", "actor_email", "group_email", "member_email", "resource_email":
		return fixtureEmail(request, fixtureEmailLocalPart(attr))
	case "severity":
		return "high"
	case "alert_severity":
		return "critical"
	case "status", "alert_status", "deployment_status", "policy_status", "secret_status":
		return "open"
	case "description", "alert_description", "policy_description":
		return fixtureDisplayName(request, family) + " " + family.Class
	case "event_type":
		return request.SourceID + "." + family.Name + ".observed"
	case "actor_id":
		return fixtureRelatedRecordID(request, "users")
	case "evidence_cas_uri", "uri":
		return fixtureEvidenceURI(request, family)
	case "evidence_cas_digest", "digest":
		return "sha256:test"
	case "evidence_cas_ref_type":
		return "source_fixture"
	case "evidence_type":
		return "evidence_cas.artifact"
	case "secret_rotation_enabled":
		return "true"
	case "alert_type", "deployment_environment", "member_type", "policy_type", "secret_type":
		return fixtureResourceType(family)
	default:
		if strings.HasSuffix(attr, "_at") || attr == "timestamp" {
			return "2026-06-01T00:00:00Z"
		}
		return strings.ReplaceAll(firstNonEmptyString(attr, "value"), "_", "-") + "-" + recordID
	}
}

func fixtureAttributeValueForMapping(request normalizedRequest, attr string, path string, family familyData) string {
	if localPart, ok := fixtureEmailLocalPartForPayloadPath(path); ok {
		return fixtureEmail(request, firstNonEmptyString(localPart, attr))
	}
	if attr == "resource_type" {
		if value := fixtureLiteralResourceType(path); value != "" {
			return value
		}
	}
	return fixtureAttributeValue(request, attr, family)
}

func fixtureEmailLocalPartForPayloadPath(rawPath string) (string, bool) {
	for _, candidate := range fixturePayloadPathCandidates(rawPath) {
		parts := strings.Split(candidate, ".")
		if len(parts) == 0 {
			continue
		}
		field := strings.TrimSpace(parts[len(parts)-1])
		switch field {
		case "email":
			if len(parts) > 1 {
				switch parent := strings.TrimSpace(parts[len(parts)-2]); parent {
				case "actor", "group", "member", "resource", "user":
					return parent, true
				}
			}
			return "email", true
		case "primary_email", "login", "actor_email", "group_email", "member_email", "resource_email":
			return fixtureEmailLocalPart(field), true
		}
	}
	return "", false
}

func fixtureEmailLocalPart(field string) string {
	return strings.TrimPrefix(strings.TrimSuffix(field, "_email"), "actor_")
}

func fixtureLiteralResourceType(rawPath string) string {
	candidates := fixturePayloadPathCandidates(rawPath)
	if len(candidates) == 0 {
		return ""
	}
	candidate := candidates[0]
	switch candidate {
	case "resource_type", "type", "kind", "metadata.resource_type":
		return ""
	default:
		if strings.Contains(candidate, ".") {
			return ""
		}
		return candidate
	}
}

func fixtureRecordID(request normalizedRequest, family familyData) string {
	return "source-" + request.SourceID + "-" + family.Name + "-1"
}

func fixtureEventID(request normalizedRequest, family familyData) string {
	return "source-" + request.SourceID + "-" + family.Name + "-event-1"
}

func fixtureRelatedRecordID(request normalizedRequest, familyName string) string {
	return request.SourceID + "-" + familyName + "-1"
}

func fixtureDisplayName(request normalizedRequest, family familyData) string {
	return titleFromID(request.SourceID) + " " + titleFromID(family.Name) + " Fixture"
}

func fixtureEvidenceURI(request normalizedRequest, family familyData) string {
	return "cas://cases/" + request.SourceID + "/" + family.Name + "/" + fixtureRecordID(request, family)
}

func fixtureAPIMethod(family familyData) string {
	if method := strings.TrimSpace(family.Method); method != "" {
		return method
	}
	return "GET"
}

func fixtureResourceType(family familyData) string {
	return firstNonEmptyString(family.Schema, family.Name, family.Class)
}

func fixtureEmail(request normalizedRequest, localPart string) string {
	local := strings.Trim(strings.ReplaceAll(strings.ToLower(localPart), "_", "-"), "-")
	if local == "" {
		local = "user"
	}
	domain := strings.Trim(strings.ReplaceAll(strings.ToLower(request.SourceID), "_", "-"), "-")
	if domain == "" {
		domain = "source"
	}
	return local + "@" + domain + ".example.test"
}

func setFixturePayloadMappedField(payload map[string]any, rawPath string, value any) {
	for _, path := range fixturePayloadPathCandidates(rawPath) {
		if path == "" {
			continue
		}
		setFixturePayloadField(payload, path, value)
		return
	}
}

func fixturePayloadPathCandidates(rawPath string) []string {
	parts := strings.Split(rawPath, "|")
	candidates := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || strings.ContainsAny(part, "$[]*{} ") {
			continue
		}
		candidates = append(candidates, part)
	}
	return candidates
}

func setFixturePayloadField(payload map[string]any, rawPath string, value any) {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return
	}
	parts := strings.Split(path, ".")
	current := payload
	for index, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return
		}
		if index == len(parts)-1 {
			current[part] = value
			return
		}
		next, ok := current[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			current[part] = next
		}
		current = next
	}
}

func renderSourceHealthReceipt(request normalizedRequest) string {
	receipt := map[string]any{
		"receipt_kind":                "source_health.receipt",
		"source_id":                   request.SourceID,
		"source_type":                 request.SourceType,
		"auth_model":                  request.AuthModel,
		"health_endpoint":             healthEndpoint(request.SourceID),
		"adapter_health_path":         request.HealthPath,
		"expected_cadence_seconds":    int64(request.FreshnessDuration.Seconds()),
		"stale_after_seconds":         int64(request.FreshnessDuration.Seconds()),
		"failure_modes":               request.FailureModes,
		"evidence_cas_reference_kind": request.SourceID + ".evidence_cas_reference",
	}
	payload, _ := json.MarshalIndent(receipt, "", "  ")
	return string(append(payload, '\n'))
}

func renderRuntimeDocs(request normalizedRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", request.Name)
	fmt.Fprintf(&b, "Generated Source Runtime SDK scaffold for `%s`.\n\n", request.SourceID)
	fmt.Fprintf(&b, "## Runtime input\n\n")
	fmt.Fprintf(&b, "- Source type: `%s`\n", request.SourceType)
	fmt.Fprintf(&b, "- Auth model: `%s`\n", request.AuthModel)
	fmt.Fprintf(&b, "- Freshness expectation: `%s`\n", request.FreshnessExpectation)
	fmt.Fprintf(&b, "- Failure modes: `%s`\n\n", strings.Join(request.FailureModes, ","))
	fmt.Fprintf(&b, "## Runtime output\n\n")
	fmt.Fprintf(&b, "- Adapter package: `sources/%s`\n", request.SourceID)
	fmt.Fprintf(&b, "- Health endpoint: `%s`\n", healthEndpoint(request.SourceID))
	fmt.Fprintf(&b, "- Source health receipt: `sources/%s/source_health_receipt.json`\n", request.SourceID)
	fmt.Fprintf(&b, "- EvidenceCAS reference kind: `%s.evidence_cas_reference`\n\n", request.SourceID)
	fmt.Fprintf(&b, "## Families\n\n")
	for _, family := range request.Families {
		fmt.Fprintf(&b, "- `%s`, emits `%s`, reads `%s`\n", family.Name, family.EventKind, family.Path)
	}
	fmt.Fprintf(&b, "\n## Tests\n\n")
	fmt.Fprintf(&b, "- Fixture pairs: `sources/%s/testdata/discover_<family>.json` and `sources/%s/testdata/read_<family>.json` for every generated family\n", request.SourceID, request.SourceID)
	fmt.Fprintf(&b, "- `go test ./sources/%s ./internal/sourceprojection -count=1`\n", request.SourceID)
	fmt.Fprintf(&b, "- `make catalog-check`\n")
	return b.String()
}

func renderPRBody(request normalizedRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "- Adds the `%s` Source Runtime SDK scaffold.\n", request.SourceID)
	fmt.Fprintf(&b, "- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.\n\n")
	fmt.Fprintf(&b, "## Generated runtime contract\n\n")
	fmt.Fprintf(&b, "- Source type: `%s`\n", request.SourceType)
	fmt.Fprintf(&b, "- Auth model: `%s`\n", request.AuthModel)
	fmt.Fprintf(&b, "- Health endpoint: `%s`\n", healthEndpoint(request.SourceID))
	fmt.Fprintf(&b, "- Freshness: `%s`\n\n", request.FreshnessExpectation)
	fmt.Fprintf(&b, "## Tests\n\n")
	fmt.Fprintf(&b, "- Fixture pairs cover discover and read payloads for every generated family.\n")
	fmt.Fprintf(&b, "- `go test ./sources/%s ./internal/sourceprojection -count=1`\n", request.SourceID)
	fmt.Fprintf(&b, "- `make catalog-check`\n")
	return b.String()
}

func renderProjectionGo(request normalizedRequest) string {
	sourcePrefix := lowerCamelIdentifier(request.SourceID)
	var b strings.Builder
	fmt.Fprintf(&b, "package sourceprojection\n\n")
	fmt.Fprintf(&b, "import (\n")
	if projectionNeedsStrings(request.Families) {
		fmt.Fprintf(&b, "\t\"strings\"\n\n")
	}
	fmt.Fprintf(&b, "\tcerebrov1 \"github.com/writer/cerebro/gen/cerebro/v1\"\n")
	if projectionNeedsConnectordefinitions(request.Families) {
		fmt.Fprintf(&b, "\t\"github.com/writer/cerebro/internal/connectordefinitions\"\n")
	}
	fmt.Fprintf(&b, "\t\"github.com/writer/cerebro/internal/ports\"\n)\n\n")
	renderedProjectionResources := map[string]struct{}{}
	for _, family := range request.Families {
		if projectionFamilyNeedsAugmentation(family) {
			if _, ok := renderedProjectionResources[family.ProjectorName]; ok {
				continue
			}
			renderedProjectionResources[family.ProjectorName] = struct{}{}
			fmt.Fprintf(&b, "var %sProjectionResource = connectordefinitions.ResourceFamily{\n\tID: %s,\n\tProjection: &connectordefinitions.ProjectionSpec{\n", family.ProjectorName, strconv.Quote(family.Name))
			renderProjectionSpecLiteral(&b, family.Projection, "\t\t")
			fmt.Fprintf(&b, "\t},\n}\n\n")
		}
	}
	renderedProjectors := map[string]struct{}{}
	for _, family := range request.Families {
		if _, ok := renderedProjectors[family.ProjectorName]; ok {
			continue
		}
		renderedProjectors[family.ProjectorName] = struct{}{}
		switch family.Class {
		case "asset":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, sourcePrefix+"GenericAssetProjections")
			fmt.Fprintf(&b, "}\n\n")
		case "finding":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, sourcePrefix+"GenericFindingProjections")
			fmt.Fprintf(&b, "}\n\n")
		case "secret":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, sourcePrefix+"GenericSecretProjections")
			fmt.Fprintf(&b, "}\n\n")
		case "policy":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, sourcePrefix+"GenericPolicyProjections")
			fmt.Fprintf(&b, "}\n\n")
		case "deployment":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, sourcePrefix+"GenericDeploymentProjections")
			fmt.Fprintf(&b, "}\n\n")
		case "alert":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, sourcePrefix+"GenericAlertProjections")
			fmt.Fprintf(&b, "}\n\n")
		case "identity_user":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			if projectionFamilyNeedsAugmentation(family) {
				fmt.Fprintf(&b, "\treturn projectCatalogRuntimeWithRelationships(%s, %sProjectionResource, func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n\t\treturn identityUserProjections(event, identityProjectionProfile{Provider: %s})\n\t}, event)\n", strconv.Quote(request.SourceID), family.ProjectorName, strconv.Quote(request.SourceID))
			} else {
				fmt.Fprintf(&b, "\treturn identityUserProjections(event, identityProjectionProfile{Provider: %s})\n", strconv.Quote(request.SourceID))
			}
			fmt.Fprintf(&b, "}\n\n")
		case "identity_group":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			if projectionFamilyNeedsAugmentation(family) {
				fmt.Fprintf(&b, "\treturn projectCatalogRuntimeWithRelationships(%s, %sProjectionResource, func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n\t\treturn identityGroupProjections(event, identityProjectionProfile{Provider: %s})\n\t}, event)\n", strconv.Quote(request.SourceID), family.ProjectorName, strconv.Quote(request.SourceID))
			} else {
				fmt.Fprintf(&b, "\treturn identityGroupProjections(event, identityProjectionProfile{Provider: %s})\n", strconv.Quote(request.SourceID))
			}
			fmt.Fprintf(&b, "}\n\n")
		case "group_membership":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			if projectionFamilyNeedsAugmentation(family) {
				fmt.Fprintf(&b, "\treturn projectCatalogRuntimeWithRelationships(%s, %sProjectionResource, func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n\t\treturn identityGroupMembershipProjections(event, identityProjectionProfile{Provider: %s})\n\t}, event)\n", strconv.Quote(request.SourceID), family.ProjectorName, strconv.Quote(request.SourceID))
			} else {
				fmt.Fprintf(&b, "\treturn identityGroupMembershipProjections(event, identityProjectionProfile{Provider: %s})\n", strconv.Quote(request.SourceID))
			}
			fmt.Fprintf(&b, "}\n\n")
		case "audit_event":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			if projectionFamilyNeedsAugmentation(family) {
				fmt.Fprintf(&b, "\treturn projectCatalogRuntimeWithRelationships(%s, %sProjectionResource, func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n\t\treturn identityAuditProjections(event, identityProjectionProfile{Provider: %s})\n\t}, event)\n", strconv.Quote(request.SourceID), family.ProjectorName, strconv.Quote(request.SourceID))
			} else {
				fmt.Fprintf(&b, "\treturn identityAuditProjections(event, identityProjectionProfile{Provider: %s})\n", strconv.Quote(request.SourceID))
			}
			fmt.Fprintf(&b, "}\n\n")
		default:
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, "runtimeEvidenceProjections")
			fmt.Fprintf(&b, "}\n\n")
		}
	}
	if firstFamilyClass(request.Families, "asset").Name != "" {
		fmt.Fprintf(&b, "func %sGenericAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", sourcePrefix)
		fmt.Fprintf(&b, "\ttenantID, err := tenantID(event)\n\tif err != nil {\n\t\treturn nil, nil, err\n\t}\n\tattributes := event.GetAttributes()\n\tresourceID := firstNonEmpty(attributes[\"resource_id\"], attributes[\"external_id\"], event.GetId())\n\tresourceType := firstNonEmpty(attributes[\"resource_type\"], attributes[\"schema\"], \"asset\")\n\tresourceURN := firstNonEmpty(attributes[\"resource_urn\"], projectionURN(tenantID, \"runtime_\"+normalizeCloudType(resourceType), resourceID))\n\tentities := map[string]*ports.ProjectedEntity{}\n\tlinks := map[string]*ports.ProjectedLink{}\n\taddEntity(entities, &ports.ProjectedEntity{URN: resourceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"runtime.\" + strings.ReplaceAll(normalizeCloudType(resourceType), \"_\", \".\"), Label: firstNonEmpty(attributes[\"resource_name\"], resourceID), Attributes: map[string]string{\"resource_id\": resourceID, \"resource_type\": resourceType, \"source_runtime_id\": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})\n\tif evidenceID := strings.TrimSpace(attributes[\"evidence_id\"]); evidenceID != \"\" {\n\t\tevidenceURN := projectionURN(tenantID, \"runtime_evidence\", evidenceID)\n\t\taddEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"runtime.evidence\", Label: evidenceID, Attributes: map[string]string{\"evidence_id\": evidenceID, \"evidence_cas_uri\": strings.TrimSpace(attributes[\"evidence_cas_uri\"]), \"evidence_cas_digest\": strings.TrimSpace(attributes[\"evidence_cas_digest\"])}})\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\treturn identityProjectionResult(entities, links)\n}\n\n")
	}
	if firstFamilyClass(request.Families, "finding").Name != "" {
		fmt.Fprintf(&b, "func %sGenericFindingProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", sourcePrefix)
		fmt.Fprintf(&b, "\ttenantID, err := tenantID(event)\n\tif err != nil {\n\t\treturn nil, nil, err\n\t}\n\tattributes := event.GetAttributes()\n\tfindingID := firstNonEmpty(attributes[\"finding_id\"], event.GetId())\n\tfindingURN := projectionURN(tenantID, \"finding\", findingID)\n\tentities := map[string]*ports.ProjectedEntity{}\n\tlinks := map[string]*ports.ProjectedLink{}\n\taddEntity(entities, &ports.ProjectedEntity{URN: findingURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"finding\", Label: firstNonEmpty(attributes[\"title\"], findingID), Attributes: map[string]string{\"finding_id\": findingID, \"severity\": strings.TrimSpace(attributes[\"severity\"]), \"status\": strings.TrimSpace(attributes[\"status\"]), \"source_runtime_id\": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})\n\tif resourceURN := strings.TrimSpace(attributes[\"resource_urn\"]); resourceURN != \"\" {\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), findingURN, resourceURN, relationAffects, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\tif evidenceID := strings.TrimSpace(attributes[\"evidence_id\"]); evidenceID != \"\" {\n\t\tevidenceURN := projectionURN(tenantID, \"runtime_evidence\", evidenceID)\n\t\taddEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"runtime_evidence\", Label: evidenceID, Attributes: map[string]string{\"evidence_id\": evidenceID, \"evidence_cas_uri\": strings.TrimSpace(attributes[\"evidence_cas_uri\"]), \"evidence_cas_digest\": strings.TrimSpace(attributes[\"evidence_cas_digest\"])}})\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, findingURN, relationSupports, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\treturn identityProjectionResult(entities, links)\n}\n")
	}
	if firstFamilyClass(request.Families, "secret").Name != "" {
		fmt.Fprintf(&b, "func %sGenericSecretProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", sourcePrefix)
		fmt.Fprintf(&b, "\ttenantID, err := tenantID(event)\n\tif err != nil {\n\t\treturn nil, nil, err\n\t}\n\tattributes := event.GetAttributes()\n\tsecretID := firstNonEmpty(attributes[\"secret_id\"], event.GetId())\n\tsecretURN := projectionURN(tenantID, \"secret\", secretID)\n\tentities := map[string]*ports.ProjectedEntity{}\n\tlinks := map[string]*ports.ProjectedLink{}\n\taddEntity(entities, &ports.ProjectedEntity{URN: secretURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"secret\", Label: firstNonEmpty(attributes[\"secret_name\"], secretID), Attributes: map[string]string{\"secret_id\": secretID, \"secret_type\": strings.TrimSpace(attributes[\"secret_type\"]), \"secret_status\": strings.TrimSpace(attributes[\"secret_status\"]), \"secret_rotation_enabled\": strings.TrimSpace(attributes[\"secret_rotation_enabled\"]), \"secret_last_rotated_at\": strings.TrimSpace(attributes[\"secret_last_rotated_at\"]), \"source_runtime_id\": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})\n\tif evidenceID := strings.TrimSpace(attributes[\"evidence_id\"]); evidenceID != \"\" {\n\t\tevidenceURN := projectionURN(tenantID, \"runtime_evidence\", evidenceID)\n\t\taddEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"runtime_evidence\", Label: evidenceID, Attributes: map[string]string{\"evidence_id\": evidenceID, \"evidence_cas_uri\": strings.TrimSpace(attributes[\"evidence_cas_uri\"]), \"evidence_cas_digest\": strings.TrimSpace(attributes[\"evidence_cas_digest\"])}})\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), secretURN, evidenceURN, relationHasEvidence, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\treturn identityProjectionResult(entities, links)\n}\n\n")
	}
	if firstFamilyClass(request.Families, "policy").Name != "" {
		fmt.Fprintf(&b, "func %sGenericPolicyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", sourcePrefix)
		fmt.Fprintf(&b, "\ttenantID, err := tenantID(event)\n\tif err != nil {\n\t\treturn nil, nil, err\n\t}\n\tattributes := event.GetAttributes()\n\tpolicyID := firstNonEmpty(attributes[\"policy_id\"], event.GetId())\n\tpolicyURN := projectionURN(tenantID, \"policy\", policyID)\n\tentities := map[string]*ports.ProjectedEntity{}\n\tlinks := map[string]*ports.ProjectedLink{}\n\taddEntity(entities, &ports.ProjectedEntity{URN: policyURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"policy\", Label: firstNonEmpty(attributes[\"policy_name\"], policyID), Attributes: map[string]string{\"policy_id\": policyID, \"policy_type\": strings.TrimSpace(attributes[\"policy_type\"]), \"policy_status\": strings.TrimSpace(attributes[\"policy_status\"]), \"policy_severity\": strings.TrimSpace(attributes[\"policy_severity\"]), \"source_runtime_id\": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})\n\tif evidenceID := strings.TrimSpace(attributes[\"evidence_id\"]); evidenceID != \"\" {\n\t\tevidenceURN := projectionURN(tenantID, \"runtime_evidence\", evidenceID)\n\t\taddEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"runtime_evidence\", Label: evidenceID, Attributes: map[string]string{\"evidence_id\": evidenceID, \"evidence_cas_uri\": strings.TrimSpace(attributes[\"evidence_cas_uri\"]), \"evidence_cas_digest\": strings.TrimSpace(attributes[\"evidence_cas_digest\"])}})\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), policyURN, evidenceURN, relationHasEvidence, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\treturn identityProjectionResult(entities, links)\n}\n")
	}
	if firstFamilyClass(request.Families, "deployment").Name != "" {
		fmt.Fprintf(&b, "func %sGenericDeploymentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", sourcePrefix)
		fmt.Fprintf(&b, "\ttenantID, err := tenantID(event)\n\tif err != nil {\n\t\treturn nil, nil, err\n\t}\n\tattributes := event.GetAttributes()\n\tdeploymentID := firstNonEmpty(attributes[\"deployment_id\"], event.GetId())\n\tdeploymentURN := projectionURN(tenantID, \"deployment\", deploymentID)\n\tentities := map[string]*ports.ProjectedEntity{}\n\tlinks := map[string]*ports.ProjectedLink{}\n\taddEntity(entities, &ports.ProjectedEntity{URN: deploymentURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"deployment\", Label: firstNonEmpty(attributes[\"deployment_name\"], deploymentID), Attributes: map[string]string{\"deployment_id\": deploymentID, \"deployment_environment\": strings.TrimSpace(attributes[\"deployment_environment\"]), \"deployment_status\": strings.TrimSpace(attributes[\"deployment_status\"]), \"deployment_url\": strings.TrimSpace(attributes[\"deployment_url\"]), \"deployment_commit_sha\": strings.TrimSpace(attributes[\"deployment_commit_sha\"]), \"deployment_branch\": strings.TrimSpace(attributes[\"deployment_branch\"]), \"source_runtime_id\": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})\n\tif evidenceID := strings.TrimSpace(attributes[\"evidence_id\"]); evidenceID != \"\" {\n\t\tevidenceURN := projectionURN(tenantID, \"runtime_evidence\", evidenceID)\n\t\taddEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"runtime_evidence\", Label: evidenceID, Attributes: map[string]string{\"evidence_id\": evidenceID, \"evidence_cas_uri\": strings.TrimSpace(attributes[\"evidence_cas_uri\"]), \"evidence_cas_digest\": strings.TrimSpace(attributes[\"evidence_cas_digest\"])}})\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), deploymentURN, evidenceURN, relationHasEvidence, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\treturn identityProjectionResult(entities, links)\n}\n")
	}
	if firstFamilyClass(request.Families, "alert").Name != "" {
		fmt.Fprintf(&b, "func %sGenericAlertProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", sourcePrefix)
		fmt.Fprintf(&b, "\ttenantID, err := tenantID(event)\n\tif err != nil {\n\t\treturn nil, nil, err\n\t}\n\tattributes := event.GetAttributes()\n\talertID := firstNonEmpty(attributes[\"alert_id\"], event.GetId())\n\talertURN := projectionURN(tenantID, \"alert\", alertID)\n\tentities := map[string]*ports.ProjectedEntity{}\n\tlinks := map[string]*ports.ProjectedLink{}\n\taddEntity(entities, &ports.ProjectedEntity{URN: alertURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"alert\", Label: firstNonEmpty(attributes[\"alert_name\"], alertID), Attributes: map[string]string{\"alert_id\": alertID, \"alert_severity\": strings.TrimSpace(attributes[\"alert_severity\"]), \"alert_status\": strings.TrimSpace(attributes[\"alert_status\"]), \"alert_type\": strings.TrimSpace(attributes[\"alert_type\"]), \"alert_source\": strings.TrimSpace(attributes[\"alert_source\"]), \"alert_fired_at\": strings.TrimSpace(attributes[\"alert_fired_at\"]), \"alert_resolved_at\": strings.TrimSpace(attributes[\"alert_resolved_at\"]), \"source_runtime_id\": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})\n\tif evidenceID := strings.TrimSpace(attributes[\"evidence_id\"]); evidenceID != \"\" {\n\t\tevidenceURN := projectionURN(tenantID, \"runtime_evidence\", evidenceID)\n\t\taddEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"runtime_evidence\", Label: evidenceID, Attributes: map[string]string{\"evidence_id\": evidenceID, \"evidence_cas_uri\": strings.TrimSpace(attributes[\"evidence_cas_uri\"]), \"evidence_cas_digest\": strings.TrimSpace(attributes[\"evidence_cas_digest\"])}})\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, evidenceURN, relationHasEvidence, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\treturn identityProjectionResult(entities, links)\n}\n")
	}
	return b.String()
}

func projectionNeedsConnectordefinitions(families []familyData) bool {
	for _, family := range families {
		if projectionFamilyNeedsAugmentation(family) {
			return true
		}
	}
	return false
}

func projectionFamilyNeedsAugmentation(family familyData) bool {
	return family.Projection != nil && (family.Projection.Entity != nil || len(family.Projection.Relationships) != 0)
}

func renderProjectionDispatchReturn(b *strings.Builder, sourceID string, family familyData, baseFunc string) {
	if projectionFamilyNeedsAugmentation(family) {
		fmt.Fprintf(b, "\treturn projectCatalogRuntimeWithRelationships(%s, %sProjectionResource, %s, event)\n", strconv.Quote(sourceID), family.ProjectorName, baseFunc)
		return
	}
	fmt.Fprintf(b, "\treturn %s(event)\n", baseFunc)
}

func renderProjectionSpecLiteral(b *strings.Builder, projection *connectordefinitions.ProjectionSpec, indent string) {
	if projection == nil {
		return
	}
	if strings.TrimSpace(projection.Template) != "" {
		fmt.Fprintf(b, "%sTemplate: %s,\n", indent, strconv.Quote(projection.Template))
	}
	if len(projection.Fields) != 0 {
		fmt.Fprintf(b, "%sFields: map[string]string{%s},\n", indent, renderedAttributeMap(projection.Fields))
	}
	if projection.Entity != nil {
		fmt.Fprintf(b, "%sEntity: &connectordefinitions.ProjectionEntitySpec{\n", indent)
		renderProjectionEntitySpecLiteral(b, *projection.Entity, indent+"\t")
		fmt.Fprintf(b, "%s},\n", indent)
	}
	if len(projection.Relationships) != 0 {
		fmt.Fprintf(b, "%sRelationships: []connectordefinitions.ProjectionRelationshipSpec{\n", indent)
		for _, relationship := range projection.Relationships {
			fmt.Fprintf(b, "%s\t{\n", indent)
			fmt.Fprintf(b, "%s\t\tRelation: %s,\n", indent, strconv.Quote(relationship.Relation))
			if relationship.From != nil {
				fmt.Fprintf(b, "%s\t\tFrom: &connectordefinitions.ProjectionEntitySpec{\n", indent)
				renderProjectionEntitySpecLiteral(b, *relationship.From, indent+"\t\t\t")
				fmt.Fprintf(b, "%s\t\t},\n", indent)
			}
			fmt.Fprintf(b, "%s\t\tTo: connectordefinitions.ProjectionEntitySpec{\n", indent)
			renderProjectionEntitySpecLiteral(b, relationship.To, indent+"\t\t\t")
			fmt.Fprintf(b, "%s\t\t},\n", indent)
			if len(relationship.RequiredAttributes) != 0 {
				fmt.Fprintf(b, "%s\t\tRequiredAttributes: []string{%s},\n", indent, quotedStrings(relationship.RequiredAttributes))
			}
			if len(relationship.LinkAttributes) != 0 {
				fmt.Fprintf(b, "%s\t\tLinkAttributes: []string{%s},\n", indent, quotedStrings(relationship.LinkAttributes))
			}
			if strings.TrimSpace(relationship.MatchType) != "" {
				fmt.Fprintf(b, "%s\t\tMatchType: %s,\n", indent, strconv.Quote(relationship.MatchType))
			}
			fmt.Fprintf(b, "%s\t},\n", indent)
		}
		fmt.Fprintf(b, "%s},\n", indent)
	}
}

func renderProjectionEntitySpecLiteral(b *strings.Builder, entity connectordefinitions.ProjectionEntitySpec, indent string) {
	if strings.TrimSpace(entity.EntityType) != "" {
		fmt.Fprintf(b, "%sEntityType: %s,\n", indent, strconv.Quote(entity.EntityType))
	}
	if strings.TrimSpace(entity.URNKind) != "" {
		fmt.Fprintf(b, "%sURNKind: %s,\n", indent, strconv.Quote(entity.URNKind))
	}
	if len(entity.IDAttributes) != 0 {
		fmt.Fprintf(b, "%sIDAttributes: []string{%s},\n", indent, quotedStrings(entity.IDAttributes))
	}
	if strings.TrimSpace(entity.LabelAttribute) != "" {
		fmt.Fprintf(b, "%sLabelAttribute: %s,\n", indent, strconv.Quote(entity.LabelAttribute))
	}
}

func projectionNeedsStrings(families []familyData) bool {
	return firstFamilyClass(families, "asset").Name != "" ||
		firstFamilyClass(families, "finding").Name != "" ||
		firstFamilyClass(families, "secret").Name != "" ||
		firstFamilyClass(families, "policy").Name != "" ||
		firstFamilyClass(families, "deployment").Name != "" ||
		firstFamilyClass(families, "alert").Name != ""
}

func renderProjectionTestGo(request normalizedRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "package sourceprojection\n\n")
	fmt.Fprintf(&b, "import (\n\t\"testing\"\n\n\tcerebrov1 \"github.com/writer/cerebro/gen/cerebro/v1\"\n)\n\n")
	classOrdinals := map[string]int{}
	testNames := map[string]int{}
	testedProjectors := map[string]struct{}{}
	for _, family := range request.Families {
		if _, ok := testedProjectors[family.ProjectorName]; ok {
			continue
		}
		testedProjectors[family.ProjectorName] = struct{}{}
		classOrdinals[family.Class]++
		renderProjectionFamilyTest(&b, request.SourceID, family, projectionTestName(request.SourceID, family, classOrdinals[family.Class], testNames))
	}
	return b.String()
}

func projectionTestName(sourceID string, family familyData, classOrdinal int, used map[string]int) string {
	suffix := pascalIdentifier(family.Name)
	if classOrdinal == 1 {
		switch family.Class {
		case "asset":
			suffix = "Asset"
		case "finding":
			suffix = "Finding"
		case "secret":
			suffix = "Secret"
		case "policy":
			suffix = "Policy"
		case "deployment":
			suffix = "Deployment"
		case "alert":
			suffix = "Alert"
		case "identity_user":
			suffix = "IdentityUser"
		case "identity_group":
			suffix = "IdentityGroup"
		case "group_membership":
			suffix = "GroupMembership"
		case "audit_event":
			suffix = "Audit"
		case "evidence_cas_reference":
			suffix = "EvidenceCAS"
		}
	}
	name := "Test" + pascalIdentifier(sourceID) + suffix + "Projection"
	seen := used[name]
	used[name] = seen + 1
	if seen > 0 {
		return name + strconv.Itoa(seen+1)
	}
	return name
}

func renderProjectionFamilyTest(b *strings.Builder, sourceID string, family familyData, testName string) {
	switch family.Class {
	case "asset":
		fmt.Fprintf(b, "func %s(t *testing.T) {\n", testName)
		fmt.Fprintf(b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"resource_id\": \"asset-1\", \"resource_type\": \"host\", \"resource_name\": \"host-1\", \"evidence_id\": \"evidence-1\", \"evidence_cas_uri\": \"cas://cases/evidence-1\", \"evidence_cas_digest\": \"sha256:test\"}}\n", strconv.Quote(sourceID), strconv.Quote(family.EventKind))
		fmt.Fprintf(b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected entities\")\n\t}\n\tif len(links) == 0 {\n\t\tt.Fatal(\"expected projected evidence links\")\n\t}\n}\n\n", family.ProjectorName)
	case "finding":
		fmt.Fprintf(b, "func %s(t *testing.T) {\n", testName)
		fmt.Fprintf(b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"finding_id\": \"finding-1\", \"title\": \"Finding One\", \"severity\": \"high\", \"status\": \"open\", \"resource_urn\": \"urn:cerebro:tenant:runtime_asset:asset-1\", \"evidence_id\": \"evidence-1\"}}\n", strconv.Quote(sourceID), strconv.Quote(family.EventKind))
		fmt.Fprintf(b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected finding\")\n\t}\n\tif len(links) == 0 {\n\t\tt.Fatal(\"expected projected finding links\")\n\t}\n\tif !hasProjectedEntityType(entities, \"runtime_evidence\") {\n\t\tt.Fatal(\"expected projected runtime evidence entity\")\n\t}\n}\n\n", family.ProjectorName)
	case "secret":
		fmt.Fprintf(b, "func %s(t *testing.T) {\n", testName)
		fmt.Fprintf(b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"secret_id\": \"secret-1\", \"secret_name\": \"DB Password\", \"secret_type\": \"password\", \"secret_status\": \"active\", \"evidence_id\": \"evidence-1\"}}\n", strconv.Quote(sourceID), strconv.Quote(family.EventKind))
		fmt.Fprintf(b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected secret\")\n\t}\n\tif len(links) == 0 {\n\t\tt.Fatal(\"expected projected evidence links\")\n\t}\n}\n\n", family.ProjectorName)
	case "policy":
		fmt.Fprintf(b, "func %s(t *testing.T) {\n", testName)
		fmt.Fprintf(b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"policy_id\": \"policy-1\", \"policy_name\": \"Require MFA\", \"policy_type\": \"access\", \"policy_status\": \"enabled\", \"evidence_id\": \"evidence-1\"}}\n", strconv.Quote(sourceID), strconv.Quote(family.EventKind))
		fmt.Fprintf(b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected policy\")\n\t}\n\tif len(links) == 0 {\n\t\tt.Fatal(\"expected projected evidence links\")\n\t}\n}\n\n", family.ProjectorName)
	case "deployment":
		fmt.Fprintf(b, "func %s(t *testing.T) {\n", testName)
		fmt.Fprintf(b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"deployment_id\": \"dep-1\", \"deployment_name\": \"Production\", \"deployment_environment\": \"production\", \"deployment_status\": \"ready\", \"evidence_id\": \"evidence-1\"}}\n", strconv.Quote(sourceID), strconv.Quote(family.EventKind))
		fmt.Fprintf(b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected deployment\")\n\t}\n\tif len(links) == 0 {\n\t\tt.Fatal(\"expected projected evidence links\")\n\t}\n}\n\n", family.ProjectorName)
	case "alert":
		fmt.Fprintf(b, "func %s(t *testing.T) {\n", testName)
		fmt.Fprintf(b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"alert_id\": \"alert-1\", \"alert_name\": \"High Error Rate\", \"alert_severity\": \"critical\", \"alert_status\": \"open\", \"evidence_id\": \"evidence-1\"}}\n", strconv.Quote(sourceID), strconv.Quote(family.EventKind))
		fmt.Fprintf(b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected alert\")\n\t}\n\tif len(links) == 0 {\n\t\tt.Fatal(\"expected projected evidence links\")\n\t}\n}\n\n", family.ProjectorName)
	case "identity_user":
		fmt.Fprintf(b, "func %s(t *testing.T) {\n", testName)
		fmt.Fprintf(b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"user_id\": \"user-1\", \"email\": \"user@example.test\", \"display_name\": \"User One\"}}\n", strconv.Quote(sourceID), strconv.Quote(family.EventKind))
		fmt.Fprintf(b, "\tentities, _, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected identity user\")\n\t}\n}\n\n", family.ProjectorName)
	case "identity_group":
		fmt.Fprintf(b, "func %s(t *testing.T) {\n", testName)
		fmt.Fprintf(b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"group_id\": \"group-1\", \"group_email\": \"group@example.test\", \"group_name\": \"Group One\"}}\n", strconv.Quote(sourceID), strconv.Quote(family.EventKind))
		fmt.Fprintf(b, "\tentities, _, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected identity group\")\n\t}\n}\n\n", family.ProjectorName)
	case "group_membership":
		fmt.Fprintf(b, "func %s(t *testing.T) {\n", testName)
		fmt.Fprintf(b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"group_id\": \"group-1\", \"group_email\": \"group@example.test\", \"member_id\": \"user-1\", \"member_email\": \"user@example.test\"}}\n", strconv.Quote(sourceID), strconv.Quote(family.EventKind))
		fmt.Fprintf(b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 || len(links) == 0 {\n\t\tt.Fatalf(\"entities/links = %%d/%%d, want membership projection\", len(entities), len(links))\n\t}\n}\n\n", family.ProjectorName)
	case "audit_event":
		fmt.Fprintf(b, "func %s(t *testing.T) {\n", testName)
		fmt.Fprintf(b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"event_type\": \"user.login\", \"actor_id\": \"user-1\", \"actor_email\": \"user@example.test\", \"resource_id\": \"app-1\", \"resource_type\": \"application\"}}\n", strconv.Quote(sourceID), strconv.Quote(family.EventKind))
		fmt.Fprintf(b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 || len(links) == 0 {\n\t\tt.Fatalf(\"entities/links = %%d/%%d, want audit projection\", len(entities), len(links))\n\t}\n}\n\n", family.ProjectorName)
	case "evidence_cas_reference":
		fmt.Fprintf(b, "func %s(t *testing.T) {\n", testName)
		fmt.Fprintf(b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"evidence_id\": \"evidence-1\", \"evidence_type\": \"evidence_cas.artifact\", \"source_event_id\": \"provider-event-1\", \"evidence_cas_uri\": \"cas://cases/evidence-1\", \"evidence_cas_digest\": \"sha256:test\"}}\n", strconv.Quote(sourceID), strconv.Quote(family.EventKind))
		fmt.Fprintf(b, "\tentities, _, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tvar foundEvidence bool\n\tfor _, entity := range entities {\n\t\tif entity.EntityType == \"runtime.evidence\" {\n\t\t\tfoundEvidence = true\n\t\t}\n\t}\n\tif !foundEvidence {\n\t\tt.Fatalf(\"entities = %%#v\", entities)\n\t}\n}\n", family.ProjectorName)
	}
}

func firstFamilyClass(families []familyData, class string) familyData {
	for _, family := range families {
		if family.Class == class {
			return family
		}
	}
	return familyData{}
}

func renderedAttributeMap(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, strconv.Quote(key)+": "+strconv.Quote(values[key]))
	}
	return strings.Join(parts, ", ")
}

func yamlString(value string) string {
	return strconv.Quote(strings.TrimSpace(value))
}

func quotedStrings(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, strconv.Quote(value))
	}
	return strings.Join(quoted, ", ")
}

func healthEndpoint(sourceID string) string {
	return "/source-runtimes/health?source_id=" + sourceID
}

var nonIdentifier = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func packageName(value string) string {
	name := snakeIdentifier(value)
	if name == "" {
		return "source"
	}
	return name
}

func snakeIdentifier(value string) string {
	normalized := strings.Trim(nonIdentifier.ReplaceAllString(strings.ToLower(strings.TrimSpace(value)), "_"), "_")
	if normalized == "" {
		return ""
	}
	if unicode.IsDigit([]rune(normalized)[0]) {
		return "source_" + normalized
	}
	return normalized
}

func lowerCamelIdentifier(value string) string {
	pascal := pascalIdentifier(value)
	if pascal == "" {
		return "source"
	}
	return strings.ToLower(pascal[:1]) + pascal[1:]
}

func pascalIdentifier(value string) string {
	parts := strings.Split(snakeIdentifier(value), "_")
	var b strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		runes := []rune(part)
		runes[0] = unicode.ToUpper(runes[0])
		b.WriteString(string(runes))
	}
	if b.Len() == 0 {
		return "Source"
	}
	return b.String()
}

func titleFromID(value string) string {
	parts := strings.Split(snakeIdentifier(value), "_")
	for index, part := range parts {
		if part == "" {
			continue
		}
		runes := []rune(part)
		runes[0] = unicode.ToUpper(runes[0])
		parts[index] = string(runes)
	}
	return strings.Join(parts, " ")
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// extractTemplateKeys finds all ${prefix.key} placeholders in a template string
// and returns the key names, ensuring they are included in templateKeys so
// renderTemplate can resolve them at runtime.
func extractTemplateKeys(template string) []string {
	var keys []string
	for _, prefix := range []string{"config", "credential", "connection"} {
		prefixPattern := "${" + prefix + "."
		search := template
		for {
			idx := strings.Index(search, prefixPattern)
			if idx == -1 {
				break
			}
			search = search[idx+len(prefixPattern):]
			endIdx := strings.Index(search, "}")
			if endIdx == -1 {
				break
			}
			key := strings.TrimSpace(search[:endIdx])
			if key != "" {
				keys = append(keys, key)
			}
			search = search[endIdx+1:]
		}
	}
	return keys
}
