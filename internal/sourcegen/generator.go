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
	TokenScheme       string
	TokenConfigKey    string
	AuthTokenURL      string
	OAuthScopes       []string
	OAuthTokenParams  map[string]string
	OAuthTokenMethod  string
	EnvPrefix         string
	PackageName       string
	DefaultFamily     string
	DefaultPath       string
	BaseURLTemplate   string
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
	URNKind               string
	EventKind             string
	SchemaRef             string
	IDKeys                []string
	ListKeys              []string
	CursorParam           string
	NextCursorKeys        []string
	LinkHeader            string
	PageSizeParams        []string
	DisablePageSize       bool
	StaticQuery           map[string]string
	ConfigQuery           map[string]string
	RequiredAttributes    []string
	RequiredPayloadFields []string
	Projection            *connectordefinitions.ProjectionSpec
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
		TokenScheme:       tokenScheme,
		TokenConfigKey:    tokenConfigKey,
		AuthTokenURL:      strings.TrimSpace(definition.Auth.TokenURL),
		OAuthScopes:       append([]string(nil), definition.Auth.Scopes...),
		OAuthTokenParams:  cloneStringMap(definition.Auth.TokenParams),
		OAuthTokenMethod:  strings.TrimSpace(definition.Auth.TokenRequestAuthMethod),
		EnvPrefix:         strings.ToUpper(strings.NewReplacer("-", "_").Replace(sourceID)),
		PackageName:       packageName(sourceID),
		BaseURLTemplate:   transportBaseURL(definition.Transport),
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
		families = append(families, familyData{
			Name:                  name,
			Schema:                schemaNameFromRef(schemaRef, name),
			Class:                 class,
			ConstName:             "family" + pascalIdentifier(name),
			ProjectorName:         lowerCamelIdentifier(request.SourceID + "_" + name + "_projections"),
			Path:                  resource.Path,
			Method:                methodForResource(resource),
			URNKind:               urnKind,
			EventKind:             eventKind,
			SchemaRef:             schemaRef,
			IDKeys:                idKeysForResource(resource),
			ListKeys:              listKeysForResource(resource),
			CursorParam:           cursorParamForResource(resource),
			NextCursorKeys:        nextCursorKeysForResource(resource),
			LinkHeader:            linkHeaderForResource(resource),
			PageSizeParams:        pageSizeParamsForResource(resource),
			DisablePageSize:       disablePageSizeForResource(resource),
			StaticQuery:           resource.StaticQuery,
			ConfigQuery:           resource.ConfigQuery,
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
	return resource.Pagination != nil && resource.Pagination.DisablePageSize
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
		{Path: filepath.Join(sourceRoot, "source_test.go"), Content: renderSourceTestGo(request)},
		{Path: filepath.Join(sourceRoot, "testdata", "read_"+request.DefaultFamily+".json"), Content: renderReadFixture()},
		{Path: filepath.Join(sourceRoot, "source_health_receipt.json"), Content: renderSourceHealthReceipt(request)},
		{Path: filepath.Join(sourceRoot, "SOURCE_RUNTIME.md"), Content: renderRuntimeDocs(request)},
		{Path: filepath.Join(sourceRoot, "PR_BODY.md"), Content: renderPRBody(request)},
		{Path: filepath.Join(request.OutputDir, "internal", "sourceprojection", request.SourceID+".go"), Content: renderProjectionGo(request)},
		{Path: filepath.Join(request.OutputDir, "internal", "sourceprojection", request.SourceID+"_test.go"), Content: renderProjectionTestGo(request)},
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
	fmt.Fprintf(&b, "emitted_kinds:\n")
	for _, family := range request.Families {
		fmt.Fprintf(&b, "  - %s\n", family.EventKind)
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
		fmt.Fprintf(&b, "    - id: %s\n", family.Name)
		fmt.Fprintf(&b, "      type: entity_family\n")
		fmt.Fprintf(&b, "      title: %s\n", yamlString(titleFromID(family.Name)))
		fmt.Fprintf(&b, "      families: [%s]\n", family.Name)
		fmt.Fprintf(&b, "      support: partial\n")
		fmt.Fprintf(&b, "      high_value: true\n")
		fmt.Fprintf(&b, "      evidence_types: [source_snapshot]\n")
		fmt.Fprintf(&b, "      control_domains: [asset_inventory]\n")
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

func renderDeploy(request normalizedRequest) string {
	tokenEnv := request.EnvPrefix + "_TOKEN"
	if request.TokenConfigKey == "api_token" {
		tokenEnv = request.EnvPrefix + "_API_TOKEN"
	}
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
	if request.OAuth != nil {
		for _, key := range request.CredentialKeys {
			secretKeys = append(secretKeys, envNameForConfigKey(request, key))
		}
	} else {
		secretKeys = append(secretKeys, tokenEnv)
	}
	for _, key := range uniqueStrings(secretKeys) {
		fmt.Fprintf(&b, "  - %s\n", key)
	}
	fmt.Fprintf(&b, "runtimes:\n")
	fmt.Fprintf(&b, "  - localId: %s\n", strings.ReplaceAll(request.DefaultFamily, "_", "-"))
	fmt.Fprintf(&b, "    config:\n")
	if len(request.ConfigKeys) == 0 && strings.TrimSpace(request.BaseURLTemplate) == "" {
		fmt.Fprintf(&b, "      base_url: env:%s_BASE_URL\n", request.EnvPrefix)
	}
	for _, key := range request.ConfigKeys {
		fmt.Fprintf(&b, "      %s: env:%s\n", key, envNameForConfigKey(request, key))
	}
	fmt.Fprintf(&b, "      family: %s\n", request.DefaultFamily)
	fmt.Fprintf(&b, "      failure_modes: %s\n", strings.Join(request.FailureModes, ","))
	fmt.Fprintf(&b, "      health_path: %s\n", request.HealthPath)
	fmt.Fprintf(&b, "      expected_cadence_seconds: %q\n", strconv.FormatInt(int64(request.FreshnessDuration.Seconds()), 10))
	fmt.Fprintf(&b, "      stale_after_seconds: %q\n", strconv.FormatInt(int64(request.FreshnessDuration.Seconds()), 10))
	fmt.Fprintf(&b, "      per_page: %q\n", "100")
	if request.OAuth != nil {
		for _, key := range request.CredentialKeys {
			fmt.Fprintf(&b, "      %s: env:%s\n", key, envNameForConfigKey(request, key))
		}
	} else {
		fmt.Fprintf(&b, "      %s: env:%s\n", request.TokenConfigKey, tokenEnv)
	}
	return b.String()
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
	}
	fmt.Fprintf(&b, "type Source struct {\n\tinner *jsonapi.Source\n\tallowLoopback bool\n")
	if request.OAuth != nil {
		fmt.Fprintf(&b, "\ttokenCache sourcehttp.ClientCredentialsCache\n")
	}
	fmt.Fprintf(&b, "}\n\n")
	fmt.Fprintf(&b, "func New() (*Source, error) {\n")
	fmt.Fprintf(&b, "\tspec, err := loadSpec()\n\tif err != nil {\n\t\treturn nil, err\n\t}\n")
	fmt.Fprintf(&b, "\tinner, err := jsonapi.New(spec, jsonapi.Options{\n")
	fmt.Fprintf(&b, "\t\tSourceID: sourceID,\n\t\tDefaultFamily: defaultFamily,\n\t\tRequireTenantID: true,\n\t\tAuthModel: %s,\n\t\tTokenScheme: tokenScheme,\n", strconv.Quote(request.AuthModel))
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
	fmt.Fprintf(&b, "\t\tFamilies: []jsonapi.Family{\n")
	for _, family := range request.Families {
		fmt.Fprintf(&b, "\t\t\t{\n")
		fmt.Fprintf(&b, "\t\t\t\tName: %s,\n", family.ConstName)
		fmt.Fprintf(&b, "\t\t\t\tPath: %s,\n", strconv.Quote(family.Path))
		if strings.TrimSpace(family.Method) != "" {
			fmt.Fprintf(&b, "\t\t\t\tMethod: %s,\n", strconv.Quote(family.Method))
		}
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
		fmt.Fprintf(&b, "\t\t\t\tTimestampKeys: []string{%s},\n", quotedStrings([]string{"observed_at", "updated_at", "last_seen_at", "created_at"}))
		fmt.Fprintf(&b, "\t\t\t\tAttributes: map[string]string{%s},\n", renderedAttributeMap(attributePathsForFamily(family)))
		fmt.Fprintf(&b, "\t\t\t\tStaticAttributes: map[string]string{%s},\n", renderedAttributeMap(staticAttributesForFamily(request, family)))
		if len(family.StaticQuery) != 0 || len(family.ConfigQuery) != 0 {
			fmt.Fprintf(&b, "\t\t\t\tConfig: jsonapi.FamilyConfig{\n")
			if len(family.StaticQuery) != 0 {
				fmt.Fprintf(&b, "\t\t\t\t\tStaticQuery: map[string]string{%s},\n", renderedAttributeMap(family.StaticQuery))
			}
			if len(family.ConfigQuery) != 0 {
				fmt.Fprintf(&b, "\t\t\t\t\tConfigQuery: map[string]string{%s},\n", renderedAttributeMap(family.ConfigQuery))
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
		fmt.Fprintf(&b, "func (s *Source) runtimeConfig(ctx context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {\n\tvalues := cfg.Values()\n\tif strings.TrimSpace(values[\"base_url\"]) == \"\" && strings.TrimSpace(defaultBaseURLTemplate) != \"\" {\n\t\tbaseURL, err := sourcecdk.RenderConfigTemplate(sourceID, defaultBaseURLTemplate, cfg, templateKeys)\n\t\tif err != nil {\n\t\t\treturn sourcecdk.Config{}, err\n\t\t}\n\t\tvalues[\"base_url\"] = baseURL\n\t}\n")
		fmt.Fprintf(&b, "\tif s == nil {\n\t\treturn sourcecdk.Config{}, fmt.Errorf(\"%%s source is required\", sourceID)\n\t}\n\ttoken, err := s.tokenCache.Token(ctx, cfg, sourcehttp.ClientCredentialsOptions{\n\t\tSourceID: sourceID,\n\t\tTokenURLTemplate: oauthTokenURLTemplate,\n\t\tTemplateKeys: templateKeys,\n\t\tScopes: oauthScopes,\n\t\tScopeSeparator: oauthScopeSeparator,\n\t\tTokenParams: oauthTokenParams,\n\t\tExpirationBuffer: oauthTokenExpirationBuffer,\n\t\tAllowLoopback: s.allowLoopback,\n\t})\n\tif err != nil {\n\t\treturn sourcecdk.Config{}, err\n\t}\n\tvalues[\"token\"] = token\n")
		fmt.Fprintf(&b, "\treturn sourcecdk.NewConfig(values), nil\n}\n\n")
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

func renderSourceTestGo(request normalizedRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "package %s\n\n", request.PackageName)
	fmt.Fprintf(&b, "import (\n\t\"context\"\n\t\"encoding/json\"\n\t\"net/http\"\n\t\"net/http/httptest\"\n\t\"strings\"\n\t\"testing\"\n\n\t\"github.com/writer/cerebro/internal/sourcecdk\"\n)\n\n")
	fmt.Fprintf(&b, "func TestSourceCheckAndRead(t *testing.T) {\n")
	fmt.Fprintf(&b, "\tsource, err := New()\n\tif err != nil {\n\t\tt.Fatalf(\"New() error = %%v\", err)\n\t}\n\tsource.allowLoopbackForTest()\n")
	if request.OAuth != nil {
		fmt.Fprintf(&b, "\ttokenRequests := 0\n")
	}
	fmt.Fprintf(&b, "\tserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n")
	if request.OAuth != nil {
		fmt.Fprintf(&b, "\t\tif r.URL.Path == \"/oauth/token\" {\n\t\t\ttokenRequests++\n\t\t\tif r.Method != http.MethodPost {\n\t\t\t\tt.Fatalf(\"token method = %%s\", r.Method)\n\t\t\t}\n\t\t\tr.Body = http.MaxBytesReader(w, r.Body, 1<<20)\n\t\t\tif err := r.ParseForm(); err != nil {\n\t\t\t\tt.Fatalf(\"ParseForm() error = %%v\", err)\n\t\t\t}\n\t\t\tif got := r.Form.Get(\"grant_type\"); got != \"client_credentials\" {\n\t\t\t\tt.Fatalf(\"grant_type = %%q\", got)\n\t\t\t}\n\t\t\tif got := r.Form.Get(\"client_id\"); got != \"client-id\" {\n\t\t\t\tt.Fatalf(\"client_id = %%q\", got)\n\t\t\t}\n\t\t\tif got := r.Form.Get(\"client_secret\"); got != \"client-secret\" {\n\t\t\t\tt.Fatalf(\"client_secret = %%q\", got)\n\t\t\t}\n\t\t\tw.Header().Set(\"Content-Type\", \"application/json\")\n\t\t\t_ = json.NewEncoder(w).Encode(map[string]any{\"access_token\": \"test-token\", \"expires_in\": 600})\n\t\t\treturn\n\t\t}\n")
	}
	fmt.Fprintf(&b, "\t\tif r.Header.Get(\"Authorization\") != %s {\n\t\t\tt.Fatalf(\"Authorization = %%q\", r.Header.Get(\"Authorization\"))\n\t\t}\n", strconv.Quote(request.TokenScheme+" test-token"))
	if request.HealthPath != request.DefaultPath {
		fmt.Fprintf(&b, "\t\tif r.URL.RequestURI() == %s {\n\t\t\tw.WriteHeader(http.StatusNoContent)\n\t\t\treturn\n\t\t}\n", strconv.Quote(renderTestPath(request.HealthPath)))
	}
	fmt.Fprintf(&b, "\t\tif r.URL.Path != %s {\n\t\t\tt.Fatalf(\"path = %%q\", r.URL.Path)\n\t\t}\n", strconv.Quote(renderTestPath(request.DefaultPath)))
	fmt.Fprintf(&b, "\t\tw.Header().Set(\"Content-Type\", \"application/json\")\n")
	fmt.Fprintf(&b, "\t\t_ = json.NewEncoder(w).Encode(map[string]any{\"items\": []map[string]string{{\"id\": \"record-1\", \"resource_urn\": \"urn:cerebro:tenant:runtime_asset:record-1\", \"resource_type\": \"asset\", \"resource_id\": \"record-1\", \"name\": \"Record One\", \"updated_at\": \"2026-06-01T00:00:00Z\"}}})\n")
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
	} else {
		emitCfgValue(request.TokenConfigKey, strconv.Quote("test-token"))
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
	fmt.Fprintf(&b, "\tpull, err := source.Read(context.Background(), cfg, nil)\n\tif err != nil {\n\t\tt.Fatalf(\"Read() error = %%v\", err)\n\t}\n\tif len(pull.Events) != 1 {\n\t\tt.Fatalf(\"events = %%d, want 1\", len(pull.Events))\n\t}\n\tevent := pull.Events[0]\n")
	if request.OAuth != nil {
		fmt.Fprintf(&b, "\tif tokenRequests != 1 {\n\t\tt.Fatalf(\"token requests = %%d, want 1 cached token\", tokenRequests)\n\t}\n")
	}
	fmt.Fprintf(&b, "\tif event.Kind != %s {\n\t\tt.Fatalf(\"kind = %%q\", event.Kind)\n\t}\n\tif strings.TrimSpace(event.Id) == \"\" {\n\t\tt.Fatalf(\"event id is empty: %%#v\", event)\n\t}\n}\n", strconv.Quote(request.Families[0].EventKind))
	return b.String()
}

func testConfigValue(key string) string {
	switch strings.TrimSpace(key) {
	case "domain":
		return "example.test"
	default:
		return "test-" + strings.TrimSpace(key)
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

func renderReadFixture() string {
	fixture := map[string]any{
		"items": []map[string]any{
			{
				"id":                  "record-1",
				"resource_urn":        "urn:cerebro:tenant:runtime_asset:record-1",
				"resource_type":       "asset",
				"resource_id":         "record-1",
				"name":                "Record One",
				"updated_at":          "2026-06-01T00:00:00Z",
				"evidence_cas_uri":    "cas://cases/record-1",
				"evidence_cas_digest": "sha256:test",
			},
		},
	}
	payload, _ := json.MarshalIndent(fixture, "", "  ")
	return string(append(payload, '\n'))
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
	for _, family := range request.Families {
		if projectionFamilyNeedsAugmentation(family) {
			fmt.Fprintf(&b, "var %sProjectionResource = connectordefinitions.ResourceFamily{\n\tID: %s,\n\tProjection: &connectordefinitions.ProjectionSpec{\n", family.ProjectorName, strconv.Quote(family.Name))
			renderProjectionSpecLiteral(&b, family.Projection, "\t\t")
			fmt.Fprintf(&b, "\t},\n}\n\n")
		}
	}
	for _, family := range request.Families {
		switch family.Class {
		case "asset":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, sourcePrefix+"AssetProjections")
			fmt.Fprintf(&b, "}\n\n")
		case "finding":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, sourcePrefix+"FindingProjections")
			fmt.Fprintf(&b, "}\n\n")
		case "secret":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, sourcePrefix+"SecretProjections")
			fmt.Fprintf(&b, "}\n\n")
		case "policy":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, sourcePrefix+"PolicyProjections")
			fmt.Fprintf(&b, "}\n\n")
		case "deployment":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, sourcePrefix+"DeploymentProjections")
			fmt.Fprintf(&b, "}\n\n")
		case "alert":
			fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", family.ProjectorName)
			renderProjectionDispatchReturn(&b, request.SourceID, family, sourcePrefix+"AlertProjections")
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
		fmt.Fprintf(&b, "func %sAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", sourcePrefix)
		fmt.Fprintf(&b, "\ttenantID, err := tenantID(event)\n\tif err != nil {\n\t\treturn nil, nil, err\n\t}\n\tattributes := event.GetAttributes()\n\tresourceID := firstNonEmpty(attributes[\"resource_id\"], attributes[\"external_id\"], event.GetId())\n\tresourceType := firstNonEmpty(attributes[\"resource_type\"], attributes[\"schema\"], \"asset\")\n\tresourceURN := firstNonEmpty(attributes[\"resource_urn\"], projectionURN(tenantID, \"runtime_\"+normalizeCloudType(resourceType), resourceID))\n\tentities := map[string]*ports.ProjectedEntity{}\n\tlinks := map[string]*ports.ProjectedLink{}\n\taddEntity(entities, &ports.ProjectedEntity{URN: resourceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"runtime.\" + strings.ReplaceAll(normalizeCloudType(resourceType), \"_\", \".\"), Label: firstNonEmpty(attributes[\"resource_name\"], resourceID), Attributes: map[string]string{\"resource_id\": resourceID, \"resource_type\": resourceType, \"source_runtime_id\": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})\n\tif evidenceID := strings.TrimSpace(attributes[\"evidence_id\"]); evidenceID != \"\" {\n\t\tevidenceURN := projectionURN(tenantID, \"runtime_evidence\", evidenceID)\n\t\taddEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"runtime.evidence\", Label: evidenceID, Attributes: map[string]string{\"evidence_id\": evidenceID, \"evidence_cas_uri\": strings.TrimSpace(attributes[\"evidence_cas_uri\"]), \"evidence_cas_digest\": strings.TrimSpace(attributes[\"evidence_cas_digest\"])}})\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\treturn identityProjectionResult(entities, links)\n}\n\n")
	}
	if firstFamilyClass(request.Families, "finding").Name != "" {
		fmt.Fprintf(&b, "func %sFindingProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", sourcePrefix)
		fmt.Fprintf(&b, "\ttenantID, err := tenantID(event)\n\tif err != nil {\n\t\treturn nil, nil, err\n\t}\n\tattributes := event.GetAttributes()\n\tfindingID := firstNonEmpty(attributes[\"finding_id\"], event.GetId())\n\tfindingURN := projectionURN(tenantID, \"finding\", findingID)\n\tentities := map[string]*ports.ProjectedEntity{}\n\tlinks := map[string]*ports.ProjectedLink{}\n\taddEntity(entities, &ports.ProjectedEntity{URN: findingURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"finding\", Label: firstNonEmpty(attributes[\"title\"], findingID), Attributes: map[string]string{\"finding_id\": findingID, \"severity\": strings.TrimSpace(attributes[\"severity\"]), \"status\": strings.TrimSpace(attributes[\"status\"]), \"source_runtime_id\": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})\n\tif resourceURN := strings.TrimSpace(attributes[\"resource_urn\"]); resourceURN != \"\" {\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), findingURN, resourceURN, relationAffects, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\tif evidenceID := strings.TrimSpace(attributes[\"evidence_id\"]); evidenceID != \"\" {\n\t\tevidenceURN := projectionURN(tenantID, \"runtime_evidence\", evidenceID)\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, findingURN, relationSupports, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\treturn identityProjectionResult(entities, links)\n}\n")
	}
	if firstFamilyClass(request.Families, "secret").Name != "" {
		fmt.Fprintf(&b, "func %sSecretProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", sourcePrefix)
		fmt.Fprintf(&b, "\ttenantID, err := tenantID(event)\n\tif err != nil {\n\t\treturn nil, nil, err\n\t}\n\tattributes := event.GetAttributes()\n\tsecretID := firstNonEmpty(attributes[\"secret_id\"], event.GetId())\n\tsecretURN := projectionURN(tenantID, \"secret\", secretID)\n\tentities := map[string]*ports.ProjectedEntity{}\n\tlinks := map[string]*ports.ProjectedLink{}\n\taddEntity(entities, &ports.ProjectedEntity{URN: secretURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"secret\", Label: firstNonEmpty(attributes[\"secret_name\"], secretID), Attributes: map[string]string{\"secret_id\": secretID, \"secret_type\": strings.TrimSpace(attributes[\"secret_type\"]), \"secret_status\": strings.TrimSpace(attributes[\"secret_status\"]), \"secret_rotation_enabled\": strings.TrimSpace(attributes[\"secret_rotation_enabled\"]), \"secret_last_rotated_at\": strings.TrimSpace(attributes[\"secret_last_rotated_at\"]), \"source_runtime_id\": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})\n\tif evidenceID := strings.TrimSpace(attributes[\"evidence_id\"]); evidenceID != \"\" {\n\t\tevidenceURN := projectionURN(tenantID, \"runtime_evidence\", evidenceID)\n\t\taddEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"runtime_evidence\", Label: evidenceID, Attributes: map[string]string{\"evidence_id\": evidenceID, \"evidence_cas_uri\": strings.TrimSpace(attributes[\"evidence_cas_uri\"]), \"evidence_cas_digest\": strings.TrimSpace(attributes[\"evidence_cas_digest\"])}})\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), secretURN, evidenceURN, relationHasEvidence, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\treturn identityProjectionResult(entities, links)\n}\n\n")
	}
	if firstFamilyClass(request.Families, "policy").Name != "" {
		fmt.Fprintf(&b, "func %sPolicyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", sourcePrefix)
		fmt.Fprintf(&b, "\ttenantID, err := tenantID(event)\n\tif err != nil {\n\t\treturn nil, nil, err\n\t}\n\tattributes := event.GetAttributes()\n\tpolicyID := firstNonEmpty(attributes[\"policy_id\"], event.GetId())\n\tpolicyURN := projectionURN(tenantID, \"policy\", policyID)\n\tentities := map[string]*ports.ProjectedEntity{}\n\tlinks := map[string]*ports.ProjectedLink{}\n\taddEntity(entities, &ports.ProjectedEntity{URN: policyURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"policy\", Label: firstNonEmpty(attributes[\"policy_name\"], policyID), Attributes: map[string]string{\"policy_id\": policyID, \"policy_type\": strings.TrimSpace(attributes[\"policy_type\"]), \"policy_status\": strings.TrimSpace(attributes[\"policy_status\"]), \"policy_severity\": strings.TrimSpace(attributes[\"policy_severity\"]), \"source_runtime_id\": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})\n\tif evidenceID := strings.TrimSpace(attributes[\"evidence_id\"]); evidenceID != \"\" {\n\t\tevidenceURN := projectionURN(tenantID, \"runtime_evidence\", evidenceID)\n\t\taddEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"runtime_evidence\", Label: evidenceID, Attributes: map[string]string{\"evidence_id\": evidenceID, \"evidence_cas_uri\": strings.TrimSpace(attributes[\"evidence_cas_uri\"]), \"evidence_cas_digest\": strings.TrimSpace(attributes[\"evidence_cas_digest\"])}})\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), policyURN, evidenceURN, relationHasEvidence, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\treturn identityProjectionResult(entities, links)\n}\n")
	}
	if firstFamilyClass(request.Families, "deployment").Name != "" {
		fmt.Fprintf(&b, "func %sDeploymentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", sourcePrefix)
		fmt.Fprintf(&b, "\ttenantID, err := tenantID(event)\n\tif err != nil {\n\t\treturn nil, nil, err\n\t}\n\tattributes := event.GetAttributes()\n\tdeploymentID := firstNonEmpty(attributes[\"deployment_id\"], event.GetId())\n\tdeploymentURN := projectionURN(tenantID, \"deployment\", deploymentID)\n\tentities := map[string]*ports.ProjectedEntity{}\n\tlinks := map[string]*ports.ProjectedLink{}\n\taddEntity(entities, &ports.ProjectedEntity{URN: deploymentURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"deployment\", Label: firstNonEmpty(attributes[\"deployment_name\"], deploymentID), Attributes: map[string]string{\"deployment_id\": deploymentID, \"deployment_environment\": strings.TrimSpace(attributes[\"deployment_environment\"]), \"deployment_status\": strings.TrimSpace(attributes[\"deployment_status\"]), \"deployment_url\": strings.TrimSpace(attributes[\"deployment_url\"]), \"deployment_commit_sha\": strings.TrimSpace(attributes[\"deployment_commit_sha\"]), \"deployment_branch\": strings.TrimSpace(attributes[\"deployment_branch\"]), \"source_runtime_id\": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})\n\tif evidenceID := strings.TrimSpace(attributes[\"evidence_id\"]); evidenceID != \"\" {\n\t\tevidenceURN := projectionURN(tenantID, \"runtime_evidence\", evidenceID)\n\t\taddEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: \"runtime_evidence\", Label: evidenceID, Attributes: map[string]string{\"evidence_id\": evidenceID, \"evidence_cas_uri\": strings.TrimSpace(attributes[\"evidence_cas_uri\"]), \"evidence_cas_digest\": strings.TrimSpace(attributes[\"evidence_cas_digest\"])}})\n\t\taddLink(links, projectedLink(tenantID, event.GetSourceId(), deploymentURN, evidenceURN, relationHasEvidence, map[string]string{\"event_id\": event.GetId()}))\n\t}\n\treturn identityProjectionResult(entities, links)\n}\n")
	}
	if firstFamilyClass(request.Families, "alert").Name != "" {
		fmt.Fprintf(&b, "func %sAlertProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {\n", sourcePrefix)
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
	assetFamily := firstFamilyClass(request.Families, "asset")
	findingFamily := firstFamilyClass(request.Families, "finding")
	secretFamily := firstFamilyClass(request.Families, "secret")
	policyFamily := firstFamilyClass(request.Families, "policy")
	deploymentFamily := firstFamilyClass(request.Families, "deployment")
	alertFamily := firstFamilyClass(request.Families, "alert")
	userFamily := firstFamilyClass(request.Families, "identity_user")
	groupFamily := firstFamilyClass(request.Families, "identity_group")
	membershipFamily := firstFamilyClass(request.Families, "group_membership")
	auditFamily := firstFamilyClass(request.Families, "audit_event")
	evidenceFamily := firstFamilyClass(request.Families, "evidence_cas_reference")
	var b strings.Builder
	fmt.Fprintf(&b, "package sourceprojection\n\n")
	fmt.Fprintf(&b, "import (\n\t\"testing\"\n\n\tcerebrov1 \"github.com/writer/cerebro/gen/cerebro/v1\"\n)\n\n")
	if assetFamily.Class == "asset" {
		fmt.Fprintf(&b, "func Test%sAssetProjection(t *testing.T) {\n", pascalIdentifier(request.SourceID))
		fmt.Fprintf(&b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"resource_id\": \"asset-1\", \"resource_type\": \"host\", \"resource_name\": \"host-1\", \"evidence_id\": \"evidence-1\", \"evidence_cas_uri\": \"cas://cases/evidence-1\", \"evidence_cas_digest\": \"sha256:test\"}}\n", strconv.Quote(request.SourceID), strconv.Quote(assetFamily.EventKind))
		fmt.Fprintf(&b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected entities\")\n\t}\n\tif len(links) == 0 {\n\t\tt.Fatal(\"expected projected evidence links\")\n\t}\n}\n\n", assetFamily.ProjectorName)
	}
	if findingFamily.Class == "finding" {
		fmt.Fprintf(&b, "func Test%sFindingProjection(t *testing.T) {\n", pascalIdentifier(request.SourceID))
		fmt.Fprintf(&b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"finding_id\": \"finding-1\", \"title\": \"Finding One\", \"severity\": \"high\", \"status\": \"open\", \"resource_urn\": \"urn:cerebro:tenant:runtime_asset:asset-1\", \"evidence_id\": \"evidence-1\"}}\n", strconv.Quote(request.SourceID), strconv.Quote(findingFamily.EventKind))
		fmt.Fprintf(&b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected finding\")\n\t}\n\tif len(links) == 0 {\n\t\tt.Fatal(\"expected projected finding links\")\n\t}\n}\n\n", findingFamily.ProjectorName)
	}
	if secretFamily.Class == "secret" {
		fmt.Fprintf(&b, "func Test%sSecretProjection(t *testing.T) {\n", pascalIdentifier(request.SourceID))
		fmt.Fprintf(&b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"secret_id\": \"secret-1\", \"secret_name\": \"DB Password\", \"secret_type\": \"password\", \"secret_status\": \"active\", \"evidence_id\": \"evidence-1\"}}\n", strconv.Quote(request.SourceID), strconv.Quote(secretFamily.EventKind))
		fmt.Fprintf(&b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected secret\")\n\t}\n\tif len(links) == 0 {\n\t\tt.Fatal(\"expected projected evidence links\")\n\t}\n}\n\n", secretFamily.ProjectorName)
	}
	if policyFamily.Class == "policy" {
		fmt.Fprintf(&b, "func Test%sPolicyProjection(t *testing.T) {\n", pascalIdentifier(request.SourceID))
		fmt.Fprintf(&b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"policy_id\": \"policy-1\", \"policy_name\": \"Require MFA\", \"policy_type\": \"access\", \"policy_status\": \"enabled\", \"evidence_id\": \"evidence-1\"}}\n", strconv.Quote(request.SourceID), strconv.Quote(policyFamily.EventKind))
		fmt.Fprintf(&b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected policy\")\n\t}\n\tif len(links) == 0 {\n\t\tt.Fatal(\"expected projected evidence links\")\n\t}\n}\n\n", policyFamily.ProjectorName)
	}
	if deploymentFamily.Class == "deployment" {
		fmt.Fprintf(&b, "func Test%sDeploymentProjection(t *testing.T) {\n", pascalIdentifier(request.SourceID))
		fmt.Fprintf(&b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"deployment_id\": \"dep-1\", \"deployment_name\": \"Production\", \"deployment_environment\": \"production\", \"deployment_status\": \"ready\", \"evidence_id\": \"evidence-1\"}}\n", strconv.Quote(request.SourceID), strconv.Quote(deploymentFamily.EventKind))
		fmt.Fprintf(&b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected deployment\")\n\t}\n\tif len(links) == 0 {\n\t\tt.Fatal(\"expected projected evidence links\")\n\t}\n}\n\n", deploymentFamily.ProjectorName)
	}
	if alertFamily.Class == "alert" {
		fmt.Fprintf(&b, "func Test%sAlertProjection(t *testing.T) {\n", pascalIdentifier(request.SourceID))
		fmt.Fprintf(&b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"alert_id\": \"alert-1\", \"alert_name\": \"High Error Rate\", \"alert_severity\": \"critical\", \"alert_status\": \"open\", \"evidence_id\": \"evidence-1\"}}\n", strconv.Quote(request.SourceID), strconv.Quote(alertFamily.EventKind))
		fmt.Fprintf(&b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected alert\")\n\t}\n\tif len(links) == 0 {\n\t\tt.Fatal(\"expected projected evidence links\")\n\t}\n}\n\n", alertFamily.ProjectorName)
	}
	if userFamily.Class == "identity_user" {
		fmt.Fprintf(&b, "func Test%sIdentityUserProjection(t *testing.T) {\n", pascalIdentifier(request.SourceID))
		fmt.Fprintf(&b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"user_id\": \"user-1\", \"email\": \"user@example.test\", \"display_name\": \"User One\"}}\n", strconv.Quote(request.SourceID), strconv.Quote(userFamily.EventKind))
		fmt.Fprintf(&b, "\tentities, _, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected identity user\")\n\t}\n}\n\n", userFamily.ProjectorName)
	}
	if groupFamily.Class == "identity_group" {
		fmt.Fprintf(&b, "func Test%sIdentityGroupProjection(t *testing.T) {\n", pascalIdentifier(request.SourceID))
		fmt.Fprintf(&b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"group_id\": \"group-1\", \"group_email\": \"group@example.test\", \"group_name\": \"Group One\"}}\n", strconv.Quote(request.SourceID), strconv.Quote(groupFamily.EventKind))
		fmt.Fprintf(&b, "\tentities, _, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 {\n\t\tt.Fatal(\"expected projected identity group\")\n\t}\n}\n\n", groupFamily.ProjectorName)
	}
	if membershipFamily.Class == "group_membership" {
		fmt.Fprintf(&b, "func Test%sGroupMembershipProjection(t *testing.T) {\n", pascalIdentifier(request.SourceID))
		fmt.Fprintf(&b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"group_id\": \"group-1\", \"group_email\": \"group@example.test\", \"member_id\": \"user-1\", \"member_email\": \"user@example.test\"}}\n", strconv.Quote(request.SourceID), strconv.Quote(membershipFamily.EventKind))
		fmt.Fprintf(&b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 || len(links) == 0 {\n\t\tt.Fatalf(\"entities/links = %%d/%%d, want membership projection\", len(entities), len(links))\n\t}\n}\n\n", membershipFamily.ProjectorName)
	}
	if auditFamily.Class == "audit_event" {
		fmt.Fprintf(&b, "func Test%sAuditProjection(t *testing.T) {\n", pascalIdentifier(request.SourceID))
		fmt.Fprintf(&b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"event_type\": \"user.login\", \"actor_id\": \"user-1\", \"actor_email\": \"user@example.test\", \"resource_id\": \"app-1\", \"resource_type\": \"application\"}}\n", strconv.Quote(request.SourceID), strconv.Quote(auditFamily.EventKind))
		fmt.Fprintf(&b, "\tentities, links, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tif len(entities) == 0 || len(links) == 0 {\n\t\tt.Fatalf(\"entities/links = %%d/%%d, want audit projection\", len(entities), len(links))\n\t}\n}\n\n", auditFamily.ProjectorName)
	}
	if evidenceFamily.Class == "evidence_cas_reference" {
		fmt.Fprintf(&b, "func Test%sEvidenceCASProjection(t *testing.T) {\n", pascalIdentifier(request.SourceID))
		fmt.Fprintf(&b, "\tevent := &cerebrov1.EventEnvelope{Id: \"event-1\", TenantId: \"tenant\", SourceId: %s, Kind: %s, Attributes: map[string]string{\"evidence_id\": \"evidence-1\", \"evidence_type\": \"evidence_cas.artifact\", \"source_event_id\": \"provider-event-1\", \"evidence_cas_uri\": \"cas://cases/evidence-1\", \"evidence_cas_digest\": \"sha256:test\"}}\n", strconv.Quote(request.SourceID), strconv.Quote(evidenceFamily.EventKind))
		fmt.Fprintf(&b, "\tentities, _, err := %s(event)\n\tif err != nil {\n\t\tt.Fatalf(\"projection error = %%v\", err)\n\t}\n\tvar foundEvidence bool\n\tfor _, entity := range entities {\n\t\tif entity.EntityType == \"runtime.evidence\" {\n\t\t\tfoundEvidence = true\n\t\t}\n\t}\n\tif !foundEvidence {\n\t\tt.Fatalf(\"entities = %%#v\", entities)\n\t}\n}\n", evidenceFamily.ProjectorName)
	}
	return b.String()
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
