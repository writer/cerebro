package connectorsecretstores

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/sourceconfig"
)

const (
	StoreInfisical         = "infisical"
	StoreGoogleSecretMgr   = "google_secret_manager"
	StoreAWSSecretsManager = "aws_secrets_manager"
	StoreAzureKeyVault     = "azure_key_vault"
	StoreHashiCorpVault    = "hashicorp_vault"

	PrefixInfisical         = "infisical:"
	PrefixGoogleSecretMgr   = "gsm:"
	PrefixAWSSecretsManager = "aws-sm:"
	PrefixAzureKeyVault     = "azkv:"
	PrefixHashiCorpVault    = "vault:"
)

var (
	ErrInvalidReference    = errors.New("invalid connector secret reference")
	ErrResolverUnavailable = errors.New("connector secret-store resolver unavailable")

	awsRegionPrefixPattern = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z0-9-]+-\d$`)
)

// Reference is the parsed, non-secret address of a value in an operator-managed
// secret store. The value identifies where the backend should fetch the secret;
// it never contains the secret material itself.
type Reference struct {
	StoreID  string
	Prefix   string
	Raw      string
	SecretID string
	Region   string
	Field    string
}

type awsSecretsManagerAPI interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type awsClientFactory func(context.Context, config.AWSSecretsManagerStoreConfig, Reference) (awsSecretsManagerAPI, error)

// Resolver resolves native connector secret-store references that are not
// handled by the existing env: and credential: runtime resolvers.
type Resolver struct {
	cfg              config.ConnectorSecretStoreConfig
	awsClientFactory awsClientFactory
}

// NewResolver constructs a resolver chain for configured connector secret stores.
func NewResolver(cfg config.ConnectorSecretStoreConfig) *Resolver {
	return &Resolver{
		cfg:              cfg,
		awsClientFactory: newAWSSecretsManagerClient,
	}
}

// ReferencePrefixes returns the accepted non-secret reference prefixes for one
// connector store. env: is intentionally included for stores that are projected
// into the deployment environment by an external controller or CLI.
func ReferencePrefixes(storeID string) []string {
	switch strings.TrimSpace(storeID) {
	case StoreAWSSecretsManager:
		return []string{"env:", PrefixAWSSecretsManager}
	default:
		return []string{"env:"}
	}
}

// NativeReferencePrefix returns the store-native reference prefix, if the store
// has one.
func NativeReferencePrefix(storeID string) string {
	switch strings.TrimSpace(storeID) {
	case StoreInfisical:
		return PrefixInfisical
	case StoreGoogleSecretMgr:
		return PrefixGoogleSecretMgr
	case StoreAWSSecretsManager:
		return PrefixAWSSecretsManager
	case StoreAzureKeyVault:
		return PrefixAzureKeyVault
	case StoreHashiCorpVault:
		return PrefixHashiCorpVault
	default:
		return ""
	}
}

// NativeResolutionAvailable reports whether Cerebro can fetch native references
// for the store without relying on deployment-side env projection.
func NativeResolutionAvailable(cfg config.ConnectorSecretStoreConfig, storeID string) bool {
	switch strings.TrimSpace(storeID) {
	case StoreAWSSecretsManager:
		return StoreEnabled(cfg, storeID) && strings.TrimSpace(cfg.AWSSecretsManager.Region) != ""
	default:
		return false
	}
}

// StoreEnabled reports whether an operator explicitly enabled a reference store.
func StoreEnabled(cfg config.ConnectorSecretStoreConfig, storeID string) bool {
	normalized := strings.TrimSpace(storeID)
	if normalized == "" {
		return false
	}
	for _, enabled := range cfg.Enabled {
		if strings.TrimSpace(enabled) == normalized {
			return true
		}
	}
	return false
}

// IsReference reports whether value is a supported non-secret reference shape.
func IsReference(value string) bool {
	if sourceconfig.IsSecretReference(value) {
		return true
	}
	_, ok, err := ParseReference(value)
	return ok && err == nil
}

// ValidateReferenceForStore checks that a non-secret reference belongs to the
// selected store. env: references are accepted for reference stores because
// Infisical, GSM, Vault, and other controllers commonly project secret-store
// values into the Cerebro runtime environment.
func ValidateReferenceForStore(storeID string, value string) error {
	if sourceconfig.IsSecretReference(value) {
		return nil
	}
	ref, ok, err := ParseReference(value)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: reference must start with one of %s", ErrInvalidReference, strings.Join(ReferencePrefixes(storeID), ", "))
	}
	if ref.StoreID != strings.TrimSpace(storeID) {
		return fmt.Errorf("%w: %s reference cannot be used with %s", ErrInvalidReference, ref.StoreID, strings.TrimSpace(storeID))
	}
	if ref.StoreID != StoreAWSSecretsManager {
		return fmt.Errorf("%w: native %s references are not supported yet; use env: projection", ErrInvalidReference, ref.StoreID)
	}
	return nil
}

// RuntimeSecretPrefix returns the operator-managed secret namespace that a
// runtime is allowed to dereference natively.
func RuntimeSecretPrefix(tenantID string, sourceID string, runtimeID string) string {
	tenantSegment := referencePathSegment(tenantID)
	sourceSegment := referencePathSegment(sourceID)
	runtimeSegment := referencePathSegment(runtimeID)
	if tenantSegment == "" || sourceSegment == "" || runtimeSegment == "" {
		return ""
	}
	return "cerebro/" + tenantSegment + "/" + sourceSegment + "/" + runtimeSegment + "/"
}

// AuthorizeRuntimeReferences checks that native references are constrained to
// the requesting runtime's secret namespace before any backend resolver uses
// operator credentials to fetch them.
func AuthorizeRuntimeReferences(sourceID string, tenantID string, runtimeID string, values map[string]string) error {
	prefix := RuntimeSecretPrefix(tenantID, sourceID, runtimeID)
	for key, value := range values {
		ref, ok, err := ParseReference(value)
		if err != nil {
			return err
		}
		if !ok || ref.StoreID != StoreAWSSecretsManager {
			continue
		}
		if prefix == "" {
			return fmt.Errorf("%w: aws-sm reference %q requires tenant, source, and runtime scope", ErrInvalidReference, strings.TrimSpace(key))
		}
		if !strings.HasPrefix(awsSecretName(ref.SecretID), prefix) {
			return fmt.Errorf("%w: aws-sm reference %q must use scoped secret prefix %q", ErrInvalidReference, strings.TrimSpace(key), prefix)
		}
	}
	return nil
}

// ParseReference parses a store-native reference. env: and credential: are
// handled elsewhere and return ok=false here.
func ParseReference(value string) (Reference, bool, error) {
	trimmed := strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(trimmed, PrefixAWSSecretsManager):
		return parseAWSReference(strings.TrimPrefix(trimmed, PrefixAWSSecretsManager))
	case strings.HasPrefix(trimmed, PrefixGoogleSecretMgr):
		return parseOpaqueReference(StoreGoogleSecretMgr, PrefixGoogleSecretMgr, strings.TrimPrefix(trimmed, PrefixGoogleSecretMgr))
	case strings.HasPrefix(trimmed, PrefixAzureKeyVault):
		return parseOpaqueReference(StoreAzureKeyVault, PrefixAzureKeyVault, strings.TrimPrefix(trimmed, PrefixAzureKeyVault))
	case strings.HasPrefix(trimmed, PrefixHashiCorpVault):
		return parseOpaqueReference(StoreHashiCorpVault, PrefixHashiCorpVault, strings.TrimPrefix(trimmed, PrefixHashiCorpVault))
	case strings.HasPrefix(trimmed, PrefixInfisical):
		return parseOpaqueReference(StoreInfisical, PrefixInfisical, strings.TrimPrefix(trimmed, PrefixInfisical))
	default:
		return Reference{}, false, nil
	}
}

// ResolveReferences resolves all native connector secret-store references in
// values. env: and credential: references are intentionally left untouched for
// the existing runtime resolvers.
func (r *Resolver) ResolveReferences(ctx context.Context, values map[string]string) (map[string]string, error) {
	if values == nil {
		return map[string]string{}, nil
	}
	resolved := make(map[string]string, len(values))
	for key, value := range values {
		resolved[key] = value
		ref, ok, err := ParseReference(value)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		secret, err := r.Resolve(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("resolve connector secret reference %q: %w", strings.TrimSpace(key), err)
		}
		resolved[key] = secret
	}
	return resolved, nil
}

// Resolve resolves one parsed native reference.
func (r *Resolver) Resolve(ctx context.Context, ref Reference) (string, error) {
	if r == nil {
		return "", ErrResolverUnavailable
	}
	if !StoreEnabled(r.cfg, ref.StoreID) {
		return "", fmt.Errorf("%w: %s is not enabled", ErrResolverUnavailable, ref.StoreID)
	}
	switch ref.StoreID {
	case StoreAWSSecretsManager:
		if strings.TrimSpace(r.cfg.AWSSecretsManager.Region) == "" && strings.TrimSpace(ref.Region) == "" {
			return "", fmt.Errorf("%w: CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_REGION is required", ErrResolverUnavailable)
		}
		client, err := r.awsClientFactory(ctx, r.cfg.AWSSecretsManager, ref)
		if err != nil {
			return "", err
		}
		return resolveAWSSecret(ctx, client, ref)
	default:
		return "", fmt.Errorf("%w: native %s references require deployment-side env projection", ErrResolverUnavailable, ref.StoreID)
	}
}

func parseAWSReference(body string) (Reference, bool, error) {
	secretID, field := splitReferenceField(body)
	if strings.TrimSpace(secretID) == "" {
		return Reference{}, true, fmt.Errorf("%w: aws-sm reference requires a secret id", ErrInvalidReference)
	}
	ref := Reference{StoreID: StoreAWSSecretsManager, Prefix: PrefixAWSSecretsManager, Raw: strings.TrimSpace(body), SecretID: strings.TrimSpace(secretID), Field: strings.TrimSpace(field)}
	if strings.HasPrefix(ref.SecretID, "arn:") {
		parts := strings.Split(ref.SecretID, ":")
		if len(parts) > 3 {
			ref.Region = strings.TrimSpace(parts[3])
		}
		return ref, true, nil
	}
	before, after, hasRegion := strings.Cut(ref.SecretID, ":")
	if hasRegion && awsRegionPrefixPattern.MatchString(before) && strings.TrimSpace(after) != "" {
		ref.Region = strings.TrimSpace(before)
		ref.SecretID = strings.TrimSpace(after)
	}
	return ref, true, nil
}

func parseOpaqueReference(storeID string, prefix string, body string) (Reference, bool, error) {
	secretID, field := splitReferenceField(body)
	if strings.TrimSpace(secretID) == "" {
		return Reference{}, true, fmt.Errorf("%w: %s reference requires a secret id", ErrInvalidReference, prefix)
	}
	return Reference{
		StoreID:  storeID,
		Prefix:   prefix,
		Raw:      strings.TrimSpace(body),
		SecretID: strings.TrimSpace(secretID),
		Field:    strings.TrimSpace(field),
	}, true, nil
}

func splitReferenceField(body string) (string, string) {
	secretID, field, ok := strings.Cut(strings.TrimSpace(body), "#")
	if !ok {
		return secretID, ""
	}
	return strings.TrimSpace(secretID), strings.TrimSpace(field)
}

func awsSecretName(secretID string) string {
	trimmed := strings.TrimSpace(secretID)
	if index := strings.LastIndex(trimmed, ":secret:"); index >= 0 {
		return strings.TrimSpace(trimmed[index+len(":secret:"):])
	}
	return trimmed
}

func referencePathSegment(value string) string {
	var builder strings.Builder
	for _, char := range strings.TrimSpace(value) {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char)
		case char >= 'A' && char <= 'Z':
			builder.WriteRune(char)
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
		case char == '-' || char == '_' || char == '.':
			builder.WriteRune(char)
		default:
			builder.WriteByte('_')
		}
	}
	return strings.Trim(builder.String(), "_")
}

func newAWSSecretsManagerClient(ctx context.Context, cfg config.AWSSecretsManagerStoreConfig, ref Reference) (awsSecretsManagerAPI, error) {
	region := strings.TrimSpace(ref.Region)
	if region == "" {
		region = strings.TrimSpace(cfg.Region)
	}
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if profile := strings.TrimSpace(cfg.Profile); profile != "" {
		options = append(options, awsconfig.WithSharedConfigProfile(profile))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("load aws config for connector secret store: %w", err)
	}
	if roleARN := strings.TrimSpace(cfg.RoleARN); roleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsCfg), roleARN, func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = "cerebro-connector-secret-store"
			if externalID := strings.TrimSpace(cfg.ExternalID); externalID != "" {
				options.ExternalID = awssdk.String(externalID)
			}
		})
		awsCfg.Credentials = awssdk.NewCredentialsCache(provider)
	}
	return secretsmanager.NewFromConfig(awsCfg, func(options *secretsmanager.Options) {
		if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
			options.BaseEndpoint = awssdk.String(endpoint)
		}
	}), nil
}

func resolveAWSSecret(ctx context.Context, client awsSecretsManagerAPI, ref Reference) (string, error) {
	if client == nil {
		return "", ErrResolverUnavailable
	}
	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: awssdk.String(ref.SecretID)})
	if err != nil {
		return "", err
	}
	secretValue := ""
	switch {
	case out.SecretString != nil:
		secretValue = awssdk.ToString(out.SecretString)
	case len(out.SecretBinary) > 0:
		secretValue = base64.StdEncoding.EncodeToString(out.SecretBinary)
	default:
		return "", fmt.Errorf("%w: AWS Secrets Manager returned an empty secret value", ErrInvalidReference)
	}
	if strings.TrimSpace(ref.Field) == "" {
		return secretValue, nil
	}
	return jsonField(secretValue, ref.Field)
}

func jsonField(secretValue string, field string) (string, error) {
	var object map[string]any
	decoder := json.NewDecoder(strings.NewReader(secretValue))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		return "", fmt.Errorf("%w: referenced field requires a JSON secret string", ErrInvalidReference)
	}
	value, ok := object[strings.TrimSpace(field)]
	if !ok {
		return "", fmt.Errorf("%w: referenced field %q is missing", ErrInvalidReference, strings.TrimSpace(field))
	}
	switch typed := value.(type) {
	case string:
		return typed, nil
	case json.Number:
		return typed.String(), nil
	case bool:
		return fmt.Sprint(typed), nil
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return "", fmt.Errorf("%w: referenced field %q is not string-serializable", ErrInvalidReference, strings.TrimSpace(field))
		}
		return string(encoded), nil
	}
}
