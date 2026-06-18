package config

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/writer/cerebro/internal/sourceconfig"
)

const (
	sourceConfigEnvAllowlistEnv = "CEREBRO_SOURCE_CONFIG_ENV_ALLOWLIST"
	awsAssumeRoleARNsEnv        = "CEREBRO_AWS_ASSUME_ROLE_ARNS"
	gcpWIFBindingsEnv           = "CEREBRO_GCP_WIF_BINDINGS" // #nosec G101 -- env var name, not credential material.
)

func ResolveSourceConfigSecretReferences(ctx context.Context, sourceID string, values map[string]string) (map[string]string, error) {
	return resolveSourceConfigSecretReferences(ctx, sourceID, values, true, false)
}

func ResolveSourceRuntimeConfigSecretReferences(ctx context.Context, sourceID string, values map[string]string) (map[string]string, error) {
	return resolveSourceConfigSecretReferences(ctx, sourceID, values, true, true)
}

func resolveSourceConfigSecretReferences(ctx context.Context, sourceID string, values map[string]string, preserveLiteralQueryValues bool, injectRuntimeAllowlist bool) (map[string]string, error) {
	_ = ctx
	resolved := make(map[string]string, len(values))
	for key, value := range values {
		resolved[key] = value
		envName, ok := sourceconfig.SecretReferenceName(value)
		if !ok {
			continue
		}
		if preserveLiteralQueryValues && sourceconfig.LiteralEnvPrefixKey(key) && !SourceConfigEnvReferenceAllowed(sourceID, key, envName) {
			continue
		}
		if envName == "" {
			return nil, fmt.Errorf("source config %q has empty env reference", strings.TrimSpace(key))
		}
		if !SourceConfigEnvReferenceAllowed(sourceID, key, envName) {
			return nil, fmt.Errorf("source config %q references disallowed environment variable %q; use %q or list it in %s", strings.TrimSpace(key), envName, sourceConfigEnvName(sourceID, key), sourceConfigEnvAllowlistEnv)
		}
		secret, ok := os.LookupEnv(envName)
		if !ok {
			return nil, fmt.Errorf("source config %q references unset environment variable %q", strings.TrimSpace(key), envName)
		}
		if sourceconfig.SensitiveKey(key) && strings.TrimSpace(secret) == "" {
			return nil, fmt.Errorf("source config %q references empty environment variable %q", strings.TrimSpace(key), envName)
		}
		resolved[key] = secret
	}
	if injectRuntimeAllowlist && (strings.EqualFold(strings.TrimSpace(sourceID), "aws") || strings.TrimSpace(values["role_arn"]) != "") {
		resolved[sourceconfig.AWSAssumeRoleAllowlistKey] = strings.TrimSpace(os.Getenv(awsAssumeRoleARNsEnv))
	}
	if injectRuntimeAllowlist && (strings.EqualFold(strings.TrimSpace(sourceID), "gcp") || strings.TrimSpace(values["wif_audience"]) != "" || strings.TrimSpace(values["wif_service_account_email"]) != "") {
		resolved[sourceconfig.GCPWIFAllowlistKey] = strings.TrimSpace(os.Getenv(gcpWIFBindingsEnv))
	}
	return resolved, nil
}

func SourceConfigEnvReferenceAllowed(sourceID string, key string, envName string) bool {
	trimmedEnvName := strings.TrimSpace(envName)
	if trimmedEnvName == "" {
		return false
	}
	if trimmedEnvName == sourceConfigEnvName(sourceID, key) {
		return true
	}
	for _, allowed := range strings.Split(os.Getenv(sourceConfigEnvAllowlistEnv), ",") {
		if strings.TrimSpace(allowed) == trimmedEnvName {
			return true
		}
	}
	return false
}

func sourceConfigEnvName(sourceID string, key string) string {
	return "CEREBRO_SOURCE_" + sourceConfigEnvComponent(sourceID) + "_" + sourceConfigEnvComponent(key)
}

func sourceConfigEnvComponent(value string) string {
	var builder strings.Builder
	for _, char := range strings.TrimSpace(value) {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char - 'a' + 'A')
		case char >= 'A' && char <= 'Z':
			builder.WriteRune(char)
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
		default:
			builder.WriteByte('_')
		}
	}
	component := strings.Trim(builder.String(), "_")
	if component == "" {
		return "CONFIG"
	}
	return component
}
