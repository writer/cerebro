package sourceconfig

import (
	"context"
	"strings"
)

const (
	envPrefix                 = "env:"
	credentialPrefix          = "credential:"
	AWSAssumeRoleAllowlistKey = "__cerebro_aws_assume_role_arns"
	RuntimeIDKey              = "__cerebro_runtime_id"
	RuntimeTenantIDKey        = "__cerebro_runtime_tenant_id"
)

type Resolver func(context.Context, string, map[string]string) (map[string]string, error)

func IsSecretReference(value string) bool {
	_, ok := SecretReferenceName(value)
	return ok
}

func IsCredentialReference(value string) bool {
	_, _, ok := CredentialReference(value)
	return ok
}

func CredentialReference(value string) (string, string, bool) {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, credentialPrefix) {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(trimmed, credentialPrefix), ":")
	if len(parts) != 2 {
		return "", "", false
	}
	id := strings.TrimSpace(parts[0])
	field := strings.TrimSpace(parts[1])
	return id, field, id != "" && field != ""
}

func CredentialReferenceValue(id string, field string) string {
	return credentialPrefix + strings.TrimSpace(id) + ":" + strings.TrimSpace(field)
}

func SecretReferenceName(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, envPrefix) {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(trimmed, envPrefix)), true
}

func LiteralEnvPrefixKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "filter", "phrase", "q", "search":
		return true
	default:
		return false
	}
}

func InternalKey(key string) bool {
	return strings.HasPrefix(strings.TrimSpace(key), "__cerebro_")
}

func WithRuntimeTenant(values map[string]string, tenantID string) map[string]string {
	return WithRuntimeContext(values, tenantID, "")
}

func WithRuntimeContext(values map[string]string, tenantID string, runtimeID string) map[string]string {
	cloned := make(map[string]string, len(values)+2)
	for key, value := range values {
		cloned[key] = value
	}
	if runtimeID := strings.TrimSpace(runtimeID); runtimeID != "" {
		cloned[RuntimeIDKey] = runtimeID
	}
	if tenantID := strings.TrimSpace(tenantID); tenantID != "" {
		cloned[RuntimeTenantIDKey] = tenantID
	}
	return cloned
}

func SensitiveKey(key string) bool {
	value := strings.ToLower(strings.TrimSpace(key))
	if value == "" {
		return false
	}
	if strings.Contains(value, "token") || strings.Contains(value, "secret") || strings.Contains(value, "password") {
		return true
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(value)
	if strings.Contains(compact, "apikey") || strings.Contains(compact, "privatekey") {
		return true
	}
	return value == "key" || compact == "key"
}
