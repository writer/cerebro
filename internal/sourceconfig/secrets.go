package sourceconfig

import (
	"context"
	"regexp"
	"strings"
)

const (
	envPrefix                 = "env:"
	credentialPrefix          = "credential:" // #nosec G101 -- runtime reference prefix, not secret material.
	AWSAssumeRoleAllowlistKey = "__cerebro_aws_assume_role_arns"
	GCPWIFAllowlistKey        = "__cerebro_gcp_wif_bindings" // #nosec G101 -- internal allowlist key, not secret material.
	RuntimeIDKey              = "__cerebro_runtime_id"
	RuntimeTenantIDKey        = "__cerebro_runtime_tenant_id"
)

type Resolver func(context.Context, string, map[string]string) (map[string]string, error)

var awsRoleARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$`)

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

func ValidateAWSCredentialSource(profile string, accessKeyID string, secretAccessKey string, sessionToken string, roleARN string) error {
	if strings.TrimSpace(profile) != "" {
		return sourceConfigError("aws profile is not supported for source runtimes")
	}
	hasRuntimeCredential := strings.TrimSpace(accessKeyID) != "" || strings.TrimSpace(secretAccessKey) != "" || strings.TrimSpace(sessionToken) != ""
	if hasRuntimeCredential {
		if strings.TrimSpace(accessKeyID) == "" || strings.TrimSpace(secretAccessKey) == "" {
			return sourceConfigError("aws access_key_id and secret_access_key must be provided together")
		}
		return nil
	}
	if strings.TrimSpace(roleARN) != "" {
		return nil
	}
	return sourceConfigError("aws access_key_id and secret_access_key or allowlisted role_arn is required")
}

func ValidateAWSAssumeRoleBinding(accountID string, tenantID string, roleARN string, allowlist string) error {
	matches := awsRoleARNPattern.FindStringSubmatch(strings.TrimSpace(roleARN))
	if len(matches) != 3 {
		return sourceConfigError("aws role_arn must be an IAM role ARN")
	}
	if strings.TrimSpace(accountID) != matches[2] {
		return sourceConfigError("aws role_arn account must match account_id")
	}
	if strings.TrimSpace(tenantID) == "" {
		return sourceConfigError("aws role_arn requires runtime tenant_id")
	}
	if !AWSAssumeRoleARNAllowed(tenantID, roleARN, allowlist) {
		return sourceConfigError("aws role_arn is not allowed")
	}
	return nil
}

func AWSAssumeRoleARNAllowed(tenantID string, roleARN string, allowlist string) bool {
	tenantID = strings.TrimSpace(tenantID)
	roleARN = strings.TrimSpace(roleARN)
	if tenantID == "" || roleARN == "" {
		return false
	}
	for _, value := range strings.FieldsFunc(allowlist, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	}) {
		value = strings.TrimSpace(value)
		tenant, arn, ok := strings.Cut(value, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(tenant) == tenantID && strings.TrimSpace(arn) == roleARN {
			return true
		}
	}
	return false
}

func ValidateGCPTokenOrWIF(token string, audience string, serviceAccount string, tenantID string, allowlist string) error {
	if strings.TrimSpace(token) != "" {
		return nil
	}
	if strings.TrimSpace(audience) == "" && strings.TrimSpace(serviceAccount) == "" {
		return sourceConfigError("gcp token or wif_audience and wif_service_account_email are required")
	}
	if strings.TrimSpace(audience) == "" {
		return sourceConfigError("gcp wif_audience is required when token is not provided")
	}
	if strings.TrimSpace(serviceAccount) == "" {
		return sourceConfigError("gcp wif_service_account_email is required when token is not provided")
	}
	return ValidateGCPWIFBinding(tenantID, audience, serviceAccount, allowlist)
}

func ValidateGCPWIFBinding(tenantID string, audience string, serviceAccount string, allowlist string) error {
	if strings.TrimSpace(tenantID) == "" {
		return sourceConfigError("gcp wif auth requires runtime tenant_id")
	}
	if !GCPWIFBindingAllowed(tenantID, audience, serviceAccount, allowlist) {
		return sourceConfigError("gcp wif audience and service account are not allowed")
	}
	return nil
}

func GCPWIFBindingAllowed(tenantID string, audience string, serviceAccount string, allowlist string) bool {
	tenantID = strings.TrimSpace(tenantID)
	audience = strings.TrimSpace(audience)
	serviceAccount = strings.TrimSpace(serviceAccount)
	if tenantID == "" || audience == "" || serviceAccount == "" {
		return false
	}
	for _, value := range strings.FieldsFunc(allowlist, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	}) {
		value = strings.TrimSpace(value)
		tenant, binding, ok := strings.Cut(value, "=")
		if !ok || strings.TrimSpace(tenant) != tenantID {
			continue
		}
		allowedAudience, allowedServiceAccount, ok := strings.Cut(strings.TrimSpace(binding), "|")
		if !ok {
			continue
		}
		if strings.TrimSpace(allowedAudience) == audience && strings.TrimSpace(allowedServiceAccount) == serviceAccount {
			return true
		}
	}
	return false
}

func sourceConfigError(message string) error {
	return &SourceConfigError{Message: strings.TrimSpace(message)}
}

type SourceConfigError struct {
	Message string
}

func (e *SourceConfigError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
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
