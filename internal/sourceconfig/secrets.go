package sourceconfig

import (
	"context"
	"strings"
)

const envPrefix = "env:"

type Resolver func(context.Context, string, map[string]string) (map[string]string, error)

func IsSecretReference(value string) bool {
	_, ok := SecretReferenceName(value)
	return ok
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
