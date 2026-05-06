package config

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/writer/cerebro/internal/sourceconfig"
)

func ResolveSourceConfigSecretReferences(ctx context.Context, sourceID string, values map[string]string) (map[string]string, error) {
	_ = ctx
	_ = sourceID
	resolved := make(map[string]string, len(values))
	for key, value := range values {
		resolved[key] = value
		if !sourceconfig.IsSecretReference(value) {
			continue
		}
		envName := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "env:"))
		if envName == "" {
			return nil, fmt.Errorf("source config %q has empty env secret reference", strings.TrimSpace(key))
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
	return resolved, nil
}
