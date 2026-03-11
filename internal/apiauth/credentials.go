package apiauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Credential struct {
	ID              string            `json:"id"`
	Name            string            `json:"name,omitempty"`
	UserID          string            `json:"user_id"`
	Kind            string            `json:"kind,omitempty"`
	Surface         string            `json:"surface,omitempty"`
	ClientID        string            `json:"client_id,omitempty"`
	Scopes          []string          `json:"scopes,omitempty"`
	RateLimitBucket string            `json:"rate_limit_bucket,omitempty"`
	TenantID        string            `json:"tenant_id,omitempty"`
	Enabled         bool              `json:"enabled"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type CredentialConfig struct {
	Key             string            `json:"key"`
	ID              string            `json:"id,omitempty"`
	Name            string            `json:"name,omitempty"`
	UserID          string            `json:"user_id,omitempty"`
	Kind            string            `json:"kind,omitempty"`
	Surface         string            `json:"surface,omitempty"`
	ClientID        string            `json:"client_id,omitempty"`
	Scopes          []string          `json:"scopes,omitempty"`
	RateLimitBucket string            `json:"rate_limit_bucket,omitempty"`
	TenantID        string            `json:"tenant_id,omitempty"`
	Enabled         *bool             `json:"enabled,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

func ParseCredentialsJSON(value string) (map[string]Credential, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return map[string]Credential{}, nil
	}
	var configs []CredentialConfig
	if err := json.Unmarshal([]byte(value), &configs); err != nil {
		return nil, fmt.Errorf("decode API_CREDENTIALS_JSON: %w", err)
	}
	credentials := make(map[string]Credential, len(configs))
	for _, cfg := range configs {
		key := strings.TrimSpace(cfg.Key)
		if key == "" {
			return nil, fmt.Errorf("credential key is required")
		}
		credential := CredentialFromConfig(cfg)
		if !credential.Enabled {
			continue
		}
		credentials[key] = credential
	}
	return credentials, nil
}

func CredentialFromConfig(cfg CredentialConfig) Credential {
	key := strings.TrimSpace(cfg.Key)
	userID := strings.TrimSpace(cfg.UserID)
	if userID == "" {
		userID = DefaultUserIDForKey(key)
	}
	enabled := true
	if cfg.Enabled != nil {
		enabled = *cfg.Enabled
	}
	credential := Credential{
		ID:              firstNonEmpty(strings.TrimSpace(cfg.ID), DefaultCredentialIDForKey(key)),
		Name:            strings.TrimSpace(cfg.Name),
		UserID:          userID,
		Kind:            firstNonEmpty(strings.TrimSpace(cfg.Kind), "api_key"),
		Surface:         strings.TrimSpace(cfg.Surface),
		ClientID:        strings.TrimSpace(cfg.ClientID),
		Scopes:          normalizeScopes(cfg.Scopes),
		RateLimitBucket: strings.TrimSpace(cfg.RateLimitBucket),
		TenantID:        strings.TrimSpace(cfg.TenantID),
		Enabled:         enabled,
		Metadata:        cloneStringMap(cfg.Metadata),
	}
	if credential.Name == "" {
		credential.Name = credential.ID
	}
	if credential.RateLimitBucket == "" {
		credential.RateLimitBucket = credential.ID
	}
	return credential
}

func DefaultCredentialForAPIKey(key, userID string) Credential {
	if strings.TrimSpace(userID) == "" {
		userID = DefaultUserIDForKey(key)
	}
	id := DefaultCredentialIDForKey(key)
	return Credential{
		ID:              id,
		Name:            id,
		UserID:          strings.TrimSpace(userID),
		Kind:            "api_key",
		Scopes:          nil,
		Enabled:         true,
		RateLimitBucket: id,
	}
}

func DefaultCredentialIDForKey(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return "cred-" + hex.EncodeToString(sum[:8])
}

func DefaultUserIDForKey(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return "api-key-" + hex.EncodeToString(sum[:8])
}

func CredentialsToUserMap(credentials map[string]Credential) map[string]string {
	users := make(map[string]string, len(credentials))
	for key, credential := range credentials {
		if !credential.Enabled {
			continue
		}
		users[key] = strings.TrimSpace(credential.UserID)
	}
	return users
}

func CloneCredentials(credentials map[string]Credential) map[string]Credential {
	cloned := make(map[string]Credential, len(credentials))
	for key, credential := range credentials {
		credential.Metadata = cloneStringMap(credential.Metadata)
		credential.Scopes = append([]string(nil), credential.Scopes...)
		cloned[key] = credential
	}
	return cloned
}

func EqualCredentials(a, b map[string]Credential) bool {
	if len(a) != len(b) {
		return false
	}
	for key, left := range a {
		right, ok := b[key]
		if !ok {
			return false
		}
		left.Metadata = cloneStringMap(left.Metadata)
		right.Metadata = cloneStringMap(right.Metadata)
		left.Scopes = append([]string(nil), left.Scopes...)
		right.Scopes = append([]string(nil), right.Scopes...)
		leftJSON, err := json.Marshal(left)
		if err != nil {
			return false
		}
		rightJSON, err := json.Marshal(right)
		if err != nil {
			return false
		}
		if string(leftJSON) != string(rightJSON) {
			return false
		}
	}
	return true
}

func SortedKeys(credentials map[string]Credential) []string {
	keys := make([]string, 0, len(credentials))
	for key := range credentials {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func LookupCredential(credentials map[string]Credential, key string) (Credential, bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return Credential{}, false
	}
	for candidate, credential := range credentials {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(key)) == 1 {
			if !credential.Enabled {
				return Credential{}, false
			}
			return credential, true
		}
	}
	return Credential{}, false
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

func normalizeScopes(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
