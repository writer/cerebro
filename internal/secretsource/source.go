package secretsource

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	KindEnv   = "env"
	KindFile  = "file"
	KindVault = "vault"

	defaultVaultTimeout = 10 * time.Second
)

// Source resolves configuration values from a secret-bearing source.
type Source interface {
	Kind() string
	Lookup(key string) (string, bool)
}

// Config configures a concrete secret source.
type Config struct {
	Kind           string
	FileDir        string
	VaultAddress   string
	VaultToken     string
	VaultNamespace string
	VaultPath      string
	VaultKVVersion int
	HTTPClient     *http.Client
}

// New constructs the configured secret source. The returned source is a
// point-in-time snapshot suitable for one LoadConfig() pass.
func New(cfg Config) (Source, error) {
	switch normalizeKind(cfg.Kind) {
	case KindEnv:
		return EnvSource{}, nil
	case KindFile:
		return newFileSource(cfg.FileDir)
	case KindVault:
		return newVaultSource(cfg)
	default:
		return nil, fmt.Errorf("unsupported credential source %q", strings.TrimSpace(cfg.Kind))
	}
}

func normalizeKind(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		return KindEnv
	}
	return kind
}

// EnvSource resolves values directly from process environment variables.
type EnvSource struct{}

func (EnvSource) Kind() string { return KindEnv }

func (EnvSource) Lookup(key string) (string, bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", false
	}
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

type fileSource struct {
	dir    string
	values map[string]string
}

func newFileSource(dir string) (Source, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("credential file directory is required")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(entries))
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name())
		if name == "" || entry.IsDir() {
			continue
		}
		file, err := root.Open(name)
		if err != nil {
			return nil, fmt.Errorf("open credential file %s: %w", filepath.Join(dir, name), err)
		}
		data, readErr := io.ReadAll(file)
		_ = file.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read credential file %s: %w", filepath.Join(dir, name), readErr)
		}
		value := strings.TrimSpace(string(data))
		if value == "" {
			continue
		}
		values[strings.ToUpper(name)] = value
	}
	return &fileSource{dir: dir, values: values}, nil
}

func (s *fileSource) Kind() string { return KindFile }

func (s *fileSource) Lookup(key string) (string, bool) {
	if s == nil {
		return "", false
	}
	value, ok := s.values[strings.ToUpper(strings.TrimSpace(key))]
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

type vaultSource struct {
	values map[string]string
}

func newVaultSource(cfg Config) (Source, error) {
	address := strings.TrimSpace(cfg.VaultAddress)
	token := strings.TrimSpace(cfg.VaultToken)
	path := strings.TrimSpace(cfg.VaultPath)
	kvVersion := cfg.VaultKVVersion
	if kvVersion == 0 {
		kvVersion = 2
	}
	if address == "" {
		return nil, fmt.Errorf("credential vault address is required")
	}
	if !vaultAddressAllowed(address) {
		return nil, fmt.Errorf("credential vault address must use https unless it targets localhost or a loopback address")
	}
	if token == "" {
		return nil, fmt.Errorf("credential vault token is required")
	}
	if path == "" {
		return nil, fmt.Errorf("credential vault path is required")
	}
	if kvVersion != 1 && kvVersion != 2 {
		return nil, fmt.Errorf("credential vault kv version must be 1 or 2")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultVaultTimeout}
	}

	apiPath := normalizeVaultAPIPath(path, kvVersion)
	url := strings.TrimRight(address, "/") + "/v1/" + apiPath
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	if namespace := strings.TrimSpace(cfg.VaultNamespace); namespace != "" {
		req.Header.Set("X-Vault-Namespace", namespace)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read vault secret %s: %w", apiPath, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read vault response %s: %w", apiPath, err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("vault API error %d for %s: %s", resp.StatusCode, apiPath, strings.TrimSpace(string(body)))
	}

	values, err := decodeVaultValues(body, kvVersion)
	if err != nil {
		return nil, fmt.Errorf("decode vault secret %s: %w", apiPath, err)
	}
	return &vaultSource{values: values}, nil
}

func (s *vaultSource) Kind() string { return KindVault }

func (s *vaultSource) Lookup(key string) (string, bool) {
	if s == nil {
		return "", false
	}
	value, ok := s.values[strings.ToUpper(strings.TrimSpace(key))]
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

func normalizeVaultAPIPath(path string, kvVersion int) string {
	path = strings.Trim(strings.TrimSpace(path), "/")
	if kvVersion != 2 || path == "" {
		return path
	}
	parts := strings.Split(path, "/")
	for idx := 0; idx < len(parts); idx++ {
		if parts[idx] == "data" {
			return path
		}
	}
	if len(parts) == 1 {
		return parts[0] + "/data"
	}
	return parts[0] + "/data/" + strings.Join(parts[1:], "/")
}

func decodeVaultValues(body []byte, kvVersion int) (map[string]string, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	rawData, ok := payload["data"]
	if !ok {
		return map[string]string{}, nil
	}
	if kvVersion == 2 {
		outer, ok := rawData.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("vault kv v2 response data must be an object")
		}
		rawData = outer["data"]
	}
	data, ok := rawData.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("vault response data must be an object")
	}

	values := make(map[string]string, len(data))
	for key, value := range data {
		rendered, ok := renderVaultValue(value)
		if !ok {
			continue
		}
		values[strings.ToUpper(strings.TrimSpace(key))] = rendered
	}
	return values, nil
}

func renderVaultValue(value any) (string, bool) {
	switch typed := value.(type) {
	case nil:
		return "", false
	case string:
		if strings.TrimSpace(typed) == "" {
			return "", false
		}
		return typed, true
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return "", false
		}
		if strings.TrimSpace(string(data)) == "" {
			return "", false
		}
		return string(data), true
	}
}

func vaultAddressAllowed(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "https":
		return parsed.Hostname() != ""
	case "http":
		host := strings.TrimSpace(parsed.Hostname())
		if host == "localhost" {
			return true
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	default:
		return false
	}
}
