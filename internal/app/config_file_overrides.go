package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

var (
	configFileCacheMu     sync.RWMutex
	configFileCachePath   string
	configFileCacheValues map[string]string
)

func lookupConfigFileValue(key string) (string, bool) {
	path := strings.TrimSpace(firstNonEmpty(os.Getenv("CEREBRO_CONFIG_FILE"), os.Getenv("CONFIG_FILE")))
	if path == "" {
		return "", false
	}

	values, err := loadConfigFileValuesCached(path)
	if err != nil {
		return "", false
	}

	value, ok := values[strings.ToUpper(strings.TrimSpace(key))]
	if !ok || value == "" {
		return "", false
	}
	return value, true
}

func loadConfigFileValuesCached(path string) (map[string]string, error) {
	trustedRoot, relPath, absPath, err := resolveTrustedConfigPath(path)
	if err != nil {
		return nil, err
	}

	configFileCacheMu.RLock()
	if configFileCachePath == absPath && configFileCacheValues != nil {
		cached := configFileCacheValues
		configFileCacheMu.RUnlock()
		return cached, nil
	}
	configFileCacheMu.RUnlock()

	values, err := loadConfigFileValues(trustedRoot, relPath, absPath)
	if err != nil {
		return nil, err
	}

	configFileCacheMu.Lock()
	configFileCachePath = absPath
	configFileCacheValues = values
	configFileCacheMu.Unlock()

	return values, nil
}

func trustedConfigRoot() (string, error) {
	root := strings.TrimSpace(os.Getenv("CEREBRO_CONFIG_ROOT"))
	if root == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		root = cwd
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absRoot), nil
}

func resolveTrustedConfigPath(path string) (trustedRoot, relativePath, absolutePath string, err error) {
	trustedRoot, err = trustedConfigRoot()
	if err != nil {
		return "", "", "", err
	}

	candidate := strings.TrimSpace(path)
	if candidate == "" {
		return "", "", "", fmt.Errorf("config file path is required")
	}

	candidate = filepath.Clean(candidate)
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(trustedRoot, candidate)
	}

	absPath, err := filepath.Abs(candidate)
	if err != nil {
		return "", "", "", err
	}
	absPath = filepath.Clean(absPath)

	relPath, err := filepath.Rel(trustedRoot, absPath)
	if err != nil {
		return "", "", "", err
	}
	if relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
		return "", "", "", fmt.Errorf("config path %q escapes trusted root %q", absPath, trustedRoot)
	}

	return trustedRoot, relPath, absPath, nil
}

func loadConfigFileValues(trustedRoot, relativePath, absolutePath string) (map[string]string, error) {
	root, err := os.OpenRoot(trustedRoot)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	file, err := root.Open(relativePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	raw := make(map[string]any)
	switch strings.ToLower(filepath.Ext(absolutePath)) {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
	case ".toml":
		if err := toml.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
	case ".json":
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported config file extension: %s", filepath.Ext(absolutePath))
	}

	flattened := make(map[string]string)
	flattenConfigValues("", raw, flattened)
	return flattened, nil
}

func flattenConfigValues(prefix string, value any, out map[string]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			flattenConfigValues(joinConfigKey(prefix, key), nested, out)
		}
	case map[any]any:
		for key, nested := range typed {
			flattenConfigValues(joinConfigKey(prefix, fmt.Sprint(key)), nested, out)
		}
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, configValueString(item))
		}
		if key := normalizeConfigKey(prefix); key != "" {
			out[key] = strings.Join(parts, ",")
		}
	default:
		if key := normalizeConfigKey(prefix); key != "" {
			out[key] = configValueString(typed)
		}
	}
}

func joinConfigKey(prefix, key string) string {
	key = strings.TrimSpace(key)
	if prefix == "" {
		return key
	}
	if key == "" {
		return prefix
	}
	return prefix + "_" + key
}

func normalizeConfigKey(key string) string {
	replacer := strings.NewReplacer("-", "_", ".", "_", " ", "_")
	normalized := strings.TrimSpace(replacer.Replace(key))
	if normalized == "" {
		return ""
	}
	return strings.ToUpper(normalized)
}

func configValueString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}
