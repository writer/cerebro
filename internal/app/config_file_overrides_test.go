package app

import (
	"os"
	"path/filepath"
	"testing"
)

func resetConfigFileCacheForTest() {
	configFileCacheMu.Lock()
	defer configFileCacheMu.Unlock()
	configFileCachePath = ""
	configFileCacheValues = nil
}

func TestResolveTrustedConfigPathRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CEREBRO_CONFIG_ROOT", root)

	if _, _, _, err := resolveTrustedConfigPath("../outside.yaml"); err == nil {
		t.Fatal("expected traversal path to be rejected")
		return
	}
}

func TestLoadConfigFileValuesCachedWithinTrustedRoot(t *testing.T) {
	resetConfigFileCacheForTest()
	t.Cleanup(resetConfigFileCacheForTest)

	root := t.TempDir()
	configPath := filepath.Join(root, "cerebro.yaml")
	if err := os.WriteFile(configPath, []byte("api_port: 9191\n"), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	t.Setenv("CEREBRO_CONFIG_ROOT", root)

	values, err := loadConfigFileValuesCached("cerebro.yaml")
	if err != nil {
		t.Fatalf("loadConfigFileValuesCached failed: %v", err)
	}

	if got := values["API_PORT"]; got != "9191" {
		t.Fatalf("expected API_PORT=9191, got %q", got)
	}
}
