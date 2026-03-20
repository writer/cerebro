package secretsource

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvSourceLookup(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")

	source := EnvSource{}
	value, ok := source.Lookup("OPENAI_API_KEY")
	if !ok {
		t.Fatal("expected env source lookup to succeed")
	}
	if value != "sk-test" {
		t.Fatalf("expected env value sk-test, got %q", value)
	}
}

func TestFileSourceLookup(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "OPENAI_API_KEY"), []byte(" sk-file \n"), 0o600); err != nil {
		t.Fatalf("write openai secret: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "API_CREDENTIALS_JSON"), []byte(` [{"key":"k","user_id":"u"}] `), 0o600); err != nil {
		t.Fatalf("write api credentials secret: %v", err)
	}

	source, err := New(Config{Kind: KindFile, FileDir: dir})
	if err != nil {
		t.Fatalf("new file source: %v", err)
	}

	value, ok := source.Lookup("OPENAI_API_KEY")
	if !ok || value != "sk-file" {
		t.Fatalf("expected trimmed file-backed key, got %q ok=%v", value, ok)
	}
	jsonValue, ok := source.Lookup("API_CREDENTIALS_JSON")
	if !ok || !strings.Contains(jsonValue, `"key":"k"`) {
		t.Fatalf("expected JSON payload from file source, got %q ok=%v", jsonValue, ok)
	}
}

func TestVaultSourceLookupKV2(t *testing.T) {
	var requestPath string
	var requestNamespace string
	var requestToken string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		requestNamespace = r.Header.Get("X-Vault-Namespace")
		requestToken = r.Header.Get("X-Vault-Token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"data":{"OPENAI_API_KEY":"sk-vault","API_CREDENTIALS_JSON":[{"key":"vault-key","user_id":"vault-user"}]}}}`)
	}))
	defer server.Close()

	source, err := New(Config{
		Kind:           KindVault,
		VaultAddress:   server.URL,
		VaultToken:     "vault-token",
		VaultNamespace: "tenant-a",
		VaultPath:      "secret/cerebro",
		VaultKVVersion: 2,
	})
	if err != nil {
		t.Fatalf("new vault source: %v", err)
	}

	if requestPath != "/v1/secret/data/cerebro" {
		t.Fatalf("expected kv v2 API path, got %q", requestPath)
	}
	if requestNamespace != "tenant-a" {
		t.Fatalf("expected vault namespace tenant-a, got %q", requestNamespace)
	}
	if requestToken != "vault-token" {
		t.Fatalf("expected vault token to be forwarded")
	}

	value, ok := source.Lookup("OPENAI_API_KEY")
	if !ok || value != "sk-vault" {
		t.Fatalf("expected vault source key sk-vault, got %q ok=%v", value, ok)
	}
	jsonValue, ok := source.Lookup("API_CREDENTIALS_JSON")
	if !ok || !strings.Contains(jsonValue, `"vault-key"`) {
		t.Fatalf("expected JSON-encoded structured vault secret, got %q ok=%v", jsonValue, ok)
	}
}

func TestVaultSourceRejectsNonHTTPSRemoteAddress(t *testing.T) {
	_, err := New(Config{
		Kind:           KindVault,
		VaultAddress:   "http://vault.example.com",
		VaultToken:     "vault-token",
		VaultPath:      "secret/cerebro",
		VaultKVVersion: 2,
	})
	if err == nil {
		t.Fatal("expected non-https remote vault address to be rejected")
	}
	if !strings.Contains(err.Error(), "must use https unless it targets localhost or a loopback address") {
		t.Fatalf("unexpected error: %v", err)
	}
}
