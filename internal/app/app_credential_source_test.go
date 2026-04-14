package app

import (
	"strings"
	"testing"
)

func TestCredentialVaultAddressAllowed(t *testing.T) {
	cases := []struct {
		name    string
		address string
		want    bool
	}{
		{name: "https remote", address: "https://vault.example.com", want: true},
		{name: "http localhost", address: "http://localhost:8200", want: true},
		{name: "http loopback", address: "http://127.0.0.1:8200", want: true},
		{name: "http remote", address: "http://vault.example.com", want: false},
		{name: "invalid scheme", address: "ftp://vault.example.com", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := credentialVaultAddressAllowed(tc.address); got != tc.want {
				t.Fatalf("credentialVaultAddressAllowed(%q) = %v, want %v", tc.address, got, tc.want)
			}
		})
	}
}

func TestLoadConfigCredentialVaultAddressValidation(t *testing.T) {
	t.Setenv("CEREBRO_CREDENTIAL_SOURCE", "vault")
	t.Setenv("CEREBRO_CREDENTIAL_VAULT_ADDRESS", "http://vault.example.com")
	t.Setenv("CEREBRO_CREDENTIAL_VAULT_TOKEN", "bootstrap-token")
	t.Setenv("CEREBRO_CREDENTIAL_VAULT_PATH", "secret/cerebro")

	cfg := LoadConfig()
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for non-https remote vault address")
		return
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "CEREBRO_CREDENTIAL_VAULT_ADDRESS must use https unless it targets localhost or a loopback address") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestCredentialSourceEligibleKeyUsesExplicitAllowlist(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{key: "OPENAI_API_KEY", want: true},
		{key: "API_KEYS", want: true},
		{key: "GRAPH_CROSS_TENANT_SIGNING_KEY", want: false},
		{key: "FINDING_ATTESTATION_SIGNING_KEY", want: false},
		{key: "API_AUTH_ENABLED", want: false},
		{key: "LOG_LEVEL", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			if got := credentialSourceEligibleKey(tc.key); got != tc.want {
				t.Fatalf("credentialSourceEligibleKey(%q) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}
