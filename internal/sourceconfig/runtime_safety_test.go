package sourceconfig

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRuntimeConfigSafetyCredentialReferencesRemainOpaque(t *testing.T) {
	value := CredentialReferenceValue("credential-id", "token")
	if !IsCredentialReference(value) {
		t.Fatalf("IsCredentialReference(%q) = false, want true", value)
	}
	id, field, ok := CredentialReference(" " + value + " ")
	if !ok || id != "credential-id" || field != "token" {
		t.Fatalf("CredentialReference() = (%q, %q, %t), want credential-id token true", id, field, ok)
	}
	if IsCredentialReference("credential:credential-id:token:extra") {
		t.Fatal("CredentialReference accepted an over-broad reference")
	}
}

func TestSourceRuntimeRejectsSecretLeakage(t *testing.T) {
	err := sourceConfigError("credential lease rejected")
	var configErr *SourceConfigError
	if !errors.As(err, &configErr) || configErr.Message != "credential lease rejected" {
		t.Fatalf("source config error = %#v, want typed redacted error", err)
	}
	for _, key := range []string{"api_key", "clientSecret", "bearer-token", "private.key", "password"} {
		if !SensitiveKey(key) {
			t.Fatalf("SensitiveKey(%q) = false, want true", key)
		}
	}
}

func TestRedactedRuntimeConfigPreservation(t *testing.T) {
	redacted := strings.Repeat("*", 8)
	prior := map[string]string{
		"token":        "credential:credential-id:token",
		"organization": "writer",
	}
	update := map[string]string{
		"token":        redacted,
		"organization": "writer-platform",
	}
	restored, err := PreserveRedactedRuntimeConfig(prior, update, redacted)
	if err != nil {
		t.Fatalf("PreserveRedactedRuntimeConfig() error = %v", err)
	}
	if restored["token"] != prior["token"] {
		t.Fatalf("restored token = %q, want prior reference", restored["token"])
	}
	if restored["organization"] != "writer-platform" {
		t.Fatalf("restored organization = %q", restored["organization"])
	}
}

func TestRuntimeConfigResolverFailureDoesNotExposeSecret(t *testing.T) {
	resolverFailure := errors.New("resolver failed")
	resolver := Resolver(func(context.Context, string, map[string]string) (map[string]string, error) {
		return nil, resolverFailure
	})
	_, err := resolver(context.Background(), "source-a", map[string]string{"token": "secret-sentinel"})
	if err == nil {
		t.Fatal("resolver error = nil, want non-nil")
	}
	if !errors.Is(err, resolverFailure) {
		t.Fatalf("resolver error = %v, want original typed failure", err)
	}
}
