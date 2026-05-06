package sourceconfig

import "testing"

func TestSensitiveKeyDetectsCommonSecretNames(t *testing.T) {
	for _, key := range []string{"token", "api_key", "client-secret", "private.key", "password"} {
		if !SensitiveKey(key) {
			t.Fatalf("SensitiveKey(%q) = false, want true", key)
		}
	}
	if SensitiveKey("owner") {
		t.Fatal("SensitiveKey(owner) = true, want false")
	}
}

func TestLiteralEnvPrefixKeyDetectsQueryLikeKeys(t *testing.T) {
	for _, key := range []string{"filter", "phrase", "q", "search"} {
		if !LiteralEnvPrefixKey(key) {
			t.Fatalf("LiteralEnvPrefixKey(%q) = false, want true", key)
		}
	}
	if LiteralEnvPrefixKey("token") {
		t.Fatal("LiteralEnvPrefixKey(token) = true, want false")
	}
}
