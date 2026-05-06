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
