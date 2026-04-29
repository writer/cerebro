package graphingest

import "testing"

func TestSensitiveConfigKeyTreatsKeySuffixesAsSensitive(t *testing.T) {
	for _, key := range []string{"key", "api_key", "private_key"} {
		if !sensitiveConfigKey(key) {
			t.Fatalf("sensitiveConfigKey(%q) = false, want true", key)
		}
	}
}

func TestConfigHashIgnoresSensitiveKeyValues(t *testing.T) {
	left := configHash(map[string]string{
		"api_key": "first",
		"domain":  "writer.okta.com",
	})
	right := configHash(map[string]string{
		"api_key": "second",
		"domain":  "writer.okta.com",
	})
	if left != right {
		t.Fatalf("configHash() differed when only api_key changed")
	}
}
