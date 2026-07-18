package sourcefixture

import (
	"strings"
	"testing"
)

func TestSanitizeImportedJSONPreservesShape(t *testing.T) {
	payload, changed, err := SanitizeImportedJSON([]byte(`{"data":[{"email":"person@company.com","secret":"redacted-value","active":true}]}`))
	if err != nil {
		t.Fatalf("SanitizeImportedJSON() error = %v", err)
	}
	text := string(payload)
	if strings.Contains(text, "person@company.com") || strings.Contains(text, "redacted-value") || !strings.Contains(text, `"secret": ""`) || !strings.Contains(text, `"active": true`) {
		t.Fatalf("sanitized payload = %s", payload)
	}
	if len(changed) != 2 || changed[0] != "$.data[0].email" || changed[1] != "$.data[0].secret" {
		t.Fatalf("changed fields = %#v", changed)
	}
}
