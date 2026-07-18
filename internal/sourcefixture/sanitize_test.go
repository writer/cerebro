package sourcefixture

import (
	"strings"
	"testing"
)

func TestSanitizeImportedJSONPreservesShape(t *testing.T) {
	tenantID := "00u" + "1234567890ABCDEFG"
	payload, changed, err := SanitizeImportedJSONWithKeys([]byte(`{"data":[{"email":"person@company.com","firstName":"Alice","name":"Alice's Token","secret":"redacted-value","active":true,"userId":"`+tenantID+`"}]}`), []string{"name"})
	if err != nil {
		t.Fatalf("SanitizeImportedJSON() error = %v", err)
	}
	text := string(payload)
	if strings.Contains(text, "person@company.com") || strings.Contains(text, "Alice") || strings.Contains(text, "redacted-value") || strings.Contains(text, tenantID) || !strings.Contains(text, `"secret": ""`) || !strings.Contains(text, `"active": true`) || !strings.Contains(text, `"userId": "example-`) {
		t.Fatalf("sanitized payload = %s", payload)
	}
	if len(changed) != 5 || changed[0] != "$.data[0].email" || changed[1] != "$.data[0].firstName" || changed[2] != "$.data[0].name" || changed[3] != "$.data[0].secret" || changed[4] != "$.data[0].userId" {
		t.Fatalf("changed fields = %#v", changed)
	}
}
