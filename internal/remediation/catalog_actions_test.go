package remediation

import "testing"

func TestPublicStorageAccessStillEnabled_ParsesResourceJSON(t *testing.T) {
	execution := &Execution{
		TriggerData: map[string]any{
			"resource_json": `{"public_access":"true"}`,
		},
	}

	public, detail := publicStorageAccessStillEnabled(execution)
	if !public {
		t.Fatalf("public = false, want true (detail=%q)", detail)
	}
}
