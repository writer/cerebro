package observability

import (
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

func TestSourceRuntimeDiagnosticAttributesIncludeTenantDrilldownFields(t *testing.T) {
	attrs := SourceRuntimeDiagnosticAttributes(SourceRuntimeDiagnosticContext{
		RuntimeID: " writer-okta-user ",
		SourceID:  " okta ",
		TenantID:  " writer ",
	})

	for key, want := range map[string]string{
		"runtime_id":               "writer-okta-user",
		"source_id":                "okta",
		"tenant_id":                "writer",
		"source_runtime.id":        "writer-okta-user",
		"source_runtime.source_id": "okta",
		"source_runtime.tenant_id": "writer",
	} {
		if got := attrs.OTELAttributes(); !attributeSetContains(got, key, want) {
			t.Fatalf("diagnostic attributes missing %s=%q in %#v", key, want, got)
		}
	}
}

func TestSourceProjectionDiagnosticAttributesIncludeTenantDrilldownFields(t *testing.T) {
	attrs := SourceProjectionDiagnosticAttributes(SourceProjectionDiagnosticContext{
		RuntimeID: " writer-github-audit ",
		SourceID:  " github ",
		TenantID:  " writer ",
		EventKind: " github.audit ",
	})

	for key, want := range map[string]string{
		"runtime_id":                   "writer-github-audit",
		"source_id":                    "github",
		"tenant_id":                    "writer",
		"event_kind":                   "github.audit",
		"source_projection.runtime_id": "writer-github-audit",
		"source_projection.source_id":  "github",
		"source_projection.tenant_id":  "writer",
		"source_projection.event_kind": "github.audit",
	} {
		if got := attrs.OTELAttributes(); !attributeSetContains(got, key, want) {
			t.Fatalf("diagnostic attributes missing %s=%q in %#v", key, want, got)
		}
	}
}

func attributeSetContains(attrs []attribute.KeyValue, key string, value string) bool {
	for _, attr := range attrs {
		if string(attr.Key) == key && attr.Value.AsString() == value {
			return true
		}
	}
	return false
}
