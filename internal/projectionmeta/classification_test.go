package projectionmeta

import "testing"

func TestClassifyEntityDistinguishesDurableEvidenceLifecycleAndEphemeral(t *testing.T) {
	for _, tc := range []struct {
		name       string
		entityType string
		attrs      map[string]string
		want       string
	}{
		{name: "durable default", entityType: "github.code.repository", want: ClassDurableState},
		{name: "runtime evidence", entityType: "runtime.evidence", want: ClassEvidence},
		{name: "finding lifecycle", entityType: "finding", want: ClassLifecycleState},
		{name: "activity event", entityType: "sentinelone.activity", want: ClassEphemeralEvent},
		{name: "hosted workflow runner", entityType: "github.runner", attrs: map[string]string{"action": "workflows.completed"}, want: ClassEphemeralEvent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyEntity(tc.entityType, tc.attrs).Class; got != tc.want {
				t.Fatalf("ClassifyEntity(%q) = %q, want %q", tc.entityType, got, tc.want)
			}
		})
	}
}

func TestApplyEntityMetadataPreservesExplicitClassification(t *testing.T) {
	attrs := ApplyEntityMetadata("finding", map[string]string{
		AttributeProjectionClass: "custom",
		"status":                 "open",
	})

	if attrs[AttributeProjectionClass] != "custom" {
		t.Fatalf("projection class = %q, want explicit custom", attrs[AttributeProjectionClass])
	}
	if attrs[AttributeProjectionReason] == "" {
		t.Fatal("projection reason was not populated")
	}
	if attrs["status"] != "open" {
		t.Fatalf("status = %q, want open", attrs["status"])
	}
}
