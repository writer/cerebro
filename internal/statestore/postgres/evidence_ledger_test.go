package postgres

import (
	"strings"
	"testing"
)

func TestEvidenceLedgerSchemaKeepsTenantAndImmutableRevisionBoundaries(t *testing.T) {
	t.Parallel()
	joined := strings.Join(ensureEvidenceLedgerStatements, "\n")
	for _, required := range []string{
		"PRIMARY KEY (tenant_id, id)",
		"UNIQUE (tenant_id, artifact_id, revision_version)",
		"FOREIGN KEY (tenant_id, artifact_id)",
		"FOREIGN KEY (tenant_id, artifact_version_id)",
		"payload_digest TEXT NOT NULL",
		"content_digest TEXT NOT NULL",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("evidence ledger schema missing %q", required)
		}
	}
	if strings.Contains(joined, "content_bytes") || strings.Contains(joined, "BYTEA") {
		t.Fatal("evidence ledger schema must not store raw evidence bytes")
	}
}

func TestEvidenceJSONDigestIsDeterministic(t *testing.T) {
	t.Parallel()
	left := jsonDigest([]byte(`{"id":"evidence-1"}`))
	right := jsonDigest([]byte(`{"id":"evidence-1"}`))
	if left != right || !strings.HasPrefix(left, "sha256:") {
		t.Fatalf("digests = %q and %q", left, right)
	}
}
