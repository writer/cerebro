package postgres

import (
	"strings"
	"testing"
)

func TestSourceRuntimePageLedgerSchemaSeparatesCapturedAndPendingQuarantines(t *testing.T) {
	joined := strings.Join(ensureSourceRuntimePageLedgerStatements, "\n")
	for _, fragment := range []string{
		"admission_contracts_json JSONB",
		"source_runtime_event_quarantine",
		"PRIMARY KEY (tenant_id, quarantine_id)",
		"state IN ('captured', 'pending', 'resolved', 'discarded')",
		"source_runtime_event_quarantine_runtime_state_idx",
		"source_runtime_page_quarantine",
		"PRIMARY KEY (attempt_id, input_index)",
		"FOREIGN KEY (tenant_id, quarantine_id)",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("source runtime page ledger schema missing %q:\n%s", fragment, joined)
		}
	}
}
