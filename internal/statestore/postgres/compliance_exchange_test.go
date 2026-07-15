package postgres

import (
	"strings"
	"testing"
)

func TestComplianceExchangeSchemaKeepsImportStateTenantScopedAndDurable(t *testing.T) {
	joined := strings.Join(ensureComplianceExchangeStatements, "\n")
	for _, fragment := range []string{
		"compliance_exchange_staged_packages",
		"compliance_exchange_staged_files",
		"compliance_exchange_validations",
		"compliance_exchange_commit_intents",
		"PRIMARY KEY (tenant_id, id)",
		"file_ordinal INTEGER NOT NULL",
		"PRIMARY KEY (tenant_id, staging_id, file_ordinal)",
		"PRIMARY KEY (tenant_id, staging_id, request_digest)",
		"UNIQUE (tenant_id, idempotency_key)",
		"FOREIGN KEY (tenant_id, staging_id)",
		"manifest_bytes BYTEA",
		"content BYTEA",
		"validation_result_json JSONB",
		"signature_receipt_json JSONB",
		"expected_staging_version BIGINT",
		"authorized_at TIMESTAMPTZ",
		"expires_at TIMESTAMPTZ",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("compliance exchange schema missing %q:\n%s", fragment, joined)
		}
	}
}

func TestComplianceExchangeSchemaDoesNotWriteCanonicalDomainTables(t *testing.T) {
	joined := strings.ToLower(strings.Join(ensureComplianceExchangeStatements, "\n"))
	for _, table := range []string{"grc_programs", "grc_assessments", "grc_work_items", "findings", "resources"} {
		if strings.Contains(joined, "insert into "+table) || strings.Contains(joined, "update "+table) {
			t.Fatalf("compliance exchange staging schema mutates canonical table %q", table)
		}
	}
}
