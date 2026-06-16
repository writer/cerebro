package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsConnectorCredentialIdempotencyConflict(t *testing.T) {
	err := &pgconn.PgError{
		Code:           "23505",
		ConstraintName: "connector_credentials_idempotency_idx",
	}
	if !isConnectorCredentialIdempotencyConflict(err) {
		t.Fatal("isConnectorCredentialIdempotencyConflict() = false, want true")
	}
	if isConnectorCredentialIdempotencyConflict(errors.New("not unique")) {
		t.Fatal("isConnectorCredentialIdempotencyConflict(non-pg error) = true, want false")
	}
	if isConnectorCredentialIdempotencyConflict(&pgconn.PgError{
		Code:           "23505",
		ConstraintName: "connector_credentials_pkey",
	}) {
		t.Fatal("isConnectorCredentialIdempotencyConflict(primary key conflict) = true, want false")
	}
}
