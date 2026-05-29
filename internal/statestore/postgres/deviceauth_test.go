package postgres

import (
	"strings"
	"testing"
)

func TestConsumeRefreshTokenLocksDeviceRow(t *testing.T) {
	query := strings.ToUpper(consumeRefreshDeviceStatusSQL)
	for _, want := range []string{
		"FROM DEVICE_RECORDS",
		"WHERE DEVICE_ID = $1",
		"FOR UPDATE",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("consume refresh device status query missing %q: %s", want, consumeRefreshDeviceStatusSQL)
		}
	}
}

func TestDeviceAuthSchemaIncludesRiskObservationStore(t *testing.T) {
	joined := strings.Join(ensureDeviceAuthStatements, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS device_risk_observations",
		"device_id TEXT PRIMARY KEY",
		"observed_at TIMESTAMPTZ NOT NULL",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("device auth schema missing %q:\n%s", want, joined)
		}
	}
}
