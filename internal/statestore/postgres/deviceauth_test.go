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
