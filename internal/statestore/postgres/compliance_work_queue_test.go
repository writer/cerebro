package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/complianceremediation"
)

func TestComplianceWorkItemCursorRoundTripAndMalformedInput(t *testing.T) {
	want := complianceWorkItemCursor{UpdatedAt: time.Date(2026, 7, 15, 12, 0, 0, 123, time.UTC), ID: "work-a"}
	encoded, err := encodeComplianceWorkItemCursor(want)
	if err != nil {
		t.Fatalf("encodeComplianceWorkItemCursor() error = %v", err)
	}
	got, err := decodeComplianceWorkItemCursor(encoded)
	if err != nil || got.ID != want.ID || !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Fatalf("decodeComplianceWorkItemCursor() = %+v, %v; want %+v", got, err, want)
	}
	for _, value := range []string{"not-base64", "e30"} {
		if _, err := decodeComplianceWorkItemCursor(value); !errors.Is(err, complianceremediation.ErrInvalidRequest) {
			t.Fatalf("decodeComplianceWorkItemCursor(%q) error = %v, want ErrInvalidRequest", value, err)
		}
	}
}
