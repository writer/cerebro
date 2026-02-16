package sync

import (
	"errors"
	"testing"
)

func TestPartialFetchError(t *testing.T) {
	baseErr := errors.New("boom")
	err := newPartialFetchError(baseErr)

	if !isPartialFetchError(err) {
		t.Fatalf("expected partial fetch error")
	}
	if !errors.Is(err, baseErr) {
		t.Fatalf("expected wrapped error")
	}
}
