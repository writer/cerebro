package providers

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func TestSSEReaderAcceptsLargeDataLines(t *testing.T) {
	payload := strings.Repeat("x", 70*1024)
	reader := newSSEReader(strings.NewReader("data: " + payload + "\n\n"))

	event, err := reader.Next()
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if event == nil {
		t.Fatal("expected event")
	}
	if event.Data != payload {
		t.Fatalf("event.Data length = %d, want %d", len(event.Data), len(payload))
	}
}

func TestSSEReaderReturnsErrTooLongForOversizedDataLines(t *testing.T) {
	payload := strings.Repeat("x", sseReaderMaxBufferSize+1)
	reader := newSSEReader(strings.NewReader("data: " + payload + "\n\n"))

	_, err := reader.Next()
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("expected ErrTooLong, got %v", err)
	}
}
