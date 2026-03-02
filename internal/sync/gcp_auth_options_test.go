package sync

import (
	"context"
	"testing"

	"google.golang.org/api/option"
)

func TestWithGCPClientOptions(t *testing.T) {
	base := context.Background()
	if got := WithGCPClientOptions(base); got != base {
		t.Fatalf("expected context to be unchanged when no options provided")
	}

	ctx := WithGCPClientOptions(base, option.WithUserAgent("cerebro-test"))
	opts := gcpClientOptionsFromContext(ctx)
	if len(opts) != 1 {
		t.Fatalf("expected one client option, got %d", len(opts))
	}

	// Ensure callers receive a defensive copy.
	opts[0] = nil
	optsAgain := gcpClientOptionsFromContext(ctx)
	if len(optsAgain) != 1 || optsAgain[0] == nil {
		t.Fatalf("expected stored options to remain intact, got %#v", optsAgain)
	}
}
