package cli

import (
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/app"
)

func TestValidateServeSecurityMode(t *testing.T) {
	t.Run("rejects disabled auth outside dev mode", func(t *testing.T) {
		err := validateServeSecurityMode(&app.Config{APIAuthEnabled: false})
		if err == nil {
			t.Fatal("expected serve security validation error")
		}
		if !strings.Contains(err.Error(), "CEREBRO_DEV_MODE=1") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("allows dev mode", func(t *testing.T) {
		if err := validateServeSecurityMode(&app.Config{APIAuthEnabled: false, DevMode: true}); err != nil {
			t.Fatalf("expected dev mode to bypass serve guard, got %v", err)
		}
	})
}

func TestServeSecurityWarning(t *testing.T) {
	if got := serveSecurityWarning(&app.Config{DevMode: true}); got != "DEV MODE: API authentication and rate limiting are disabled" {
		t.Fatalf("unexpected dev mode warning %q", got)
	}
	if got := serveSecurityWarning(&app.Config{DevMode: false}); got != "" {
		t.Fatalf("expected no warning when dev mode is disabled, got %q", got)
	}
}
