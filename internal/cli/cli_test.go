package cli

import (
	"testing"
)

func TestRootCmd(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("rootCmd should not be nil")
	}

	if rootCmd.Use != "cerebro" {
		t.Errorf("expected Use 'cerebro', got %s", rootCmd.Use)
	}

	if rootCmd.Short == "" {
		t.Error("Short description should not be empty")
	}

	if rootCmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestSubcommands(t *testing.T) {
	// Verify subcommands are registered
	subcommands := rootCmd.Commands()

	if len(subcommands) == 0 {
		t.Error("expected subcommands to be registered")
	}

	// Check at least some expected commands exist
	foundServe := false
	foundPolicy := false
	for _, cmd := range subcommands {
		if cmd.Name() == "serve" {
			foundServe = true
		}
		if cmd.Name() == "policy" {
			foundPolicy = true
		}
	}

	if !foundServe {
		t.Error("expected serve subcommand")
	}

	if !foundPolicy {
		t.Error("expected policy subcommand")
	}
}

func TestServeCmd(t *testing.T) {
	if serveCmd == nil {
		t.Fatal("serveCmd should not be nil")
	}

	if serveCmd.Use != "serve" {
		t.Errorf("expected Use 'serve', got %s", serveCmd.Use)
	}
}

func TestSyncCmd(t *testing.T) {
	if syncCmd == nil {
		t.Fatal("syncCmd should not be nil")
	}

	if syncCmd.Use != "sync" {
		t.Errorf("expected Use 'sync', got %s", syncCmd.Use)
	}
}

func TestPolicyCmd(t *testing.T) {
	if policyCmd == nil {
		t.Fatal("policyCmd should not be nil")
	}

	if policyCmd.Use != "policy" {
		t.Errorf("expected Use 'policy', got %s", policyCmd.Use)
	}
}

func TestQueryCmd(t *testing.T) {
	if queryCmd == nil {
		t.Fatal("queryCmd should not be nil")
	}

	// Query cmd has arguments in Use field
	if queryCmd.Name() != "query" {
		t.Errorf("expected Name 'query', got %s", queryCmd.Name())
	}
}

func TestBootstrapCmd(t *testing.T) {
	if bootstrapCmd == nil {
		t.Fatal("bootstrapCmd should not be nil")
	}

	if bootstrapCmd.Use != "bootstrap" {
		t.Errorf("expected Use 'bootstrap', got %s", bootstrapCmd.Use)
	}
}
