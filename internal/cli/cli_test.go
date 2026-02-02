package cli

import (
	"io"
	"os"
	"strings"
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

func TestVersionCommandOutput(t *testing.T) {
	currentVersion := Version
	currentCommit := Commit
	currentBuild := BuildDate
	t.Cleanup(func() {
		Version = currentVersion
		Commit = currentCommit
		BuildDate = currentBuild
	})

	Version = "1.2.3"
	Commit = "abc123"
	BuildDate = "2026-01-21"

	output := captureStdout(t, func() {
		if err := versionCmd.RunE(versionCmd, nil); err != nil {
			t.Fatalf("unexpected version error: %v", err)
		}
	})

	if !strings.Contains(output, "cerebro 1.2.3") {
		t.Fatalf("unexpected version output: %q", output)
	}
	if !strings.Contains(output, "commit:  abc123") {
		t.Fatalf("unexpected commit output: %q", output)
	}
	if !strings.Contains(output, "built:   2026-01-21") {
		t.Fatalf("unexpected build output: %q", output)
	}
}

func TestCompletionCommandOutput(t *testing.T) {
	output := captureStdout(t, func() {
		if err := completionCmd.RunE(completionCmd, []string{"bash"}); err != nil {
			t.Fatalf("unexpected completion error: %v", err)
		}
	})

	if output == "" {
		t.Fatal("expected completion output")
	}
}

func TestCompletionCommandArgs(t *testing.T) {
	if err := completionCmd.Args(completionCmd, []string{"invalid"}); err == nil {
		t.Fatal("expected args validation error")
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	os.Stdout = writer
	fn()
	_ = writer.Close()
	os.Stdout = originalStdout

	output, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	return string(output)
}
