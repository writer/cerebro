package cli

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/writer/cerebro/internal/workloadscan"
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
	foundWorkloadScan := false
	foundImageScan := false
	foundVulnDB := false
	for _, cmd := range subcommands {
		if cmd.Name() == "serve" {
			foundServe = true
		}
		if cmd.Name() == "policy" {
			foundPolicy = true
		}
		if cmd.Name() == "workload-scan" {
			foundWorkloadScan = true
		}
		if cmd.Name() == "image-scan" {
			foundImageScan = true
		}
		if cmd.Name() == "vulndb" {
			foundVulnDB = true
		}
	}

	if !foundServe {
		t.Error("expected serve subcommand")
	}

	if !foundPolicy {
		t.Error("expected policy subcommand")
	}

	if !foundWorkloadScan {
		t.Error("expected workload-scan subcommand")
	}
	if !foundImageScan {
		t.Error("expected image-scan subcommand")
	}
	if !foundVulnDB {
		t.Error("expected vulndb subcommand")
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

func TestWorkloadScanCommands(t *testing.T) {
	if workloadScanCmd == nil {
		t.Fatal("workloadScanCmd should not be nil")
	}

	if workloadScanCmd.Name() != "workload-scan" {
		t.Fatalf("expected workload-scan command, got %s", workloadScanCmd.Name())
	}

	subcommands := workloadScanCmd.Commands()
	foundList := false
	foundRun := false
	foundReconcile := false
	for _, cmd := range subcommands {
		switch cmd.Name() {
		case "list":
			foundList = true
		case "run":
			foundRun = true
		case "reconcile":
			foundReconcile = true
		}
	}
	if !foundList || !foundRun || !foundReconcile {
		t.Fatalf("expected workload-scan list/run/reconcile subcommands, got list=%t run=%t reconcile=%t", foundList, foundRun, foundReconcile)
	}
}

func TestWorkloadScanAWSRequiredFlags(t *testing.T) {
	for _, name := range []string{"region", "instance-id", "scanner-instance-id", "scanner-zone"} {
		flag := workloadScanRunAWSCmd.Flags().Lookup(name)
		if flag == nil {
			t.Fatalf("expected %s flag to exist", name)
		}
		if values, ok := flag.Annotations[cobra.BashCompOneRequiredFlag]; !ok || len(values) == 0 {
			t.Fatalf("expected %s to be marked required", name)
		}
	}
}

func TestWorkloadScanReconcileAWSRequiredFlags(t *testing.T) {
	flag := workloadScanReconcileAWSCmd.Flags().Lookup("region")
	if flag == nil {
		t.Fatal("expected reconcile aws region flag to exist")
	}
	if values, ok := flag.Annotations[cobra.BashCompOneRequiredFlag]; !ok || len(values) == 0 {
		t.Fatal("expected reconcile aws region flag to be marked required")
	}
}

func TestParseWorkloadScanPriorityOverride(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    *workloadscan.PriorityAssessment
		wantErr string
	}{
		{
			name: "empty",
			raw:  "",
		},
		{
			name: "critical alias",
			raw:  "urgent",
			want: &workloadscan.PriorityAssessment{
				Priority: workloadscan.ScanPriorityCritical,
				Score:    100,
				Eligible: true,
				Source:   "manual_override",
			},
		},
		{
			name:    "invalid",
			raw:     "asap-ish",
			wantErr: "priority override must be one of critical, high, medium, low",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseWorkloadScanPriorityOverride(tc.raw)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseWorkloadScanPriorityOverride(%q): %v", tc.raw, err)
			}
			if tc.want == nil {
				if got != nil {
					t.Fatalf("expected nil priority assessment, got %#v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected priority assessment")
			}
			if got.Priority != tc.want.Priority || got.Score != tc.want.Score || got.Eligible != tc.want.Eligible || got.Source != tc.want.Source {
				t.Fatalf("unexpected priority assessment: %#v", got)
			}
		})
	}
}

func TestImageScanCommands(t *testing.T) {
	if imageScanCmd == nil {
		t.Fatal("imageScanCmd should not be nil")
	}
	if imageScanCmd.Name() != "image-scan" {
		t.Fatalf("expected image-scan command, got %s", imageScanCmd.Name())
	}
	subcommands := imageScanCmd.Commands()
	foundList := false
	foundRun := false
	for _, cmd := range subcommands {
		switch cmd.Name() {
		case "list":
			foundList = true
		case "run":
			foundRun = true
		}
	}
	if !foundList || !foundRun {
		t.Fatalf("expected image-scan list/run subcommands, got list=%t run=%t", foundList, foundRun)
	}
}

func TestImageScanRegistryRequiredFlags(t *testing.T) {
	for _, tc := range []struct {
		cmd   *cobra.Command
		flags []string
	}{
		{cmd: imageScanRunECRCmd, flags: []string{"region", "repository"}},
		{cmd: imageScanRunGCRCmd, flags: []string{"project-id", "repository"}},
		{cmd: imageScanRunACRCmd, flags: []string{"registry-name", "repository"}},
	} {
		for _, name := range tc.flags {
			flag := tc.cmd.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("expected %s flag to exist on %s", name, tc.cmd.Name())
			}
			if values, ok := flag.Annotations[cobra.BashCompOneRequiredFlag]; !ok || len(values) == 0 {
				t.Fatalf("expected %s flag on %s to be marked required", name, tc.cmd.Name())
			}
		}
	}
}

func TestVulnDBCommands(t *testing.T) {
	if vulndbCmd == nil {
		t.Fatal("vulndbCmd should not be nil")
	}
	if vulndbCmd.Name() != "vulndb" {
		t.Fatalf("expected vulndb command, got %s", vulndbCmd.Name())
	}
	subcommands := vulndbCmd.Commands()
	foundStats := false
	foundImportOSV := false
	foundImportKEV := false
	foundImportEPSS := false
	foundSync := false
	for _, cmd := range subcommands {
		switch cmd.Name() {
		case "stats":
			foundStats = true
		case "import-osv":
			foundImportOSV = true
		case "import-kev":
			foundImportKEV = true
		case "import-epss":
			foundImportEPSS = true
		case "sync":
			foundSync = true
		}
	}
	if !foundStats || !foundImportOSV || !foundImportKEV || !foundImportEPSS || !foundSync {
		t.Fatalf("expected vuln db subcommands, got stats=%t import-osv=%t import-kev=%t import-epss=%t sync=%t", foundStats, foundImportOSV, foundImportKEV, foundImportEPSS, foundSync)
	}
}

func TestFunctionScanCommands(t *testing.T) {
	if functionScanCmd == nil {
		t.Fatal("functionScanCmd should not be nil")
	}
	if functionScanCmd.Name() != "function-scan" {
		t.Fatalf("expected function-scan command, got %s", functionScanCmd.Name())
	}
	subcommands := functionScanCmd.Commands()
	foundList := false
	foundRun := false
	for _, cmd := range subcommands {
		switch cmd.Name() {
		case "list":
			foundList = true
		case "run":
			foundRun = true
		}
	}
	if !foundList || !foundRun {
		t.Fatalf("expected function-scan list/run subcommands, got list=%t run=%t", foundList, foundRun)
	}
}

func TestFunctionScanRequiredFlags(t *testing.T) {
	for _, tc := range []struct {
		cmd   *cobra.Command
		flags []string
	}{
		{cmd: functionScanRunAWSCmd, flags: []string{"region"}},
		{cmd: functionScanRunGCPCmd, flags: []string{"project-id", "location", "function-name"}},
		{cmd: functionScanRunAzureCmd, flags: []string{"subscription-id", "resource-group", "app-name"}},
	} {
		for _, name := range tc.flags {
			flag := tc.cmd.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("expected %s flag to exist on %s", name, tc.cmd.Name())
			}
			if values, ok := flag.Annotations[cobra.BashCompOneRequiredFlag]; !ok || len(values) == 0 {
				t.Fatalf("expected %s flag on %s to be marked required", name, tc.cmd.Name())
			}
		}
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	file, err := os.CreateTemp(t.TempDir(), "cerebro-cli-stdout-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp stdout file: %v", err)
	}
	defer func() { _ = file.Close() }()

	os.Stdout = file
	fn()
	os.Stdout = originalStdout

	if _, err := file.Seek(0, 0); err != nil {
		t.Fatalf("failed to rewind stdout capture: %v", err)
	}

	output, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	return string(output)
}
