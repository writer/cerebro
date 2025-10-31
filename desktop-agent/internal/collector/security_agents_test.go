package collector

import (
	"os"
	"testing"
	"time"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

func TestDetectSecurityAgents(t *testing.T) {
	original := securityAgentPathExists
	defer func() { securityAgentPathExists = original }()
	originalVersion := appVersionReader
	defer func() { appVersionReader = originalVersion }()
	originalDaemon := daemonProgramReader
	defer func() { daemonProgramReader = originalDaemon }()
	originalLoader := customSignatureLoader
	defer func() { customSignatureLoader = originalLoader }()
	originalCache := customSignatureCache
	defer func() { customSignatureCache = originalCache }()
	originalExecutor := commandExecutor
	defer func() { commandExecutor = originalExecutor }()

	securityAgentPathExists = func(path string) bool {
		switch path {
		case "/Library/SentinelOne":
			return true
		case "/Library/Kandji":
			return true
		case "/Library/LaunchDaemons/com.sentinelone.sentineld.plist":
			return true
		case "/Library/LaunchDaemons/com.kandji.agent.plist":
			return true
		case "/Applications/SentinelAgent.app":
			return true
		case "/Applications/Kandji Self Service.app":
			return true
		case "/usr/local/bin/sentinelctl":
			return true
		case "/usr/local/bin/kandji":
			return true
		default:
			return false
		}
	}

	appVersionReader = func(path string) string {
		switch path {
		case "/Applications/SentinelAgent.app":
			return "23.2.1"
		case "/Applications/Kandji Self Service.app":
			return "5.8.0"
		default:
			return ""
		}
	}
	daemonProgramReader = func(path string) string {
		return path + ":exec"
	}
	commandExecutor = func(args []string, _ time.Duration) (string, error) {
		return args[0] + " status ok", nil
	}

	processes := []types.ProcessSnapshot{
		{Name: "SentinelAgent"},
		{Name: "Kandji"},
	}

	customSignatureLoader = func(string) []vendorSignature { return nil }
	customSignatureCache = newSignatureCache()
	agents := detectSecurityAgents(processes, config.Config{})
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}

	found := map[string]types.SecuritySoftware{}
	for _, agent := range agents {
		found[agent.Vendor] = agent
	}

	if !found["SentinelOne"].Installed || !found["SentinelOne"].Running {
		t.Fatalf("expected SentinelOne to be installed and running")
	}
	if found["SentinelOne"].InstallPath == "" {
		t.Fatalf("expected SentinelOne install path to be recorded")
	}
	if found["SentinelOne"].Notes["version"] != "23.2.1" {
		t.Fatalf("expected SentinelOne version note")
	}
	if found["SentinelOne"].Notes["daemon"] != "/Library/LaunchDaemons/com.sentinelone.sentineld.plist" {
		t.Fatalf("expected SentinelOne daemon note")
	}
	if found["SentinelOne"].Notes["daemon_program"] != "/Library/LaunchDaemons/com.sentinelone.sentineld.plist:exec" {
		t.Fatalf("expected SentinelOne daemon program note")
	}
	if found["SentinelOne"].Notes["cli_status"] == "" {
		t.Fatalf("expected SentinelOne CLI status note")
	}
	if !found["Kandji"].Installed || !found["Kandji"].Running {
		t.Fatalf("expected Kandji to be installed and running")
	}
	if found["Kandji"].Notes["version"] != "5.8.0" {
		t.Fatalf("expected Kandji version note")
	}
	if found["Kandji"].Notes["cli_status"] == "" {
		t.Fatalf("expected Kandji CLI status note")
	}
}

func TestDetectSecurityAgentsNone(t *testing.T) {
	original := securityAgentPathExists
	defer func() { securityAgentPathExists = original }()
	originalVersion := appVersionReader
	defer func() { appVersionReader = originalVersion }()
	originalDaemon := daemonProgramReader
	defer func() { daemonProgramReader = originalDaemon }()
	originalLoader := customSignatureLoader
	defer func() { customSignatureLoader = originalLoader }()
	originalCache := customSignatureCache
	defer func() { customSignatureCache = originalCache }()
	originalExecutor := commandExecutor
	defer func() { commandExecutor = originalExecutor }()

	securityAgentPathExists = func(string) bool { return false }
	appVersionReader = func(string) string { return "" }
	customSignatureLoader = func(string) []vendorSignature { return nil }
	customSignatureCache = newSignatureCache()
	daemonProgramReader = func(string) string { return "" }
	commandExecutor = func([]string, time.Duration) (string, error) { return "", nil }
	if agents := detectSecurityAgents(nil, config.Config{}); len(agents) != 0 {
		t.Fatalf("expected no agents, got %d", len(agents))
	}
}

func TestDetectSecurityAgentsLaunchDaemonOnly(t *testing.T) {
	original := securityAgentPathExists
	defer func() { securityAgentPathExists = original }()
	originalVersion := appVersionReader
	defer func() { appVersionReader = originalVersion }()
	originalDaemon := daemonProgramReader
	defer func() { daemonProgramReader = originalDaemon }()
	originalLoader := customSignatureLoader
	defer func() { customSignatureLoader = originalLoader }()
	originalCache := customSignatureCache
	defer func() { customSignatureCache = originalCache }()
	originalExecutor := commandExecutor
	defer func() { commandExecutor = originalExecutor }()

	securityAgentPathExists = func(path string) bool {
		return path == "/Library/LaunchDaemons/com.sentinelone.sentineld.plist"
	}
	appVersionReader = func(string) string { return "" }
	customSignatureLoader = func(string) []vendorSignature { return nil }
	customSignatureCache = newSignatureCache()
	daemonProgramReader = func(path string) string { return path + ":exec" }
	commandExecutor = func([]string, time.Duration) (string, error) { return "", nil }
	agents := detectSecurityAgents(nil, config.Config{})
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	agent := agents[0]
	if agent.Vendor != "SentinelOne" {
		t.Fatalf("unexpected vendor %q", agent.Vendor)
	}
	if !agent.Installed {
		t.Fatalf("expected agent to be marked installed")
	}
	if agent.Running {
		t.Fatalf("expected agent to be marked not running")
	}
	if agent.InstallPath != "/Library/LaunchDaemons/com.sentinelone.sentineld.plist" {
		t.Fatalf("unexpected install path %q", agent.InstallPath)
	}
	if agent.Notes["daemon_program"] != "/Library/LaunchDaemons/com.sentinelone.sentineld.plist:exec" {
		t.Fatalf("expected daemon program note")
	}
}

func TestDetectSecurityAgentsCustomSignatures(t *testing.T) {
	originalPathExists := securityAgentPathExists
	defer func() { securityAgentPathExists = originalPathExists }()
	originalLoader := customSignatureLoader
	defer func() { customSignatureLoader = originalLoader }()
	originalCache := customSignatureCache
	customSignatureCache = newSignatureCache()
	defer func() { customSignatureCache = originalCache }()
	originalVersion := appVersionReader
	defer func() { appVersionReader = originalVersion }()
	originalDaemon := daemonProgramReader
	defer func() { daemonProgramReader = originalDaemon }()
	originalExecutor := commandExecutor
	defer func() { commandExecutor = originalExecutor }()

	customFile, err := os.CreateTemp(t.TempDir(), "signatures-*.json")
	if err != nil {
		t.Fatalf("failed creating temp file: %v", err)
	}
	defer customFile.Close()

	if _, err := customFile.WriteString(`[
		{
			"vendor": "Jamf",
			"product": "Jamf Protect",
			"process_hints": ["jamf", "protect"],
			"install_paths": ["/Applications/JamfProtect.app"],
			"daemon_paths": ["/Library/LaunchDaemons/com.jamf.protect.daemon.plist"],
			"cli_paths": ["/usr/local/bin/jamfprotect"],
			"version_paths": ["/Applications/JamfProtect.app"],
			"status_commands": [["/usr/local/bin/jamfprotect", "status"]]
		}
	]`); err != nil {
		t.Fatalf("failed writing signatures: %v", err)
	}
	if err := customFile.Close(); err != nil {
		t.Fatalf("failed closing file: %v", err)
	}

	securityAgentPathExists = func(path string) bool {
		return path == "/Applications/JamfProtect.app" || path == "/Library/LaunchDaemons/com.jamf.protect.daemon.plist" || path == "/usr/local/bin/jamfprotect"
	}
	appVersionReader = func(string) string { return "1.2.3" }
	daemonProgramReader = func(path string) string { return path + ":exec" }
	customSignatureLoader = loadCustomSignatures
	commandExecutor = func(args []string, _ time.Duration) (string, error) {
		return "status ok", nil
	}

	agents := detectSecurityAgents([]types.ProcessSnapshot{{Name: "JamfProtect"}}, config.Config{SecuritySignatures: customFile.Name()})
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	agent := agents[0]
	if agent.Vendor != "Jamf" {
		t.Fatalf("unexpected vendor %q", agent.Vendor)
	}
	if agent.Notes["version"] != "1.2.3" {
		t.Fatalf("expected version note")
	}
	if agent.Notes["daemon_program"] != "/Library/LaunchDaemons/com.jamf.protect.daemon.plist:exec" {
		t.Fatalf("expected daemon program")
	}
	if agent.Notes["cli_status"] != "status ok" {
		t.Fatalf("expected CLI status note")
	}

	// Ensure cache reuses without re-read after file mtime.
	agents = detectSecurityAgents(nil, config.Config{SecuritySignatures: customFile.Name()})
	if len(agents) != 1 {
		t.Fatalf("expected cached agent, got %d", len(agents))
	}
}
