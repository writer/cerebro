package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

type mockFileInfo struct {
	name    string
	size    int64
	modTime time.Time
}

func (m mockFileInfo) Name() string       { return m.name }
func (m mockFileInfo) Size() int64        { return m.size }
func (m mockFileInfo) Mode() os.FileMode  { return 0 }
func (m mockFileInfo) ModTime() time.Time { return m.modTime }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() any           { return nil }

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
	originalStat := fileInfoFunc
	defer func() { fileInfoFunc = originalStat }()
	originalReader := fileReaderFunc
	defer func() { fileReaderFunc = originalReader }()

	securityAgentPathExists = func(path string) bool {
		switch path {
		case "/Library/SentinelOne":
			return true
		case "/Library/SentinelOne/data/com.sentinelone.registration-token":
			return true
		case "/Library/Application Support/SentinelOne/com.sentinelone.registration-token":
			return true
		case "/Library/Kandji":
			return true
		case "/Library/LaunchDaemons/com.sentinelone.sentineld.plist":
			return true
		case "/Library/LaunchDaemons/com.kandji.agent.plist":
			return true
		case "/Library/Application Support/SentinelOne":
			return true
		case "/Library/Application Support/Kandji":
			return true
		case "/Library/Application Support/JAMF/Waiting Room/com.sentinelone.install.mobileconfig":
			return true
		case "/Library/Managed Preferences/com.sentinelone.agent.plist":
			return true
		case "/Applications/SentinelAgent.app":
			return true
		case "/Applications/Kandji Self Service.app":
			return true
		case "/usr/local/bin/sentinelctl":
			return true
		case "/opt/sentinelone/bin/sentinelctl":
			return true
		case "/usr/local/bin/kandji":
			return true
		case "/bin/systemctl":
			return true
		case "/usr/bin/rpm":
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
	lastScan := time.Now().UTC().Add(-time.Hour)
	kandjiLastRun := time.Now().UTC().Add(-2 * time.Hour)
	kandjiLastCheck := time.Now().UTC().Add(-3 * time.Hour)
	commandExecutor = func(args []string, _ time.Duration) (string, error) {
		switch strings.Join(args, " ") {
		case "/usr/local/bin/sentinelctl stats agent_info":
			return "Connected: on\nSite Token: example-token\nAgent UUID: 1234-uuid", nil
		case "/usr/local/bin/sentinelctl management status":
			return "Connectivity: on\nAnti Tamper: Enabled\nAgent Enabled: true\nSite Name: Example Org\nPolicy: Example Policy\nVersion: 23.2.1\nManagement URL: https://sentinelone.example", nil
		case "/usr/local/bin/sentinelctl status":
			return "Status: running", nil
		case "/usr/local/bin/sentinelctl scan status":
			return fmt.Sprintf("Status: idle\nLast Scan: %s", lastScan.Format(time.RFC3339)), nil
		case "/usr/local/bin/sentinelctl version":
			return "Version: 23.2.1", nil
		case "/opt/sentinelone/bin/sentinelctl stats agent_info":
			return "Connected: on", nil
		case "/bin/systemctl status sentinelone-agent --no-pager":
			return "Active: active (running)", nil
		case "/usr/bin/rpm -q sentinelone":
			return "sentinelone-23.2.1-1.x86_64", nil
		case "/usr/local/bin/kandji library --state":
			return fmt.Sprintf("State: idle\nLast Run: %s", kandjiLastRun.Format(time.RFC3339)), nil
		case "/usr/local/bin/kandji version":
			return "Version: 5.8.0", nil
		default:
			return "", nil
		}
	}
	fileInfoFunc = func(path string) (os.FileInfo, error) {
		return mockFileInfo{
			name:    filepath.Base(path),
			size:    128,
			modTime: time.Now().Add(-time.Hour),
		}, nil
	}
	kandjiPlist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>last_check_in</key>
    <string>%s</string>
    <key>enforcement_state</key>
    <string>enforced</string>
    <key>blueprint_name</key>
    <string>Corp Blueprint</string>
    <key>device_uuid</key>
    <string>device-uuid-123</string>
    <key>pending_items</key>
    <string>0</string>
</dict>
</plist>`, kandjiLastCheck.Format(time.RFC3339))
	fileReaderFunc = func(path string) ([]byte, error) {
		if path == "/Library/Managed Preferences/com.kandji.agent.plist" {
			return []byte(kandjiPlist), nil
		}
		return nil, os.ErrNotExist
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
	if found["SentinelOne"].Notes["sentinelctl_stats_agent_info_connected"] != "on" {
		t.Fatalf("expected SentinelOne connected note")
	}
	if found["SentinelOne"].Notes["sentinelctl_management_status_management_url"] != "https://sentinelone.example" {
		t.Fatalf("expected SentinelOne management URL note")
	}
	if found["SentinelOne"].Notes["sentinelctl_version_version"] != "23.2.1" {
		t.Fatalf("expected SentinelOne version note from CLI")
	}
	if found["SentinelOne"].Notes["sentinelctl_stats_agent_info_site_token"] != "example-token" {
		t.Fatalf("expected sentinelctl stats site token note")
	}
	if found["SentinelOne"].Notes["registration_token_path"] == "" {
		t.Fatalf("expected SentinelOne registration token path")
	}
	if found["SentinelOne"].Notes["registration_token_present"] != "true" {
		t.Fatalf("expected SentinelOne registration token present flag")
	}
	if found["SentinelOne"].Notes["connectivity_ok"] != "true" {
		t.Fatalf("expected SentinelOne connectivity ok flag")
	}
	if found["SentinelOne"].Notes["anti_tamper_enabled"] != "true" {
		t.Fatalf("expected SentinelOne anti tamper flag")
	}
	if found["SentinelOne"].Notes["agent_enabled"] != "true" {
		t.Fatalf("expected SentinelOne agent enabled flag")
	}
	if found["SentinelOne"].Notes["scan_in_progress"] != "false" {
		t.Fatalf("expected SentinelOne scan in progress flag")
	}
	if found["SentinelOne"].Notes["scan_recent"] != "true" {
		t.Fatalf("expected SentinelOne scan recent flag")
	}
	if found["SentinelOne"].Notes["scan_last_seen_hours"] == "" {
		t.Fatalf("expected SentinelOne scan last seen hours note")
	}
	if found["SentinelOne"].Notes["agent_uuid"] != "1234-uuid" {
		t.Fatalf("expected SentinelOne agent uuid note")
	}
	if found["SentinelOne"].Notes["site_name"] != "Example Org" {
		t.Fatalf("expected SentinelOne site name note")
	}
	if found["SentinelOne"].Notes["policy_name"] != "Example Policy" {
		t.Fatalf("expected SentinelOne policy name note")
	}
	if found["SentinelOne"].Notes["management_version"] != "23.2.1" {
		t.Fatalf("expected SentinelOne management version note")
	}
	if found["SentinelOne"].Notes["service_active"] != "true" {
		t.Fatalf("expected SentinelOne service active flag")
	}
	if found["SentinelOne"].Notes["management_profile_present"] != "true" {
		t.Fatalf("expected SentinelOne management profile flag")
	}
	if found["SentinelOne"].Notes["management_profile_path"] != "/Library/Application Support/JAMF/Waiting Room/com.sentinelone.install.mobileconfig" {
		t.Fatalf("expected SentinelOne management profile path")
	}
	if found["SentinelOne"].Notes["registration_token_stale"] != "false" {
		t.Fatalf("expected SentinelOne registration token stale flag")
	}
	if found["SentinelOne"].Notes["package_version"] != "23.2.1-1" {
		t.Fatalf("expected SentinelOne package version note")
	}
	if found["SentinelOne"].Notes["package_version_mismatch"] != "false" {
		t.Fatalf("expected SentinelOne package version mismatch flag")
	}
	if found["SentinelOne"].Notes["management_url_host"] != "sentinelone.example" {
		t.Fatalf("expected SentinelOne management url host")
	}
	if found["SentinelOne"].Notes["health_ok"] != "true" {
		t.Fatalf("expected SentinelOne health ok")
	}
	if found["SentinelOne"].Notes["health_issues"] != "" {
		t.Fatalf("expected SentinelOne health issues empty")
	}
	if !found["Kandji"].Installed || !found["Kandji"].Running {
		t.Fatalf("expected Kandji to be installed and running")
	}
	if found["Kandji"].Notes["version"] != "5.8.0" {
		t.Fatalf("expected Kandji version note")
	}
	if found["Kandji"].Notes["kandji_library_state_state"] != "idle" {
		t.Fatalf("expected Kandji library state note")
	}
	if found["Kandji"].Notes["kandji_version_version"] != "5.8.0" {
		t.Fatalf("expected Kandji CLI version note")
	}
	if found["Kandji"].Notes["kandji_library_state_ok"] != "true" {
		t.Fatalf("expected Kandji library state ok flag")
	}
	if found["Kandji"].Notes["kandji_last_run_recent"] != "true" {
		t.Fatalf("expected Kandji last run recent flag")
	}
	if found["Kandji"].Notes["kandji_last_run_hours"] == "" {
		t.Fatalf("expected Kandji last run hours note")
	}
	if found["Kandji"].Notes["kandji_prefs_present"] != "true" {
		t.Fatalf("expected Kandji prefs presence flag")
	}
	if found["Kandji"].Notes["kandji_prefs_last_check_in"] == "" {
		t.Fatalf("expected Kandji prefs last check-in note")
	}
	if found["Kandji"].Notes["kandji_last_check_in_recent"] != "true" {
		t.Fatalf("expected Kandji last check-in recent flag")
	}
	if found["Kandji"].Notes["kandji_enforced"] != "true" {
		t.Fatalf("expected Kandji enforced flag")
	}
	if found["Kandji"].Notes["kandji_pending_items"] != "0" {
		t.Fatalf("expected Kandji pending items note")
	}
	if found["Kandji"].Notes["kandji_has_pending"] != "false" {
		t.Fatalf("expected Kandji has pending flag")
	}
	if found["Kandji"].Notes["kandji_health_ok"] != "true" {
		t.Fatalf("expected Kandji health ok")
	}
	if found["Kandji"].Notes["kandji_health_issues"] != "" {
		t.Fatalf("expected Kandji health issues empty")
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
		return "Status: ok", nil
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
	if agent.Notes["jamfprotect_status_status"] != "ok" {
		t.Fatalf("expected CLI status note")
	}

	// Ensure cache reuses without re-read after file mtime.
	agents = detectSecurityAgents(nil, config.Config{SecuritySignatures: customFile.Name()})
	if len(agents) != 1 {
		t.Fatalf("expected cached agent, got %d", len(agents))
	}
}
