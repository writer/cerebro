package collector

import (
	"testing"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

func TestDetectSecurityAgents(t *testing.T) {
	original := securityAgentPathExists
	defer func() { securityAgentPathExists = original }()
	originalVersion := appVersionReader
	defer func() { appVersionReader = originalVersion }()
	originalDaemon := daemonProgramReader
	defer func() { daemonProgramReader = originalDaemon }()

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
		case "/Library/CS/falcon":
			return true
		case "/Applications/Falcon.app":
			return true
		case "/Library/LaunchDaemons/com.crowdstrike.falcon.Agent.plist":
			return true
		case "/Applications/Falcon.app/Contents/Resources/falconctl":
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
		case "/Applications/Falcon.app":
			return "7.0.0"
		default:
			return ""
		}
	}
	daemonProgramReader = func(path string) string {
		return path + ":exec"
	}

	processes := []types.ProcessSnapshot{
		{Name: "SentinelAgent"},
		{Name: "Kandji"},
		{Name: "falcon"},
	}

	agents := detectSecurityAgents(processes)
	if len(agents) != 3 {
		t.Fatalf("expected 3 agents, got %d", len(agents))
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
	if !found["Kandji"].Installed || !found["Kandji"].Running {
		t.Fatalf("expected Kandji to be installed and running")
	}
	if found["Kandji"].Notes["version"] != "5.8.0" {
		t.Fatalf("expected Kandji version note")
	}
	if !found["CrowdStrike"].Installed || !found["CrowdStrike"].Running {
		t.Fatalf("expected CrowdStrike to be installed and running")
	}
	if found["CrowdStrike"].Notes["version"] != "7.0.0" {
		t.Fatalf("expected CrowdStrike version note")
	}
	if found["CrowdStrike"].Notes["cli"] != "/Applications/Falcon.app/Contents/Resources/falconctl" {
		t.Fatalf("expected CrowdStrike CLI note")
	}
	if found["CrowdStrike"].Notes["daemon_program"] != "/Library/LaunchDaemons/com.crowdstrike.falcon.Agent.plist:exec" {
		t.Fatalf("expected CrowdStrike daemon program note")
	}
}

func TestDetectSecurityAgentsNone(t *testing.T) {
	original := securityAgentPathExists
	defer func() { securityAgentPathExists = original }()
	originalVersion := appVersionReader
	defer func() { appVersionReader = originalVersion }()
	originalDaemon := daemonProgramReader
	defer func() { daemonProgramReader = originalDaemon }()

	securityAgentPathExists = func(string) bool { return false }
	appVersionReader = func(string) string { return "" }
	daemonProgramReader = func(string) string { return "" }

	if agents := detectSecurityAgents(nil); len(agents) != 0 {
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

	securityAgentPathExists = func(path string) bool {
		return path == "/Library/LaunchDaemons/com.sentinelone.sentineld.plist"
	}
	appVersionReader = func(string) string { return "" }
	daemonProgramReader = func(path string) string { return path + ":exec" }

	agents := detectSecurityAgents(nil)
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
