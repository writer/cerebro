package collector

import (
	"testing"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

func TestDetectSecurityAgents(t *testing.T) {
	original := securityAgentPathExists
	defer func() { securityAgentPathExists = original }()

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
		default:
			return false
		}
	}

	processes := []types.ProcessSnapshot{
		{Name: "SentinelAgent"},
		{Name: "Kandji"},
	}

	agents := detectSecurityAgents(processes)
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
	if !found["Kandji"].Installed || !found["Kandji"].Running {
		t.Fatalf("expected Kandji to be installed and running")
	}
}

func TestDetectSecurityAgentsNone(t *testing.T) {
	original := securityAgentPathExists
	defer func() { securityAgentPathExists = original }()

	securityAgentPathExists = func(string) bool { return false }

	if agents := detectSecurityAgents(nil); len(agents) != 0 {
		t.Fatalf("expected no agents, got %d", len(agents))
	}
}

func TestDetectSecurityAgentsLaunchDaemonOnly(t *testing.T) {
	original := securityAgentPathExists
	defer func() { securityAgentPathExists = original }()

	securityAgentPathExists = func(path string) bool {
		return path == "/Library/LaunchDaemons/com.sentinelone.sentineld.plist"
	}

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
}
