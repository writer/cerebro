package collector

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
	plist "howett.net/plist"
)

var securityAgentPathExists = func(path string) bool {
	if path == "" {
		return false
	}
	if info, err := os.Stat(path); err == nil {
		return info.IsDir() || info.Mode().IsRegular()
	}
	return false
}

type vendorSignature struct {
	vendor          string
	product         string
	processHints    []string
	installPaths    []string
	daemonPaths     []string
	cliPaths        []string
	versionAppPaths []string
}

var securityVendors = []vendorSignature{
	{
		vendor:       "SentinelOne",
		product:      "SentinelOne Agent",
		processHints: []string{"sentinelone", "sentinelagent", "sentinel agent", "com.sentinelone.sentineld"},
		installPaths: []string{
			"/Library/SentinelOne",
		},
		daemonPaths: []string{
			"/Library/LaunchDaemons/com.sentinelone.sentineld.plist",
		},
		cliPaths: []string{
			"/usr/local/bin/sentinelctl",
		},
		versionAppPaths: []string{
			"/Applications/SentinelAgent.app",
		},
	},
	{
		vendor:       "Kandji",
		product:      "Kandji Agent",
		processHints: []string{"kandji", "com.kandji.agent"},
		installPaths: []string{
			"/Library/Kandji",
		},
		daemonPaths: []string{
			"/Library/LaunchDaemons/com.kandji.agent.plist",
		},
		cliPaths: []string{
			"/usr/local/bin/kandji",
		},
		versionAppPaths: []string{
			"/Applications/Kandji Self Service.app",
		},
	},
	{
		vendor:       "CrowdStrike",
		product:      "Falcon Sensor",
		processHints: []string{"crowdstrike", "falcon", "com.crowdstrike.falcon.agent"},
		installPaths: []string{
			"/Library/CS/falcon",
			"/Applications/Falcon.app",
		},
		daemonPaths: []string{
			"/Library/LaunchDaemons/com.crowdstrike.falcon.Agent.plist",
		},
		cliPaths: []string{
			"/Applications/Falcon.app/Contents/Resources/falconctl",
		},
		versionAppPaths: []string{
			"/Applications/Falcon.app",
		},
	},
}

var appVersionReader = readAppVersion
var daemonProgramReader = readDaemonProgram

func detectSecurityAgents(processes []types.ProcessSnapshot) []types.SecuritySoftware {
	results := make([]types.SecuritySoftware, 0, len(securityVendors))
	for _, vendor := range securityVendors {
		installed, installPath := existsAny(vendor.installPaths)
		daemonPresent, daemonPath := existsAny(vendor.daemonPaths)
		cliPresent, cliPath := existsAny(vendor.cliPaths)
		running := matchProcesses(processes, vendor.processHints)
		version := resolveVersion(vendor.versionAppPaths)
		if !(installed || daemonPresent || cliPresent || running || version != "") {
			continue
		}
		logicalInstalled := installed || daemonPresent || cliPresent
		notes := map[string]string{}
		if installPath != "" {
			notes["install_path"] = installPath
		}
		if daemonPresent {
			notes["daemon"] = daemonPath
			if program := daemonProgramReader(daemonPath); program != "" {
				notes["daemon_program"] = program
			}
		}
		if cliPresent {
			notes["cli"] = cliPath
		}
		if version != "" {
			notes["version"] = version
		}
		resolvedInstallPath := installPath
		if resolvedInstallPath == "" {
			resolvedInstallPath = daemonPath
			if resolvedInstallPath == "" {
				resolvedInstallPath = cliPath
			}
		}
		results = append(results, types.SecuritySoftware{
			Vendor:      vendor.vendor,
			Product:     vendor.product,
			Installed:   logicalInstalled,
			Running:     running,
			InstallPath: resolvedInstallPath,
			Notes:       notes,
		})
	}
	return results
}

func existsAny(paths []string) (bool, string) {
	for _, path := range paths {
		if strings.Contains(path, "*") {
			matches, _ := filepath.Glob(path)
			for _, match := range matches {
				if securityAgentPathExists(match) {
					return true, match
				}
			}
			continue
		}
		if securityAgentPathExists(path) {
			return true, path
		}
	}
	return false, ""
}

func matchProcesses(processes []types.ProcessSnapshot, hints []string) bool {
	if len(processes) == 0 || len(hints) == 0 {
		return false
	}
	for _, proc := range processes {
		name := strings.ToLower(proc.Name)
		cmd := strings.ToLower(proc.Command)
		for _, hint := range hints {
			needle := strings.ToLower(hint)
			if strings.Contains(name, needle) || strings.Contains(cmd, needle) {
				return true
			}
		}
	}
	return false
}

func resolveVersion(appPaths []string) string {
	for _, app := range appPaths {
		if !securityAgentPathExists(app) {
			continue
		}
		if version := appVersionReader(app); version != "" {
			return version
		}
	}
	return ""
}

func readAppVersion(appPath string) string {
	if appPath == "" {
		return ""
	}
	infoPath := filepath.Join(appPath, "Contents", "Info.plist")
	data, err := os.ReadFile(infoPath)
	if err != nil {
		return ""
	}
	var parsed map[string]any
	if _, err := plist.Unmarshal(data, &parsed); err != nil {
		return ""
	}
	if v, ok := parsed["CFBundleShortVersionString"].(string); ok {
		return v
	}
	if v, ok := parsed["CFBundleVersion"].(string); ok {
		return v
	}
	return ""
}

func readDaemonProgram(daemonPath string) string {
	if daemonPath == "" {
		return ""
	}
	data, err := os.ReadFile(daemonPath)
	if err != nil {
		return ""
	}
	var parsed map[string]any
	if _, err := plist.Unmarshal(data, &parsed); err != nil {
		return ""
	}
	if program, ok := parsed["Program"].(string); ok && program != "" {
		return program
	}
	if args, ok := parsed["ProgramArguments"].([]any); ok {
		if len(args) > 0 {
			if first, ok := args[0].(string); ok {
				return first
			}
		}
	}
	return ""
}
