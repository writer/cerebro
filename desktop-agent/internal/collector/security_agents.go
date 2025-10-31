package collector

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
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
	vendor       string
	product      string
	processHints []string
	paths        []string
}

var securityVendors = []vendorSignature{
	{
		vendor:       "SentinelOne",
		product:      "SentinelOne Agent",
		processHints: []string{"sentinelone", "sentinelagent", "sentinel agent"},
		paths: []string{
			"/Library/SentinelOne",
			"/Applications/SentinelAgent.app",
		},
	},
	{
		vendor:       "Kandji",
		product:      "Kandji Agent",
		processHints: []string{"kandji"},
		paths: []string{
			"/Library/Kandji",
			"/usr/local/bin/kandji",
		},
	},
}

func detectSecurityAgents(processes []types.ProcessSnapshot) []types.SecuritySoftware {
	results := make([]types.SecuritySoftware, 0, len(securityVendors))
	for _, vendor := range securityVendors {
		installed, installPath := checkInstallPaths(vendor.paths)
		running := matchProcesses(processes, vendor.processHints)
		if !installed && !running {
			continue
		}
		notes := map[string]string{}
		if installPath != "" {
			notes["path"] = installPath
		}
		results = append(results, types.SecuritySoftware{
			Vendor:      vendor.vendor,
			Product:     vendor.product,
			Installed:   installed,
			Running:     running,
			InstallPath: installPath,
			Notes:       notes,
		})
	}
	return results
}

func checkInstallPaths(paths []string) (bool, string) {
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
