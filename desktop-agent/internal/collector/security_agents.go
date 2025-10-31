package collector

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
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
	statusCommands  [][]string
}

var defaultSecurityVendors = []vendorSignature{
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
		statusCommands: [][]string{
			{"/usr/local/bin/sentinelctl", "stats", "agent_info"},
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
		statusCommands: [][]string{
			{"/usr/local/bin/kandji", "library", "--state"},
		},
	},
}

var appVersionReader = readAppVersion
var daemonProgramReader = readDaemonProgram
var customSignatureLoader = loadCustomSignatures
var signatureMerger = mergeSignatures
var customSignatureCache = newSignatureCache()
var commandExecutor = runCommand

const (
	cliStatusTimeout = 5 * time.Second
	maxCLIStatusLen  = 1024
)

func detectSecurityAgents(processes []types.ProcessSnapshot, cfg config.Config) []types.SecuritySoftware {
	vendors := signatureMerger(defaultSecurityVendors, customSignatureLoader(cfg.SecuritySignatures))
	results := make([]types.SecuritySoftware, 0, len(vendors))
	for _, vendor := range vendors {
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
		if cliPresent && len(vendor.statusCommands) > 0 {
			if status, statusErr := collectCLIStatus(vendor); status != "" {
				notes["cli_status"] = status
				if statusErr != "" {
					notes["cli_status_error"] = statusErr
				}
			} else if statusErr != "" {
				notes["cli_status_error"] = statusErr
			}
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

func collectCLIStatus(vendor vendorSignature) (string, string) {
	var lastErr error
	for _, cmd := range vendor.statusCommands {
		if len(cmd) == 0 {
			continue
		}
		if !securityAgentPathExists(cmd[0]) {
			continue
		}
		output, err := commandExecutor(cmd, cliStatusTimeout)
		trimmed := strings.TrimSpace(output)
		if err == nil && trimmed != "" {
			return truncate(trimmed, maxCLIStatusLen), ""
		}
		if err != nil {
			if trimmed != "" {
				return truncate(trimmed, maxCLIStatusLen), err.Error()
			}
			lastErr = err
		}
	}
	if lastErr != nil {
		return "", lastErr.Error()
	}
	return "", ""
}

func runCommand(args []string, timeout time.Duration) (string, error) {
	if len(args) == 0 {
		return "", errors.New("no command provided")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(output), ctx.Err()
	}
	return string(output), err
}

type signatureCache struct {
	mu         sync.Mutex
	path       string
	modTime    time.Time
	signatures []vendorSignature
}

func newSignatureCache() *signatureCache {
	return &signatureCache{}
}

func (c *signatureCache) get(path string, loader func(string, time.Time) ([]vendorSignature, error)) []vendorSignature {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	modTime := info.ModTime()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.path == path && modTime.Equal(c.modTime) {
		return c.signatures
	}
	signatures, err := loader(path, modTime)
	if err != nil {
		return nil
	}
	c.path = path
	c.modTime = modTime
	c.signatures = signatures
	return signatures
}

type vendorSignatureSpec struct {
	Vendor          string     `json:"vendor"`
	Product         string     `json:"product"`
	ProcessHints    []string   `json:"process_hints"`
	InstallPaths    []string   `json:"install_paths"`
	DaemonPaths     []string   `json:"daemon_paths"`
	CLIPaths        []string   `json:"cli_paths"`
	VersionAppPaths []string   `json:"version_paths"`
	StatusCommands  [][]string `json:"status_commands"`
}

func loadCustomSignatures(path string) []vendorSignature {
	return customSignatureCache.get(path, func(p string, _ time.Time) ([]vendorSignature, error) {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var specs []vendorSignatureSpec
		if err := json.Unmarshal(data, &specs); err != nil {
			return nil, err
		}
		signatures := make([]vendorSignature, 0, len(specs))
		for _, spec := range specs {
			if spec.Vendor == "" || spec.Product == "" {
				continue
			}
			signatures = append(signatures, vendorSignature{
				vendor:          spec.Vendor,
				product:         spec.Product,
				processHints:    cloneStrings(spec.ProcessHints),
				installPaths:    cloneStrings(spec.InstallPaths),
				daemonPaths:     cloneStrings(spec.DaemonPaths),
				cliPaths:        cloneStrings(spec.CLIPaths),
				versionAppPaths: cloneStrings(spec.VersionAppPaths),
				statusCommands:  cloneCommands(spec.StatusCommands),
			})
		}
		return signatures, nil
	})
}

func mergeSignatures(defaults, extras []vendorSignature) []vendorSignature {
	result := make([]vendorSignature, 0, len(defaults)+len(extras))
	for _, sig := range defaults {
		result = append(result, cloneSignature(sig))
	}
	for _, sig := range extras {
		result = append(result, cloneSignature(sig))
	}
	return result
}

func truncate(input string, max int) string {
	if len(input) <= max {
		return input
	}
	return input[:max]
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneSignature(sig vendorSignature) vendorSignature {
	return vendorSignature{
		vendor:          sig.vendor,
		product:         sig.product,
		processHints:    cloneStrings(sig.processHints),
		installPaths:    cloneStrings(sig.installPaths),
		daemonPaths:     cloneStrings(sig.daemonPaths),
		cliPaths:        cloneStrings(sig.cliPaths),
		versionAppPaths: cloneStrings(sig.versionAppPaths),
		statusCommands:  cloneCommands(sig.statusCommands),
	}
}

func cloneCommands(in [][]string) [][]string {
	if len(in) == 0 {
		return nil
	}
	out := make([][]string, len(in))
	for i, cmd := range in {
		out[i] = cloneStrings(cmd)
	}
	return out
}
