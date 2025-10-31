package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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
	tokenPaths      []string
	mobileConfig    []string
}

var defaultSecurityVendors = []vendorSignature{
	{
		vendor:       "SentinelOne",
		product:      "SentinelOne Agent",
		processHints: []string{"sentinelone", "sentinelagent", "sentinel agent", "com.sentinelone.sentineld"},
		installPaths: []string{
			"/Library/SentinelOne",
			"/opt/sentinelone",
			"/Library/Application Support/SentinelOne",
			"/etc/sentinelone",
		},
		daemonPaths: []string{
			"/Library/LaunchDaemons/com.sentinelone.sentineld.plist",
		},
		cliPaths: []string{
			"/usr/local/bin/sentinelctl",
			"/opt/sentinelone/bin/sentinelctl",
		},
		versionAppPaths: []string{
			"/Applications/SentinelAgent.app",
		},
		statusCommands: [][]string{
			{"/usr/local/bin/sentinelctl", "stats", "agent_info"},
			{"/usr/local/bin/sentinelctl", "management", "status"},
			{"/usr/local/bin/sentinelctl", "status"},
			{"/usr/local/bin/sentinelctl", "scan", "status"},
			{"/usr/local/bin/sentinelctl", "version"},
			{"/opt/sentinelone/bin/sentinelctl", "stats", "agent_info"},
			{"/opt/sentinelone/bin/sentinelctl", "management", "status"},
			{"/opt/sentinelone/bin/sentinelctl", "status"},
			{"/opt/sentinelone/bin/sentinelctl", "scan", "status"},
			{"/opt/sentinelone/bin/sentinelctl", "version"},
			{"/bin/systemctl", "status", "sentinelone-agent", "--no-pager"},
			{"/usr/bin/systemctl", "status", "sentinelone-agent", "--no-pager"},
			{"/usr/bin/rpm", "-q", "sentinelone"},
			{"/usr/bin/dpkg-query", "-W", "sentinelone"},
		},
		tokenPaths: []string{
			"/Library/SentinelOne/data/com.sentinelone.registration-token",
			"/Library/Application Support/JAMF/Waiting Room/com.sentinelone.registration-token",
			"/Library/Application Support/SentinelOne/com.sentinelone.registration-token",
			"/etc/sentinelone/com.sentinelone.registration-token",
		},
		mobileConfig: []string{
			"/Library/Application Support/JAMF/Waiting Room/com.sentinelone.install.mobileconfig",
			"/Library/Application Support/JAMF/Waiting Room/com.sentinelone.network-extension.mobileconfig",
			"/Library/Application Support/JAMF/Waiting Room/com.sentinelone.privacy.mobileconfig",
			"/Library/Application Support/JAMF/Waiting Room/com.sentinelone.system-extension.mobileconfig",
			"/Library/Managed Preferences/com.sentinelone.agent.plist",
		},
	},
	{
		vendor:       "Kandji",
		product:      "Kandji Agent",
		processHints: []string{"kandji", "com.kandji.agent"},
		installPaths: []string{
			"/Library/Kandji",
			"/Library/Application Support/Kandji",
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
			{"/usr/local/bin/kandji", "version"},
		},
		mobileConfig: []string{
			"/Library/Managed Preferences/com.kandji.agent.plist",
		},
	},
}

var appVersionReader = readAppVersion
var daemonProgramReader = readDaemonProgram
var customSignatureLoader = loadCustomSignatures
var signatureMerger = mergeSignatures
var customSignatureCache = newSignatureCache()
var commandExecutor = runCommand
var fileInfoFunc = func(path string) (os.FileInfo, error) { return os.Stat(path) }
var fileReaderFunc = os.ReadFile

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
			for key, value := range collectCLIData(vendor) {
				notes[key] = value
			}
		}
		if present, tokenPath := existsAny(vendor.tokenPaths); present {
			notes["registration_token_present"] = "true"
			notes["registration_token_path"] = tokenPath
			annotateFileMetadata(notes, tokenPath, "registration_token")
		} else {
			notes["registration_token_present"] = "false"
		}
		if len(vendor.mobileConfig) > 0 {
			if present, profilePath := existsAny(vendor.mobileConfig); present {
				notes["management_profile_present"] = "true"
				notes["management_profile_path"] = profilePath
			} else {
				notes["management_profile_present"] = "false"
			}
		}
		applyDerivedNotes(vendor.vendor, notes)

		if version != "" {
			switch vendor.vendor {
			case "SentinelOne":
				if cliVersion, ok := notes["sentinelctl_version_version"]; ok && cliVersion != "" && cliVersion != version {
					notes["version_mismatch"] = "true"
					notes["version_cli"] = cliVersion
					notes["version_app"] = version
				}
			case "Kandji":
				if cliVersion, ok := notes["kandji_version_version"]; ok && cliVersion != "" && cliVersion != version {
					notes["version_mismatch"] = "true"
					notes["version_cli"] = cliVersion
					notes["version_app"] = version
				}
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

func collectCLIData(vendor vendorSignature) map[string]string {
	results := map[string]string{}
	for _, cmd := range vendor.statusCommands {
		if len(cmd) == 0 {
			continue
		}
		if !securityAgentPathExists(cmd[0]) {
			continue
		}
		output, err := commandExecutor(cmd, cliStatusTimeout)
		trimmed := strings.TrimSpace(output)
		if trimmed == "" && err == nil {
			continue
		}
		baseKey := commandKey(cmd)
		if trimmed != "" {
			if existing, ok := results[baseKey+"_raw"]; ok {
				results[baseKey+"_raw"] = truncate(existing+"\n"+trimmed, maxCLIStatusLen)
			} else {
				results[baseKey+"_raw"] = truncate(trimmed, maxCLIStatusLen)
			}
			for k, v := range parseKeyValueOutput(trimmed) {
				results[baseKey+"_"+k] = v
			}
		}
		if err != nil {
			results[baseKey+"_error"] = err.Error()
		}
	}
	return results
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
	TokenPaths      []string   `json:"token_paths"`
	MobileConfig    []string   `json:"mobile_config_paths"`
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
				tokenPaths:      cloneStrings(spec.TokenPaths),
				mobileConfig:    cloneStrings(spec.MobileConfig),
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
		tokenPaths:      cloneStrings(sig.tokenPaths),
		mobileConfig:    cloneStrings(sig.mobileConfig),
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

var nonAlphaNumeric = regexp.MustCompile(`[^a-z0-9]+`)

func commandKey(cmd []string) string {
	if len(cmd) == 0 {
		return "cli"
	}
	parts := make([]string, 0, len(cmd))
	base := sanitizeKey(filepath.Base(cmd[0]))
	if base != "" {
		parts = append(parts, base)
	}
	for _, arg := range cmd[1:] {
		sanitized := sanitizeKey(arg)
		if sanitized != "" {
			parts = append(parts, sanitized)
		}
	}
	if len(parts) == 0 {
		return "cli"
	}
	return strings.Join(parts, "_")
}

func sanitizeKey(input string) string {
	s := strings.ToLower(strings.TrimSpace(input))
	s = nonAlphaNumeric.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	return s
}

func parseKeyValueOutput(output string) map[string]string {
	result := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		sep := strings.Index(line, ":")
		if sep <= 0 {
			continue
		}
		key := sanitizeKey(line[:sep])
		value := strings.TrimSpace(line[sep+1:])
		if key == "" || value == "" {
			continue
		}
		result[key] = value
	}
	return result
}

func applyDerivedNotes(vendor string, notes map[string]string) {
	applyCommonDerivedNotes(notes)
	switch vendor {
	case "SentinelOne":
		deriveSentinelOneNotes(notes)
	case "Kandji":
		augmentKandjiPreferences(notes)
		deriveKandjiNotes(notes)
	}
}

func deriveSentinelOneNotes(notes map[string]string) {
	if value, ok := notes["sentinelctl_management_status_connectivity"]; ok {
		notes["connectivity_ok"] = boolToString(isTruthy(value))
	}
	if value, ok := notes["sentinelctl_management_status_anti_tamper"]; ok {
		notes["anti_tamper_enabled"] = boolToString(isTruthy(value))
	}
	if value, ok := notes["sentinelctl_management_status_agent_enabled"]; ok {
		notes["agent_enabled"] = boolToString(isTruthy(value))
	}
	if uuid, ok := notes["sentinelctl_stats_agent_info_agent_uuid"]; ok && uuid != "" {
		notes["agent_uuid"] = uuid
	}
	if token, ok := notes["sentinelctl_management_status_site_token"]; ok && token != "" {
		notes["site_token"] = token
	} else if token, ok := notes["sentinelctl_stats_agent_info_site_token"]; ok && token != "" {
		notes["site_token"] = token
	}
	if name, ok := notes["sentinelctl_management_status_site_name"]; ok && name != "" {
		notes["site_name"] = name
	}
	if policy, ok := notes["sentinelctl_management_status_policy"]; ok && policy != "" {
		notes["policy_name"] = policy
	}
	if version, ok := notes["sentinelctl_management_status_version"]; ok && version != "" {
		notes["management_version"] = version
	}
	if rawURL, ok := notes["sentinelctl_management_status_management_url"]; ok && rawURL != "" {
		if parsed, err := url.Parse(rawURL); err == nil {
			notes["management_url_host"] = parsed.Hostname()
		}
	}
	if pkg := parsePackageVersion(notes); pkg != "" {
		notes["package_version"] = pkg
	}
	if status, ok := notes["sentinelctl_scan_status_status"]; ok && status != "" {
		inProgress := !strings.EqualFold(status, "idle") && !strings.EqualFold(status, "not running") && !strings.EqualFold(status, "completed")
		notes["scan_in_progress"] = boolToString(inProgress)
	}
	if raw, ok := notes["sentinelctl_scan_status_last_scan"]; ok && raw != "" {
		if ts, parsed := parseFlexibleTime(raw); parsed {
			notes["sentinelctl_scan_status_last_scan_at"] = ts.UTC().Format(time.RFC3339)
			hours := time.Since(ts).Hours()
			if hours < 0 {
				hours = -hours
			}
			notes["scan_last_seen_hours"] = fmt.Sprintf("%.1f", hours)
			notes["scan_recent"] = boolToString(hours <= 168)
		}
	}
	for key, value := range notes {
		if strings.Contains(key, "systemctl") && strings.HasSuffix(key, "_active") {
			notes["service_active"] = boolToString(isTruthy(value))
		}
	}
	if pkg, ok := notes["package_version"]; ok && pkg != "" {
		if version, ok := notes["version"]; ok && version != "" {
			notes["package_version_mismatch"] = boolToString(!strings.HasPrefix(pkg, version))
		}
	}
	healthIssues := make([]string, 0)
	if notes["connectivity_ok"] != "true" {
		healthIssues = append(healthIssues, "connectivity")
	}
	if notes["anti_tamper_enabled"] != "true" {
		healthIssues = append(healthIssues, "anti_tamper")
	}
	if notes["agent_enabled"] != "true" {
		healthIssues = append(healthIssues, "agent_disabled")
	}
	if notes["service_active"] == "false" {
		healthIssues = append(healthIssues, "service_inactive")
	}
	if notes["registration_token_present"] != "true" {
		healthIssues = append(healthIssues, "token_missing")
	} else if notes["registration_token_stale"] == "true" {
		healthIssues = append(healthIssues, "token_stale")
	}
	if notes["management_profile_present"] != "true" {
		healthIssues = append(healthIssues, "profile_missing")
	}
	if notes["package_version_mismatch"] == "true" {
		healthIssues = append(healthIssues, "package_mismatch")
	}
	if notes["scan_recent"] == "false" {
		healthIssues = append(healthIssues, "scan_stale")
	}
	if len(healthIssues) == 0 {
		notes["health_ok"] = "true"
		notes["health_issues"] = ""
	} else {
		notes["health_ok"] = "false"
		notes["health_issues"] = strings.Join(healthIssues, ",")
	}
}

func deriveKandjiNotes(notes map[string]string) {
	if state, ok := notes["kandji_library_state_state"]; ok && state != "" {
		notes["kandji_library_state_ok"] = boolToString(isHealthyKandjiState(state))
	}
	if raw, ok := notes["kandji_library_state_last_run"]; ok && raw != "" {
		if ts, parsed := parseFlexibleTime(raw); parsed {
			notes["kandji_last_run_at"] = ts.UTC().Format(time.RFC3339)
			hours := time.Since(ts).Hours()
			if hours < 0 {
				hours = -hours
			}
			notes["kandji_last_run_hours"] = fmt.Sprintf("%.1f", hours)
			notes["kandji_last_run_recent"] = boolToString(hours <= 24)
		}
	}
	if raw, ok := notes["kandji_prefs_last_check_in"]; ok && raw != "" {
		if ts, parsed := parseFlexibleTime(raw); parsed {
			notes["kandji_last_check_in_at"] = ts.UTC().Format(time.RFC3339)
			hours := time.Since(ts).Hours()
			if hours < 0 {
				hours = -hours
			}
			notes["kandji_last_check_in_hours"] = fmt.Sprintf("%.1f", hours)
			notes["kandji_last_check_in_recent"] = boolToString(hours <= 24)
		}
	}
	if enforcement, ok := notes["kandji_prefs_enforcement"]; ok && enforcement != "" {
		notes["kandji_enforced"] = boolToString(isTruthy(enforcement))
	}
	if pending, ok := notes["kandji_prefs_pending_items"]; ok && pending != "" {
		if val, err := strconv.Atoi(pending); err == nil {
			notes["kandji_pending_items"] = strconv.Itoa(val)
			notes["kandji_has_pending"] = boolToString(val > 0)
		}
	}
	healthIssues := make([]string, 0)
	if notes["kandji_library_state_ok"] != "true" {
		healthIssues = append(healthIssues, "library_state")
	}
	if notes["kandji_last_run_recent"] != "true" {
		healthIssues = append(healthIssues, "last_run_stale")
	}
	if notes["kandji_last_check_in_recent"] != "true" {
		healthIssues = append(healthIssues, "check_in_stale")
	}
	if notes["kandji_enforced"] != "true" {
		healthIssues = append(healthIssues, "not_enforced")
	}
	if notes["kandji_has_pending"] == "true" {
		healthIssues = append(healthIssues, "pending_items")
	}
	if len(healthIssues) == 0 {
		notes["kandji_health_ok"] = "true"
		notes["kandji_health_issues"] = ""
	} else {
		notes["kandji_health_ok"] = "false"
		notes["kandji_health_issues"] = strings.Join(healthIssues, ",")
	}
}

func isHealthyKandjiState(state string) bool {
	s := strings.ToLower(strings.TrimSpace(state))
	switch s {
	case "idle", "complete", "completed", "success", "succeeded", "ready", "ok":
		return true
	default:
		return false
	}
}

func parseFlexibleTime(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05 MST",
		time.RFC1123Z,
		time.RFC1123,
		time.RFC850,
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, trimmed); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

func isTruthy(value string) bool {
	s := strings.ToLower(strings.TrimSpace(value))
	switch s {
	case "1", "on", "true", "enabled", "yes", "running", "connected", "active", "enforced":
		return true
	default:
		return strings.HasPrefix(s, "active") || strings.HasPrefix(s, "running") || strings.HasPrefix(s, "enabled") || strings.HasPrefix(s, "connected") || strings.HasPrefix(s, "true") || strings.HasPrefix(s, "yes") || strings.HasPrefix(s, "enforc")
	}
}

func boolToString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func annotateFileMetadata(notes map[string]string, path, prefix string) {
	info, err := fileInfoFunc(path)
	if err != nil {
		notes[prefix+"_error"] = err.Error()
		return
	}
	notes[prefix+"_mtime"] = info.ModTime().UTC().Format(time.RFC3339)
	hours := time.Since(info.ModTime()).Hours()
	if hours < 0 {
		hours = -hours
	}
	notes[prefix+"_age_hours"] = fmt.Sprintf("%.1f", hours)
	notes[prefix+"_size_bytes"] = strconv.FormatInt(info.Size(), 10)
	notes[prefix+"_stale"] = boolToString(hours > 48)
}

func augmentKandjiPreferences(notes map[string]string) {
	paths := []string{
		"/Library/Managed Preferences/com.kandji.agent.plist",
		"/Library/Preferences/com.kandji.agent.plist",
	}
	for _, path := range paths {
		data, err := fileReaderFunc(path)
		if err != nil {
			continue
		}
		var parsed map[string]any
		if _, err := plist.Unmarshal(data, &parsed); err != nil {
			continue
		}
		notes["kandji_prefs_present"] = "true"
		notes["kandji_prefs_path"] = path
		assignIfPresent(notes, "kandji_prefs_last_check_in", parsed, "last_check_in")
		assignIfPresent(notes, "kandji_prefs_enforcement", parsed, "enforcement_state")
		assignIfPresent(notes, "kandji_prefs_blueprint", parsed, "blueprint_name")
		assignIfPresent(notes, "kandji_prefs_device_uuid", parsed, "device_uuid")
		assignIfPresent(notes, "kandji_prefs_pending_items", parsed, "pending_items")
		return
	}
}

func assignIfPresent(notes map[string]string, key string, source map[string]any, field string) {
	if value, ok := source[field]; ok {
		if str := stringFromAny(value); str != "" {
			notes[key] = str
		}
	}
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case []byte:
		return string(v)
	case bool:
		return strconv.FormatBool(v)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return fmt.Sprintf("%.0f", v)
	default:
		return ""
	}
}

func applyCommonDerivedNotes(notes map[string]string) {
	if count := countCLIErrorNotes(notes); count > 0 {
		notes["cli_error_count"] = strconv.Itoa(count)
	}
}

func countCLIErrorNotes(notes map[string]string) int {
	count := 0
	for key := range notes {
		if strings.HasSuffix(key, "_error") {
			count++
		}
	}
	return count
}

func parsePackageVersion(notes map[string]string) string {
	if raw, ok := notes["rpm_q_sentinelone_raw"]; ok && raw != "" {
		if v := parseRPMVersion(raw); v != "" {
			return v
		}
	}
	if raw, ok := notes["dpkg_query_w_sentinelone_raw"]; ok && raw != "" {
		if v := parseDPKGVersion(raw); v != "" {
			return v
		}
	}
	return ""
}

func parseRPMVersion(raw string) string {
	line := strings.TrimSpace(raw)
	if line == "" {
		return ""
	}
	parts := strings.SplitN(line, "-", 2)
	if len(parts) != 2 {
		return ""
	}
	rest := parts[1]
	if idx := strings.LastIndex(rest, "."); idx != -1 {
		rest = rest[:idx]
	}
	return strings.TrimSpace(rest)
}

func parseDPKGVersion(raw string) string {
	line := strings.TrimSpace(raw)
	if line == "" {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		return strings.TrimSpace(fields[1])
	}
	if idx := strings.Index(line, "	"); idx != -1 {
		return strings.TrimSpace(line[idx+1:])
	}
	if idx := strings.Index(line, ":"); idx != -1 {
		return strings.TrimSpace(line[idx+1:])
	}
	return ""
}
