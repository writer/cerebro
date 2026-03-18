// Package runtime provides real-time threat detection and response capabilities
// for cloud-native workloads. It processes telemetry events from deployed agents
// and applies detection rules to identify security threats.
//
// The package implements a detection engine that:
//   - Processes events from Kubernetes pods, EC2 instances, and Lambda functions
//   - Applies configurable detection rules with MITRE ATT&CK mapping
//   - Generates security findings with severity ratings
//   - Supports automated response actions (alert, isolate, kill, quarantine)
//
// Detection categories include crypto mining, container escape, privilege escalation,
// lateral movement, data exfiltration, reverse shells, malware, persistence mechanisms,
// credential access, and container drift.
//
// Example usage:
//
//	engine := runtime.NewDetectionEngine()
//	findings := engine.ProcessEvent(ctx, event)
//	for _, f := range findings {
//	    log.Printf("Detection: %s (severity: %s)", f.RuleName, f.Severity)
//	}
package runtime

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DetectionEngine is the core runtime threat detection component. It maintains
// a set of detection rules and processes incoming telemetry events to identify
// security threats in real-time.
//
// The engine supports rule suppression to reduce alert fatigue for known-good
// behaviors and provides MITRE ATT&CK technique mapping for all detections.
//
// Thread-safe for concurrent event processing.
type DetectionEngine struct {
	rules          []DetectionRule // Active detection rules
	rulesByMask    [16][]DetectionRule
	suppressions   map[string]bool  // Rule IDs that are suppressed
	recentFindings []RuntimeFinding // Recent findings ring buffer
	maxFindings    int              // Max findings to retain
	mu             sync.RWMutex     // Protects recentFindings
}

// DetectionRule defines a runtime threat detection rule with conditions,
// severity rating, and response configuration. Rules are evaluated against
// incoming telemetry events to identify potential security threats.
//
// Each rule includes MITRE ATT&CK technique IDs for threat intelligence
// correlation and incident response prioritization.
type DetectionRule struct {
	ID           string            `json:"id"`           // Unique rule identifier
	Name         string            `json:"name"`         // Human-readable rule name
	Description  string            `json:"description"`  // Detailed description of what the rule detects
	Category     DetectionCategory `json:"category"`     // Threat category for grouping/filtering
	Severity     string            `json:"severity"`     // critical, high, medium, low
	Enabled      bool              `json:"enabled"`      // Whether rule is active
	Conditions   []Condition       `json:"conditions"`   // Conditions that must match
	MITRE        []string          `json:"mitre_attack"` // MITRE ATT&CK technique IDs (e.g., T1496)
	Response     ResponseAction    `json:"response"`     // Automated response configuration
	requiredMask detectionFieldMask
}

// DetectionCategory classifies the type of threat being detected.
// Categories align with common security frameworks and help with
// alert triage and incident response workflows.
type DetectionCategory string

// Detection categories covering the major classes of runtime threats.
// These map to common attack patterns observed in cloud-native environments.
const (
	CategoryCryptoMining        DetectionCategory = "crypto_mining"        // Unauthorized cryptocurrency mining
	CategoryContainerEscape     DetectionCategory = "container_escape"     // Attempts to break out of container isolation
	CategoryPrivilegeEscalation DetectionCategory = "privilege_escalation" // Elevation of privileges beyond authorized level
	CategoryLateralMovement     DetectionCategory = "lateral_movement"     // Movement between systems/resources
	CategoryDataExfiltration    DetectionCategory = "data_exfiltration"    // Unauthorized data transfer out of environment
	CategoryReverseShell        DetectionCategory = "reverse_shell"        // Outbound shell connections for remote access
	CategoryMalware             DetectionCategory = "malware"              // Known malicious software patterns
	CategoryPersistence         DetectionCategory = "persistence"          // Mechanisms for maintaining access
	CategoryCredentialAccess    DetectionCategory = "credential_access"    //nolint:gosec // Attempts to steal credentials
	CategoryContainerDrift      DetectionCategory = "container_drift"      // Unexpected changes to container filesystem
)

type Condition struct {
	Field         string `json:"field"`
	Operator      string `json:"operator"` // eq, neq, contains, regex, gt, lt
	Value         string `json:"value"`
	compiledRegex *regexp.Regexp
}

type ResponseAction struct {
	Type        string `json:"type"` // alert, isolate, kill, quarantine
	AutoExecute bool   `json:"auto_execute"`
}

type detectionFieldMask uint8

const (
	detectionFieldProcess detectionFieldMask = 1 << iota
	detectionFieldNetwork
	detectionFieldFile
	detectionFieldContainer
)

// RuntimeEvent represents a telemetry event from agents
type RuntimeEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	Source       string                 `json:"source"`        // agent ID
	ResourceID   string                 `json:"resource_id"`   // pod, VM, function
	ResourceType string                 `json:"resource_type"` // pod, ec2, lambda
	EventType    string                 `json:"event_type"`    // process, network, file
	Process      *ProcessEvent          `json:"process,omitempty"`
	Network      *NetworkEvent          `json:"network,omitempty"`
	File         *FileEvent             `json:"file,omitempty"`
	Container    *ContainerEvent        `json:"container,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type ProcessEvent struct {
	PID        int      `json:"pid"`
	PPID       int      `json:"ppid"`
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Cmdline    string   `json:"cmdline"`
	User       string   `json:"user"`
	UID        int      `json:"uid"`
	Hash       string   `json:"hash"`
	ParentName string   `json:"parent_name"`
	Ancestors  []string `json:"ancestors"`
}

type NetworkEvent struct {
	Direction string `json:"direction"` // inbound, outbound
	Protocol  string `json:"protocol"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DstIP     string `json:"dst_ip"`
	DstPort   int    `json:"dst_port"`
	Domain    string `json:"domain,omitempty"`
	BytesSent int64  `json:"bytes_sent"`
	BytesRecv int64  `json:"bytes_recv"`
}

type FileEvent struct {
	Operation string `json:"operation"` // create, modify, delete, read
	Path      string `json:"path"`
	Hash      string `json:"hash,omitempty"`
	Size      int64  `json:"size"`
	User      string `json:"user"`
}

type ContainerEvent struct {
	ContainerID   string   `json:"container_id"`
	ContainerName string   `json:"container_name"`
	Image         string   `json:"image"`
	ImageID       string   `json:"image_id"`
	Namespace     string   `json:"namespace"`
	PodName       string   `json:"pod_name"`
	Privileged    bool     `json:"privileged"`
	Capabilities  []string `json:"capabilities"`
}

// RuntimeFinding represents a detected threat
type RuntimeFinding struct {
	ID           string              `json:"id"`
	RuleID       string              `json:"rule_id"`
	RuleName     string              `json:"rule_name"`
	Category     DetectionCategory   `json:"category"`
	Severity     string              `json:"severity"`
	ResourceID   string              `json:"resource_id"`
	ResourceType string              `json:"resource_type"`
	Description  string              `json:"description"`
	Event        *RuntimeEvent       `json:"event"`
	Observation  *RuntimeObservation `json:"observation,omitempty"`
	MITRE        []string            `json:"mitre_attack"`
	Remediation  string              `json:"remediation"`
	Suppressed   bool                `json:"suppressed"`
	Timestamp    time.Time           `json:"timestamp"`
}

func NewDetectionEngine() *DetectionEngine {
	engine := &DetectionEngine{
		rules:          make([]DetectionRule, 0),
		suppressions:   make(map[string]bool),
		recentFindings: make([]RuntimeFinding, 0),
		maxFindings:    1000,
	}
	engine.loadDefaultRules()
	return engine
}

func (e *DetectionEngine) loadDefaultRules() {
	e.rules = e.prepareRules([]DetectionRule{
		// Crypto Mining Detection
		{
			ID:          "crypto-mining-process",
			Name:        "Cryptocurrency Mining Process",
			Description: "Detected process associated with cryptocurrency mining",
			Category:    CategoryCryptoMining,
			Severity:    "high",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "process.name", Operator: "regex", Value: "(?i)(xmrig|minerd|cgminer|bfgminer|ethminer|cpuminer|stratum)"},
			},
			MITRE:    []string{"T1496"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},
		{
			ID:          "crypto-mining-pool-connection",
			Name:        "Connection to Mining Pool",
			Description: "Detected network connection to known cryptocurrency mining pool",
			Category:    CategoryCryptoMining,
			Severity:    "high",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "network.dst_port", Operator: "eq", Value: "3333"},
				{Field: "network.domain", Operator: "regex", Value: "(?i)(pool\\.|mining\\.|stratum\\.)"},
			},
			MITRE:    []string{"T1496"},
			Response: ResponseAction{Type: "isolate", AutoExecute: false},
		},

		// Container Escape Detection
		{
			ID:          "container-escape-nsenter",
			Name:        "Container Escape via nsenter",
			Description: "Detected nsenter execution which can be used for container escape",
			Category:    CategoryContainerEscape,
			Severity:    "critical",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "process.name", Operator: "eq", Value: "nsenter"},
				{Field: "container.container_id", Operator: "neq", Value: ""},
			},
			MITRE:    []string{"T1611"},
			Response: ResponseAction{Type: "kill", AutoExecute: true},
		},
		{
			ID:          "container-escape-mount-host",
			Name:        "Container Mounting Host Filesystem",
			Description: "Container process attempting to mount host filesystem",
			Category:    CategoryContainerEscape,
			Severity:    "critical",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "process.cmdline", Operator: "contains", Value: "mount"},
				{Field: "process.cmdline", Operator: "regex", Value: "/host|/proc/1"},
			},
			MITRE:    []string{"T1611"},
			Response: ResponseAction{Type: "kill", AutoExecute: true},
		},
		{
			ID:          "container-privileged-shell",
			Name:        "Privileged Container Shell Access",
			Description: "Interactive shell spawned in privileged container",
			Category:    CategoryContainerEscape,
			Severity:    "high",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "container.privileged", Operator: "eq", Value: "true"},
				{Field: "process.name", Operator: "regex", Value: "^(bash|sh|zsh|fish)$"},
				{Field: "process.parent_name", Operator: "neq", Value: "entrypoint"},
			},
			MITRE:    []string{"T1059.004"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},

		// Privilege Escalation
		{
			ID:          "privesc-setuid-execution",
			Name:        "Setuid Binary Execution",
			Description: "Execution of setuid binary for potential privilege escalation",
			Category:    CategoryPrivilegeEscalation,
			Severity:    "medium",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "process.path", Operator: "regex", Value: "(/usr)?/bin/(sudo|su|pkexec|doas)"},
				{Field: "process.uid", Operator: "neq", Value: "0"},
			},
			MITRE:    []string{"T1548.001"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},
		{
			ID:          "privesc-cap-sys-admin",
			Name:        "Process with CAP_SYS_ADMIN",
			Description: "Non-root process gained CAP_SYS_ADMIN capability",
			Category:    CategoryPrivilegeEscalation,
			Severity:    "high",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "container.capabilities", Operator: "contains", Value: "CAP_SYS_ADMIN"},
				{Field: "process.uid", Operator: "neq", Value: "0"},
			},
			MITRE:    []string{"T1548"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},

		// Reverse Shell Detection
		{
			ID:          "reverse-shell-bash",
			Name:        "Bash Reverse Shell",
			Description: "Detected bash reverse shell pattern",
			Category:    CategoryReverseShell,
			Severity:    "critical",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "process.cmdline", Operator: "regex", Value: "bash.*-i.*>&.*/dev/tcp|nc.*-e.*/bin/(ba)?sh"},
			},
			MITRE:    []string{"T1059.004", "T1571"},
			Response: ResponseAction{Type: "kill", AutoExecute: true},
		},
		{
			ID:          "reverse-shell-python",
			Name:        "Python Reverse Shell",
			Description: "Detected Python reverse shell pattern",
			Category:    CategoryReverseShell,
			Severity:    "critical",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "process.name", Operator: "regex", Value: "python"},
				{Field: "process.cmdline", Operator: "contains", Value: "socket"},
				{Field: "process.cmdline", Operator: "regex", Value: "subprocess|os\\.dup2|pty\\.spawn"},
			},
			MITRE:    []string{"T1059.006", "T1571"},
			Response: ResponseAction{Type: "kill", AutoExecute: true},
		},

		// Lateral Movement
		{
			ID:          "lateral-movement-ssh-unusual",
			Name:        "Unusual SSH Connection",
			Description: "SSH connection from unusual source process",
			Category:    CategoryLateralMovement,
			Severity:    "medium",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "network.dst_port", Operator: "eq", Value: "22"},
				{Field: "process.name", Operator: "neq", Value: "ssh"},
			},
			MITRE:    []string{"T1021.004"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},
		{
			ID:          "lateral-movement-imds-access",
			Name:        "IMDS Token Theft Attempt",
			Description: "Process accessing cloud instance metadata service",
			Category:    CategoryCredentialAccess,
			Severity:    "high",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "network.dst_ip", Operator: "eq", Value: "169.254.169.254"},
				{Field: "process.name", Operator: "neq", Value: "amazon-ssm-agent"},
			},
			MITRE:    []string{"T1552.005"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},

		// Data Exfiltration
		{
			ID:          "exfil-large-dns-query",
			Name:        "Large DNS Query (DNS Tunneling)",
			Description: "Unusually large DNS query suggesting DNS tunneling",
			Category:    CategoryDataExfiltration,
			Severity:    "high",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "network.protocol", Operator: "eq", Value: "dns"},
				{Field: "network.bytes_sent", Operator: "gt", Value: "512"},
			},
			MITRE:    []string{"T1048.003"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},
		{
			ID:          "exfil-cloud-storage-unusual",
			Name:        "Unusual Cloud Storage Upload",
			Description: "Large upload to cloud storage from unexpected process",
			Category:    CategoryDataExfiltration,
			Severity:    "medium",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "network.domain", Operator: "regex", Value: "(s3\\.amazonaws|storage\\.googleapis|blob\\.core\\.windows)\\."},
				{Field: "network.bytes_sent", Operator: "gt", Value: "104857600"}, // 100MB
			},
			MITRE:    []string{"T1567.002"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},

		// Container Drift
		{
			ID:          "container-drift-new-binary",
			Name:        "New Binary in Running Container",
			Description: "New executable created in running container filesystem",
			Category:    CategoryContainerDrift,
			Severity:    "high",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "file.operation", Operator: "eq", Value: "create"},
				{Field: "file.path", Operator: "regex", Value: "\\.(exe|elf|so|bin)$|^/usr/(local/)?(s)?bin/"},
				{Field: "container.container_id", Operator: "neq", Value: ""},
			},
			MITRE:    []string{"T1036"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},
		{
			ID:          "container-drift-package-install",
			Name:        "Package Manager in Container",
			Description: "Package manager executed in running container",
			Category:    CategoryContainerDrift,
			Severity:    "medium",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "process.name", Operator: "regex", Value: "^(apt|apt-get|yum|dnf|apk|pip|npm)$"},
				{Field: "container.container_id", Operator: "neq", Value: ""},
			},
			MITRE:    []string{"T1059"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},

		// Persistence
		{
			ID:          "persistence-cron-modification",
			Name:        "Cron Job Modification",
			Description: "Modification to cron configuration detected",
			Category:    CategoryPersistence,
			Severity:    "medium",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "file.operation", Operator: "regex", Value: "create|modify"},
				{Field: "file.path", Operator: "regex", Value: "/etc/cron|/var/spool/cron"},
			},
			MITRE:    []string{"T1053.003"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},
		{
			ID:          "persistence-ssh-key-added",
			Name:        "SSH Authorized Keys Modified",
			Description: "SSH authorized_keys file modified",
			Category:    CategoryPersistence,
			Severity:    "high",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "file.operation", Operator: "regex", Value: "create|modify"},
				{Field: "file.path", Operator: "contains", Value: "authorized_keys"},
			},
			MITRE:    []string{"T1098.004"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},

		// Credential Access
		{
			ID:          "credential-access-shadow-read",
			Name:        "Shadow File Access",
			Description: "Process reading /etc/shadow password file",
			Category:    CategoryCredentialAccess,
			Severity:    "high",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "file.operation", Operator: "eq", Value: "read"},
				{Field: "file.path", Operator: "eq", Value: "/etc/shadow"},
				{Field: "process.name", Operator: "neq", Value: "passwd"},
			},
			MITRE:    []string{"T1003.008"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},
		{
			ID:          "credential-access-aws-credentials",
			Name:        "AWS Credentials File Access",
			Description: "Process accessing AWS credentials file",
			Category:    CategoryCredentialAccess,
			Severity:    "medium",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "file.operation", Operator: "eq", Value: "read"},
				{Field: "file.path", Operator: "contains", Value: ".aws/credentials"},
			},
			MITRE:    []string{"T1552.001"},
			Response: ResponseAction{Type: "alert", AutoExecute: true},
		},
	})
	e.rebuildRuleMaskIndex()
}

// ProcessEvent evaluates an event against all rules and stores resulting findings
func (e *DetectionEngine) ProcessEvent(ctx context.Context, event *RuntimeEvent) []RuntimeFinding {
	observation := observationFromEventBase(event)
	if normalized, err := NormalizeObservation(observation); err == nil {
		observation = normalized
	}
	return e.process(ctx, event, observation)
}

// ProcessObservation evaluates a runtime observation after normalizing it.
func (e *DetectionEngine) ProcessObservation(ctx context.Context, observation *RuntimeObservation) []RuntimeFinding {
	if observation == nil {
		return nil
	}
	normalized, err := NormalizeObservation(observation)
	if err != nil {
		return nil
	}
	return e.ProcessNormalizedObservation(ctx, normalized)
}

// ProcessNormalizedObservation evaluates a previously-normalized runtime
// observation without re-running normalization in the hot path.
func (e *DetectionEngine) ProcessNormalizedObservation(ctx context.Context, observation *RuntimeObservation) []RuntimeFinding {
	if observation == nil {
		return nil
	}
	return e.process(ctx, observation.AsRuntimeEvent(), observation)
}

func (e *DetectionEngine) process(_ context.Context, event *RuntimeEvent, observation *RuntimeObservation) []RuntimeFinding {
	if event == nil {
		return nil
	}
	var findings []RuntimeFinding

	for _, rule := range e.candidateRulesForEvent(event) {
		if !rule.Enabled {
			continue
		}

		if e.matchesRule(event, rule) {
			finding := RuntimeFinding{
				ID:           generateFindingID(rule.ID, event),
				RuleID:       rule.ID,
				RuleName:     rule.Name,
				Category:     rule.Category,
				Severity:     rule.Severity,
				ResourceID:   event.ResourceID,
				ResourceType: event.ResourceType,
				Description:  rule.Description,
				Event:        event,
				Observation:  observation,
				MITRE:        rule.MITRE,
				Remediation:  getRemediation(rule),
				Suppressed:   e.suppressions[rule.ID],
				Timestamp:    time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	if len(findings) > 0 {
		e.storeFindings(findings)
	}

	return findings
}

// storeFindings appends findings to the in-memory ring buffer
func (e *DetectionEngine) storeFindings(findings []RuntimeFinding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.recentFindings = append(e.recentFindings, findings...)
	if len(e.recentFindings) > e.maxFindings {
		e.recentFindings = e.recentFindings[len(e.recentFindings)-e.maxFindings:]
	}
}

// RecentFindings returns the most recent runtime findings, up to limit
func (e *DetectionEngine) RecentFindings(limit int) []RuntimeFinding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if limit <= 0 || limit > len(e.recentFindings) {
		limit = len(e.recentFindings)
	}
	start := len(e.recentFindings) - limit
	result := make([]RuntimeFinding, limit)
	copy(result, e.recentFindings[start:])
	return result
}

func (e *DetectionEngine) matchesRule(event *RuntimeEvent, rule DetectionRule) bool {
	for _, cond := range rule.Conditions {
		if !e.evaluateCondition(event, cond) {
			return false
		}
	}
	return true
}

func (e *DetectionEngine) evaluateCondition(event *RuntimeEvent, cond Condition) bool {
	value := e.extractField(event, cond.Field)

	switch cond.Operator {
	case "eq":
		return value == cond.Value
	case "neq":
		return value != cond.Value
	case "contains":
		return strings.Contains(value, cond.Value)
	case "regex":
		if cond.compiledRegex != nil {
			return cond.compiledRegex.MatchString(value)
		}
		matched, _ := regexp.MatchString(cond.Value, value)
		return matched
	case "gt":
		// Simple numeric comparison for bytes
		return len(value) > len(cond.Value)
	case "lt":
		return len(value) < len(cond.Value)
	}

	return false
}

func (e *DetectionEngine) extractField(event *RuntimeEvent, field string) string {
	parts := strings.Split(field, ".")
	if len(parts) < 2 {
		return ""
	}

	switch parts[0] {
	case "process":
		if event.Process == nil {
			return ""
		}
		switch parts[1] {
		case "name":
			return event.Process.Name
		case "path":
			return event.Process.Path
		case "cmdline":
			return event.Process.Cmdline
		case "user":
			return event.Process.User
		case "uid":
			return itoa(event.Process.UID)
		case "parent_name":
			return event.Process.ParentName
		}
	case "network":
		if event.Network == nil {
			return ""
		}
		switch parts[1] {
		case "dst_ip":
			return event.Network.DstIP
		case "dst_port":
			return itoa(event.Network.DstPort)
		case "src_ip":
			return event.Network.SrcIP
		case "domain":
			return event.Network.Domain
		case "protocol":
			return event.Network.Protocol
		case "bytes_sent":
			return itoa64(event.Network.BytesSent)
		}
	case "file":
		if event.File == nil {
			return ""
		}
		switch parts[1] {
		case "operation":
			return event.File.Operation
		case "path":
			return event.File.Path
		}
	case "container":
		if event.Container == nil {
			return ""
		}
		switch parts[1] {
		case "container_id":
			return event.Container.ContainerID
		case "privileged":
			if event.Container.Privileged {
				return "true"
			}
			return "false"
		case "capabilities":
			return strings.Join(event.Container.Capabilities, ",")
		}
	}

	return ""
}

func (e *DetectionEngine) AddRule(rule DetectionRule) {
	prepared := e.prepareRule(rule)
	e.rules = append(e.rules, prepared)
	e.addRuleToMaskIndex(prepared)
}

func (e *DetectionEngine) SetSuppression(ruleID string, suppressed bool) {
	e.suppressions[ruleID] = suppressed
}

func (e *DetectionEngine) ListRules() []DetectionRule {
	return e.rules
}

func (e *DetectionEngine) candidateRulesForEvent(event *RuntimeEvent) []DetectionRule {
	return e.rulesByMask[eventFieldMask(event)]
}

func (e *DetectionEngine) prepareRules(rules []DetectionRule) []DetectionRule {
	prepared := make([]DetectionRule, 0, len(rules))
	for _, rule := range rules {
		prepared = append(prepared, e.prepareRule(rule))
	}
	return prepared
}

func (e *DetectionEngine) prepareRule(rule DetectionRule) DetectionRule {
	conditions := make([]Condition, 0, len(rule.Conditions))
	var mask detectionFieldMask
	for _, cond := range rule.Conditions {
		cond.compiledRegex = nil
		if cond.Operator == "regex" {
			if compiled, err := regexp.Compile(cond.Value); err == nil {
				cond.compiledRegex = compiled
			}
		}
		if !conditionCanMatchEmpty(cond) {
			mask |= conditionFieldMask(cond.Field)
		}
		conditions = append(conditions, cond)
	}
	rule.Conditions = conditions
	rule.requiredMask = mask
	return rule
}

func (e *DetectionEngine) rebuildRuleMaskIndex() {
	e.rulesByMask = [16][]DetectionRule{}
	for _, rule := range e.rules {
		e.addRuleToMaskIndex(rule)
	}
}

func (e *DetectionEngine) addRuleToMaskIndex(rule DetectionRule) {
	for mask := detectionFieldMask(0); mask < 16; mask++ {
		if mask&rule.requiredMask != rule.requiredMask {
			continue
		}
		e.rulesByMask[mask] = append(e.rulesByMask[mask], rule)
	}
}

func eventFieldMask(event *RuntimeEvent) detectionFieldMask {
	if event == nil {
		return 0
	}
	var mask detectionFieldMask
	if event.Process != nil {
		mask |= detectionFieldProcess
	}
	if event.Network != nil {
		mask |= detectionFieldNetwork
	}
	if event.File != nil {
		mask |= detectionFieldFile
	}
	if event.Container != nil {
		mask |= detectionFieldContainer
	}
	return mask
}

func conditionFieldMask(field string) detectionFieldMask {
	switch strings.SplitN(field, ".", 2)[0] {
	case "process":
		return detectionFieldProcess
	case "network":
		return detectionFieldNetwork
	case "file":
		return detectionFieldFile
	case "container":
		return detectionFieldContainer
	default:
		return 0
	}
}

func conditionCanMatchEmpty(cond Condition) bool {
	switch cond.Operator {
	case "eq":
		return cond.Value == ""
	case "neq":
		return cond.Value != ""
	case "contains":
		return cond.Value == ""
	case "regex":
		if cond.compiledRegex != nil {
			return cond.compiledRegex.MatchString("")
		}
		matched, err := regexp.MatchString(cond.Value, "")
		return err == nil && matched
	case "gt":
		return false
	case "lt":
		return len(cond.Value) > 0
	default:
		return false
	}
}

func generateFindingID(ruleID string, event *RuntimeEvent) string {
	return ruleID + "-" + event.ID
}

func getRemediation(rule DetectionRule) string {
	remediations := map[DetectionCategory]string{
		CategoryCryptoMining:        "Terminate the mining process and investigate how it was deployed. Check for unauthorized access.",
		CategoryContainerEscape:     "Isolate the container/pod immediately. Review container security context and capabilities.",
		CategoryPrivilegeEscalation: "Review the process legitimacy. Check for misconfigurations allowing privilege escalation.",
		CategoryLateralMovement:     "Block the network connection. Investigate the source and destination for compromise indicators.",
		CategoryDataExfiltration:    "Block the network connection. Investigate data access patterns and scope of potential data loss.",
		CategoryReverseShell:        "Kill the process and isolate the host. Investigate initial access vector.",
		CategoryMalware:             "Quarantine the affected system. Collect forensic evidence and investigate infection vector.",
		CategoryPersistence:         "Review and revert unauthorized changes. Investigate how persistence was established.",
		CategoryCredentialAccess:    "Rotate affected credentials immediately. Review access logs for unauthorized usage.",
		CategoryContainerDrift:      "Investigate the drift. Consider redeploying from trusted image.",
	}

	if rem, ok := remediations[rule.Category]; ok {
		return rem
	}
	return "Investigate the alert and take appropriate action based on your security policies."
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}

func itoa64(i int64) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}
