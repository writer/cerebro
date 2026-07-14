package mcpoperations

import (
	"encoding/json"
	"sort"
	"strings"
)

const ScopeSecurityRead = "cerebro.cosmo.security.read"

type Behavior string

const (
	BehaviorRead    Behavior = "read"
	BehaviorPropose Behavior = "propose"
)

type Classification string

const (
	ClassificationTask   Classification = "task-level"
	ClassificationExpert Classification = "expert"
)

// Operation is the checked-in inventory record for one public MCP tool.
type Operation struct {
	Name             string
	OwnerDomain      string
	Behavior         Behavior
	RequiredScopes   []string
	Classification   Classification
	ResponseContract string
	Deprecated       bool
	SelectionTerms   []string
}

var operationRegistry = buildOperationRegistry()

func buildOperationRegistry() map[string]Operation {
	operations := []Operation{
		taskRead("cerebro.health", "runtime", "service health", "health", "dependency"),
		taskRead("cerebro.version", "runtime", "build and API version", "version", "build"),
		expertRead("cerebro.sources.list", "sources", "source catalog"),
		expertRead("cerebro.sources.check", "sources", "live source check"),
		expertRead("cerebro.sources.discover", "sources", "live source discovery"),
		expertRead("cerebro.sources.read", "sources", "live source page"),
		expertRead("cerebro.source_runtimes.list", "source-runtime", "source runtime list"),
		expertRead("cerebro.connector_definitions.list", "connectors", "connector definition list"),
		expertRead("cerebro.connector_definitions.validate", "connectors", "connector definition validation"),
		expertRead("cerebro.findings.list", "findings", "runtime finding list"),
		expertRead("cerebro.findings.get", "findings", "finding record"),
		expertRead("cerebro.findings.search", "findings", "finding search results"),
		expertRead("cerebro.runtimes.status", "source-runtime", "runtime status and risk summary"),
		expertRead("cerebro.evidence.list", "findings", "finding evidence list"),
		expertRead("cerebro.evidence.get", "findings", "finding evidence record"),
		expertRead("cerebro.assets.search", "graph", "asset search results"),
		expertRead("cerebro.assets.get", "graph", "asset record"),
		expertRead("cerebro.risk.summary", "risk", "finding risk summary"),
		expertRead("cerebro.risk.actions.list", "risk", "risk action plan"),
		expertRead("cerebro.risk.actions.explain", "risk", "risk action explanation"),
		expertRead("cerebro.graph.neighborhood", "graph", "graph neighborhood"),
		expertRead("cerebro.graph.impact", "graph", "graph impact"),
		expertRead("cerebro.graph.paths", "graph", "attack paths"),
		expertRead("cerebro.graph.facts.list", "graph-facts", "graph fact list"),
		expertRead("cerebro.graph.facts.explain", "graph-facts", "graph fact explanation"),
		expertRead("cerebro.graph.facts.trace", "graph-facts", "graph fact trace"),
		expertRead("cerebro.agent.control_plane", "agent-platform", "agent control-plane contract"),
		expertRead("cerebro.agent.preflight", "agent-platform", "agent preflight"),
		expertRead("cerebro.agent.claims.verify", "agent-platform", "claim verification"),
		expertRead("cerebro.agent.work.contract", "agent-platform", "agent work contract"),
		expertRead("cerebro.graph.reason", "graph-agent", "graph reasoning trace"),
		expertRead("cerebro.investigation.context", "findings", "finding investigation context"),
		expertPropose("cerebro.findings.action.propose", "findings", "finding action proposal"),
		expertPropose("cerebro.source_runtimes.refresh.propose", "source-runtime", "runtime refresh proposal"),
		taskRead("cerebro.risk.explain", "findings", "task result with finding, evidence, assets, and optional graph context", "explain risk", "investigate finding", "why is this risky", "finding evidence"),
		taskRead("cerebro.evidence.packet", "agent-platform", "task result with an agent evidence packet and coverage state", "evidence packet", "collect evidence", "prepare evidence", "decision evidence"),
		taskRead("cerebro.sources.health", "source-runtime", "task result with source coverage and blind spots", "source health", "connector health", "blind spot", "coverage gap", "stale source"),
		taskPropose("cerebro.action.plan", "risk", "task result with ranked non-mutating action candidates", "plan remediation", "recommend action", "what should we fix", "next action", "execute remediation"),
	}
	registry := make(map[string]Operation, len(operations))
	for _, operation := range operations {
		registry[operation.Name] = operation
	}
	return registry
}

func taskRead(name string, domain string, response string, terms ...string) Operation {
	return operation(name, domain, BehaviorRead, ClassificationTask, response, terms)
}

func taskPropose(name string, domain string, response string, terms ...string) Operation {
	return operation(name, domain, BehaviorPropose, ClassificationTask, response, terms)
}

func expertRead(name string, domain string, response string) Operation {
	return operation(name, domain, BehaviorRead, ClassificationExpert, response, nil)
}

func expertPropose(name string, domain string, response string) Operation {
	return operation(name, domain, BehaviorPropose, ClassificationExpert, response, nil)
}

func operation(name string, domain string, behavior Behavior, classification Classification, response string, terms []string) Operation {
	return Operation{
		Name:             name,
		OwnerDomain:      domain,
		Behavior:         behavior,
		RequiredScopes:   []string{ScopeSecurityRead},
		Classification:   classification,
		ResponseContract: response,
		SelectionTerms:   append([]string(nil), terms...),
	}
}

func Lookup(name string) (Operation, bool) {
	operation, ok := operationRegistry[strings.TrimSpace(name)]
	if !ok {
		return Operation{}, false
	}
	operation.RequiredScopes = append([]string(nil), operation.RequiredScopes...)
	operation.SelectionTerms = append([]string(nil), operation.SelectionTerms...)
	return operation, true
}

func Operations() []Operation {
	operations := make([]Operation, 0, len(operationRegistry))
	for name := range operationRegistry {
		operation, _ := Lookup(name)
		operations = append(operations, operation)
	}
	sort.Slice(operations, func(i, j int) bool { return operations[i].Name < operations[j].Name })
	return operations
}

func TaskTools() []Operation {
	operations := Operations()
	tasks := make([]Operation, 0, len(operations))
	for _, operation := range operations {
		if operation.Classification == ClassificationTask {
			tasks = append(tasks, operation)
		}
	}
	return tasks
}

func IsTaskTool(name string) bool {
	operation, ok := Lookup(name)
	return ok && operation.Classification == ClassificationTask
}

func IsKnownTool(name string) bool {
	_, ok := Lookup(name)
	return ok
}

type Toolsets map[string]bool

func ParseToolsets(header string, rawParams []byte) Toolsets {
	values := strings.Split(header, ",")
	if len(rawParams) != 0 {
		var params struct {
			Toolsets json.RawMessage `json:"toolsets"`
		}
		if json.Unmarshal(rawParams, &params) == nil && len(params.Toolsets) != 0 {
			var list []string
			if json.Unmarshal(params.Toolsets, &list) == nil {
				values = append(values, list...)
			} else {
				var value string
				if json.Unmarshal(params.Toolsets, &value) == nil {
					values = append(values, strings.Split(value, ",")...)
				}
			}
		}
	}
	toolsets := Toolsets{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && value != "all" && value != "full" {
			toolsets[value] = true
		}
	}
	return toolsets
}

func EnabledForToolsets(name string, enabled Toolsets) bool {
	operation, known := Lookup(name)
	if enabled["task"] && known && operation.Classification == ClassificationTask {
		return true
	}
	if enabled["expert"] && known && (operation.Classification == ClassificationExpert || operation.OwnerDomain == "runtime") {
		return true
	}
	return enabled[ToolsetForName(name)]
}

func ToolsetForName(name string) string {
	name = strings.TrimPrefix(strings.TrimSpace(name), "cerebro.")
	switch {
	case strings.HasPrefix(name, "graph."):
		return "graph"
	case strings.HasPrefix(name, "risk."):
		return "risk"
	case strings.HasPrefix(name, "findings."), strings.HasPrefix(name, "evidence."), strings.HasPrefix(name, "investigation."):
		return "findings"
	case strings.HasPrefix(name, "assets."):
		return "assets"
	case strings.HasPrefix(name, "sources."), strings.HasPrefix(name, "source_runtimes."), strings.HasPrefix(name, "runtimes."), strings.HasPrefix(name, "connector_definitions."):
		return "operations"
	case strings.HasPrefix(name, "agent."):
		return "agent"
	default:
		return "core"
	}
}

func ToolFamily(name string) string {
	name = strings.TrimPrefix(strings.TrimSpace(name), "cerebro.")
	family, _, _ := strings.Cut(name, ".")
	if len(family) > 64 {
		family = family[:64]
	}
	return family
}

type TelemetryMetadata struct {
	Classification string
	Behavior       string
	OwnerDomain    string
	Task           bool
}

func TelemetryForTool(name string) (TelemetryMetadata, bool) {
	operation, ok := Lookup(name)
	if !ok {
		return TelemetryMetadata{}, false
	}
	return TelemetryMetadata{Classification: string(operation.Classification), Behavior: string(operation.Behavior), OwnerDomain: operation.OwnerDomain, Task: operation.Classification == ClassificationTask}, true
}

func SanitizeTelemetryValue(value string, limit int) string {
	value = strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(strings.TrimSpace(value))
	if limit > 0 && len(value) > limit {
		return value[:limit]
	}
	return value
}

func TelemetryOutcomeFailed(outcome string) bool {
	switch strings.TrimSpace(outcome) {
	case "ok", "notification", "client_message":
		return false
	default:
		return true
	}
}
