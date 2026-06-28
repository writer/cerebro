package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/bootstrap"
	appconfig "github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphagent"
)

type preflightReceipt struct {
	Kind                    string                    `json:"kind"`
	Status                  string                    `json:"status"`
	GeneratedAt             string                    `json:"generated_at"`
	RuntimeProfile          string                    `json:"runtime_profile,omitempty"`
	EnabledCapabilities     []string                  `json:"enabled_capabilities,omitempty"`
	RequiredBackingServices []preflightBackingService `json:"required_backing_services,omitempty"`
	RequiredSecretNames     []string                  `json:"required_secret_names,omitempty"`
	OperatorActions         []string                  `json:"operator_actions,omitempty"`
	Checks                  []preflightCheck          `json:"checks"`
}

type preflightCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type preflightBackingService struct {
	Name        string   `json:"name"`
	RequiredFor string   `json:"required_for"`
	ConfigVars  []string `json:"config_vars,omitempty"`
}

type preflightOptions struct {
	Format string
	Stdout io.Writer
}

type preflightRuntime struct {
	loadConfig       func() (appconfig.Config, error)
	openDependencies func(context.Context, appconfig.Config) (bootstrap.Dependencies, func() error, error)
	probeLLM         func(context.Context, graphagent.LLMClient) error
}

var (
	preflightDetailURLRe              = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)
	preflightDetailSecretAssignmentRe = regexp.MustCompile(`(?i)\b(access[_-]?token|api[_-]?key|authorization|client[_-]?secret|key|password|secret|token)=([^\s,;)&]+)`)
)

func runDeploy(args []string) error {
	if len(args) == 0 {
		return usageError("usage: cerebro deploy [preflight]")
	}
	switch args[0] {
	case "preflight":
		return runDeployPreflight(args[1:], preflightOptions{Stdout: os.Stdout})
	default:
		return usageError("usage: cerebro deploy [preflight]")
	}
}

func runDeployPreflight(args []string, opts preflightOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	fs := flag.NewFlagSet("deploy preflight", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "json", "output format: json or text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts.Format = strings.ToLower(strings.TrimSpace(firstNonEmptyString(opts.Format, *format)))
	if opts.Format == "" {
		opts.Format = "json"
	}
	receipt := executeDeployPreflight(context.Background())
	if err := writePreflightReceipt(opts.Stdout, receipt, opts.Format); err != nil {
		return err
	}
	if receipt.Status != "pass" {
		return fmt.Errorf("deploy preflight failed")
	}
	return nil
}

func executeDeployPreflight(ctx context.Context) preflightReceipt {
	return executeDeployPreflightWith(ctx, preflightRuntime{
		loadConfig:       appconfig.Load,
		openDependencies: bootstrap.OpenDependencies,
		probeLLM:         graphagent.ProbeLLM,
	})
}

func executeDeployPreflightWith(ctx context.Context, runtime preflightRuntime) (receipt preflightReceipt) {
	receipt = preflightReceipt{
		Kind:        "cerebro.deploy_preflight",
		Status:      "pass",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	addCheck := func(name string, err error) {
		check := preflightCheck{Name: name, Status: "pass"}
		if err != nil {
			check.Status = "fail"
			check.Detail = preflightErrorDetail(err)
			receipt.Status = "fail"
		}
		receipt.Checks = append(receipt.Checks, check)
	}

	cfg, err := runtime.loadConfig()
	addCheck("config.load", err)
	if err != nil {
		return receipt
	}
	annotatePreflightReceipt(&receipt, cfg)
	serveConfigErr := validateServeConfig(cfg)
	addCheck("serve_config.validate", serveConfigErr)
	if serveConfigErr != nil {
		return receipt
	}
	deps, closeDeps, err := runtime.openDependencies(ctx, cfg)
	addCheck("dependencies.open", err)
	if err != nil {
		return receipt
	}
	defer func() {
		addCheck("dependencies.close", closeDeps())
	}()
	addCheck("graph_agent_llm.probe", runtime.probeLLM(ctx, deps.GraphAgentLLM))
	return receipt
}

func writePreflightReceipt(w io.Writer, receipt preflightReceipt, format string) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(receipt)
	case "text":
		_, err := fmt.Fprintf(w, "deploy preflight: %s\n", receipt.Status)
		if err != nil {
			return err
		}
		for _, check := range receipt.Checks {
			line := fmt.Sprintf("- %s: %s", check.Name, check.Status)
			if check.Detail != "" {
				line += " (" + check.Detail + ")"
			}
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
		}
		if receipt.RuntimeProfile != "" {
			if _, err := fmt.Fprintf(w, "runtime profile: %s\n", receipt.RuntimeProfile); err != nil {
				return err
			}
		}
		writeTextList := func(title string, values []string) error {
			if len(values) == 0 {
				return nil
			}
			if _, err := fmt.Fprintln(w, title+":"); err != nil {
				return err
			}
			for _, value := range values {
				if _, err := fmt.Fprintln(w, "- "+value); err != nil {
					return err
				}
			}
			return nil
		}
		if err := writeTextList("enabled capabilities", receipt.EnabledCapabilities); err != nil {
			return err
		}
		if len(receipt.RequiredBackingServices) > 0 {
			if _, err := fmt.Fprintln(w, "required backing services:"); err != nil {
				return err
			}
			for _, service := range receipt.RequiredBackingServices {
				line := fmt.Sprintf("- %s: %s", service.Name, service.RequiredFor)
				if len(service.ConfigVars) > 0 {
					line += " (" + strings.Join(service.ConfigVars, ", ") + ")"
				}
				if _, err := fmt.Fprintln(w, line); err != nil {
					return err
				}
			}
		}
		if err := writeTextList("required secret names", receipt.RequiredSecretNames); err != nil {
			return err
		}
		if err := writeTextList("operator actions", receipt.OperatorActions); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported preflight output format %q", format)
	}
}

func annotatePreflightReceipt(receipt *preflightReceipt, cfg appconfig.Config) {
	receipt.RuntimeProfile = preflightRuntimeProfile(cfg)
	receipt.EnabledCapabilities = preflightEnabledCapabilities(cfg)
	receipt.RequiredBackingServices = preflightRequiredBackingServices(cfg)
	receipt.RequiredSecretNames = preflightRequiredSecretNames(cfg)
	receipt.OperatorActions = preflightOperatorActions(cfg)
}

func preflightRuntimeProfile(cfg appconfig.Config) string {
	if cfg.GraphStore.Driver == appconfig.GraphStoreDriverNeo4j {
		return "graph-enabled"
	}
	if cfg.AppendLog.Driver == appconfig.AppendLogDriverJetStream {
		return "durable-sync"
	}
	if cfg.StateStore.Driver == appconfig.StateStoreDriverPostgres {
		return "durable-api"
	}
	return "lightweight-api"
}

func preflightEnabledCapabilities(cfg appconfig.Config) []string {
	capabilities := map[string]struct{}{}
	if cfg.Auth.Enabled {
		capabilities["api.auth"] = struct{}{}
	}
	if cfg.RateLimit.Enabled {
		capabilities["api.rate_limit"] = struct{}{}
	}
	if cfg.StateStore.Driver == appconfig.StateStoreDriverPostgres {
		capabilities["state_store.postgres"] = struct{}{}
	}
	if cfg.AppendLog.Driver == appconfig.AppendLogDriverJetStream {
		capabilities["append_log.jetstream"] = struct{}{}
		if cfg.AppendLog.JetStreamRuntimeIndexEnabled {
			capabilities["append_log.runtime_index"] = struct{}{}
		}
	}
	if cfg.GraphStore.Driver == appconfig.GraphStoreDriverNeo4j {
		capabilities["graph_store.neo4j"] = struct{}{}
	}
	switch cfg.Cache.Driver {
	case appconfig.CacheDriverMemory:
		capabilities["cache.memory"] = struct{}{}
	case appconfig.CacheDriverRedis, appconfig.CacheDriverValkey:
		capabilities["cache."+cfg.Cache.Driver] = struct{}{}
	}
	if cfg.Auth.MCPOAuth.Enabled {
		capabilities["mcp.oauth"] = struct{}{}
	}
	if cfg.Auth.DeviceAuth.Enabled {
		capabilities["device_auth"] = struct{}{}
	}
	if cfg.OTEL.Enabled {
		capabilities["otel.export"] = struct{}{}
	}
	if strings.TrimSpace(cfg.GraphAgentLLM.Provider) != "" || strings.TrimSpace(cfg.GraphAgentLLM.OpenRouterAPIKey) != "" || strings.TrimSpace(cfg.GraphAgentLLM.BedrockRegion) != "" {
		capabilities["graph_agent.llm"] = struct{}{}
	}
	if strings.TrimSpace(cfg.GraphActions.AccessApprovals.BaseURL) != "" {
		capabilities["graph_actions.access_approvals"] = struct{}{}
	}
	return sortedPreflightSet(capabilities)
}

func preflightRequiredBackingServices(cfg appconfig.Config) []preflightBackingService {
	var services []preflightBackingService
	if cfg.StateStore.Driver == appconfig.StateStoreDriverPostgres {
		services = append(services, preflightBackingService{
			Name:        "postgres",
			RequiredFor: "durable runtime state, claims, findings, reports, OAuth, and device auth",
			ConfigVars:  []string{"CEREBRO_STATE_STORE_DRIVER", "CEREBRO_POSTGRES_DSN"},
		})
	}
	if cfg.AppendLog.Driver == appconfig.AppendLogDriverJetStream {
		services = append(services, preflightBackingService{
			Name:        "nats-jetstream",
			RequiredFor: "append-log sync, replay, and source runtime workflows",
			ConfigVars:  []string{"CEREBRO_APPEND_LOG_DRIVER", "CEREBRO_JETSTREAM_URL"},
		})
	}
	if cfg.GraphStore.Driver == appconfig.GraphStoreDriverNeo4j {
		services = append(services, preflightBackingService{
			Name:        "neo4j",
			RequiredFor: "graph projection, graph queries, graph health, and graph-agent flows",
			ConfigVars:  []string{"CEREBRO_GRAPH_STORE_DRIVER", "CEREBRO_NEO4J_URI", "CEREBRO_NEO4J_USERNAME", "CEREBRO_NEO4J_PASSWORD"},
		})
	}
	if cfg.Auth.MCPOAuth.Enabled {
		services = append(services, preflightBackingService{
			Name:        "upstream-oauth-provider",
			RequiredFor: "MCP OAuth authorization-code exchange and entitlement checks",
			ConfigVars:  []string{"CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER", "CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID", "CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET", "CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI"},
		})
	}
	if cfg.Cache.Driver == appconfig.CacheDriverRedis || cfg.Cache.Driver == appconfig.CacheDriverValkey {
		services = append(services, preflightBackingService{
			Name:        cfg.Cache.Driver,
			RequiredFor: "shared query cache",
			ConfigVars:  []string{"CEREBRO_CACHE_MODE", "CEREBRO_CACHE_URL"},
		})
	}
	if cfg.OTEL.Enabled {
		services = append(services, preflightBackingService{
			Name:        "otlp-collector",
			RequiredFor: "OpenTelemetry export",
			ConfigVars:  []string{"CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT"},
		})
	}
	if strings.TrimSpace(cfg.GraphActions.AccessApprovals.BaseURL) != "" {
		services = append(services, preflightBackingService{
			Name:        "access-approvals",
			RequiredFor: "provider-backed graph actions and reconciliation",
			ConfigVars:  []string{"CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BASE_URL", "CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN"},
		})
	}
	return services
}

func preflightRequiredSecretNames(cfg appconfig.Config) []string {
	secrets := map[string]struct{}{}
	if cfg.Auth.Enabled {
		if len(cfg.Auth.APIKeys) > 0 {
			secrets["CEREBRO_API_KEYS"] = struct{}{}
		}
		if len(cfg.Auth.APICredentials) > 0 {
			secrets["CEREBRO_API_CREDENTIALS_JSON"] = struct{}{}
		}
		if len(cfg.Auth.CapabilityTokenSecrets) > 0 || cfg.Auth.MCPOAuth.Enabled {
			secrets["CEREBRO_CAPABILITY_TOKEN_SECRETS"] = struct{}{}
		}
		if !cfg.Auth.HasCredentialMaterial() {
			secrets["one of CEREBRO_API_KEYS, CEREBRO_API_CREDENTIALS_JSON, or CEREBRO_CAPABILITY_TOKEN_SECRETS"] = struct{}{}
		}
	}
	if cfg.Auth.MCPOAuth.Enabled {
		if len(cfg.Auth.MCPOAuth.Clients) > 0 {
			secrets["CEREBRO_MCP_OAUTH_CLIENTS_JSON"] = struct{}{}
		}
		secrets["CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET"] = struct{}{}
	}
	if cfg.Auth.DeviceAuth.Enabled {
		secrets["CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON"] = struct{}{}
	}
	if cfg.StateStore.Driver == appconfig.StateStoreDriverPostgres {
		secrets["CEREBRO_POSTGRES_DSN"] = struct{}{}
	}
	if cfg.AppendLog.Driver == appconfig.AppendLogDriverJetStream {
		secrets["CEREBRO_JETSTREAM_URL"] = struct{}{}
	}
	if cfg.GraphStore.Driver == appconfig.GraphStoreDriverNeo4j {
		secrets["CEREBRO_NEO4J_URI"] = struct{}{}
		secrets["CEREBRO_NEO4J_USERNAME"] = struct{}{}
		secrets["CEREBRO_NEO4J_PASSWORD"] = struct{}{}
	}
	if cfg.Cache.Driver == appconfig.CacheDriverRedis || cfg.Cache.Driver == appconfig.CacheDriverValkey {
		secrets["CEREBRO_CACHE_URL"] = struct{}{}
	}
	if strings.TrimSpace(cfg.ConnectorCredentials.Key) != "" {
		secrets["CEREBRO_CONNECTOR_CREDENTIAL_KEY"] = struct{}{}
	}
	if strings.TrimSpace(cfg.ConnectorCredentials.TransitPrivateKey) != "" {
		secrets["CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY"] = struct{}{}
	}
	if strings.TrimSpace(cfg.GraphActions.AccessApprovals.BaseURL) != "" {
		secrets["CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN"] = struct{}{}
	}
	if cfg.OTEL.Enabled && len(cfg.OTEL.Headers) > 0 {
		secrets["CEREBRO_OTEL_EXPORTER_OTLP_HEADERS"] = struct{}{}
	}
	if strings.TrimSpace(cfg.GraphAgentLLM.OpenRouterAPIKey) != "" {
		secrets["CEREBRO_OPENROUTER_API_KEY"] = struct{}{}
	}
	return sortedPreflightSet(secrets)
}

func preflightOperatorActions(cfg appconfig.Config) []string {
	actions := []string{
		"wire liveness to /livez or /healthz and readiness to /health",
		"record the immutable image tag and config version before rollout",
		"keep account IDs, hostnames, schedules, secret paths, and tenant assignments in deployment records",
	}
	if cfg.Auth.Enabled {
		actions = append(actions, "rotate API credentials through the deployment secret manager")
	}
	if cfg.StateStore.Driver == appconfig.StateStoreDriverPostgres {
		actions = append(actions, "enable Postgres backups and test restore before broad rollout")
	}
	if cfg.AppendLog.Driver == appconfig.AppendLogDriverJetStream {
		actions = append(actions, "monitor JetStream stream health, storage, and consumer lag")
		actions = append(actions, "forbid overlapping source sync jobs for cursor-sensitive runtimes")
	}
	if cfg.GraphStore.Driver == appconfig.GraphStoreDriverNeo4j {
		actions = append(actions, "run graph health after rollout and before graph-dependent workflows")
	}
	if cfg.OTEL.Enabled {
		actions = append(actions, "confirm traces, metrics, and structured logs reach the deployed collector")
	}
	return actions
}

func sortedPreflightSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	sort.Strings(out)
	return out
}

func preflightErrorDetail(err error) string {
	if err == nil {
		return ""
	}
	detail := redactPreflightErrorDetail(sanitizeLogValue(err.Error()))
	if len(detail) > 240 {
		detail = detail[:240]
	}
	return detail
}

func redactPreflightErrorDetail(detail string) string {
	detail = preflightDetailURLRe.ReplaceAllStringFunc(detail, redactPreflightDetailURL)
	return preflightDetailSecretAssignmentRe.ReplaceAllString(detail, "$1=<redacted>")
}

func redactPreflightDetailURL(raw string) string {
	trailing := ""
	trimmed := strings.TrimRightFunc(raw, func(r rune) bool {
		switch r {
		case '.', ',', ';', ')', ']':
			trailing = string(r) + trailing
			return true
		default:
			return false
		}
	})
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "<redacted-url>" + trailing
	}
	parsed.User = nil
	if parsed.RawQuery != "" {
		query := parsed.Query()
		for key, values := range query {
			if preflightSensitiveQueryKey(key) {
				for i := range values {
					values[i] = "<redacted>"
				}
				query[key] = values
			}
		}
		parsed.RawQuery = query.Encode()
	}
	return parsed.String() + trailing
}

func preflightSensitiveQueryKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
	switch normalized {
	case "access_token", "api_key", "apikey", "auth", "authorization", "client_secret", "key", "password", "secret", "token":
		return true
	default:
		return false
	}
}
