package boot

import (
	"strings"
	"time"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/graph"
)

type InitConfig struct {
	WarehouseBackend string
}

// SubsystemConfig provides grouped, subsystem-scoped views over the env-backed
// top-level app config without changing the external config surface.
type SubsystemConfig struct {
	Agents   AgentConfig
	Runtime  RuntimeConfig
	Graph    GraphConfig
	AppState AppStateConfig
	Events   EventConfig
}

type AgentConfig struct {
	AnthropicAPIKey string
	OpenAIAPIKey    string
	GitHubToken     string
	GitLabToken     string
	GitLabBaseURL   string
	RemoteTools     agents.RemoteToolProviderConfig
	ToolPublisher   agents.ToolPublisherConfig
}

func (c AgentConfig) HasModelProvider() bool {
	return strings.TrimSpace(c.AnthropicAPIKey) != "" || strings.TrimSpace(c.OpenAIAPIKey) != ""
}

func (c AgentConfig) RemoteToolingEnabled() bool {
	return c.RemoteTools.Enabled || c.ToolPublisher.Enabled
}

type RuntimeConfig struct {
	ExecutionStoreFile string
}

type GraphConfig struct {
	SnapshotPath                 string
	SnapshotMaxRetained          int
	StoreBackend                 graph.StoreBackend
	SearchBackend                graph.EntitySearchBackendType
	SchemaValidationMode         string
	PropertyHistoryMaxEntries    int
	PropertyHistoryTTL           time.Duration
	WriterLeaseEnabled           bool
	WriterLeaseName              string
	WriterLeaseOwnerID           string
	WriterLeaseTTL               time.Duration
	WriterLeaseHeartbeat         time.Duration
	MigrateLegacyActivityOnStart bool
}

type AppStateConfig struct {
	JobDatabaseURL       string
	WarehouseBackend     string
	WarehousePostgresDSN string
}

func (c AppStateConfig) DatabaseURL() string {
	if dsn := strings.TrimSpace(c.JobDatabaseURL); dsn != "" {
		return dsn
	}
	if strings.EqualFold(strings.TrimSpace(c.WarehouseBackend), "postgres") {
		return strings.TrimSpace(c.WarehousePostgresDSN)
	}
	return ""
}

type EventConfig struct {
	NATSJetStreamEnabled     bool
	NATSConsumerEnabled      bool
	NATSConsumerSubjects     []string
	NATSConsumerDurable      string
	NATSConsumerDrainTimeout time.Duration
	AlertRouterEnabled       bool
	AlertRouterConfigPath    string
	AlertRouterNotifyPrefix  string
}

func (c EventConfig) AlertRoutingEnabled() bool {
	return c.AlertRouterEnabled && c.NATSJetStreamEnabled
}

func (c EventConfig) TapGraphConsumerEnabled() bool {
	return c.NATSConsumerEnabled
}
