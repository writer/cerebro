package app

import (
	"reflect"
	"testing"
	"time"
)

func TestBuildSubsystemConfig_GroupsSubsystemViews(t *testing.T) {
	cfg := &Config{
		AnthropicAPIKey:                   "anthropic-key",
		GitHubToken:                       "github-token",
		GitLabToken:                       "gitlab-token",
		GitLabBaseURL:                     "https://gitlab.example.com",
		AgentRemoteToolsEnabled:           true,
		AgentToolPublisherEnabled:         true,
		GraphSnapshotPath:                 "/tmp/graph",
		GraphSnapshotMaxRetained:          7,
		GraphStoreBackend:                 "sqlite",
		GraphSearchBackend:                "opensearch",
		GraphSchemaValidationMode:         "strict",
		GraphPropertyHistoryMaxEntries:    42,
		GraphPropertyHistoryTTL:           15 * time.Minute,
		GraphWriterLeaseEnabled:           true,
		GraphWriterLeaseName:              "writer-lease",
		GraphWriterLeaseOwnerID:           "writer-a",
		GraphWriterLeaseTTL:               30 * time.Second,
		GraphWriterLeaseHeartbeat:         10 * time.Second,
		GraphMigrateLegacyActivityOnStart: true,
		JobDatabaseURL:                    "postgres://jobs",
		ExecutionStoreFile:                "/tmp/executions.db",
		NATSJetStreamEnabled:              true,
		NATSConsumerEnabled:               true,
		NATSConsumerSubjects:              []string{"graph.events", "graph.rebuilds"},
		NATSConsumerDurable:               "graph-worker",
		NATSConsumerDrainTimeout:          12 * time.Second,
		AlertRouterEnabled:                true,
		AlertRouterConfigPath:             "/tmp/alert-router.yaml",
		AlertRouterNotifyPrefix:           "ensemble.notify",
	}

	subsystems := cfg.BuildSubsystemConfig()

	if !subsystems.Agents.HasModelProvider() {
		t.Fatal("expected agent config to report a configured model provider")
	}
	if !subsystems.Agents.RemoteToolingEnabled() {
		t.Fatal("expected agent config to report remote tooling enabled")
	}
	if got, want := subsystems.Runtime.ExecutionStoreFile, cfg.ExecutionStoreFile; got != want {
		t.Fatalf("runtime execution store file = %q, want %q", got, want)
	}
	if got, want := subsystems.AppState.DatabaseURL(), cfg.JobDatabaseURL; got != want {
		t.Fatalf("appstate database url = %q, want %q", got, want)
	}
	if got, want := subsystems.Graph.SnapshotPath, cfg.GraphSnapshotPath; got != want {
		t.Fatalf("graph snapshot path = %q, want %q", got, want)
	}
	if got, want := subsystems.Graph.PropertyHistoryTTL, cfg.GraphPropertyHistoryTTL; got != want {
		t.Fatalf("graph history ttl = %s, want %s", got, want)
	}
	if !subsystems.Events.AlertRoutingEnabled() {
		t.Fatal("expected alert routing to be enabled when JetStream is enabled")
	}
	if !subsystems.Events.TapGraphConsumerEnabled() {
		t.Fatal("expected tap graph consumer to be enabled")
	}
	if got, want := subsystems.Events.NATSConsumerDurable, cfg.NATSConsumerDurable; got != want {
		t.Fatalf("tap durable = %q, want %q", got, want)
	}
	if got, want := subsystems.Events.NATSConsumerSubjects, cfg.NATSConsumerSubjects; !reflect.DeepEqual(got, want) {
		t.Fatalf("tap subjects = %v, want %v", got, want)
	}

	subsystems.Events.NATSConsumerSubjects[0] = "changed"
	if cfg.NATSConsumerSubjects[0] != "graph.events" {
		t.Fatal("expected event subjects to be copied when building subsystem config")
	}
}

func TestAppStateConfigDatabaseURLFallsBackToWarehousePostgresDSN(t *testing.T) {
	cfg := AppStateConfig{
		WarehouseBackend:     "postgres",
		WarehousePostgresDSN: "postgres://warehouse",
	}

	if got, want := cfg.DatabaseURL(), "postgres://warehouse"; got != want {
		t.Fatalf("DatabaseURL() = %q, want %q", got, want)
	}
}

func TestEventConfigAlertRoutingEnabledRequiresJetStream(t *testing.T) {
	cfg := EventConfig{
		NATSJetStreamEnabled: false,
		AlertRouterEnabled:   true,
	}

	if cfg.AlertRoutingEnabled() {
		t.Fatal("expected alert routing to require JetStream")
	}
}
