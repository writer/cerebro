package app

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/agents"
)

func findRegisteredAgentTool(tools []agents.Tool, name string) *agents.Tool {
	for i := range tools {
		if tools[i].Name == name {
			return &tools[i]
		}
	}
	return nil
}

func TestRemoteToolProviderConfigFromConfig(t *testing.T) {
	cfg := &Config{
		AgentRemoteToolsEnabled:         true,
		NATSJetStreamURLs:               []string{"nats://a:4222", "nats://b:4222"},
		AgentRemoteToolsManifestSubject: "ensemble.manifest",
		AgentRemoteToolsRequestPrefix:   "ensemble.request",
		AgentRemoteToolsDiscoverTimeout: 7 * time.Second,
		AgentRemoteToolsRequestTimeout:  42 * time.Second,
		AgentRemoteToolsMaxTools:        123,
		NATSJetStreamConnectTimeout:     3 * time.Second,
		NATSJetStreamAuthMode:           "userpass",
		NATSJetStreamUsername:           "user-a",
		NATSJetStreamPassword:           "pass-a",
		NATSJetStreamNKeySeed:           "seed-a",
		NATSJetStreamUserJWT:            "jwt-a",
		NATSJetStreamTLSEnabled:         true,
		NATSJetStreamTLSCAFile:          "/tmp/ca.pem",
		NATSJetStreamTLSCertFile:        "/tmp/cert.pem",
		NATSJetStreamTLSKeyFile:         "/tmp/key.pem",
		NATSJetStreamTLSServerName:      "nats.internal",
		NATSJetStreamTLSInsecure:        true,
		AllowInsecureTLS:                true,
	}

	got := remoteToolProviderConfigFromConfig(cfg)
	want := agents.RemoteToolProviderConfig{
		Enabled:               true,
		URLs:                  []string{"nats://a:4222", "nats://b:4222"},
		ManifestSubject:       "ensemble.manifest",
		RequestPrefix:         "ensemble.request",
		DiscoverTimeout:       7 * time.Second,
		RequestTimeout:        42 * time.Second,
		MaxTools:              123,
		ConnectTimeout:        3 * time.Second,
		AuthMode:              "userpass",
		Username:              "user-a",
		Password:              "pass-a",
		NKeySeed:              "seed-a",
		UserJWT:               "jwt-a",
		TLSEnabled:            true,
		TLSCAFile:             "/tmp/ca.pem",
		TLSCertFile:           "/tmp/cert.pem",
		TLSKeyFile:            "/tmp/key.pem",
		TLSServerName:         "nats.internal",
		TLSInsecureSkipVerify: true,
		AllowInsecureTLS:      true,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected remote tool provider config:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestToolPublisherConfigFromConfig(t *testing.T) {
	cfg := &Config{
		AgentToolPublisherEnabled:         true,
		NATSJetStreamURLs:                 []string{"nats://a:4222", "nats://b:4222"},
		AgentToolPublisherManifestSubject: "cerebro.manifest",
		AgentToolPublisherRequestPrefix:   "cerebro.request",
		AgentToolPublisherRequestTimeout:  55 * time.Second,
		NATSJetStreamConnectTimeout:       4 * time.Second,
		NATSJetStreamAuthMode:             "jwt",
		NATSJetStreamUsername:             "user-b",
		NATSJetStreamPassword:             "pass-b",
		NATSJetStreamNKeySeed:             "seed-b",
		NATSJetStreamUserJWT:              "jwt-b",
		NATSJetStreamTLSEnabled:           true,
		NATSJetStreamTLSCAFile:            "/tmp/ca2.pem",
		NATSJetStreamTLSCertFile:          "/tmp/cert2.pem",
		NATSJetStreamTLSKeyFile:           "/tmp/key2.pem",
		NATSJetStreamTLSServerName:        "nats.tools.internal",
		NATSJetStreamTLSInsecure:          true,
		AllowInsecureTLS:                  true,
	}

	got := toolPublisherConfigFromConfig(cfg)
	want := agents.ToolPublisherConfig{
		Enabled:               true,
		URLs:                  []string{"nats://a:4222", "nats://b:4222"},
		ManifestSubject:       "cerebro.manifest",
		RequestPrefix:         "cerebro.request",
		RequestTimeout:        55 * time.Second,
		ConnectTimeout:        4 * time.Second,
		AuthMode:              "jwt",
		Username:              "user-b",
		Password:              "pass-b",
		NKeySeed:              "seed-b",
		UserJWT:               "jwt-b",
		TLSEnabled:            true,
		TLSCAFile:             "/tmp/ca2.pem",
		TLSCertFile:           "/tmp/cert2.pem",
		TLSKeyFile:            "/tmp/key2.pem",
		TLSServerName:         "nats.tools.internal",
		TLSInsecureSkipVerify: true,
		AllowInsecureTLS:      true,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected tool publisher config:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestRegisterConfiguredAIAgents(t *testing.T) {
	testCases := []struct {
		name         string
		cfg          *Config
		expectedIDs  []string
		unexpectedID string
	}{
		{
			name:        "no providers configured",
			cfg:         &Config{},
			expectedIDs: nil,
		},
		{
			name: "anthropic only",
			cfg: &Config{
				AnthropicAPIKey: "anthropic-key",
			},
			expectedIDs:  []string{"security-analyst"},
			unexpectedID: "incident-responder",
		},
		{
			name: "openai only",
			cfg: &Config{
				OpenAIAPIKey: "openai-key",
			},
			expectedIDs:  []string{"incident-responder"},
			unexpectedID: "security-analyst",
		},
		{
			name: "both providers configured",
			cfg: &Config{
				AnthropicAPIKey: "anthropic-key",
				OpenAIAPIKey:    "openai-key",
			},
			expectedIDs: []string{"incident-responder", "security-analyst"},
		},
	}

	tools := []agents.Tool{{Name: "lookupFinding", Description: "lookup finding details"}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			registry := agents.NewAgentRegistry()
			registerConfiguredAIAgents(registry, tc.cfg, tools)

			listed := registry.ListAgents()
			if len(listed) != len(tc.expectedIDs) {
				t.Fatalf("expected %d agents, got %d", len(tc.expectedIDs), len(listed))
			}

			var gotIDs []string
			for _, a := range listed {
				gotIDs = append(gotIDs, a.ID)
			}
			sort.Strings(gotIDs)
			sort.Strings(tc.expectedIDs)
			if !reflect.DeepEqual(gotIDs, tc.expectedIDs) {
				t.Fatalf("unexpected agent IDs: got %v want %v", gotIDs, tc.expectedIDs)
			}

			for _, id := range tc.expectedIDs {
				agent, ok := registry.GetAgent(id)
				if !ok {
					t.Fatalf("expected agent %q to be registered", id)
				}
				if len(agent.Tools) != len(tools) {
					t.Fatalf("expected %d tools for %s, got %d", len(tools), id, len(agent.Tools))
				}
				if agent.Memory == nil {
					t.Fatalf("expected non-nil memory for %s", id)
					return
				}
			}

			if tc.unexpectedID != "" {
				if _, ok := registry.GetAgent(tc.unexpectedID); ok {
					t.Fatalf("did not expect agent %q to be registered", tc.unexpectedID)
				}
			}
		})
	}
}

func TestSyncConfiguredAIAgentsPreservesMemoryAndRemovesDisabledAgents(t *testing.T) {
	registry := agents.NewAgentRegistry()
	existingMemory := agents.NewMemory(10)
	registry.RegisterAgent(&agents.Agent{
		ID:     "security-analyst",
		Name:   "Security Analyst",
		Tools:  []agents.Tool{{Name: "query_assets", Description: "stale"}, {Name: "remote_tool", Description: "remote"}},
		Memory: existingMemory,
	})

	cfg := &Config{
		OpenAIAPIKey: "openai-key",
	}
	tools := []agents.Tool{{Name: "query_assets", Description: "fresh"}}

	syncConfiguredAIAgents(registry, cfg, tools)

	if _, ok := registry.GetAgent("security-analyst"); ok {
		t.Fatal("expected security-analyst to be removed when Anthropic key is absent")
	}

	agent, ok := registry.GetAgent("incident-responder")
	if !ok {
		t.Fatal("expected incident-responder to be registered")
	}
	if agent.Memory == nil {
		t.Fatal("expected incident-responder memory to be initialized")
		return
	}
	queryAssets := findRegisteredAgentTool(agent.Tools, "query_assets")
	if queryAssets == nil || queryAssets.Description != "fresh" {
		t.Fatalf("expected incident-responder query_assets tool to be refreshed, got %#v", queryAssets)
	}
}

func TestSyncConfiguredAIAgentsPreservesExistingAgentMemoryAndExtraTools(t *testing.T) {
	registry := agents.NewAgentRegistry()
	existingMemory := agents.NewMemory(10)
	registry.RegisterAgent(&agents.Agent{
		ID:     "security-analyst",
		Name:   "Security Analyst",
		Tools:  []agents.Tool{{Name: "query_assets", Description: "stale"}, {Name: "remote_tool", Description: "remote"}},
		Memory: existingMemory,
	})

	cfg := &Config{
		AnthropicAPIKey: "anthropic-key",
	}
	tools := []agents.Tool{{Name: "query_assets", Description: "fresh"}, {Name: "list_findings", Description: "list"}}

	syncConfiguredAIAgents(registry, cfg, tools)

	agent, ok := registry.GetAgent("security-analyst")
	if !ok {
		t.Fatal("expected security-analyst to remain registered")
	}
	if agent.Memory != existingMemory {
		t.Fatal("expected existing memory to be preserved")
	}
	if tool := findRegisteredAgentTool(agent.Tools, "query_assets"); tool == nil || tool.Description != "fresh" {
		t.Fatalf("expected query_assets tool to be refreshed, got %#v", tool)
	}
	if tool := findRegisteredAgentTool(agent.Tools, "remote_tool"); tool == nil || tool.Description != "remote" {
		t.Fatalf("expected remote_tool to be preserved, got %#v", tool)
	}
}

func TestAppSyncConfiguredAIAgentsIncludesCachedRemoteToolsForNewAgents(t *testing.T) {
	application := &App{
		Agents:           agents.NewAgentRegistry(),
		remoteAgentTools: []agents.Tool{{Name: "remote_tool", Description: "remote"}},
	}

	application.syncConfiguredAIAgents(&Config{
		OpenAIAPIKey: "openai-key",
	})

	agent, ok := application.Agents.GetAgent("incident-responder")
	if !ok {
		t.Fatal("expected incident-responder to be registered")
	}
	if tool := findRegisteredAgentTool(agent.Tools, "remote_tool"); tool == nil || tool.Description != "remote" {
		t.Fatalf("expected remote_tool to be included for newly registered agent, got %#v", tool)
	}
}
